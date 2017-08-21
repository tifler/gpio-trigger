/*
 * arch/arm/mach-gdm/gpio-trigger.c - GPIO Trigger API
 *
 * Copyright (c) 2015-2017 Anapass Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#define pr_fmt(fmt)                     "[trigger] " fmt
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/suspend.h>
#include <linux/debugfs.h>
#include <linux/gpio.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <mach/pm.h>
#include <mach/regs.h>
#include <mach/gpio-trigger.h>

#include "common.h"

/*****************************************************************************/

#define	MAX_NAME_LENGTH		(127)
#define	MIN(a, b)		((a) < (b) ? (a) : (b))
#define	GPIO_TRIGGER_CHANNELS	ARRAY_SIZE(gpio_trigger_channels)
#define	CHID(c)			((((unsigned long)c) - \
				  (unsigned long)&gpio_trigger_channels[0]) /\
				 sizeof(*c))

#define	__CHECK_LINE__			pr_info("[%s:%d]\n", __FILE__, __LINE__)

/*****************************************************************************/

struct gpio_trigger_client;

struct gpio_trigger_channel {
	int gpio;
	char *name;
	bool high;				/* high at bootup */
	u32 log;
	struct list_head clients;
	struct gpio_trigger_client *owner;
	struct mutex mutex;
	struct dentry *root;
};

struct gpio_trigger_client {
	struct gpio_trigger_channel *channel;
	struct list_head entry;
	char *name;
	int maxcnt;
	int refcnt;
	bool low_active;
	bool from_userspace;
	struct dentry *root;
	spinlock_t slock;
};

static struct gpio_trigger_channel gpio_trigger_channels[] = {
	[0] = {
		.gpio = GDM_GPC(16),
		.name = "GPC16",
	},
};

/*****************************************************************************/

static void gpio_trigger_update(struct gpio_trigger_client *client)
{
	if (!client || !client->channel || !client->channel->owner)
		return;

	if (client->channel->owner != client)
		return;

	if (client->refcnt >= client->maxcnt)
		__gpio_set_value(client->channel->gpio, client->low_active ? 0 : 1);
	else
		__gpio_set_value(client->channel->gpio, client->low_active ? 1 : 0);

	if (client->channel->log)
		pr_info("%s@%s=%d(cur=%d, max=%d)\n",
			client->name, client->channel->name,
			__gpio_get_value(client->channel->gpio),
			client->refcnt, client->maxcnt);
}

static void gpio_trigger_alt(struct gpio_trigger_client *client, int value)
{
	spin_lock(&client->slock);
	client->refcnt += value;
	if (client->refcnt < 0 || client->refcnt > client->maxcnt)
		pr_warn("unbalanced refcnt(%d, 0-%d)\n",
			client->refcnt, client->maxcnt);
	gpio_trigger_update(client);
	spin_unlock(&client->slock);
}

/*****************************************************************************/

static int gpio_trigger_show_add(struct seq_file *seq, void *unused)
{
	return 0;
}

static int gpio_trigger_open_add(struct inode *inode, struct file *file)
{
	return single_open(file, gpio_trigger_show_add, inode->i_private);
}

static ssize_t gpio_trigger_write_add(struct file *f,
					const char __user *userbuf,
					size_t length, loff_t *off)
{
	char name[MAX_NAME_LENGTH + 1], *p;
	struct gpio_trigger_channel *chan;
	struct gpio_trigger_client *client;

	chan = (struct gpio_trigger_channel *)f->f_inode->i_private;
	BUG_ON(!chan);

	if (copy_from_user(name, userbuf, MIN(length, MAX_NAME_LENGTH))) {
		length = -EFAULT;
		goto done;
	}

	p = strchr(name, '\n');
	if (p)
		*p = 0;

	mutex_lock(&chan->mutex);

	list_for_each_entry(client, &chan->clients, entry) {
		if (!strcmp(client->name, name)) {
			pr_err("%s: already registered.\n", name);
			mutex_unlock(&chan->mutex);
			goto done;
		}
	}

	mutex_unlock(&chan->mutex);

	client = gpio_trigger_create_client(name, 1, false);
	if (!client) {
		pr_err("%s: failed to create client.\n", name);
		goto done;
	}
	client->from_userspace = true;

	gpio_trigger_attach(client, CHID(chan));

done:
	return length;
}

static struct file_operations fops_add = {
	.open = gpio_trigger_open_add,
	.read = seq_read,
	.write = gpio_trigger_write_add,
	.llseek = seq_lseek,
	.release = single_release,
};

static int gpio_trigger_show_remove(struct seq_file *seq, void *unused)
{
	return 0;
}

static int gpio_trigger_open_remove(struct inode *inode, struct file *file)
{
	return single_open(file, gpio_trigger_show_remove, inode->i_private);
}

static ssize_t gpio_trigger_write_remove(struct file *f,
					const char __user *userbuf,
					size_t length, loff_t *off)
{
	char name[MAX_NAME_LENGTH + 1], *p;
	struct gpio_trigger_channel *chan;
	struct gpio_trigger_client *c, *client = NULL;

	chan = (struct gpio_trigger_channel *)f->f_inode->i_private;
	BUG_ON(!chan);

	if (copy_from_user(name, userbuf, MIN(length, MAX_NAME_LENGTH))) {
		length = -EFAULT;
		goto done;
	}

	p = strchr(name, '\n');
	if (p)
		*p = 0;

	mutex_lock(&chan->mutex);

	list_for_each_entry(c, &chan->clients, entry) {
		if (!strcmp(c->name, name)) {
			client = c;
			break;
		}
	}

	mutex_unlock(&chan->mutex);

	if (!client) {
		pr_err("%s: Not found.\n", name);
		goto done;
	}

	if (!client->from_userspace) {
		pr_err("%s: Kernel owns.\n", name);
		goto done;
	}

	gpio_trigger_detach(client);
	gpio_trigger_destroy_client(client);

done:
	return length;
}

static struct file_operations fops_remove = {
	.open = gpio_trigger_open_remove,
	.read = seq_read,
	.write = gpio_trigger_write_remove,
	.llseek = seq_lseek,
	.release = single_release,
};

/*****************************************************************************/

static int gpio_trigger_show_owner(struct seq_file *seq, void *unused)
{
	struct gpio_trigger_channel *chan;

	chan = (struct gpio_trigger_channel *)seq->private;
	BUG_ON(!chan);

	mutex_lock(&chan->mutex);
	seq_printf(seq, "%s\n", chan->owner ? chan->owner->name : "(null)");
	mutex_unlock(&chan->mutex);

	return 0;
}

static int gpio_trigger_open_owner(struct inode *inode, struct file *file)
{
	return single_open(file, gpio_trigger_show_owner, inode->i_private);
}

static ssize_t gpio_trigger_write_owner(struct file *f,
					const char __user *userbuf,
					size_t length, loff_t *off)
{
	char name[MAX_NAME_LENGTH + 1], *p;
	struct gpio_trigger_channel *chan;
	struct gpio_trigger_client *c, *client = NULL;

	chan = (struct gpio_trigger_channel *)f->f_inode->i_private;
	BUG_ON(!chan);

	if (copy_from_user(name, userbuf, MIN(length, MAX_NAME_LENGTH))) {
		length = -EFAULT;
		goto done;
	}

	p = strchr(name, '\n');
	if (p)
		*p = 0;

	mutex_lock(&chan->mutex);

	list_for_each_entry(c, &chan->clients, entry) {
		if (!strcmp(c->name, name)) {
			client = c;
			break;
		}
	}
	chan->owner = client;
	if (chan->owner) {
		spin_lock(&chan->owner->slock);
		gpio_trigger_update(chan->owner);
		spin_unlock(&chan->owner->slock);
	}
	else {
		/* XXX am i right? */
		__gpio_set_value(chan->gpio, chan->high ? 1 : 0);
	}

	mutex_unlock(&chan->mutex);

done:
	return length;
}

static struct file_operations fops_owner = {
	.open = gpio_trigger_open_owner,
	.read = seq_read,
	.write = gpio_trigger_write_owner,
	.llseek = seq_lseek,
	.release = single_release,
};

static int inc_debug_set(void *data, u64 val)
{
	struct gpio_trigger_client *client = (struct gpio_trigger_client *)data;

	spin_lock(&client->slock);
	if (val) {
		client->refcnt += (int)val;
		gpio_trigger_update(client);
	}
	spin_unlock(&client->slock);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(fops_inc, NULL, inc_debug_set, "%llu\n");

static int dec_debug_set(void *data, u64 val)
{
	struct gpio_trigger_client *client = (struct gpio_trigger_client *)data;

	spin_lock(&client->slock);
	if (val) {
		client->refcnt -= (int)val;
		gpio_trigger_update(client);
	}
	spin_unlock(&client->slock);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(fops_dec, NULL, dec_debug_set, "%llu\n");

static int maxcnt_debug_get(void *data, u64 *val)
{
	struct gpio_trigger_client *client = (struct gpio_trigger_client *)data;

	spin_lock(&client->slock);
	*val = client->maxcnt;
	spin_unlock(&client->slock);

	return 0;
}

static int maxcnt_debug_set(void *data, u64 val)
{
	struct gpio_trigger_client *client = (struct gpio_trigger_client *)data;

	spin_lock(&client->slock);
	if (val)
		client->maxcnt = (int)val;
	gpio_trigger_update(client);
	spin_unlock(&client->slock);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(fops_maxcnt, maxcnt_debug_get, maxcnt_debug_set, "%llu\n");

static int refcnt_debug_get(void *data, u64 *val)
{
	struct gpio_trigger_client *client = (struct gpio_trigger_client *)data;

	spin_lock(&client->slock);
	*val = client->refcnt;
	spin_unlock(&client->slock);

	return 0;
}

static int refcnt_debug_set(void *data, u64 val)
{
	struct gpio_trigger_client *client = (struct gpio_trigger_client *)data;

	spin_lock(&client->slock);
	if (val)
		client->refcnt = (int)val;
	gpio_trigger_update(client);
	spin_unlock(&client->slock);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(fops_refcnt, refcnt_debug_get, refcnt_debug_set, "%llu\n");

static int low_active_debug_get(void *data, u64 *val)
{
	struct gpio_trigger_client *client = (struct gpio_trigger_client *)data;

	spin_lock(&client->slock);
	*val = client->low_active ? 1 : 0;
	spin_unlock(&client->slock);

	return 0;
}

static int low_active_debug_set(void *data, u64 val)
{
	struct gpio_trigger_client *client = (struct gpio_trigger_client *)data;

	spin_lock(&client->slock);
	client->low_active = !!val;
	gpio_trigger_update(client);
	spin_unlock(&client->slock);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(fops_low_active,
			low_active_debug_get, low_active_debug_set, "%llu\n");

/*****************************************************************************/

static void __init gpio_trigger_init_channel(struct gpio_trigger_channel *chan,
					     int id)
{
	int ret;
	char name[32];
	struct dentry *node;

	ret = gpio_request(chan->gpio, chan->name);
	BUG_ON(ret);

	ret = gpio_direction_output(chan->gpio, chan->high ? 1 : 0);
	BUG_ON(ret);

	mutex_init(&chan->mutex);
	INIT_LIST_HEAD(&chan->clients);

	sprintf(name, "trigger-%d", id);
	chan->root = debugfs_create_dir(name, NULL);
	BUG_ON(!chan->root);

	node = debugfs_create_file("owner", 0664, chan->root, chan, &fops_owner);
	BUG_ON(!node);

	node = debugfs_create_file("add", 0664, chan->root, chan, &fops_add);
	BUG_ON(!node);

	node = debugfs_create_file("remove", 0664, chan->root, chan, &fops_remove);
	BUG_ON(!node);

	node = debugfs_create_u32("gpio", 0440, chan->root, &chan->gpio);
	BUG_ON(!node);

	node = debugfs_create_bool("log", 0664, chan->root, &chan->log);
	BUG_ON(!node);
}

static int __init gpio_trigger_init(void)
{
	int i;

	for (i = 0; i < GPIO_TRIGGER_CHANNELS; i++)
		gpio_trigger_init_channel(&gpio_trigger_channels[i], i);

	pr_info("Registered gpio-trigger %d channels.\n", i);

	return 0;
}
arch_initcall(gpio_trigger_init);

/*****************************************************************************/

struct gpio_trigger_client *gpio_trigger_create_client(const char *name,
						       int threshold,
						       bool low_active)
{
	struct gpio_trigger_client *client;

	client = kzalloc(sizeof(*client), GFP_KERNEL);
	BUG_ON(!client);

	client->maxcnt = threshold;
	client->low_active = low_active;
	INIT_LIST_HEAD(&client->entry);
	spin_lock_init(&client->slock);
	client->name = kstrdup(name, GFP_KERNEL);
	BUG_ON(!client->name);

	return client;
}
EXPORT_SYMBOL(gpio_trigger_create_client);

void gpio_trigger_destroy_client(struct gpio_trigger_client *client)
{
	kfree(client->name);
	kfree(client);
}
EXPORT_SYMBOL(gpio_trigger_destroy_client);

void gpio_trigger_attach(struct gpio_trigger_client *client, int chid)
{
	struct dentry *node;
	struct gpio_trigger_channel *chan;

	BUG_ON(!client);
	BUG_ON(client->channel);
	BUG_ON(chid < 0 || chid >= GPIO_TRIGGER_CHANNELS);

	chan = &gpio_trigger_channels[chid];

	mutex_lock(&chan->mutex);
	list_add_tail(&client->entry, &chan->clients);
	client->root = debugfs_create_dir(client->name, chan->root);
	BUG_ON(!client->root);
	node = debugfs_create_file("inc", 0664, client->root, client, &fops_inc);
	BUG_ON(!node);
	node = debugfs_create_file("dec", 0664, client->root, client, &fops_dec);
	BUG_ON(!node);
	node = debugfs_create_file("maxcnt", 0664, client->root, client, &fops_maxcnt);
	BUG_ON(!node);
	node = debugfs_create_file("refcnt", 0664, client->root, client, &fops_refcnt);
	BUG_ON(!node);
	node = debugfs_create_file("low_active", 0664, client->root, client, &fops_low_active);
	BUG_ON(!node);
	mutex_unlock(&chan->mutex);

	client->channel = chan;
}
EXPORT_SYMBOL(gpio_trigger_attach);

void gpio_trigger_detach(struct gpio_trigger_client *client)
{
	BUG_ON(!client);
	BUG_ON(!client->channel);

	mutex_lock(&client->channel->mutex);
	list_del(&client->entry);
	if (client->channel->owner == client) {
		client->channel->owner = (struct gpio_trigger_client *)NULL;
		/* XXX am i right? */
		__gpio_set_value(client->channel->gpio,
				 client->channel->high ? 1 : 0);
	}

	debugfs_remove_recursive(client->root);
	mutex_unlock(&client->channel->mutex);
	client->channel = (struct gpio_trigger_channel *)NULL;
}
EXPORT_SYMBOL(gpio_trigger_detach);

void gpio_trigger_inc(struct gpio_trigger_client *client)
{
	gpio_trigger_alt(client, 1);
}
EXPORT_SYMBOL(gpio_trigger_inc);

void gpio_trigger_dec(struct gpio_trigger_client *client)
{
	gpio_trigger_alt(client, -1);
}
EXPORT_SYMBOL(gpio_trigger_dec);
