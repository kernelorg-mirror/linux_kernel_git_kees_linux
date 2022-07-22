// SPDX-License-Identifier: GPL-2.0-only
/*
 * This module has so many bugs.
 *
 * API is via /sys/devices/virtual/misc/workshop/{offset,public,secret}
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sysfs.h>

#define SECRET "Gur cnffcuenfr vf: 'Pna jr hfr Ehfg abj?'"
#define PUBLIC "Hello! Nice to meet you."

struct workshop_info {
	int	offset;
	char	secret[sizeof(SECRET)];
	char	public[sizeof(PUBLIC)];
};

static struct workshop_info *workshop;
static char *important;

/* Worst encryption evar. */
static void workshop_encrypt(char *buf)
{
	int i;

	for (i = 0; buf[i]; i ++) {
		if (buf[i] >= 'a' && buf[i] <= 'z')
			buf[i] = 'a' + (((buf[i] - 'a') + 13) % 26);
		if (buf[i] >= 'A' && buf[i] <= 'Z')
			buf[i] = 'A' + (((buf[i] - 'A') + 13) % 26);
	}
}

static ssize_t workshop_offset_show(struct device *dev,
				    struct device_attribute *attr,
				    char *buf)
{
	return sysfs_emit(buf, "%d\n", workshop->offset);
}

static ssize_t workshop_offset_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t len)
{
	int rc;

	rc = kstrtoint(buf, 0, &workshop->offset);
	if (rc)
		return rc;

	/* Report that all bytes have been consumed. */
	return len;
}

static ssize_t workshop_public_show(struct device *dev,
				    struct device_attribute *attr,
				    char *buf)
{
	return sysfs_emit(buf, "%s\n", &workshop->public[workshop->offset]);
}

static ssize_t workshop_public_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t len)
{
	strscpy(workshop->public, buf, len);

	/* Report that all bytes have been consumed. */
	return len;
}

static ssize_t workshop_important_show(struct device *dev,
				       struct device_attribute *attr,
				       char *buf)
{
	return sysfs_emit(buf, "%s\n", important);
}

static ssize_t workshop_secret_show(struct device *dev,
				    struct device_attribute *attr,
				    char *buf)
{
	char encrypted[sizeof(workshop->secret)];

	/* Don't expose the decrypted version; re-encrypt before showing. */
	strcpy(encrypted, workshop->secret);
	workshop_encrypt(encrypted);

	return sysfs_emit(buf, "%s\n", encrypted);
}

static DEVICE_ATTR(important, 0444, workshop_important_show, NULL);
static DEVICE_ATTR(offset, 0600, workshop_offset_show, workshop_offset_store);
static DEVICE_ATTR(public, 0644, workshop_public_show, workshop_public_store);
/* Make the secret unreadable! */
static DEVICE_ATTR(secret, 0000, workshop_secret_show, NULL);

static struct attribute *workshop_dev_attrs[] = {
	&dev_attr_important.attr,
	&dev_attr_offset.attr,
	&dev_attr_public.attr,
	&dev_attr_secret.attr,
	NULL
};

ATTRIBUTE_GROUPS(workshop_dev);

static struct miscdevice workshop_misc = {
	.name =		"workshop",
	.minor =	MISC_DYNAMIC_MINOR,
	.groups =	workshop_dev_groups,
};

static int __init workshop_init(void)
{
	int rc;
	char *alloc;
	size_t size = sizeof(*workshop) + 32;

	alloc = kzalloc(size, GFP_KERNEL);
	if (!alloc) {
		rc = -ENOMEM;
		goto failure;
	}
	workshop = (void *)alloc;

	/* Fill memory after workshop_info with NUL-terminated "X" string. */
	important = alloc + sizeof(*workshop);
	memset(important, 'X', size - sizeof(*workshop) - 1);

	*workshop = (struct workshop_info){
		.offset = 0,
		.secret = SECRET,
		.public = PUBLIC,
	};

	rc = misc_register(&workshop_misc);
	if (rc) {
		pr_err("misc_register failed: %d\n", rc);
		kfree(workshop);
		goto failure;
	}

	/* Decrypt the secret in memory. */
	workshop_encrypt(workshop->secret);

	pr_warn("loaded\n");

failure:
	return rc;
}
module_init(workshop_init);

static void __exit workshop_exit(void)
{
	misc_deregister(&workshop_misc);
	kfree(workshop);

	pr_warn("exited\n");
}
module_exit(workshop_exit);

MODULE_AUTHOR("Kees Cook <keescook@chromium.org>");
MODULE_LICENSE("GPL");
