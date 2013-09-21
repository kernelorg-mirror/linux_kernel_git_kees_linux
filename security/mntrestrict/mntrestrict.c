/*
 * Mount Restriction Security Module
 *
 * Copyright 2011-2015 Google Inc.
 *
 * Authors:
 *      Stephan Uphoff  <ups@google.com>
 *      Kees Cook       <keescook@chromium.org>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define pr_fmt(fmt) "MntRestrict: " fmt

#include <linux/module.h>
#include <linux/lsm_hooks.h>
#include <linux/namei.h>
#include <linux/sched.h>

static int mntrestrict_sb_mount(const char *dev_name, struct path *path,
				const char *type, unsigned long flags,
				void *data)
{
	/* Check how many symlinks we've currently followed. */
	if (get_total_link_count() == 0)
		return 0;

	pr_notice("Mount path with symlinks prohibited - pid=%d\n",
		  task_pid_nr(current));
	return -ELOOP;
}

static struct security_hook_list mntrestrict_hooks[] = {
	LSM_HOOK_INIT(sb_mount, mntrestrict_sb_mount),
};

void __init mntrestrict_add_hooks(void)
{
	pr_info("symlink mount destinations will be blocked.\n");
	security_add_hooks(mntrestrict_hooks, ARRAY_SIZE(mntrestrict_hooks));
}
