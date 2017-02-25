/*
 * Copyright 2006, Red Hat, Inc., Dave Jones
 * Released under the General Public License (GPL).
 *
 * This file contains the linked list validation for DEBUG_LIST.
 */

#include <linux/export.h>
#include <linux/list.h>
#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/rculist.h>
#include <linux/mm.h>
#include <linux/write-rarely.h>

#ifdef CONFIG_DEBUG_LIST
/*
 * Check that the data structures for the list manipulations are reasonably
 * valid. Failures here indicate memory corruption (and possibly an exploit
 * attempt).
 */

bool __list_add_valid(struct list_head *new, struct list_head *prev,
		      struct list_head *next)
{
	if (CHECK_DATA_CORRUPTION(next->prev != prev,
			"list_add corruption. next->prev should be prev (%p), but was %p. (next=%p).\n",
			prev, next->prev, next) ||
	    CHECK_DATA_CORRUPTION(prev->next != next,
			"list_add corruption. prev->next should be next (%p), but was %p. (prev=%p).\n",
			next, prev->next, prev) ||
	    CHECK_DATA_CORRUPTION(new == prev || new == next,
			"list_add double add: new=%p, prev=%p, next=%p.\n",
			new, prev, next))
		return false;

	return true;
}
EXPORT_SYMBOL(__list_add_valid);

bool __list_del_entry_valid(struct list_head *entry)
{
	struct list_head *prev, *next;

	prev = entry->prev;
	next = entry->next;

	if (CHECK_DATA_CORRUPTION(next == LIST_POISON1,
			"list_del corruption, %p->next is LIST_POISON1 (%p)\n",
			entry, LIST_POISON1) ||
	    CHECK_DATA_CORRUPTION(prev == LIST_POISON2,
			"list_del corruption, %p->prev is LIST_POISON2 (%p)\n",
			entry, LIST_POISON2) ||
	    CHECK_DATA_CORRUPTION(prev->next != entry,
			"list_del corruption. prev->next should be %p, but was %p\n",
			entry, prev->next) ||
	    CHECK_DATA_CORRUPTION(next->prev != entry,
			"list_del corruption. next->prev should be %p, but was %p\n",
			entry, next->prev))
		return false;

	return true;

}
EXPORT_SYMBOL(__list_del_entry_valid);

#endif /* CONFIG_DEBUG_LIST */

void __rare_list_add(struct list_head *new, struct list_head *prev,
		     struct list_head *next)
{
	if (!__list_add_valid(new, prev, next))
		return;

	rare_write_begin();
	__rare_write(next->prev, new);
	__rare_write(new->next, next);
	__rare_write(new->prev, prev);
	__rare_write(prev->next, new);
	rare_write_end();
}
EXPORT_SYMBOL(__rare_list_add);

void rare_list_del(__wr_rare_type struct list_head *entry_const)
{
	struct list_head *entry = (struct list_head *)entry_const;
	struct list_head *prev = entry->prev;
	struct list_head *next = entry->next;

	if (!__list_del_entry_valid(entry))
		return;

	rare_write_begin();
	__rare_write(next->prev, prev);
	__rare_write(prev->next, next);
	__rare_write(entry->next, LIST_POISON1);
	__rare_write(entry->prev, LIST_POISON2);
	rare_write_end();
}
EXPORT_SYMBOL(rare_list_del);
