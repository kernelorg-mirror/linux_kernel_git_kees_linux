#include "misc.h"

#ifdef CONFIG_EARLY_PRINTK

#include "../early_serial_console.c"

unsigned long early_serial_base;
int early_serial_type;

#endif
