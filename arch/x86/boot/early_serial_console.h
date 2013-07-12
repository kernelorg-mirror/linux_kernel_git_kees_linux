#include <linux/serial_reg.h>

#define DEFAULT_SERIAL_PORT 0x3f8 /* ttyS0 */
#define DEFAULT_BAUD 9600

#define EARLY_SERIAL_IO		0
#define EARLY_SERIAL_MMIO	1
#define EARLY_SERIAL_MMIO32	2

extern unsigned long early_serial_base;
extern int early_serial_type;

static inline unsigned int early_serial_in(int offset)
{
	switch (early_serial_type) {
	case EARLY_SERIAL_IO:
		return inb(early_serial_base + offset);
	case EARLY_SERIAL_MMIO:
		return readb((const volatile void *)early_serial_base +
				offset);
	case EARLY_SERIAL_MMIO32:
		return readl((const volatile void *)early_serial_base +
				(offset << 2));
	default:
		return 0;
	}
}

static inline void early_serial_out(int offset, int value)
{
	switch (early_serial_type) {
	case EARLY_SERIAL_IO:
		outb(value, early_serial_base + offset);
		break;
	case EARLY_SERIAL_MMIO:
		writeb(value, (volatile void *)early_serial_base + offset);
		break;
	case EARLY_SERIAL_MMIO32:
		writel(value, (volatile void *)early_serial_base +
				(offset << 2));
		break;
	}
}
