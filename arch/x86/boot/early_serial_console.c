#include "boot.h"
#include "early_serial_console.h"

static void early_serial_init(int type, unsigned long port, int baud,
			      int base_baud)
{
	unsigned char c;
	unsigned divisor;

	early_serial_type = type;
	early_serial_base = port;

	early_serial_out(UART_LCR, UART_LCR_WLEN8);	/* 8n1 */
	early_serial_out(UART_IER, 0);			/* no interrupts */
	early_serial_out(UART_FCR, 0);			/* no fifo */
	early_serial_out(UART_MCR, UART_MCR_DTR | UART_MCR_RTS);

	divisor	= base_baud / baud;
	c = early_serial_in(UART_LCR);
	early_serial_out(UART_LCR, c | UART_LCR_DLAB);
	early_serial_out(UART_DLL, divisor & 0xff);
	early_serial_out(UART_DLM, (divisor >> 8) & 0xff);
	early_serial_out(UART_LCR, c & ~UART_LCR_DLAB);
}

static void parse_earlyprintk(void)
{
	int baud = DEFAULT_BAUD;
	char arg[32];
	int pos = 0;
	unsigned long port = 0;

	if (cmdline_find_option("earlyprintk", arg, sizeof arg) > 0) {
		char *e;

		if (!strncmp(arg, "serial", 6)) {
			port = DEFAULT_SERIAL_PORT;
			pos += 6;
		}

		if (arg[pos] == ',')
			pos++;

		/*
		 * make sure we have
		 *	"serial,0x3f8,115200"
		 *	"serial,ttyS0,115200"
		 *	"ttyS0,115200"
		 */
		if (pos == 7 && !strncmp(arg + pos, "0x", 2)) {
			port = simple_strtoull(arg + pos, &e, 16);
			if (port == 0 || arg + pos == e)
				port = DEFAULT_SERIAL_PORT;
			else
				pos = e - arg;
		} else if (!strncmp(arg + pos, "ttyS", 4)) {
			static const int bases[] = { 0x3f8, 0x2f8 };
			int idx = 0;

			if (!strncmp(arg + pos, "ttyS", 4))
				pos += 4;

			if (arg[pos++] == '1')
				idx = 1;

			port = bases[idx];
		}

		if (arg[pos] == ',')
			pos++;

		baud = simple_strtoull(arg + pos, &e, 0);
		if (baud == 0 || arg + pos == e)
			baud = DEFAULT_BAUD;
	}

	if (port)
		early_serial_init(EARLY_SERIAL_IO, port, baud,
				  SERIAL_BAUD_BASE);
}

static unsigned int probe_baud(int type, unsigned long port)
{
	unsigned char lcr, dll, dlh;
	unsigned int quot;
	int saved_type;
	unsigned long saved_port;

	saved_type = early_serial_type;
	saved_port = early_serial_base;
	early_serial_type = type;
	early_serial_base = port;

	lcr = early_serial_in(UART_LCR);
	early_serial_out(UART_LCR, lcr | UART_LCR_DLAB);
	dll = early_serial_in(UART_DLL);
	dlh = early_serial_in(UART_DLM);
	early_serial_out(UART_LCR, lcr);
	quot = (dlh << 8) | dll;

	early_serial_type = saved_type;
	early_serial_base = saved_port;

	return SERIAL_BAUD_BASE / quot;
}

static void parse_console_uart8250(void)
{
	char optstr[64], *options;
	int baud = DEFAULT_BAUD;
	int base_baud = SERIAL_BAUD_BASE;
	int type = EARLY_SERIAL_IO;
	unsigned long port = 0;

	/*
	 * console=uart8250,io,0x3f8,115200n8
	 * console=uart,mmio,0xe080100,115200n8
	 * console=uart,mmio32,0xe0801000,115200n8
	 * need to make sure it is last one console !
	 */
	if (cmdline_find_option("console", optstr, sizeof optstr) <= 0)
		return;

	options = optstr;

	if (strncmp(options, "uart", 4))
		return;
	options += 4;
	if (!strncmp(options, "8250", 4))
		options += 4;
	if (*options++ != ',')
		return;

	if (!strncmp(options, "io,", 3))
		port = simple_strtoull(options + 3, &options, 0);
	else if (!strncmp(options, "mmio", 4)) {
		options += 4;
		type = EARLY_SERIAL_MMIO;
		if (!strncmp(options, "32", 2)) {
			options += 2;
			type = EARLY_SERIAL_MMIO32;
		}
		if (*options++ != ',')
			return;
		port = simple_strtoull(options, &options, 0);
	} else
		return;

	if (options && (options[0] == ',')) {
		baud = simple_strtoull(options + 1, &options, 0);
		while (*options != ' ' && *options != ',' && *options != '\0')
			options++;
		if (*options == ',')
			base_baud = simple_strtoull(options + 1, &options, 0);
	}
	else
		baud = probe_baud(type, port);

	if (port)
		early_serial_init(type, port, baud, base_baud);
}

void console_init(void)
{
	parse_earlyprintk();

	if (!early_serial_base)
		parse_console_uart8250();
}
