#ifndef _LINUX_WRITE_RARELY_H
#define _LINUX_WRITE_RARELY_H

#include <linux/kernel.h>
#include <linux/preempt.h>
#include <asm/pgtable.h>

/*
 * Build "write rarely" infrastructure for flipping memory r/w
 * on a per-CPU basis.
 */
#ifdef CONFIG_HAVE_ARCH_RARE_WRITE
# ifdef CONFIG_HAVE_ARCH_RARE_WRITE_MEMCPY
#  define __rare_write_n(dst, src, len)		({			\
		BUILD_BUG_ON(!builtin_const(len),			\
			     "Size cannot be runtime determined");	\
		__arch_rare_write_memcpy((dst), (src), (len));		\
	})
#  define __rare_write(var, val)	({			\
		typeof(var) __src = (val);			\
		__rare_write_n(&(var), &__src, sizeof(var))	\
	})
# else
#  define __rare_write(var, val) ((*(typeof((typeof(var))0) *)&(var)) = (val))
# endif
static __always_inline void rare_write_begin(void)
{
	preempt_disable();
	local_irq_disable();
	barrier();
	__arch_rare_write_begin();
	barrier();
}
static __always_inline void rare_write_end(void)
{
	barrier();
	__arch_rare_write_end();
	barrier();
	local_irq_enable();
	preempt_enable_no_resched();
}
#else
# define __rare_write(__var, __val)	(__var = (__val))
static inline void rare_write_begin(void) { }
static inline void rare_write_end(void) { }
#endif

#define rare_write(__var, __val) ({		\
		rare_write_begin();		\
		__rare_write(__var, __val);	\
		rare_write_end();		\
		__var;				\
})

#endif
