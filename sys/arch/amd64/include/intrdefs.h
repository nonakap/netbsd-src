/*	$NetBSD: intrdefs.h,v 1.2 2011/08/10 06:30:59 cherry Exp $	*/

#include <x86/intrdefs.h>

/*
 * Local APIC masks and software interrupt masks, in order
 * of priority.  Must not conflict with SIR_* below.
 */
#define LIR_IPI		63
#define LIR_TIMER	62
#define LIR_HV		61

/*
 * XXX These should be lowest numbered, but right now would
 * conflict with the legacy IRQs.  Their current position
 * means that soft interrupt take priority over hardware
 * interrupts when lowering the priority level!
 */
#define	SIR_SERIAL	60
#define	SIR_NET		59
#define	SIR_BIO		58
#define	SIR_CLOCK	57
#define	SIR_PREEMPT	56

/*
 * Maximum # of interrupt sources per CPU. 64 to fit in one word.
 * ioapics can theoretically produce more, but it's not likely to
 * happen. For multiple ioapics, things can be routed to different
 * CPUs.
 */
#define MAX_INTR_SOURCES	64

#ifdef XEN
#include <xen/intrdefs.h>
#endif /* XEN */
