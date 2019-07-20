/*	$NetBSD: intrdefs.h,v 1.4 2011/08/10 06:30:59 cherry Exp $	*/

#include <x86/intrdefs.h>

/*
 * Local APIC masks and software interrupt masks, in order
 * of priority.  Must not conflict with SIR_* below.
 */
#define LIR_IPI		31
#define LIR_TIMER	30
#define LIR_HV		29

/*
 * XXX These should be lowest numbered, but right now would
 * conflict with the legacy IRQs.  Their current position
 * means that soft interrupt take priority over hardware
 * interrupts when lowering the priority level!
 */
#define	SIR_SERIAL	28
#define	SIR_NET		27
#define	SIR_BIO		26
#define	SIR_CLOCK	25
#define	SIR_PREEMPT	24

/*
 * Maximum # of interrupt sources per CPU. 32 to fit in one word.
 * ioapics can theoretically produce more, but it's not likely to
 * happen. For multiple ioapics, things can be routed to different
 * CPUs.
 */
#define MAX_INTR_SOURCES	32

#ifdef XEN
#include <xen/intrdefs.h>
#endif /* XEN */
