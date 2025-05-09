/*	$NetBSD: subr_xcall.c,v 1.39 2025/04/01 03:16:41 ozaki-r Exp $	*/

/*-
 * Copyright (c) 2007-2010, 2019 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Andrew Doran and Mindaugas Rasiukevicius.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Cross call support
 *
 * Background
 *
 *	Sometimes it is necessary to modify hardware state that is tied
 *	directly to individual CPUs (such as a CPU's local timer), and
 *	these updates can not be done remotely by another CPU.  The LWP
 *	requesting the update may be unable to guarantee that it will be
 *	running on the CPU where the update must occur, when the update
 *	occurs.
 *
 *	Additionally, it's sometimes necessary to modify per-CPU software
 *	state from a remote CPU.  Where these update operations are so
 *	rare or the access to the per-CPU data so frequent that the cost
 *	of using locking or atomic operations to provide coherency is
 *	prohibitive, another way must be found.
 *
 *	Cross calls help to solve these types of problem by allowing
 *	any LWP in the system to request that an arbitrary function be
 *	executed on a specific CPU.
 *
 * Implementation
 *
 *	A slow mechanism for making low priority cross calls is
 *	provided.  The function to be executed runs on the remote CPU
 *	within a bound kthread.  No queueing is provided, and the
 *	implementation uses global state.  The function being called may
 *	block briefly on locks, but in doing so must be careful to not
 *	interfere with other cross calls in the system.  The function is
 *	called with thread context and not from a soft interrupt, so it
 *	can ensure that it is not interrupting other code running on the
 *	CPU, and so has exclusive access to the CPU.  Since this facility
 *	is heavyweight, it's expected that it will not be used often.
 *
 *	Cross calls must not allocate memory, as the pagedaemon uses cross
 *	calls (and memory allocation may need to wait on the pagedaemon).
 *
 *	A low-overhead mechanism for high priority calls (XC_HIGHPRI) is
 *	also provided.  The function to be executed runs in software
 *	interrupt context at IPL_SOFTSERIAL level, and is expected to
 *	be very lightweight, e.g. avoid blocking.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: subr_xcall.c,v 1.39 2025/04/01 03:16:41 ozaki-r Exp $");

#include <sys/types.h>
#include <sys/param.h>
#include <sys/xcall.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/evcnt.h>
#include <sys/kthread.h>
#include <sys/cpu.h>
#include <sys/atomic.h>

#ifdef _RUMPKERNEL
#include "rump_private.h"
#endif

/* Cross-call state box. */
typedef struct {
	kmutex_t	xc_lock;
	kcondvar_t	xc_busy;
	xcfunc_t	xc_func;
	void *		xc_arg1;
	void *		xc_arg2;
	uint64_t	xc_headp;
	uint64_t	xc_donep;
	unsigned int	xc_ipl;
} xc_state_t;

/* Bit indicating high (1) or low (0) priority. */
#define	XC_PRI_BIT	(1ULL << 63)

/* Low priority xcall structures. */
static xc_state_t	xc_low_pri	__cacheline_aligned;

/* High priority xcall structures. */
static xc_state_t	xc_high_pri	__cacheline_aligned;
static void *		xc_sihs[4]	__cacheline_aligned;

/* Event counters. */
static struct evcnt	xc_unicast_ev	__cacheline_aligned;
static struct evcnt	xc_broadcast_ev	__cacheline_aligned;

static void		xc_init(void);
static void		xc_thread(void *);

static inline uint64_t	xc_highpri(xcfunc_t, void *, void *, struct cpu_info *,
			    unsigned int);
static inline uint64_t	xc_lowpri(xcfunc_t, void *, void *, struct cpu_info *);

/* The internal form of IPL */
#define XC_IPL_MASK		0xff00
/*
 * Assign 0 to XC_IPL_SOFTSERIAL to treat IPL_SOFTSERIAL as the default value
 * (just XC_HIGHPRI).
 */
#define XC_IPL_SOFTSERIAL	0
#define XC_IPL_SOFTNET		1
#define XC_IPL_SOFTBIO		2
#define XC_IPL_SOFTCLOCK	3
#define XC_IPL_MAX		XC_IPL_SOFTCLOCK

CTASSERT(XC_IPL_MAX <= __arraycount(xc_sihs));

/*
 * xc_init:
 *
 *	Initialize low and high priority cross-call structures.
 */
static void
xc_init(void)
{
	xc_state_t *xclo = &xc_low_pri, *xchi = &xc_high_pri;

	memset(xclo, 0, sizeof(xc_state_t));
	mutex_init(&xclo->xc_lock, MUTEX_DEFAULT, IPL_NONE);
	cv_init(&xclo->xc_busy, "xclow");

	memset(xchi, 0, sizeof(xc_state_t));
	mutex_init(&xchi->xc_lock, MUTEX_DEFAULT, IPL_SOFTSERIAL);
	cv_init(&xchi->xc_busy, "xchigh");

	/* Set up a softint for each IPL_SOFT*. */
#define SETUP_SOFTINT(xipl, sipl) do {					\
		xc_sihs[(xipl)] = softint_establish( (sipl) | SOFTINT_MPSAFE,\
		    xc__highpri_intr, NULL);				\
		KASSERT(xc_sihs[(xipl)] != NULL);			\
	} while (0)

	SETUP_SOFTINT(XC_IPL_SOFTSERIAL, SOFTINT_SERIAL);
	/*
	 * If a IPL_SOFTXXX have the same value of the previous, we don't use
	 * the IPL (see xc_encode_ipl).  So we don't need to allocate a softint
	 * for it.
	 */
#if IPL_SOFTNET != IPL_SOFTSERIAL
	SETUP_SOFTINT(XC_IPL_SOFTNET, SOFTINT_NET);
#endif
#if IPL_SOFTBIO != IPL_SOFTNET
	SETUP_SOFTINT(XC_IPL_SOFTBIO, SOFTINT_BIO);
#endif
#if IPL_SOFTCLOCK != IPL_SOFTBIO
	SETUP_SOFTINT(XC_IPL_SOFTCLOCK, SOFTINT_CLOCK);
#endif

#undef SETUP_SOFTINT

	evcnt_attach_dynamic(&xc_unicast_ev, EVCNT_TYPE_MISC, NULL,
	   "crosscall", "unicast");
	evcnt_attach_dynamic(&xc_broadcast_ev, EVCNT_TYPE_MISC, NULL,
	   "crosscall", "broadcast");
}

/*
 * Encode an IPL to a form that can be embedded into flags of xc_broadcast
 * or xc_unicast.
 */
unsigned int
xc_encode_ipl(int ipl)
{

	switch (ipl) {
	case IPL_SOFTSERIAL:
		return __SHIFTIN(XC_IPL_SOFTSERIAL, XC_IPL_MASK);
	/* IPL_SOFT* can be the same value (e.g., on sparc or mips). */
#if IPL_SOFTNET != IPL_SOFTSERIAL
	case IPL_SOFTNET:
		return __SHIFTIN(XC_IPL_SOFTNET, XC_IPL_MASK);
#endif
#if IPL_SOFTBIO != IPL_SOFTNET
	case IPL_SOFTBIO:
		return __SHIFTIN(XC_IPL_SOFTBIO, XC_IPL_MASK);
#endif
#if IPL_SOFTCLOCK != IPL_SOFTBIO
	case IPL_SOFTCLOCK:
		return __SHIFTIN(XC_IPL_SOFTCLOCK, XC_IPL_MASK);
#endif
	}

	panic("Invalid IPL: %d", ipl);
}

/*
 * Extract an XC_IPL from flags of xc_broadcast or xc_unicast.
 */
static inline unsigned int
xc_extract_ipl(unsigned int flags)
{

	return __SHIFTOUT(flags, XC_IPL_MASK);
}

/*
 * xc_init_cpu:
 *
 *	Initialize the cross-call subsystem.  Called once for each CPU
 *	in the system as they are attached.
 */
void
xc_init_cpu(struct cpu_info *ci)
{
	static bool again = false;
	int error __diagused;

	if (!again) {
		/* Autoconfiguration will prevent re-entry. */
		xc_init();
		again = true;
	}
	cv_init(&ci->ci_data.cpu_xcall, "xcall");
	error = kthread_create(PRI_XCALL, KTHREAD_MPSAFE, ci, xc_thread,
	    NULL, NULL, "xcall/%u", ci->ci_index);
	KASSERT(error == 0);
}

/*
 * xc_broadcast:
 *
 *	Trigger a call on all CPUs in the system.
 */
uint64_t
xc_broadcast(unsigned int flags, xcfunc_t func, void *arg1, void *arg2)
{

	KASSERT(!cpu_intr_p());
	KASSERT(!cpu_softintr_p());
	ASSERT_SLEEPABLE();

	if (__predict_false(!mp_online)) {
		int s, bound;

		if (flags & XC_HIGHPRI)
			s = splsoftserial();
		else
			bound = curlwp_bind();
		(*func)(arg1, arg2);
		if (flags & XC_HIGHPRI)
			splx(s);
		else
			curlwp_bindx(bound);
		return 0;
	}

	if ((flags & XC_HIGHPRI) != 0) {
		unsigned int ipl = xc_extract_ipl(flags);
		return xc_highpri(func, arg1, arg2, NULL, ipl);
	} else {
		return xc_lowpri(func, arg1, arg2, NULL);
	}
}

static void
xc_nop(void *arg1, void *arg2)
{

	return;
}

/*
 * xc_barrier:
 *
 *	Broadcast a nop to all CPUs in the system.
 */
void
xc_barrier(unsigned int flags)
{
	uint64_t where;

	where = xc_broadcast(flags, xc_nop, NULL, NULL);
	xc_wait(where);
}

/*
 * xc_unicast:
 *
 *	Trigger a call on one CPU.
 */
uint64_t
xc_unicast(unsigned int flags, xcfunc_t func, void *arg1, void *arg2,
    struct cpu_info *ci)
{

	KASSERT(ci != NULL);
	KASSERT(!cpu_intr_p());
	KASSERT(!cpu_softintr_p());
	ASSERT_SLEEPABLE();

	if (__predict_false(!mp_online)) {
		int s, bound;

		KASSERT(ci == curcpu());

		if (flags & XC_HIGHPRI)
			s = splsoftserial();
		else
			bound = curlwp_bind();
		(*func)(arg1, arg2);
		if (flags & XC_HIGHPRI)
			splx(s);
		else
			curlwp_bindx(bound);

		return 0;
	}

	if ((flags & XC_HIGHPRI) != 0) {
		unsigned int ipl = xc_extract_ipl(flags);
		return xc_highpri(func, arg1, arg2, ci, ipl);
	} else {
		return xc_lowpri(func, arg1, arg2, ci);
	}
}

/*
 * xc_wait:
 *
 *	Wait for a cross call to complete.
 */
void
xc_wait(uint64_t where)
{
	xc_state_t *xc;

	KASSERT(!cpu_intr_p());
	KASSERT(!cpu_softintr_p());
	ASSERT_SLEEPABLE();

	if (__predict_false(!mp_online)) {
		return;
	}

	/* Determine whether it is high or low priority cross-call. */
	if ((where & XC_PRI_BIT) != 0) {
		xc = &xc_high_pri;
		where &= ~XC_PRI_BIT;
	} else {
		xc = &xc_low_pri;
	}

#ifdef __HAVE_ATOMIC64_LOADSTORE
	/* Fast path, if already done. */
	if (atomic_load_acquire(&xc->xc_donep) >= where) {
		return;
	}
#endif

	/* Slow path: block until awoken. */
	mutex_enter(&xc->xc_lock);
	while (xc->xc_donep < where) {
		cv_wait(&xc->xc_busy, &xc->xc_lock);
	}
	mutex_exit(&xc->xc_lock);
}

/*
 * xc_lowpri:
 *
 *	Trigger a low priority call on one or more CPUs.
 */
static inline uint64_t
xc_lowpri(xcfunc_t func, void *arg1, void *arg2, struct cpu_info *ci)
{
	xc_state_t *xc = &xc_low_pri;
	CPU_INFO_ITERATOR cii;
	uint64_t where;

	mutex_enter(&xc->xc_lock);
	while (xc->xc_headp != xc->xc_donep) {
		cv_wait(&xc->xc_busy, &xc->xc_lock);
	}
	xc->xc_arg1 = arg1;
	xc->xc_arg2 = arg2;
	xc->xc_func = func;
	if (ci == NULL) {
		xc_broadcast_ev.ev_count++;
		for (CPU_INFO_FOREACH(cii, ci)) {
			if ((ci->ci_schedstate.spc_flags & SPCF_RUNNING) == 0)
				continue;
			xc->xc_headp += 1;
			ci->ci_data.cpu_xcall_pending = true;
			cv_signal(&ci->ci_data.cpu_xcall);
		}
	} else {
		xc_unicast_ev.ev_count++;
		xc->xc_headp += 1;
		ci->ci_data.cpu_xcall_pending = true;
		cv_signal(&ci->ci_data.cpu_xcall);
	}
	KASSERT(xc->xc_donep < xc->xc_headp);
	where = xc->xc_headp;
	mutex_exit(&xc->xc_lock);

	/* Return a low priority ticket. */
	KASSERT((where & XC_PRI_BIT) == 0);
	return where;
}

/*
 * xc_thread:
 *
 *	One thread per-CPU to dispatch low priority calls.
 */
static void
xc_thread(void *cookie)
{
	struct cpu_info *ci = curcpu();
	xc_state_t *xc = &xc_low_pri;
	void *arg1, *arg2;
	xcfunc_t func;
	struct lwp *l = curlwp;

	KASSERTMSG(l->l_nopreempt == 0, "lwp %p nopreempt %d",
	    l, l->l_nopreempt);

	mutex_enter(&xc->xc_lock);
	for (;;) {
		while (!ci->ci_data.cpu_xcall_pending) {
			if (xc->xc_headp == xc->xc_donep) {
				cv_broadcast(&xc->xc_busy);
			}
			cv_wait(&ci->ci_data.cpu_xcall, &xc->xc_lock);
			KASSERT(ci == curcpu());
		}
		ci->ci_data.cpu_xcall_pending = false;
		func = xc->xc_func;
		arg1 = xc->xc_arg1;
		arg2 = xc->xc_arg2;
		mutex_exit(&xc->xc_lock);

		KASSERT(func != NULL);
		(*func)(arg1, arg2);

		KASSERTMSG(l->l_nopreempt == 0, "lwp %p nopreempt %d func %p",
		    l, l->l_nopreempt, func);

		mutex_enter(&xc->xc_lock);
#ifdef __HAVE_ATOMIC64_LOADSTORE
		atomic_store_release(&xc->xc_donep, xc->xc_donep + 1);
#else
		xc->xc_donep++;
#endif
	}
	/* NOTREACHED */
}

/*
 * xc_ipi_handler:
 *
 *	Handler of cross-call IPI.
 */
void
xc_ipi_handler(void)
{
	xc_state_t *xc = & xc_high_pri;

	KASSERT(xc->xc_ipl < __arraycount(xc_sihs));
	KASSERT(xc_sihs[xc->xc_ipl] != NULL);

	/* Executes xc__highpri_intr() via software interrupt. */
	softint_schedule(xc_sihs[xc->xc_ipl]);
}

/*
 * xc__highpri_intr:
 *
 *	A software interrupt handler for high priority calls.
 */
void
xc__highpri_intr(void *dummy)
{
	xc_state_t *xc = &xc_high_pri;
	void *arg1, *arg2;
	xcfunc_t func;

	KASSERTMSG(!cpu_intr_p(), "high priority xcall for function %p",
	    xc->xc_func);
	/*
	 * Lock-less fetch of function and its arguments.
	 * Safe since it cannot change at this point.
	 */
	func = xc->xc_func;
	arg1 = xc->xc_arg1;
	arg2 = xc->xc_arg2;

	KASSERT(func != NULL);
	(*func)(arg1, arg2);

	/*
	 * Note the request as done, and if we have reached the head,
	 * cross-call has been processed - notify waiters, if any.
	 */
	mutex_enter(&xc->xc_lock);
	KASSERT(xc->xc_donep < xc->xc_headp);
#ifdef __HAVE_ATOMIC64_LOADSTORE
	atomic_store_release(&xc->xc_donep, xc->xc_donep + 1);
#else
	xc->xc_donep++;
#endif
	if (xc->xc_donep == xc->xc_headp) {
		cv_broadcast(&xc->xc_busy);
	}
	mutex_exit(&xc->xc_lock);
}

/*
 * xc_highpri:
 *
 *	Trigger a high priority call on one or more CPUs.
 */
static inline uint64_t
xc_highpri(xcfunc_t func, void *arg1, void *arg2, struct cpu_info *ci,
    unsigned int ipl)
{
	xc_state_t *xc = &xc_high_pri;
	uint64_t where;

	mutex_enter(&xc->xc_lock);
	while (xc->xc_headp != xc->xc_donep) {
		cv_wait(&xc->xc_busy, &xc->xc_lock);
	}
	xc->xc_func = func;
	xc->xc_arg1 = arg1;
	xc->xc_arg2 = arg2;
	xc->xc_headp += (ci ? 1 : ncpu);
	xc->xc_ipl = ipl;
	where = xc->xc_headp;
	mutex_exit(&xc->xc_lock);

	/*
	 * Send the IPI once lock is released.
	 * Note: it will handle the local CPU case.
	 */

#ifdef _RUMPKERNEL
	rump_xc_highpri(ci);
#else
#ifdef MULTIPROCESSOR
	kpreempt_disable();
	if (curcpu() == ci) {
		/* Unicast: local CPU. */
		xc_ipi_handler();
	} else if (ci) {
		/* Unicast: remote CPU. */
		xc_send_ipi(ci);
	} else {
		/* Broadcast: all, including local. */
		xc_send_ipi(NULL);
		xc_ipi_handler();
	}
	kpreempt_enable();
#else
	KASSERT(ci == NULL || curcpu() == ci);
	xc_ipi_handler();
#endif
#endif

	/* Indicate a high priority ticket. */
	return (where | XC_PRI_BIT);
}
