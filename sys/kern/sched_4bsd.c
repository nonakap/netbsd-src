/*	$NetBSD: sched_4bsd.c,v 1.47 2025/01/17 04:11:33 mrg Exp $	*/

/*
 * Copyright (c) 1999, 2000, 2004, 2006, 2007, 2008, 2019, 2020
 *     The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of the Numerical Aerospace Simulation Facility,
 * NASA Ames Research Center, by Charles M. Hannum, Andrew Doran, and
 * Daniel Sieger.
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
 * Copyright (c) 1982, 1986, 1990, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)kern_synch.c	8.9 (Berkeley) 5/19/95
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: sched_4bsd.c,v 1.47 2025/01/17 04:11:33 mrg Exp $");

#include "opt_ddb.h"
#include "opt_lockdebug.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/callout.h>
#include <sys/cpu.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/resourcevar.h>
#include <sys/sched.h>
#include <sys/sysctl.h>
#include <sys/lockdebug.h>
#include <sys/intr.h>
#include <sys/atomic.h>

static void updatepri(struct lwp *);
static void resetpriority(struct lwp *);

/* Number of hardclock ticks per sched_tick() */
u_int sched_rrticks __read_mostly;

/*
 * Force switch among equal priority processes every 100ms.
 * Called from hardclock every hz/10 == sched_rrticks hardclock ticks.
 */
/* ARGSUSED */
void
sched_tick(struct cpu_info *ci)
{
	struct schedstate_percpu *spc = &ci->ci_schedstate;
	pri_t pri = PRI_NONE;
	lwp_t *l;

	spc->spc_ticks = sched_rrticks;

	if (CURCPU_IDLE_P()) {
		spc_lock(ci);
		sched_resched_cpu(ci, MAXPRI_KTHREAD, true);
		/* spc now unlocked */
		return;
	}
	l = ci->ci_onproc;
	if (l == NULL) {
		return;
	}
	/*
	 * Can only be spc_lwplock or a turnstile lock at this point
	 * (if we interrupted priority inheritance trylock dance).
	 */
	KASSERT(l->l_mutex != spc->spc_mutex);
	switch (l->l_class) {
	case SCHED_FIFO:
		/* No timeslicing for FIFO jobs. */
		break;
	case SCHED_RR:
		/* Force it into mi_switch() to look for other jobs to run. */
		pri = MAXPRI_KERNEL_RT;
		break;
	default:
		if (spc->spc_flags & SPCF_SHOULDYIELD) {
			/*
			 * Process is stuck in kernel somewhere, probably
			 * due to buggy or inefficient code.  Force a
			 * kernel preemption.
			 */
			pri = MAXPRI_KERNEL_RT;
		} else if (spc->spc_flags & SPCF_SEENRR) {
			/*
			 * The process has already been through a roundrobin
			 * without switching and may be hogging the CPU.
			 * Indicate that the process should yield.
			 */
			pri = MAXPRI_KTHREAD;
			spc->spc_flags |= SPCF_SHOULDYIELD;
		} else if (!cpu_is_1stclass(ci)) {
			/*
			 * For SMT or asymmetric systems push a little
			 * harder: if this is not a 1st class CPU, try to
			 * find a better one to run this LWP.
			 */
			pri = MAXPRI_KTHREAD;
			spc->spc_flags |= SPCF_SHOULDYIELD;
		} else {
			spc->spc_flags |= SPCF_SEENRR;
		}
		break;
	}

	if (pri != PRI_NONE) {
		spc_lock(ci);
		sched_resched_cpu(ci, pri, true);
		/* spc now unlocked */
	}
}

/*
 * Why PRIO_MAX - 2? From setpriority(2):
 *
 *	prio is a value in the range -20 to 20.  The default priority is
 *	0; lower priorities cause more favorable scheduling.  A value of
 *	19 or 20 will schedule a process only when nothing at priority <=
 *	0 is runnable.
 *
 * This gives estcpu influence over 18 priority levels, and leaves nice
 * with 40 levels.  One way to think about it is that nice has 20 levels
 * either side of estcpu's 18.
 */
#define	ESTCPU_SHIFT	11
#define	ESTCPU_MAX	((PRIO_MAX - 2) << ESTCPU_SHIFT)
#define	ESTCPU_ACCUM	(1 << (ESTCPU_SHIFT - 1))
#define	ESTCPULIM(e)	uimin((e), ESTCPU_MAX)

/*
 * The main parameter used by this algorithm is 'l_estcpu'. It is an estimate
 * of the recent CPU utilization of the thread.
 *
 * l_estcpu is:
 *  - increased each time the hardclock ticks and the thread is found to
 *    be executing, in sched_schedclock() called from hardclock()
 *  - decreased (filtered) on each sched tick, in sched_pstats_hook()
 * If the lwp is sleeping for more than a second, we don't touch l_estcpu: it
 * will be updated in sched_setrunnable() when the lwp wakes up, in burst mode
 * (ie, we decrease it n times).
 *
 * Note that hardclock updates l_estcpu and l_cpticks independently.
 *
 * -----------------------------------------------------------------------------
 *
 * Here we describe how l_estcpu is decreased.
 *
 * Constants for digital decay (filter):
 *     90% of l_estcpu usage in (5 * loadavg) seconds
 *
 * We wish to decay away 90% of l_estcpu in (5 * loadavg) seconds. That is, we
 * want to compute a value of decay such that the following loop:
 *     for (i = 0; i < (5 * loadavg); i++)
 *         l_estcpu *= decay;
 * will result in
 *     l_estcpu *= 0.1;
 * for all values of loadavg.
 *
 * Mathematically this loop can be expressed by saying:
 *     decay ** (5 * loadavg) ~= .1
 *
 * And finally, the corresponding value of decay we're using is:
 *     decay = (2 * loadavg) / (2 * loadavg + 1)
 *
 * -----------------------------------------------------------------------------
 *
 * Now, let's prove that the value of decay stated above will always fulfill
 * the equation:
 *     decay ** (5 * loadavg) ~= .1
 *
 * If we compute b as:
 *     b = 2 * loadavg
 * then
 *     decay = b / (b + 1)
 *
 * We now need to prove two things:
 *     1) Given [factor ** (5 * loadavg) =~ .1], prove [factor == b/(b+1)].
 *     2) Given [b/(b+1) ** power =~ .1], prove [power == (5 * loadavg)].
 *
 * Facts:
 *   * For x real: exp(x) = 0! + x**1/1! + x**2/2! + ...
 *     Therefore, for x close to zero, exp(x) =~ 1 + x.
 *     In turn, for b large enough, exp(-1/b) =~ 1 - (1/b) = (b-1)/b.
 *
 *   * For b large enough, (b-1)/b =~ b/(b+1).
 *
 *   * For x belonging to [-1;1[, ln(1-x) = - x - x**2/2 - x**3/3 - ...
 *     Therefore ln(b/(b+1)) = ln(1 - 1/(b+1)) =~ -1/(b+1).
 *
 *   * ln(0.1) =~ -2.30
 *
 * Proof of (1):
 *     factor ** (5 * loadavg) =~ 0.1
 *  => ln(factor) =~ -2.30 / (5 * loadavg)
 *  => factor =~ exp(-1 / ((5 / 2.30) * loadavg))
 *            =~ exp(-1 / (2 * loadavg))
 *            =~ exp(-1 / b)
 *            =~ (b - 1) / b
 *            =~ b / (b + 1)
 *            =~ (2 * loadavg) / ((2 * loadavg) + 1)
 *
 * Proof of (2):
 *     (b / (b + 1)) ** power =~ .1
 *  => power * ln(b / (b + 1)) =~ -2.30
 *  => power * (-1 / (b + 1)) =~ -2.30
 *  => power =~ 2.30 * (b + 1)
 *  => power =~ 4.60 * loadavg + 2.30
 *  => power =~ 5 * loadavg
 *
 * Conclusion: decay = (2 * loadavg) / (2 * loadavg + 1)
 */

/* See calculations above */
#define	loadfactor(loadavg)  (2 * (loadavg))

static fixpt_t
decay_cpu(fixpt_t loadfac, fixpt_t estcpu)
{

	if (estcpu == 0) {
		return 0;
	}

#if !defined(_LP64)
	/* avoid 64bit arithmetics. */
#define	FIXPT_MAX ((fixpt_t)((UINTMAX_C(1) << sizeof(fixpt_t) * CHAR_BIT) - 1))
	if (__predict_true(loadfac <= FIXPT_MAX / ESTCPU_MAX)) {
		return estcpu * loadfac / (loadfac + FSCALE);
	}
#endif

	return (uint64_t)estcpu * loadfac / (loadfac + FSCALE);
}

static fixpt_t
decay_cpu_batch(fixpt_t loadfac, fixpt_t estcpu, unsigned int n)
{

	/*
	 * For all load averages >= 1 and max l_estcpu of (255 << ESTCPU_SHIFT),
	 * if we slept for at least seven times the loadfactor, we will decay
	 * l_estcpu to less than (1 << ESTCPU_SHIFT), and therefore we can
	 * return zero directly.
	 *
	 * Note that our ESTCPU_MAX is actually much smaller than
	 * (255 << ESTCPU_SHIFT).
	 */
	if ((n << FSHIFT) >= 7 * loadfac) {
		return 0;
	}

	while (estcpu != 0 && n > 1) {
		estcpu = decay_cpu(loadfac, estcpu);
		n--;
	}

	return estcpu;
}

/*
 * sched_pstats_hook:
 *
 * Periodically called from sched_pstats(); used to recalculate priorities.
 */
void
sched_pstats_hook(struct lwp *l, int batch)
{
	fixpt_t loadfac;

	/*
	 * If the LWP has slept an entire second, stop recalculating
	 * its priority until it wakes up.
	 */
	KASSERT(lwp_locked(l, NULL));
	if (l->l_stat == LSSLEEP || l->l_stat == LSSTOP ||
	    l->l_stat == LSSUSPENDED) {
		if (l->l_slptime > 1) {
			return;
		}
	}

	loadfac = loadfactor(averunnable.ldavg[0]);
	l->l_estcpu = decay_cpu(loadfac, l->l_estcpu);
	resetpriority(l);
}

/*
 * Recalculate the priority of an LWP after it has slept for a while.
 */
static void
updatepri(struct lwp *l)
{
	fixpt_t loadfac;

	KASSERT(lwp_locked(l, NULL));
	KASSERT(l->l_slptime > 1);

	loadfac = loadfactor(averunnable.ldavg[0]);

	l->l_slptime--; /* the first time was done in sched_pstats */
	l->l_estcpu = decay_cpu_batch(loadfac, l->l_estcpu, l->l_slptime);
	resetpriority(l);
}

void
sched_rqinit(void)
{

}

void
sched_setrunnable(struct lwp *l)
{

 	if (l->l_slptime > 1)
 		updatepri(l);
}

void
sched_nice(struct proc *p, int n)
{
	struct lwp *l;

	KASSERT(mutex_owned(p->p_lock));

	p->p_nice = n;
	LIST_FOREACH(l, &p->p_lwps, l_sibling) {
		lwp_lock(l);
		resetpriority(l);
		lwp_unlock(l);
	}
}

/*
 * Recompute the priority of an LWP.  Arrange to reschedule if
 * the resulting priority is better than that of the current LWP.
 */
static void
resetpriority(struct lwp *l)
{
	pri_t pri;
	struct proc *p = l->l_proc;

	KASSERT(lwp_locked(l, NULL));

	if (l->l_class != SCHED_OTHER)
		return;

	/* See comments above ESTCPU_SHIFT definition. */
	pri = (PRI_KERNEL - 1) - (l->l_estcpu >> ESTCPU_SHIFT) - p->p_nice;
	pri = imax(pri, 0);
	if (pri != l->l_priority)
		lwp_changepri(l, pri);
}

/*
 * We adjust the priority of the current LWP.  The priority of a LWP
 * gets worse as it accumulates CPU time.  The CPU usage estimator (l_estcpu)
 * is increased here.  The formula for computing priorities will compute a
 * different value each time l_estcpu increases. This can cause a switch,
 * but unless the priority crosses a PPQ boundary the actual queue will not
 * change.  The CPU usage estimator ramps up quite quickly when the process
 * is running (linearly), and decays away exponentially, at a rate which is
 * proportionally slower when the system is busy.  The basic principle is
 * that the system will 90% forget that the process used a lot of CPU time
 * in (5 * loadavg) seconds.  This causes the system to favor processes which
 * haven't run much recently, and to round-robin among other processes.
 */
void
sched_schedclock(struct lwp *l)
{

	if (l->l_class != SCHED_OTHER)
		return;

	KASSERT(!CURCPU_IDLE_P());
	l->l_estcpu = ESTCPULIM(l->l_estcpu + ESTCPU_ACCUM);
	lwp_lock(l);
	resetpriority(l);
	lwp_unlock(l);
}

/*
 * sched_proc_fork:
 *
 *	Inherit the parent's scheduler history.
 */
void
sched_proc_fork(struct proc *parent, struct proc *child)
{
	lwp_t *pl;

	KASSERT(mutex_owned(parent->p_lock));

	pl = LIST_FIRST(&parent->p_lwps);
	child->p_estcpu_inherited = pl->l_estcpu;
	child->p_forktime = sched_pstats_ticks;
}

/*
 * sched_proc_exit:
 *
 *	Chargeback parents for the sins of their children.
 */
void
sched_proc_exit(struct proc *parent, struct proc *child)
{
	fixpt_t loadfac = loadfactor(averunnable.ldavg[0]);
	fixpt_t estcpu;
	lwp_t *pl, *cl;

	/* XXX Only if parent != init?? */

	mutex_enter(parent->p_lock);
	pl = LIST_FIRST(&parent->p_lwps);
	cl = LIST_FIRST(&child->p_lwps);
	estcpu = decay_cpu_batch(loadfac, child->p_estcpu_inherited,
	    sched_pstats_ticks - child->p_forktime);
	if (cl->l_estcpu > estcpu) {
		lwp_lock(pl);
		pl->l_estcpu = ESTCPULIM(pl->l_estcpu + cl->l_estcpu - estcpu);
		lwp_unlock(pl);
	}
	mutex_exit(parent->p_lock);
}

void
sched_wakeup(struct lwp *l)
{

}

void
sched_slept(struct lwp *l)
{

}

void
sched_lwp_fork(struct lwp *l1, struct lwp *l2)
{

	l2->l_estcpu = l1->l_estcpu;
}

void
sched_lwp_collect(struct lwp *t)
{
	lwp_t *l;

	/* Absorb estcpu value of collected LWP. */
	l = curlwp;
	lwp_lock(l);
	l->l_estcpu += t->l_estcpu;
	lwp_unlock(l);
}

void
sched_oncpu(lwp_t *l)
{

}

void
sched_newts(lwp_t *l)
{

}

/*
 * Sysctl nodes and initialization.
 */

static int
sysctl_sched_rtts(SYSCTLFN_ARGS)
{
	struct sysctlnode node;
	int rttsms = hztoms(sched_rrticks);

	node = *rnode;
	node.sysctl_data = &rttsms;
	return sysctl_lookup(SYSCTLFN_CALL(&node));
}

SYSCTL_SETUP(sysctl_sched_4bsd_setup, "sysctl sched setup")
{
	const struct sysctlnode *node = NULL;

	sysctl_createv(clog, 0, NULL, &node,
		CTLFLAG_PERMANENT,
		CTLTYPE_NODE, "sched",
		SYSCTL_DESCR("Scheduler options"),
		NULL, 0, NULL, 0,
		CTL_KERN, CTL_CREATE, CTL_EOL);

	if (node == NULL)
		return;

	sched_rrticks = hz / 10;

	sysctl_createv(NULL, 0, &node, NULL,
		CTLFLAG_PERMANENT,
		CTLTYPE_STRING, "name", NULL,
		NULL, 0, __UNCONST("4.4BSD"), 0,
		CTL_CREATE, CTL_EOL);
	sysctl_createv(NULL, 0, &node, NULL,
		CTLFLAG_PERMANENT,
		CTLTYPE_INT, "rtts",
		SYSCTL_DESCR("Round-robin time quantum (in milliseconds)"),
		sysctl_sched_rtts, 0, NULL, 0,
		CTL_CREATE, CTL_EOL);
}
