/*	$NetBSD: h_segv.c,v 1.15 2024/05/14 15:54:16 riastradh Exp $	*/

/*-
 * Copyright (c) 2017 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Christos Zoulas.
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
#include <sys/cdefs.h>
__RCSID("$NetBSD: h_segv.c,v 1.15 2024/05/14 15:54:16 riastradh Exp $");

#define	__TEST_FENV

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ptrace.h>

#include <err.h>
#include <fenv.h>
#if (__arm__ && !__SOFTFP__) || __aarch64__
#include <ieeefp.h> /* only need for ARM Cortex/Neon hack */
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int flags;
#define F_RECURSE 	1
#define F_HANDLE	2
#define F_MASK		4
#define F_IGNORE	8
#define	F_CHECK		16

static struct {
	const char *n;
	int v;
} nv[] = {
	{ "recurse",	F_RECURSE },
	{ "handle",	F_HANDLE },
	{ "mask",	F_MASK },
	{ "ignore",	F_IGNORE },
	{ "check",	F_CHECK }
};

static int sig;
static struct {
	const char *n;
	int v;
} sn[] = {
	{ "segv",	SIGSEGV },
	{ "trap",	SIGTRAP },
	{ "ill",	SIGILL },
	{ "fpe",	SIGFPE },
	{ "bus",	SIGBUS }
};

static void
trigger_segv(void)
{
	volatile int *p = (int *)(intptr_t)atoi("0");

	*p = 1;
}

static void
trigger_trap(void)
{

#ifdef PTRACE_BREAKPOINT_ASM
	PTRACE_BREAKPOINT_ASM;
#else
	/* port me */
#endif	
}

static void
trigger_ill(void)
{

#ifdef PTRACE_ILLEGAL_ASM
	PTRACE_ILLEGAL_ASM;
#else
	/* port me */
#endif	
}

static void
check_fpe(void)
{
#if (__arm__ && !__SOFTFP__) || __aarch64__
	/*
	 * Some NEON fpus do not trap on IEEE 754 FP exceptions.
	 * Skip these tests if running on them and compiled for
	 * hard float.
	 */
	if (0 == fpsetmask(fpsetmask(FP_X_INV))) {
		printf("FPU does not implement traps on FP exceptions\n");
		exit(EXIT_FAILURE);
	}
#elif defined __riscv__
	printf("RISC-V does not support floating-point exception traps\n");
	exit(EXIT_FAILURE);
#endif
	exit(EXIT_SUCCESS);
}

volatile int ignore_result;

static void
trigger_fpe(void)
{
	volatile double a = getpid();
	volatile double b = strtol("0", NULL, 0);

#ifdef __HAVE_FENV
	feenableexcept(FE_ALL_EXCEPT);
#endif

	/*
	 * Try to trigger SIGFPE either by dividing by zero (which is
	 * defined to raise FE_DIVBYZERO, but may just return infinity
	 * without trapping the exception) or by converting infinity to
	 * integer.
	 */
	ignore_result = (int)(a/b);
}

static void
trigger_bus(void)
{
	FILE *fp;
	char *p;

	/* Open an empty file for writing. */
	fp = tmpfile();
	if (fp == NULL)
		err(EXIT_FAILURE, "tmpfile");

	/*
	 * Map an empty file with mmap(2) to a pointer.
	 *
	 * PROT_READ handles read-modify-write sequences emitted for
	 * certain combinations of CPUs and compilers (e.g. Alpha AXP).
	 */
	p = mmap(0, 1, PROT_READ|PROT_WRITE, MAP_PRIVATE, fileno(fp), 0);
	if (p == MAP_FAILED)
		err(EXIT_FAILURE, "mmap");

	/* Invalid memory access causes CPU trap, translated to SIGBUS */
	*p = 'a';
}

static void
trigger(void)
{

	switch (sig) {
	case SIGSEGV:
		trigger_segv();
		break;
	case SIGTRAP:
		trigger_trap();
		break;
	case SIGILL:
		trigger_ill();
		break;
	case SIGFPE:
		trigger_fpe();
		break;
	case SIGBUS:
		trigger_bus();
		break;
	default:
		break;
	}
}

static void
foo(int s)
{
	char buf[64];
	int i = snprintf(buf, sizeof(buf), "got %d\n", s);
	write(2, buf, i);

	if (flags & F_RECURSE)
		trigger();

	exit(EXIT_SUCCESS);
}

static __dead void
usage(void)
{
	const char *pname = getprogname();

	fprintf(stderr, "Usage: %s segv|trap|ill|fpe|bus "
	                "[recurse|mask|handle|ignore|check] ...\n", pname);

	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{

	if (argc == 1)
	    usage();

	for (int i = 1; i < argc; i++) {
		size_t j;
		for (j = 0; j < __arraycount(nv); j++) {
			if (strcmp(nv[j].n, argv[i]) == 0) {
				flags |= nv[j].v;
				goto consumed;
			}
		}
		for (j = 0; j < __arraycount(sn); j++) {
			if (strcmp(sn[j].n, argv[i]) == 0) {
				sig = sn[j].v;
				goto consumed;
			}
		}

		usage();

	consumed:
		continue;
	}

	if (flags == 0 || sig == 0)
		usage();

	if (flags & F_CHECK && sig != SIGFPE) {
		fprintf(stderr, "can only check for fpe support\n");
		return 1;
	}
	if (flags & F_CHECK)
		check_fpe();

	if (flags & F_HANDLE) {
		struct sigaction sa;

		sa.sa_flags = SA_RESTART;
		sa.sa_handler = foo;
		sigemptyset(&sa.sa_mask);
		if (sigaction(sig, &sa, NULL) == -1)
			err(EXIT_FAILURE, "sigaction");
	}

	if (flags & F_MASK) {
		sigset_t set;

		sigemptyset(&set);
		sigaddset(&set, sig);
		if (sigprocmask(SIG_BLOCK, &set, NULL) == -1)
			err(EXIT_FAILURE, "sigprocmask");
	}

	if (flags & F_IGNORE) {
		struct sigaction sa;

		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = SIG_IGN;
		sigemptyset(&sa.sa_mask);
		if (sigaction(sig, &sa, NULL) == -1)
			err(EXIT_FAILURE, "sigaction");
	}

	trigger();

	return EXIT_SUCCESS;
}
