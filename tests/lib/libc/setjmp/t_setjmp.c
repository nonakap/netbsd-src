/* $NetBSD: t_setjmp.c,v 1.13 2025/04/28 18:29:09 martin Exp $ */

/*-
 * Copyright (c) 2008 The NetBSD Foundation, Inc.
 * All rights reserved.
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
 * Copyright (c) 1994 Christopher G. Demetriou
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *          This product includes software developed for the
 *          NetBSD Project.  See http://www.NetBSD.org/ for
 *          information about NetBSD.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * <<Id: LICENSE,v 1.2 2000/06/14 15:57:33 cgd Exp>>
 */

#include <sys/cdefs.h>
__COPYRIGHT("@(#) Copyright (c) 2008\
 The NetBSD Foundation, inc. All rights reserved.");
__RCSID("$NetBSD: t_setjmp.c,v 1.13 2025/04/28 18:29:09 martin Exp $");

#include <sys/types.h>

#include <dlfcn.h>
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "h_macros.h"

enum test {
	TEST_SETJMP,
	TEST_U_SETJMP,
	TEST_SIGSETJMP_SAVE,
	TEST_SIGSETJMP_NOSAVE,
	TEST_LONGJMP_ZERO,
	TEST_U_LONGJMP_ZERO,

	TEST_COMPAT13_SETJMP,
	TEST_COMPAT13_SIGSETJMP_SAVE,
	TEST_COMPAT13_SIGSETJMP_NOSAVE,
	TEST_COMPAT13_LONGJMP_ZERO,
};

/*
 * Optional compat13 functions from when sigcontext was expanded.
 * Fortunately the only change visible to the caller is that the size
 * of jmp_buf increased, so we can always use the old symbols with new
 * jmp_buf arrays.
 */
int (*compat13_sigsetjmp)(sigjmp_buf, int);
void (*compat13_siglongjmp)(sigjmp_buf, int);
int (*compat13_setjmp)(jmp_buf);
void (*compat13_longjmp)(jmp_buf, int);

/*
 * compatsigsys(signo)
 *
 *	Signal handler for SIGSYS in case compat_13_sigreturn13 is not
 *	implemented by the kernel -- we will just skip the test in that
 *	case.
 */
static void
compatsigsys(int signo)
{

	atf_tc_skip("no compat syscalls to test");
}

static void
compatsetup(void)
{

	/*
	 * Grab the libc library symbols if available.
	 */
	if ((compat13_sigsetjmp = dlsym(RTLD_SELF, "sigsetjmp")) == NULL ||
	    (compat13_siglongjmp = dlsym(RTLD_SELF, "siglongjmp")) == NULL ||
	    (compat13_setjmp = dlsym(RTLD_SELF, "setjmp")) == NULL ||
	    (compat13_longjmp = dlsym(RTLD_SELF, "longjmp")) == NULL)
		atf_tc_skip("no compat functions to test");

	/*
	 * Arrange for SIGSYS to skip the test -- this happens if the
	 * libc stub has the function, but the kernel isn't built with
	 * support for the compat13 sigreturn syscall for longjmp.
	 */
	REQUIRE_LIBC(signal(SIGSYS, &compatsigsys), SIG_ERR);
}

static int expectsignal;

static void
aborthandler(int signo __unused)
{
	ATF_REQUIRE_MSG(expectsignal, "kill(SIGABRT) succeeded");
	atf_tc_pass();
}

static void
h_check(enum test test)
{
	struct sigaction sa;
	jmp_buf jb;
	sigjmp_buf sjb;
	sigset_t ss;
	int i, x;
	volatile bool did_longjmp;

	i = getpid();
	did_longjmp = false;

	switch (test) {
	case TEST_COMPAT13_SETJMP:
	case TEST_COMPAT13_SIGSETJMP_SAVE:
	case TEST_COMPAT13_LONGJMP_ZERO:
	case TEST_COMPAT13_SIGSETJMP_NOSAVE:
		compatsetup();
		break;
	default:
		break;
	}

	switch (test) {
	case TEST_SETJMP:
	case TEST_SIGSETJMP_SAVE:
	case TEST_LONGJMP_ZERO:
	case TEST_COMPAT13_SETJMP:
	case TEST_COMPAT13_SIGSETJMP_SAVE:
	case TEST_COMPAT13_LONGJMP_ZERO:
		expectsignal = 0;
		break;
	case TEST_U_SETJMP:
	case TEST_SIGSETJMP_NOSAVE:
	case TEST_U_LONGJMP_ZERO:
	case TEST_COMPAT13_SIGSETJMP_NOSAVE:
		expectsignal = 1;
		break;
	default:
		atf_tc_fail("unknown test");
	}

	sa.sa_handler = aborthandler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	RL(sigaction(SIGABRT, &sa, NULL));
	RL(sigemptyset(&ss));
	RL(sigaddset(&ss, SIGABRT));
	RL(sigprocmask(SIG_BLOCK, &ss, NULL));

	switch (test) {
	case TEST_SETJMP:
	case TEST_LONGJMP_ZERO:
		x = setjmp(jb);
		break;
	case TEST_COMPAT13_SETJMP:
	case TEST_COMPAT13_LONGJMP_ZERO:
		x = (*compat13_setjmp)(jb);
		break;
	case TEST_U_SETJMP:
	case TEST_U_LONGJMP_ZERO:
		x = _setjmp(jb);
		break;
	case TEST_SIGSETJMP_SAVE:
	case TEST_SIGSETJMP_NOSAVE:
		x = sigsetjmp(sjb, !expectsignal);
		break;
	case TEST_COMPAT13_SIGSETJMP_SAVE:
	case TEST_COMPAT13_SIGSETJMP_NOSAVE:
		x = (*compat13_sigsetjmp)(sjb, !expectsignal);
		break;
	default:
		atf_tc_fail("unknown test");
	}

	if (x != 0) {
		switch (test) {
		case TEST_LONGJMP_ZERO:
		case TEST_U_LONGJMP_ZERO:
		case TEST_COMPAT13_LONGJMP_ZERO:
			ATF_REQUIRE_MSG(x == 1, "setjmp returned wrong value");
			break;
		default:
			ATF_REQUIRE_MSG(x == i, "setjmp returned wrong value");
		}

		kill(i, SIGABRT);
		ATF_REQUIRE_MSG(!expectsignal, "kill(SIGABRT) failed");
		atf_tc_pass();
	} else if (did_longjmp) {
		atf_tc_fail("setjmp returned zero after longjmp");
	}

	RL(sigprocmask(SIG_UNBLOCK, &ss, NULL));

	did_longjmp = true;
	switch (test) {
	case TEST_SETJMP:
		longjmp(jb, i);
		break;
	case TEST_COMPAT13_SETJMP:
		(*compat13_longjmp)(jb, i);
		break;
	case TEST_LONGJMP_ZERO:
		longjmp(jb, 0);
		break;
	case TEST_COMPAT13_LONGJMP_ZERO:
		(*compat13_longjmp)(jb, 0);
		break;
	case TEST_U_SETJMP:
		_longjmp(jb, i);
		break;
	case TEST_U_LONGJMP_ZERO:
		_longjmp(jb, 0);
		break;
	case TEST_SIGSETJMP_SAVE:
	case TEST_SIGSETJMP_NOSAVE:
		siglongjmp(sjb, i);
		break;
	case TEST_COMPAT13_SIGSETJMP_SAVE:
	case TEST_COMPAT13_SIGSETJMP_NOSAVE:
		(*compat13_siglongjmp)(sjb, i);
		break;
	default:
		atf_tc_fail("unknown test");
	}

	atf_tc_fail("jmp failed");
}

ATF_TC(setjmp);
ATF_TC_HEAD(setjmp, tc)
{
	atf_tc_set_md_var(tc, "descr", "Checks setjmp(3)");
}
ATF_TC_BODY(setjmp, tc)
{
	h_check(TEST_SETJMP);
}

ATF_TC(_setjmp);
ATF_TC_HEAD(_setjmp, tc)
{
	atf_tc_set_md_var(tc, "descr", "Checks _setjmp(3)");
}
ATF_TC_BODY(_setjmp, tc)
{
	h_check(TEST_U_SETJMP);
}

ATF_TC(sigsetjmp_save);
ATF_TC_HEAD(sigsetjmp_save, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Checks sigsetjmp(3) with savemask enabled");
}
ATF_TC_BODY(sigsetjmp_save, tc)
{
	h_check(TEST_SIGSETJMP_SAVE);
}

ATF_TC(sigsetjmp_nosave);
ATF_TC_HEAD(sigsetjmp_nosave, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Checks sigsetjmp(3) with savemask disabled");
}
ATF_TC_BODY(sigsetjmp_nosave, tc)
{
	h_check(TEST_SIGSETJMP_NOSAVE);
}

ATF_TC(longjmp_zero);
ATF_TC_HEAD(longjmp_zero, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Checks longjmp(3) with a zero value");
}
ATF_TC_BODY(longjmp_zero, tc)
{
	h_check(TEST_LONGJMP_ZERO);
}

ATF_TC(_longjmp_zero);
ATF_TC_HEAD(_longjmp_zero, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Checks _longjmp(3) with a zero value");
}
ATF_TC_BODY(_longjmp_zero, tc)
{
	h_check(TEST_U_LONGJMP_ZERO);
}

ATF_TC(compat13_setjmp);
ATF_TC_HEAD(compat13_setjmp, tc)
{
	atf_tc_set_md_var(tc, "descr", "Checks compat13 setjmp(3)");
}
ATF_TC_BODY(compat13_setjmp, tc)
{
#ifdef __arm__
	atf_tc_expect_signal(-1, "PR port-arm/59351: compat_setjmp is busted");
#endif
	h_check(TEST_COMPAT13_SETJMP);
}

ATF_TC(compat13_sigsetjmp_save);
ATF_TC_HEAD(compat13_sigsetjmp_save, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Checks compat13 sigsetjmp(3) with savemask enabled");
}
ATF_TC_BODY(compat13_sigsetjmp_save, tc)
{
#ifdef __arm__
	atf_tc_expect_signal(-1, "PR port-arm/59351: compat_setjmp is busted");
#endif
	h_check(TEST_COMPAT13_SIGSETJMP_SAVE);
}

ATF_TC(compat13_sigsetjmp_nosave);
ATF_TC_HEAD(compat13_sigsetjmp_nosave, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Checks compat13 sigsetjmp(3) with savemask disabled");
}
ATF_TC_BODY(compat13_sigsetjmp_nosave, tc)
{
	h_check(TEST_COMPAT13_SIGSETJMP_NOSAVE);
}

ATF_TC(compat13_longjmp_zero);
ATF_TC_HEAD(compat13_longjmp_zero, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Checks compat13 longjmp(3) with a zero value");
}
ATF_TC_BODY(compat13_longjmp_zero, tc)
{
#ifdef __arm__
	atf_tc_expect_signal(-1, "PR port-arm/59351: compat_setjmp is busted");
#endif
	h_check(TEST_COMPAT13_LONGJMP_ZERO);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, setjmp);
	ATF_TP_ADD_TC(tp, _setjmp);
	ATF_TP_ADD_TC(tp, sigsetjmp_save);
	ATF_TP_ADD_TC(tp, sigsetjmp_nosave);
	ATF_TP_ADD_TC(tp, longjmp_zero);
	ATF_TP_ADD_TC(tp, _longjmp_zero);

	ATF_TP_ADD_TC(tp, compat13_setjmp);
	ATF_TP_ADD_TC(tp, compat13_sigsetjmp_save);
	ATF_TP_ADD_TC(tp, compat13_sigsetjmp_nosave);
	ATF_TP_ADD_TC(tp, compat13_longjmp_zero);

	return atf_no_error();
}
