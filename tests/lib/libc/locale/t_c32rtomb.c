/*	$NetBSD: t_c32rtomb.c,v 1.1 2024/08/15 14:16:34 riastradh Exp $	*/

/*-
 * Copyright (c) 2024 The NetBSD Foundation, Inc.
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

#include <sys/cdefs.h>
__RCSID("$NetBSD: t_c32rtomb.c,v 1.1 2024/08/15 14:16:34 riastradh Exp $");

#include <atf-c.h>
#include <locale.h>
#include <uchar.h>

#include "h_macros.h"

ATF_TC(c32rtomb_null);
ATF_TC_HEAD(c32rtomb_null, tc)
{
	atf_tc_set_md_var(tc, "descr", "Test null string output to c32rtomb");
}
ATF_TC_BODY(c32rtomb_null, tc)
{
	char *locale;
	mbstate_t ps = {0};
	size_t n;

	REQUIRE_LIBC((locale = setlocale(LC_ALL, "C")), NULL);
	ATF_REQUIRE_EQ_MSG(strcmp(locale, "C"), 0, "locale=%s", locale);

	ATF_CHECK_EQ_MSG((n = c32rtomb(NULL, L'x', &ps)), 1, "n=%zu", n);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, c32rtomb_null);
	return atf_no_error();
}
