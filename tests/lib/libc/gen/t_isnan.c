/* $NetBSD: t_isnan.c,v 1.6 2025/04/07 01:54:22 riastradh Exp $ */

/*
 * This file is in the Public Domain.
 *
 * The nan test is blatently copied by Simon Burge from the infinity
 * test by Ben Harris.
 */

#include <sys/param.h>

#include <atf-c.h>

#include <math.h>
#include <string.h>

ATF_TC(isnan_basic);
ATF_TC_HEAD(isnan_basic, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verify that isnan(3) works");
}

ATF_TC_BODY(isnan_basic, tc)
{

#ifdef NAN
	/* NAN is meant to be a (float)NaN. */
	ATF_CHECK(isnan(NAN) != 0);
	ATF_CHECK(isnan((double)NAN) != 0);
#else
	atf_tc_skip("No NaN on this architecture");
#endif
}

ATF_TC(isinf_basic);
ATF_TC_HEAD(isinf_basic, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verify that isinf(3) works");
}

ATF_TC_BODY(isinf_basic, tc)
{
#ifdef __vax__
	atf_tc_skip("No infinity on this architecture");
#endif

	/* HUGE_VAL is meant to be an infinity. */
	ATF_CHECK(isinf(HUGE_VAL) != 0);

	/* HUGE_VALF is the float analog of HUGE_VAL. */
	ATF_CHECK(isinf(HUGE_VALF) != 0);

	/* HUGE_VALL is the long double analog of HUGE_VAL. */
	ATF_CHECK(isinf(HUGE_VALL) != 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, isnan_basic);
	ATF_TP_ADD_TC(tp, isinf_basic);

	return atf_no_error();
}
