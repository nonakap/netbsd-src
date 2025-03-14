/*	$NetBSD: e_atan2l.c,v 1.2 2024/01/23 15:45:07 christos Exp $	*/
/* @(#)e_atan2.c 1.3 95/01/18 */
/* FreeBSD: head/lib/msun/src/e_atan2.c 176451 2008-02-22 02:30:36Z das */
/*
 * ====================================================
 * Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
 *
 * Developed at SunSoft, a Sun Microsystems, Inc. business.
 * Permission to use, copy, modify, and distribute this
 * software is freely granted, provided that this notice 
 * is preserved.
 * ====================================================
 *
 */

#include <sys/cdefs.h>
__RCSID("$NetBSD: e_atan2l.c,v 1.2 2024/01/23 15:45:07 christos Exp $");

/*
 * See comments in e_atan2.c.
 * Converted to long double by David Schultz <das@FreeBSD.ORG>.
 */

#include "namespace.h"

#ifdef __weak_alias
__weak_alias(atan2l, _atan2l)
#endif

#include <float.h>
#include <machine/ieee.h>

#include "math.h"
#include "math_private.h"

#ifdef __HAVE_LONG_DOUBLE

#if LDBL_MANT_DIG == 64
#include "../ld80/invtrig.h"
#elif LDBL_MANT_DIG == 113
#include "../ld128/invtrig.h"
#else
#error "Unsupported long double format"
#endif

#ifdef LDBL_IMPLICIT_NBIT
#define	LDBL_NBIT	0
#endif

static volatile long double
tiny  = 1.0e-300;
static const long double
zero  = 0.0;

#ifdef __i386__
/* XXX Work around the fact that gcc truncates long double constants on i386 */
static volatile double
pi1 =  3.14159265358979311600e+00,	/*  0x1.921fb54442d18p+1  */
pi2 =  1.22514845490862001043e-16;	/*  0x1.1a80000000000p-53 */
#define	pi	((long double)pi1 + pi2)
#else
static const long double
pi =  3.14159265358979323846264338327950280e+00L;
#endif

long double
atan2l(long double y, long double x)
{
	union ieee_ext_u ux, uy;
	long double z;
	int32_t k,m;
	int16_t exptx, expsignx, expty, expsigny;

	uy.extu_ld = y;
	expsigny = GET_EXPSIGN(&uy);
	expty = expsigny & 0x7fff;
	ux.extu_ld = x;
	expsignx = GET_EXPSIGN(&ux);
	exptx = expsignx & 0x7fff;

	if ((exptx==BIAS+LDBL_MAX_EXP &&
	     ((ux.extu_frach&~LDBL_NBIT)|ux.extu_fracl)!=0) ||	/* x is NaN */
	    (expty==BIAS+LDBL_MAX_EXP &&
	     ((uy.extu_frach&~LDBL_NBIT)|uy.extu_fracl)!=0))	/* y is NaN */
	    return nan_mix(x, y);
	if (expsignx==BIAS && ((ux.extu_frach&~LDBL_NBIT)|ux.extu_fracl)==0)
	    return atanl(y);					/* x=1.0 */
	m = ((expsigny>>15)&1)|((expsignx>>14)&2);	/* 2*sign(x)+sign(y) */

    /* when y = 0 */
	if(expty==0 && ((uy.extu_frach&~LDBL_NBIT)|uy.extu_fracl)==0) {
	    switch(m) {
		case 0: 
		case 1: return y; 	/* atan(+-0,+anything)=+-0 */
		case 2: return  pi+tiny;/* atan(+0,-anything) = pi */
		case 3: return -pi-tiny;/* atan(-0,-anything) =-pi */
	    }
	}
    /* when x = 0 */
	if(exptx==0 && ((ux.extu_frach&~LDBL_NBIT)|ux.extu_fracl)==0)
	    return (expsigny<0)?  -pio2_hi-tiny: pio2_hi+tiny;

    /* when x is INF */
	if(exptx==BIAS+LDBL_MAX_EXP) {
	    if(expty==BIAS+LDBL_MAX_EXP) {
		switch(m) {
		    case 0: return  pio2_hi*0.5+tiny;/* atan(+INF,+INF) */
		    case 1: return -pio2_hi*0.5-tiny;/* atan(-INF,+INF) */
		    case 2: return  1.5*pio2_hi+tiny;/*atan(+INF,-INF)*/
		    case 3: return -1.5*pio2_hi-tiny;/*atan(-INF,-INF)*/
		}
	    } else {
		switch(m) {
		    case 0: return  zero  ;	/* atan(+...,+INF) */
		    case 1: return -zero  ;	/* atan(-...,+INF) */
		    case 2: return  pi+tiny  ;	/* atan(+...,-INF) */
		    case 3: return -pi-tiny  ;	/* atan(-...,-INF) */
		}
	    }
	}
    /* when y is INF */
	if(expty==BIAS+LDBL_MAX_EXP)
	    return (expsigny<0)? -pio2_hi-tiny: pio2_hi+tiny;

    /* compute y/x */
	k = expty-exptx;
	if(k > LDBL_MANT_DIG+2) {			/* |y/x| huge */
	    z=pio2_hi+pio2_lo;
	    m&=1;
	}
	else if(expsignx<0&&k<-LDBL_MANT_DIG-2) z=0.0; 	/* |y/x| tiny, x<0 */
	else z=atanl(fabsl(y/x));		/* safe to do y/x */
	switch (m) {
	    case 0: return       z  ;	/* atan(+,+) */
	    case 1: return      -z  ;	/* atan(-,+) */
	    case 2: return  pi-(z-pi_lo);/* atan(+,-) */
	    default: /* case 3 */
	    	    return  (z-pi_lo)-pi;/* atan(-,-) */
	}
}

#else

long double
atan2l(long double y, long double x)
{
	return atan2(y, x);
}

#endif
