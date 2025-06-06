#  $NetBSD: Makefile,v 1.242 2025/04/06 23:03:06 rillig Exp $
#
#  @(#)Makefile 5.1beta 93/09/24
#
#  ====================================================
#  Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
#
#  Developed at SunPro, a Sun Microsystems, Inc. business.
#  Permission to use, copy, modify, and distribute this
#  software is freely granted, provided that this notice
#  is preserved.
#  ====================================================
#
#

NOSANITIZER=		# defined

#
# There are two options in making libm at fdlibm compile time:
# 	_IEEE_LIBM 	--- IEEE libm; smaller, and somewhat faster
#	_MULTI_LIBM	--- Support multi-standard at runtime by
#			    imposing wrapper functions defined in
#			    fdlibm.h:
#				_IEEE_MODE 	-- IEEE
#				_XOPEN_MODE 	-- X/OPEN
#				_POSIX_MODE 	-- POSIX/ANSI
#				_SVID3_MODE 	-- SVID
#
# Here is how to set up CPPFLAGS to create the desired libm at
# compile time:
#
# 	CPPFLAGS = -D_IEEE_LIBM		... IEEE libm (recommended)
#	CPPFLAGS = -D_SVID3_MODE	... Multi-standard supported
#					    libm with SVID as the
#					    default standard
#	CPPFLAGS = -D_XOPEN_MODE	... Multi-standard supported
#					    libm with XOPEN as the
#					    default standard
#	CPPFLAGS = -D_POSIX_MODE	... Multi-standard supported
#					    libm with POSIX as the
#					    default standard
#	CPPFLAGS = 			... Multi-standard supported
#					    libm with IEEE as the
#					    default standard
#

USE_SHLIBDIR=	yes

# require this for the value of I387_LIBM from mk.conf, if set.
.include <bsd.own.mk>

LIBC_MACHINE_ARCH?=	${MACHINE_ARCH}
LIBC_MACHINE_CPU?=	${MACHINE_CPU}

LINTFLAGS+=	-g		# compiler_rt uses typeof() and __extension__
LINTFLAGS+=	-X 117		# GCC sign-extends '>>' on signed int
LINTFLAGS.s_logl.c+=	-X 193	# unreachable statement (due to constant condition)
LINTFLAGS.s_logl.c+=	-X 177	# non-constant initializer

EXPSYM_SRCS=	m.common.expsym
EXPSYM_SRCS+=	m.ieee754.expsym
EXPSYM_SRCS+=	m.fenv.expsym
EXPSYM_SRCS+=	${EXPSYM_SRC_MD:U}

.if exists(${.CURDIR}/m.${LIBC_MACHINE_ARCH}.expsym)
EXPSYM_SRC_MD=	m.${LIBC_MACHINE_ARCH}.expsym
.elif exists(${.CURDIR}/m.${LIBC_MACHINE_CPU}.expsym)
EXPSYM_SRC_MD=	m.${LIBC_MACHINE_CPU}.expsym
.endif

# We will build m.expsym with a rule below, by merging all the files
# listed in EXPSYM_SRCS, which individual architectures can override.
# (The rule has to be written below after EXPSYM_SRCS has been
# determined.)
LIB_EXPSYM=	m.expsym

COPTS+=	${${ACTIVE_CC} == "gcc":? -frounding-math :}

.if (${LIBC_MACHINE_CPU} == "aarch64")
.PATH: ${.CURDIR}/arch/aarch64
ARCH_SRCS = e_sqrt.S e_sqrtf.S s_fabsf.S
ARCH_SRCS+= s_fma.S s_fmaf.S s_fmax.S s_fmaxf.S s_fmin.S s_fminf.S
.if ${MKSOFTFLOAT} == "no"
COMMON_SRCS+= fenv.c
.endif
COMMON_SRCS+= s_nexttoward.c s_rintl.c
COMMON_SRCS+= e_sqrtl.c
COMMON_SRCS+= s_fma.c s_fmaf.c s_fmal.c

.elif (${LIBC_MACHINE_ARCH} == "alpha")
.PATH: ${.CURDIR}/arch/alpha
ARCH_SRCS = s_copysign.S s_copysignf.S lrint.S
COMMON_SRCS+= fenv.c
COMMON_SRCS+= s_fma.c s_fmaf.c s_fmal.c
COPTS+=	-mfloat-ieee -mieee-with-inexact -mfp-trap-mode=sui -mtrap-precision=i

# alpha doesn't have symbols for:
#
#	feclearexcept
#	fegetexceptflag
#	fegetround
#	feraiseexcept
#	fesetexceptflag
#	fesetround
#	fetestexcept
#
# Instead, they are static inlines in fenv.h.  So we won't use
# m.fenv.expsym.
#
EXPSYM_SRCS=	m.common.expsym m.ieee754.expsym m.alpha.expsym

.elif (${LIBC_MACHINE_CPU} == "arm")
.PATH.c: ${.CURDIR}/arch/arm
.if ${MKSOFTFLOAT} == "no"
COMMON_SRCS+= fenv.c
EXPSYM_SRC_MD=	m.armhf.expsym
.endif
.for f in fenv.c lrint.S lrintf.S s_fabsf.S s_fma.S s_fmaf.S
COPTS.$f +=	-mfpu=vfp
.endfor
COMMON_SRCS+= s_fma.c s_fmaf.c s_fmal.c
.if (${MKSOFTFLOAT} == "no")
.PATH.S: ${.CURDIR}/arch/arm
ARCH_SRCS = e_sqrt.S e_sqrtf.S lrint.S lrintf.S s_fabsf.S s_fma.S s_fmaf.S
.endif

.elif (${LIBC_MACHINE_ARCH} == "ia64")
.PATH: ${.CURDIR}/arch/ia64
COMMON_SRCS += fenv.c

.elif (${LIBC_MACHINE_ARCH} == "hppa")
.PATH.c: ${.CURDIR}/arch/hppa
COMMON_SRCS+= fenv.c
COMMON_SRCS+= s_fma.c s_fmaf.c s_fmal.c

.elif (${LIBC_MACHINE_ARCH} == "sparc")
.PATH: ${.CURDIR}/arch/sparc
COMMON_SRCS+= fenv.c
COMMON_SRCS+= s_fma.c s_fmaf.c s_fmal.c

.elif (${LIBC_MACHINE_ARCH} == "sparc64")
.PATH: ${.CURDIR}/arch/sparc64
COMMON_SRCS+= fenv.c
COMMON_SRCS+= s_rintl.c
.ifndef _COMPAT_M32_MK_
COMMON_SRCS+= s_nexttoward.c
.endif
COMMON_SRCS+= s_fma.c s_fmaf.c s_fmal.c

.elif ((${MACHINE_ARCH} == "i386") || (${MACHINE_ARCH} == "x86_64"))

# XXX consider making this LIBC_MACHINE_ARCH?
.if (${MACHINE_ARCH} == "x86_64")
.PATH: ${.CURDIR}/arch/x86_64
.endif
.PATH:	${.CURDIR}/arch/i387

COMMON_SRCS+= fenv.c s_nexttoward.c s_rintl.c
COMMON_SRCS+= s_fma.c s_fmaf.c s_fmal.c

ARCH_SRCS = e_acos.S e_asin.S e_atan2.S e_exp.S e_expf.S e_fmod.S e_log.S \
	    e_logf.S e_log10.S e_log10f.S e_log2.S e_log2f.S e_remainder.S \
	    e_remainderf.S e_scalb.S e_scalbf.S e_sqrt.S e_sqrtf.S s_atan.S \
	    s_atanf.S s_ceil.S s_ceilf.S s_copysign.S s_copysignf.S \
	    s_finite.S s_finitef.S s_floor.S s_floorf.S \
	    s_log1p.S s_log1pf.S s_logb.S s_logbf.S s_logbl.S \
	    s_rint.S s_rintf.S s_rintl.S \
	    s_scalbn.S s_scalbnf.S \
	    s_significand.S s_significandf.S \
	    lrint.S
# do not pick up the i387 asm version for the following functions;
# it is incorrect
.for f in cos cosf modf ilogb ilogbl ilogbf sin sinf tan tanf
s_${f}.o s_${f}.pico s_${f}.po s_${f}.go s_${f}.d: s_${f}.c
.endfor

.if (${MACHINE_ARCH} == "i386")
SUBDIR=arch/i387
.endif

.elif (${LIBC_MACHINE_ARCH} == "m68k")
.if defined(M68060)
.PATH:	${.CURDIR}/arch/m68060
.include "${.CURDIR}/arch/m68060/Makefile.list"
COPTS+= -m68060
.PATH:	${.CURDIR}/arch/m68k
ARCH_SRCS += s_ceil.S s_copysign.S s_finite.S s_floor.S s_rint.S
.elif defined(M68040)
.PATH: ${.CURDIR}/arch/m68k
COPTS+= -m68040
ARCH_SRCS = s_copysign.S s_finite.S
.endif
.if (${MKSOFTFLOAT} == "no")
.PATH:	${.CURDIR}/arch/mc68881 ${.CURDIR}/arch/m68k
ARCH_SRCS = e_acos.S e_asin.S e_atanh.S e_cosh.S e_exp.S e_fmod.S e_log.S \
	    e_log10.S e_remainder.S e_scalb.S e_sinh.S e_sqrt.S s_atan.S \
	    s_ceil.S s_copysign.S s_cos.S s_expm1.S s_finite.S s_floor.S \
	    s_log1p.S s_logb.S s_rint.S s_scalbn.S s_sin.S s_tan.S s_tanh.S
COMMON_SRCS += fenv.c
.endif
COMMON_SRCS += s_nexttoward.c s_rintl.c
COMMON_SRCS+= s_fma.c s_fmaf.c s_fmal.c
# end of m68k

.elif (${LIBC_MACHINE_ARCH} == "vax")
.PATH:	${.CURDIR}/arch/vax

#NOIEEE_ARCH+= s_fmax.c s_fmaxf.c s_fmaxl.c
#NOIEEE_ARCH+= n_infnan.S n_argred.S n_sqrt.S
#ARCH_SRCS = n_atan2.S n_cabs.S n_cbrt.S n_support.S n_sincos.S n_tan.S
# XXX - ripped out due to lack of the insn polyd in the Mariah chip,
# and emulation code isn't written yet.
ARCH_SRCS = n_scalbn.S
WARNS?=5

# No IEEE 754 stuff.  Not all of it is actually specific to IEEE 754,
# but it's missing anyway: PR port-vax/57881.
EXPSYM_SRCS=	m.common.expsym m.vax.expsym

.elif (${LIBC_MACHINE_CPU} == "riscv")
.PATH:	${.CURDIR}/arch/riscv

COMMON_SRCS+= s_nexttoward.c s_rintl.c

.if ${MKSOFTFLOAT} == "no"
COMMON_SRCS += fenv.c
ARCH_SRCS = e_sqrt.S e_sqrtf.S
ARCH_SRCS += s_copysign.S s_copysignf.S
ARCH_SRCS += s_fabs.S s_fabsf.S
ARCH_SRCS += s_fma.S s_fmaf.S
ARCH_SRCS += s_fmax.S s_fmaxf.S
ARCH_SRCS += s_fmin.S s_fminf.S
.endif

.elif (${LIBC_MACHINE_CPU} == "powerpc")
.PATH:	${.CURDIR}/arch/powerpc
.if ${MKSOFTFLOAT} == "no"
COMMON_SRCS += fenv.c
.endif
COMMON_SRCS+= s_fma.c s_fmaf.c s_fmal.c
ARCH_SRCS += s_fma.S s_fmaf.S

.elif (${LIBC_MACHINE_CPU} == "mips")
.PATH:	${.CURDIR}/arch/mips
.if ${MKSOFTFLOAT} == "no"
COMMON_SRCS += fenv.c
.endif
.if ${MACHINE_MIPS64} && (!defined(CPUFLAGS) || empty(CPUFLAGS:M-mabi=32))
COMMON_SRCS+= s_nexttoward.c
COMMON_SRCS+= s_rintl.c
.endif
COMMON_SRCS+= s_fma.c s_fmaf.c s_fmal.c

.  if ${MKSOFTFLOAT} == "no"
.    if ${MACHINE_MIPS64} && (!defined(CPUFLAGS) || empty(CPUFLAGS:M-mabi=32))
EXPSYM_SRC_MD=	m.mips64hf.expsym
.    else
EXPSYM_SRC_MD=	m.mipshf.expsym
.    endif
.  else
.    if ${MACHINE_MIPS64} && (!defined(CPUFLAGS) || empty(CPUFLAGS:M-mabi=32))
EXPSYM_SRC_MD=	m.mips64.expsym
.    else
EXPSYM_SRC_MD=	m.mips.expsym
.    endif
.  endif

.elif (${LIBC_MACHINE_CPU} == "sh3")
.PATH:	${.CURDIR}/arch/sh3
.if ${MKSOFTFLOAT} == "no"
COMMON_SRCS += fenv.c
.endif
COMMON_SRCS+= s_fma.c s_fmaf.c s_fmal.c
.endif
# End of list of CPU tests

WARNS?=5

.PATH:	${.CURDIR}/man
.PATH:	${.CURDIR}/src
.PATH:	${.CURDIR}/noieee_src

m.expsym: ${EXPSYM_SRCS}
	${_MKTARGET_CREATE}
	LC_ALL=C sort -m ${.ALLSRC} >${.TARGET}.tmp && \
	${MV} ${.TARGET}.tmp ${.TARGET}
CLEANFILES+=	m.expsym m.expsym.tmp

.if (${LIBC_MACHINE_ARCH} == "alpha")
COPTS+= -mfp-rounding-mode=d
.endif

.if (${LIBC_MACHINE_ARCH} != "vax")
CPPFLAGS+= -D_MULTI_LIBM -D_POSIX_MODE
# XXX noieee libm is gross
COPTS+=	-fno-strict-aliasing
.endif
CPPFLAGS+=-DLIBM_SCCS

.if (${MKSOFTFLOAT} != "no" || ${MACHINE_ARCH} == "m68000")
.PATH:	${.CURDIR}/softfloat
.include "${.CURDIR}/../libc/libcincludes.mk"
CPPFLAGS+=	-I${ARCHDIR}/softfloat
COMMON_SRCS += \
	feclearexcept.c \
	fedisableexcept.c \
	feenableexcept.c \
	fegetenv.c \
	fegetexcept.c \
	fegetexceptflag.c \
	fegetround.c \
	feholdexcept.c \
	feraiseexcept.c \
	fesetenv.c \
	fesetexceptflag.c \
	fesetround.c \
	fetestexcept.c \
	feupdateenv.c
.endif

LIB=	m
COMMON_SRCS+= b_exp.c b_log.c \
	b_tgamma.c b_tgammal.c \
	e_acos.c e_acosf.c e_acosl.c \
	e_acosh.c e_acoshf.c e_acoshl.c \
	e_asin.c e_asinf.c e_asinl.c \
	e_atan2.c e_atan2f.c e_atan2l.c \
	e_atanh.c e_atanhf.c e_atanhl.c \
	e_cosh.c e_coshf.c e_coshl.c \
	e_exp.c  e_expf.c \
	e_fmod.c e_fmodf.c e_fmodl.c \
	e_hypot.c e_hypotf.c e_hypotl.c \
	e_j0.c e_j0f.c \
	e_j1.c e_j1f.c \
	e_jn.c e_jnf.c \
	e_lgammal.c \
	e_lgamma_r.c e_lgammaf_r.c e_lgammal_r.c e_log.c \
	e_log2.c e_log10.c e_log10f.c e_log2f.c e_logf.c \
	e_pow.c e_powf.c e_powl.c \
	e_rem_pio2.c e_rem_pio2f.c \
	e_remainder.c e_remainderf.c e_remainderl.c \
	e_scalb.c e_scalbf.c \
	e_sinh.c e_sinhf.c e_sinhl.c \
	e_sqrt.c e_sqrtf.c e_sqrtl.c \
	invtrig.c \
	k_cos.c k_cosf.c \
	k_rem_pio2.c k_rem_pio2f.c \
	k_sin.c k_sinf.c \
	k_standard.c k_tan.c k_tanf.c \
	s_asinh.c s_asinhf.c s_asinhl.c \
	s_atan.c s_atanf.c s_atanl.c \
	s_cbrt.c s_cbrtf.c s_cbrtl.c \
	s_ceil.c s_ceilf.c s_ceill.c s_copysign.c s_copysignf.c s_copysignl.c \
	s_cos.c s_cosf.c s_cosl.c \
	s_cospi.c s_cospif.c s_cospil.c \
	s_erf.c s_erff.c s_erfl.c \
	s_exp2.c s_exp2f.c s_expl.c s_exp2l.c s_expm1.c s_expm1f.c \
	s_fabsf.c s_fabsl.c \
	s_finite.c s_finitef.c \
	s_floor.c s_floorf.c s_floorl.c s_frexpf.c \
	s_ilogb.c s_ilogbf.c s_ilogbl.c \
	s_isinff.c s_isnanf.c s_lib_version.c s_log1p.c \
	s_llrint.c s_llrintf.c s_llrintl.c \
	s_llround.c s_llroundf.c s_llroundl.c \
	s_lrint.c s_lrintf.c s_lrintl.c \
	s_lround.c s_lroundf.c s_lroundl.c \
	s_log1pf.c s_logb.c s_logbf.c s_logbl.c s_logl.c \
	s_matherr.c s_modff.c s_modfl.c \
	s_nearbyint.c s_nextafter.c s_nextafterl.c \
	s_nextafterf.c s_nexttowardf.c \
	s_remquo.c s_remquof.c s_remquol.c \
	s_rint.c s_rintf.c \
	s_round.c s_roundf.c s_roundl.c s_scalbn.c \
	s_scalbnf.c s_scalbnl.c s_signgam.c s_significand.c s_significandf.c \
	s_sincos.c s_sincosf.c s_sincosl.c s_sin.c \
	s_sinf.c s_sinl.c \
	s_sinpi.c s_sinpif.c s_sinpil.c \
	s_tan.c s_tanf.c s_tanl.c \
	s_tanh.c s_tanhf.c s_tanhl.c \
	s_tanpi.c s_tanpif.c s_tanpil.c \
	s_tgammaf.c \
	s_trunc.c s_truncf.c s_truncl.c \
	w_acos.c w_acosf.c w_acosh.c w_acoshf.c w_asin.c w_asinf.c w_atan2.c \
	w_atan2f.c w_atanh.c w_atanhf.c w_cosh.c w_coshf.c \
	w_drem.c w_dremf.c w_exp.c w_expf.c w_fmod.c w_fmodf.c w_fmodl.c \
	w_gamma.c w_gamma_r.c w_gammaf.c w_gammaf_r.c w_hypot.c w_hypotf.c \
	w_j0.c \
	w_j0f.c w_j1.c w_j1f.c w_jn.c w_jnf.c w_lgamma.c w_lgamma_r.c \
	w_lgammaf.c w_lgammaf_r.c w_log.c w_log10.c w_log10f.c w_log2.c \
	w_log2f.c w_logf.c \
	w_pow.c w_powf.c w_remainder.c w_remainderf.c w_scalb.c w_scalbf.c \
	w_sinh.c w_sinhf.c w_sqrt.c w_sqrtf.c w_sqrtl.c \
	s_frexp.c s_frexpl.c s_modf.c \
	s_fmax.c s_fmaxf.c s_fmaxl.c \
	s_fmin.c s_fminf.c s_fminl.c s_fdim.c

.PATH:	${.CURDIR}/compat
COMMON_SRCS+= compat_cabs.c compat_cabsf.c
# XXX our compatibility cabs() is different!
COPTS.compat_cabs.c=	${${ACTIVE_CC} == "gcc":? -fno-builtin-cabs :}
COPTS.compat_cabsf.c=	${${ACTIVE_CC} == "gcc":? -fno-builtin-cabsf :}

# math routines for non-IEEE architectures.
NOIEEE_SRCS = n_asincos.c n_acosh.c n_asinh.c n_atan.c n_atanh.c n_atanhf.c \
	n_cosh.c \
	n_erf.c n_exp.c n_exp2.c n_exp2f.c n_exp__E.c n_expm1.c \
	n_floor.c n_fmod.c n_frexpf.c n_frexpl.c \
	n_gamma.c n_ilogb.c \
	n_lgamma.c n_j0.c n_j1.c n_jn.c n_log.c n_log10.c n_log1p.c \
	n_log2.c n_log__L.c n_pow.c n_sinh.c n_tanh.c \
	n_sincos.c n_sincos1.c n_tan.c \
	n_round.c n_roundf.c n_lround.c n_lroundf.c \
	n_fmax.c n_fmaxf.c n_fmin.c n_fminf.c
#	n_sqrt.c n_argred.c n_infnan.c n_atan2.c n_cabs.c n_cbrt.c n_support.c


# NetBSD's C library supplies these functions:
#COMMON_SRCS+=	s_fabs.c s_frexp.c s_isinf.c s_isnan.c s_ldexp.c s_modf.c

.if (${LIBC_MACHINE_ARCH} == "vax")
SRCS=	${NOIEEE_SRCS} ${NOIEEE_ARCH}
.else
SRCS=	${COMMON_SRCS}
.endif

.ifdef ARCH_ADDS
SRCS+= ${ARCH_ADDS}
.endif

# Substitute common sources with any arch specific sources
.for i in ${ARCH_SRCS} ${NOIEEE_ARCH}
    SRCS:=${SRCS:S/^${i:S/.S/.c/}/$i/}
.endfor

.if (${LIBC_MACHINE_ARCH} == "vax") # XXX until POLYD is written.
.PATH:	${.CURDIR}/arch/vax
SRCS:=${SRCS} n_sqrt.S n_argred.S n_infnan.S n_atan2.S n_cabs.S n_cbrt.S \
	n_support.S n_scalbn.S
.endif

.if (${LIBC_MACHINE_ARCH} == "i386")
# XXX this gets miscompiled. There should be a better fix.
COPTS.s_tanh.c+= -O0
.endif

MAN+=	acos.3 acosh.3 asin.3 asinh.3 atan.3 atan2.3 atanh.3 \
	ceil.3 copysign.3 cos.3 cosh.3 \
	erf.3 exp.3 \
	fabs.3 finite.3 fma.3 fmod.3 frexp.3 hypot.3 \
	ieee_test.3 ilogb.3 isinff.3 j0.3 ldexp.3 lgamma.3 log.3 lrint.3 \
	math.3 modf.3 nextafter.3 pow.3 \
	remainder.3 rint.3 round.3 \
	scalbn.3 sincos.3 sin.3 sinh.3 sqrt.3 \
	tan.3 tanh.3 trunc.3 fmax.3 fdim.3

# fenv.h interface
MAN+=	feclearexcept.3 feenableexcept.3 fegetenv.3 fegetround.3 fenv.3
MLINKS+=feclearexcept.3 fegetexceptflag.3	\
	feclearexcept.3 feraiseexcept.3		\
	feclearexcept.3 fesetexceptflag.3	\
	feclearexcept.3 fetestexcept.3
MLINKS+=feenableexcept.3 fedisableexcept.3	\
	feenableexcept.3 fegetexcept.3
MLINKS+=fegetenv.3 feholdexcept.3		\
	fegetenv.3 fesetenv.3			\
	fegetenv.3 feupdateenv.3
MLINKS+=fegetround.3 fesetround.3

MLINKS+=acos.3 acosf.3
MLINKS+=acosh.3 acoshf.3
MLINKS+=asin.3 asinf.3
MLINKS+=asinh.3 asinhf.3
MLINKS+=atan.3 atanf.3
MLINKS+=atan2.3 atan2f.3
MLINKS+=atanh.3 atanhf.3
MLINKS+=ceil.3 ceilf.3 \
	ceil.3 ceill.3 \
	ceil.3 floor.3 \
	ceil.3 floorf.3 \
	ceil.3 floorl.3
MLINKS+=copysign.3 copysignf.3 \
	copysign.3 copysignl.3
MLINKS+=cos.3 cosf.3
MLINKS+=cos.3 cosl.3
MLINKS+=cosh.3 coshf.3
MLINKS+=cosh.3 coshl.3
MLINKS+=erf.3 erff.3 \
	erf.3 erfl.3 \
	erf.3 erfc.3 \
	erf.3 erfcf.3 \
	erf.3 erfcl.3
MLINKS+=exp.3 expf.3 exp.3 expm1.3 exp.3 expm1f.3 			\
	exp.3 exp2.3 exp.3 exp2f.3 exp.3 expl.3				\
	exp.3 expm1l.3 exp.3 exp2l.3
MLINKS+=log.3 logf.3 \
	log.3 logl.3 \
	log.3 log10.3 \
	log.3 log10f.3 \
	log.3 log10l.3 \
	log.3 log1p.3 \
	log.3 log1pf.3 \
	log.3 log1pl.3 \
	log.3 log2.3 \
	log.3 log2f.3 \
	log.3 log2l.3
MLINKS+=pow.3 powf.3
MLINKS+=pow.3 powl.3
MLINKS+=fabs.3 fabsf.3 \
	fabs.3 fabsl.3
MLINKS+=finite.3 finitef.3
MLINKS+=fmod.3 fmodf.3 \
	fmod.3 fmodl.3
MLINKS+=hypot.3 hypotf.3 \
	hypot.3 hypotl.3
MLINKS+=ieee_test.3 logb.3 ieee_test.3 logbf.3 ieee_test.3 logbl.3
MLINKS+=ieee_test.3 scalb.3 ieee_test.3 scalbf.3
MLINKS+=ieee_test.3 significand.3 ieee_test.3 significandf.3
MLINKS+=ilogb.3 ilogbf.3 ilogb.3 ilogbl.3
MLINKS+=isinff.3 isnanf.3
MLINKS+=j0.3 j0f.3 j0.3 j1.3 j0.3 j1f.3 j0.3 jn.3 j0.3 jnf.3 \
	j0.3 y0.3 j0.3 y0f.3 j0.3 y1.3 j0.3 y1f.3 j0.3 yn.3 j0.3 ynf.3
MLINKS+=ldexp.3 ldexpf.3 \
	ldexp.3 ldexpl.3
MLINKS+=lgamma.3 lgammaf.3 lgamma.3 lgamma_r.3 lgamma.3 lgammaf_r.3 \
	lgamma.3 gamma.3 lgamma.3 gammaf.3 lgamma.3 gamma_r.3 \
	lgamma.3 gammaf_r.3 lgamma.3 tgamma.3 lgamma.3 tgammaf.3 \
	lgamma.3 lgammal.3 lgamma.3 lgammal_r.3 lgamma.3 tgammal.3
MLINKS+=modf.3 modff.3 \
	modf.3 modfl.3
MLINKS+=nextafter.3 nextafterf.3 \
	nextafter.3 nextafterl.3 \
	nextafter.3 nexttoward.3 \
	nextafter.3 nexttowardf.3 \
	nextafter.3 nexttowardl.3
MLINKS+=lrint.3 lrintf.3 lrint.3 lrintl.3 lrint.3 llrint.3 lrint.3 llrintf.3 lrint.3 llrintl.3
MLINKS+=remainder.3 remainderf.3 \
	remainder.3 remainderl.3 \
	remainder.3 remquo.3 \
	remainder.3 remquof.3 \
	remainder.3 remquol.3
MLINKS+=rint.3 rintf.3 \
	rint.3 rintl.3 \
	rint.3 nearbyint.3 \
	rint.3 nearbyintf.3 \
	rint.3 nearbyintl.3
MLINKS+=scalbn.3 scalbnf.3 \
	scalbn.3 scalbnl.3
MLINKS+=sin.3 sinf.3 \
	sin.3 sinl.3
MLINKS+=sinh.3 sinhf.3
MLINKS+=sinh.3 sinhl.3
MLINKS+=sqrt.3 sqrtf.3 sqrt.3 sqrtl.3 \
	sqrt.3 cbrt.3 sqrt.3 cbrtf.3 sqrt.3 cbrtl.3
MLINKS+=tan.3 tanf.3 \
	tan.3 tanl.3
MLINKS+=tanh.3 tanhf.3 \
	tanh.3 tanhl.3
MLINKS+=round.3 roundf.3 \
	round.3 roundl.3
MLINKS+=trunc.3 truncf.3 \
	trunc.3 truncl.3
MLINKS+=fmax.3 fmaxl.3
MLINKS+=fmax.3 fmaxf.3
MLINKS+=fmax.3 fmin.3
MLINKS+=fmax.3 fminl.3
MLINKS+=fmax.3 fminf.3
MLINKS+=fdim.3 fdiml.3
MLINKS+=fdim.3 fdimf.3
MLINKS+=fma.3 fmaf.3 \
	fma.3 fmal.3
MLINKS+=frexp.3 frexpf.3 \
	frexp.3 frexpl.3

.if (${MKCOMPLEX} != "no")
.include "${.CURDIR}/complex/Makefile.inc"
.endif

COPTS.compat_cabs.c+=	${${ACTIVE_CC} == "clang":? -Wno-incompatible-library-redeclaration :}
COPTS.compat_cabsf.c+=	${${ACTIVE_CC} == "clang":? -Wno-incompatible-library-redeclaration :}
CWARNFLAGS.clang+=		-Wno-error=implicit-int-float-conversion

.include "${.CURDIR}/compiler_rt/Makefile.inc"
.include "${.CURDIR}/gen/Makefile.inc"

.include <bsd.lib.mk>
.include <bsd.subdir.mk>
