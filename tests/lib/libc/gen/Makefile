# $NetBSD: Makefile,v 1.60 2025/04/22 13:48:24 nia Exp $

NOMAN=		# defined

.include <bsd.own.mk>

TESTSDIR=	${TESTSBASE}/lib/libc/gen
BINDIR=		${TESTSDIR}

TESTS_SUBDIRS+=	execve
TESTS_SUBDIRS+=	posix_spawn

TESTS_C+=	t_alarm
TESTS_C+=	t_arc4random
TESTS_C+=	t_assert
TESTS_C+=	t_basedirname
TESTS_C+=	t_closefrom
TESTS_C+=	t_cpuset
TESTS_C+=	t_ctype
TESTS_C+=	t_dir
TESTS_C+=	t_floatunditf
TESTS_C+=	t_fmtcheck
TESTS_C+=	t_fnmatch
TESTS_C+=	t_fpclassify
TESTS_C+=	t_fpsetmask
TESTS_C+=	t_fpsetround
TESTS_C+=	t_ftok
TESTS_C+=	t_getcwd
TESTS_C+=	t_getentropy
TESTS_C+=	t_getgrent
TESTS_C+=	t_glob
TESTS_C+=	t_humanize_number
TESTS_C+=	t_isnan
TESTS_C+=	t_nice
TESTS_C+=	t_pause
TESTS_C+=	t_raise
TESTS_C+=	t_randomid
TESTS_C+=	t_realpath
TESTS_C+=	t_setdomainname
TESTS_C+=	t_sethostname
TESTS_C+=	t_siginfo
TESTS_C+=	t_sleep
TESTS_C+=	t_syslog
TESTS_C+=	t_time
TESTS_C+=	t_timespec_get
TESTS_C+=	t_ttyname
TESTS_C+=	t_vis

PROGS+=		h_execsig

.if ${MKSANITIZER:Uno} != "yes" && ${MKLIBCSANITIZER:Uno} != "yes"
COPTS.t_siginfo.c+=	-DENABLE_TESTS
.endif

CPPFLAGS.t_arc4random.c+=-I${NETBSDSRCDIR}/lib/libc/include
CPPFLAGS.t_ctype.c+=	\
	${"${MKPIC}" == "no" || "${LDSTATIC:U}" == "-static":?-D_CTYPE_GUARD_PAGE=0:}
CPPFLAGS.t_siginfo.c+=-D__TEST_FENV
COPTS.t_fpsetround.c+=${${ACTIVE_CC} == "gcc":? -frounding-math :}

LDADD.t_siginfo+=	-lm
DPADD.t_siginfo+=	${LIBM}
LDADD.t_fpclassify+=	-lm
DPADD.t_fpclassify+=	${LIBM}
LDADD.t_fpsetround+=	-lm
DPADD.t_fpsetround+=	${LIBM}

LDADD.t_arc4random+=	-lpthread
DPADD.t_arc4random+=	${LIBPTHREAD}
LDADD.t_nice+=		-lpthread
DPADD.t_nice+=		${LIBPTHREAD}
LDADD.t_syslog+=	-lpthread
DPADD.t_syslog+=	${LIBPTHREAD}

.include <bsd.test.mk>
