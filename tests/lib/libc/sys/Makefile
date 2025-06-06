# $NetBSD: Makefile,v 1.79 2025/05/09 13:18:32 riastradh Exp $

MKMAN=	no

.include <bsd.own.mk>

.include "../arch/Makefile.exec_prot"

TESTSDIR=		${TESTSBASE}/lib/libc/sys

TESTS_C+=		t_access
TESTS_C+=		t_bind
TESTS_C+=		t_chroot
TESTS_C+=		t_clock_gettime
TESTS_C+=		t_clock_nanosleep
TESTS_C+=		t_clone
TESTS_C+=		t_connect
TESTS_C+=		t_dup
TESTS_C+=		t_eventfd
TESTS_C+=		t_fork
TESTS_C+=		t_fsync
TESTS_C+=		t_futex_ops
TESTS_C+=		t_futex_robust
TESTS_C+=		t_getcontext
TESTS_C+=		t_getgroups
TESTS_C+=		t_getitimer
TESTS_C+=		t_getlogin
TESTS_C+=		t_getpid
TESTS_C+=		t_getrandom
TESTS_C+=		t_getrusage
TESTS_C+=		t_getsid
TESTS_C+=		t_getsockname
TESTS_C+=		t_gettimeofday
TESTS_C+=		t_issetugid
TESTS_C+=		t_kevent
TESTS_C+=		t_kill
TESTS_C+=		t_link
TESTS_C+=		t_listen
TESTS_C+=		t_lwp_ctl
TESTS_C+=		t_lwp_create
TESTS_C+=		t_minherit
TESTS_C+=		t_mincore
TESTS_C+=		t_mkdir
TESTS_C+=		t_mkfifo
TESTS_C+=		t_mknod
TESTS_C+=		t_mlock
TESTS_C+=		t_mmap
TESTS_C+=		t_mprotect
TESTS_C+=		t_msgctl
TESTS_C+=		t_msgget
TESTS_C+=		t_msgrcv
TESTS_C+=		t_msgsnd
TESTS_C+=		t_msync
TESTS_C+=		t_nanosleep
TESTS_C+=		t_pipe
TESTS_C+=		t_pipe2
TESTS_C+=		t_poll
TESTS_C+=		t_pollts
TESTS_C+=		t_posix_fallocate
TESTS_C+=		t_ppoll
TESTS_C+=		t_ptrace
TESTS_C+=		t_ptrace_kill
TESTS_C+=		t_ptrace_sigchld
TESTS_C+=		t_ptrace_wait
TESTS_C+=		t_ptrace_wait3
TESTS_C+=		t_ptrace_wait4
TESTS_C+=		t_ptrace_wait6
TESTS_C+=		t_ptrace_waitid
TESTS_C+=		t_ptrace_waitpid
TESTS_C+=		t_recvmmsg
TESTS_C+=		t_revoke
TESTS_C+=		t_select
TESTS_C+=		t_sendmmsg
TESTS_C+=		t_sendrecv
TESTS_C+=		t_setrlimit
TESTS_C+=		t_setuid
TESTS_C+=		t_sigaction
TESTS_C+=		t_sigaltstack
TESTS_C+=		t_sigqueue
TESTS_C+=		t_sigtimedwait
TESTS_C+=		t_socketpair
TESTS_C+=		t_swapcontext
TESTS_C+=		t_stat
TESTS_C+=		t_syscall
TESTS_C+=		t_timer_create
TESTS_C+=		t_timerfd
TESTS_C+=		t_truncate
TESTS_C+=		t_ucontext
TESTS_C+=		t_umask
TESTS_C+=		t_unlink
TESTS_C+=		t_vfork
TESTS_C+=		t_wait
TESTS_C+=		t_wait_noproc
TESTS_C+=		t_wait_noproc_wnohang
TESTS_C+=		t_write

SRCS.t_mprotect=	t_mprotect.c ${SRCS_EXEC_PROT} t_mprotect_helper.c

LDADD.t_eventfd+=	-lpthread
LDADD.t_getpid+=	-lpthread
LDADD.t_mmap+=		-lpthread
LDADD.t_poll+=		-lpthread
LDADD.t_ptrace_kill+=	-lpthread
LDADD.t_timerfd+=	-lpthread

LDADD.t_ptrace_sigchld+=	-pthread -lm

LDADD.t_ptrace_wait+=		-pthread -lm -lelf
LDADD.t_ptrace_wait3+=		-pthread -lm -lelf
LDADD.t_ptrace_wait4+=		-pthread -lm -lelf
LDADD.t_ptrace_wait6+=		-pthread -lm -lelf
LDADD.t_ptrace_waitid+=		-pthread -lm -lelf
LDADD.t_ptrace_waitpid+=	-pthread -lm -lelf

.if (${MKRUMP} != "no") && !defined(BSD_MK_COMPAT_FILE)
CPPFLAGS.t_posix_fadvise.c += -D_KERNTYPES
TESTS_C+=		t_posix_fadvise
LDADD.t_posix_fadvise+= ${LIBRUMPBASE}
.endif

CPPFLAGS.t_futex_ops.c		+= -I${.CURDIR}/../../../../lib
CPPFLAGS.t_futex_robust.c	+= -I${.CURDIR}/../../../../lib

CPPFLAGS.t_timerfd.c		+= -I${.CURDIR}/../gen

CPPFLAGE.t_clone.c		+= -D_NETBSD_SOURCE -D_GNU_SOURCE
CPPFLAGS.t_lwp_create.c		+= -D_KERNTYPES
CPPFLAGS.t_ptrace_sigchld.c	+= -D__TEST_FENV
CPPFLAGS.t_ptrace_wait.c	+= -D_KERNTYPES -D__TEST_FENV
CPPFLAGS.t_ptrace_wait3.c	+= -D_KERNTYPES -D__TEST_FENV
CPPFLAGS.t_ptrace_wait4.c	+= -D_KERNTYPES -D__TEST_FENV
CPPFLAGS.t_ptrace_wait6.c	+= -D_KERNTYPES -D__TEST_FENV
CPPFLAGS.t_ptrace_waitid.c	+= -D_KERNTYPES -D__TEST_FENV
CPPFLAGS.t_ptrace_waitpid.c	+= -D_KERNTYPES -D__TEST_FENV
CPPFLAGS.t_ucontext.c		+= -D_KERNTYPES

.if ${MKSANITIZER:Uno} != "yes" && ${MKLIBCSANITIZER:Uno} != "yes"
CPPFLAGS.t_ptrace_wait.c	+= -DENABLE_TESTS
CPPFLAGS.t_ptrace_wait3.c	+= -DENABLE_TESTS
CPPFLAGS.t_ptrace_wait4.c	+= -DENABLE_TESTS
CPPFLAGS.t_ptrace_wait6.c	+= -DENABLE_TESTS
CPPFLAGS.t_ptrace_waitid.c	+= -DENABLE_TESTS
CPPFLAGS.t_ptrace_waitpid.c	+= -DENABLE_TESTS
.endif

FILES=		truncate_test.root_owned
FILESBUILD=	yes
FILESDIR_truncate_test.root_owned=	${TESTSDIR}
FILESMODE_truncate_test.root_owned=	0600
FILESOWNER_truncate_test.root_owned=	root
FILESGRP_truncate_test.root_owned=	wheel

CLEANFILES=   truncate_test.root_owned
truncate_test.root_owned:
	@${_MKTARGET_CREATE}
	touch ${.TARGET}

WARNS=			4

CWARNFLAGS.gcc+=	${CC_WNO_ADDRESS_OF_PACKED_MEMBER} \
			${${ACTIVE_CC} == "gcc" && ${HAVE_GCC:U0} >= 8:? -Wno-error=deprecated :}

# Explicitly breaks this
COPTS.t_wait.c+=	${CC_WNO_ARRAY_BOUNDS} ${CC_WNO_STRINGOP_OVERFLOW}

.include <bsd.test.mk>
