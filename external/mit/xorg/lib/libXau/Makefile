#	$NetBSD: Makefile,v 1.6 2025/03/09 06:03:51 mrg Exp $

.include <bsd.own.mk>

LIB=	Xau
.PATH:	${X11SRCDIR.${LIB}}
.PATH:	${X11SRCDIR.${LIB}}/man
.PATH:	${X11SRCDIR.${LIB}}/include/X11

SRCS=	AuDispose.c AuFileName.c AuGetAddr.c AuGetBest.c AuLock.c \
	AuRead.c AuUnlock.c AuWrite.c

INCS=	Xauth.h
INCSDIR=${X11INCDIR}/X11

CPPFLAGS+=	${X11FLAGS.THREADLIB}
CPPFLAGS+=	-DHAVE_EXPLICIT_MEMSET -DHAVE_PATHCONF -DHAVE_UNISTD_H

MAN=	Xau.3
MLINKS=	Xau.3 XauDisposeAuth.3 \
	Xau.3 XauFileName.3 \
	Xau.3 XauGetAuthByAddr.3 \
	Xau.3 XauGetBestAuthByAddr.3 \
	Xau.3 XauLockAuth.3 \
	Xau.3 XauReadAuth.3 \
	Xau.3 XauUnlockAuth.3 \
	Xau.3 XauWriteAuth.3

PKGDIST=	${LIB}

# libXaw 1.0.7 has 'spec' subdir with docs, maybe install them?

.include <bsd.x11.mk>
.include <bsd.lib.mk>
