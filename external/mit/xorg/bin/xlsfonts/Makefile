#	$NetBSD: Makefile,v 1.4 2024/07/04 01:02:24 mrg Exp $

.include <bsd.own.mk>

PROG=	xlsfonts
SRCS=	xlsfonts.c dsimple.c

LDADD+=	-lXext -lX11
DPADD+=	${LIBXEXT} ${LIBX11}

CPPFLAGS+=-DHAVE_REALLOCARRAY

.PATH:	${X11SRCDIR.${PROG}}
.PATH:	${X11SRCDIR.${PROG}}/man

COPTS.xlsfonts.c+=      -Wno-error

.include "../../xorg-pkg-ver.mk"

.include <bsd.x11.mk>
.include <bsd.prog.mk>
