#	$NetBSD: Makefile,v 1.10 2024/08/12 20:32:31 christos Exp $

.include <bsd.own.mk>
.include "../Makefile.inc"

LIBISPRIVATE=	yes

LIB=		opcodes

.include "${.CURDIR}/arch/${GDB_MACHINE_ARCH}/defs.mk"

GCPPFLAGS=	${G_archdefs} ${G_DEFS} ${G_INCLUDES} ${G_TDEFAULTS}
CPPFLAGS+=	-I${.CURDIR}/arch/${GDB_MACHINE_ARCH} \
		-I${.CURDIR}/../libbfd/arch/${GDB_MACHINE_ARCH} \
		-I${DIST}/include -I. \
		-I${DIST}/bfd ${GCPPFLAGS:M-D*} \
		${GCPPFLAGS:M-I*:N-I.*}

GSRCS=		${G_BFD_MACHINES}
SRCS=		${GSRCS:.lo=.c} ${G_libopcodes_la_SOURCES}

.PATH: ${DIST}/opcodes

.include <bsd.lib.mk>
