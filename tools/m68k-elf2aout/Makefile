#	$NetBSD: Makefile,v 1.5 2019/01/27 05:16:38 dholland Exp $

.include <bsd.hostinit.mk>

HOSTPROGNAME=	${_TOOL_PREFIX}m68k-elf2aout
HOST_SRCDIR=	usr.bin/elf2aout
HOST_CPPFLAGS=	-I${.CURDIR}

.include <bsd.endian.mk>

.if   ${TARGET_ENDIANNESS} == "1234"
CPPFLAGS+= -DTARGET_BYTE_ORDER=LITTLE_ENDIAN
.elif ${TARGET_ENDIANNESS} == "4321"
CPPFLAGS+= -DTARGET_BYTE_ORDER=BIG_ENDIAN
.endif

.include "${.CURDIR}/../Makefile.host"
