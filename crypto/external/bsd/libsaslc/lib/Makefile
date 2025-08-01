# $NetBSD: Makefile,v 1.13 2025/07/14 10:25:50 kre Exp $

.include <bsd.own.mk>

USE_FORT?= yes

LIB=saslc
SRCS=
SRCS+= buffer.c
SRCS+= crypto.c
SRCS+= dict.c
SRCS+= error.c
SRCS+= list.c
SRCS+= mech.c
SRCS+= mech_anonymous.c
SRCS+= mech_crammd5.c
SRCS+= mech_digestmd5.c
SRCS+= mech_external.c
.if (${MKKERBEROS} != "no")
SRCS+= mech_gssapi.c
.endif
SRCS+= mech_login.c
SRCS+= mech_plain.c
SRCS+= msg.c
SRCS+= parser.c
SRCS+= saslc.c
SRCS+= xsess.c

COPTS.msg.c = -Wno-format-nonliteral

CPPFLAGS+=-I${EXTDIST}/include
WARNS?=4

MAN=libsaslc.3
MLINKS+=libsaslc.3 saslc.d.3 \
	libsaslc.3 saslc_alloc.3 \
	libsaslc.3 saslc_end.3 \
	libsaslc.3 saslc_init.3 \
	libsaslc.3 saslc_sess_init.3 \
	libsaslc.3 saslc_sess_end.3 \
	libsaslc.3 saslc_sess_getprop.3 \
	libsaslc.3 saslc_sess_setprop.3 \
	libsaslc.3 saslc_sess_cont.3 \
	libsaslc.3 saslc_sess_decode.3 \
	libsaslc.3 saslc_sess_encode.3 \
	libsaslc.3 saslc_sess_getmech.3 \
	libsaslc.3 saslc_sess_strerror.3 \
	libsaslc.3 saslc_strerror.3

EXTDIST=${.CURDIR}/../dist

.PATH: ${EXTDIST}/include ${EXTDIST}/src ${EXTDIST}/man

INCS+= saslc.h
INCSDIR=/usr/include

LIBDPLIBS+= crypto ${NETBSDSRCDIR}/crypto/external/${EXTERNAL_OPENSSL_SUBDIR}/lib/libcrypto
LIBDPLIBS+= ssl ${NETBSDSRCDIR}/crypto/external/${EXTERNAL_OPENSSL_SUBDIR}/lib/libssl
.if (${MKKERBEROS} != "no")
LIBDPLIBS+= gssapi ${NETBSDSRCDIR}/crypto/external/bsd/heimdal/lib/libgssapi

.endif

COPTS.crypto.c+=-Wno-error=deprecated-declarations

EXPSYM_SRCS+=	saslc.common.expsym
.if ${MKKERBEROS:Uno} != "no"
EXPSYM_SRCS+=	saslc.kerberos.expsym
.endif

LIB_EXPSYM=	saslc.expsym
saslc.expsym: ${EXPSYM_SRCS}
	${_MKTARGET_CREATE}
	LC_ALL=C sort -m ${.ALLSRC} >${.TARGET}.tmp && \
	${MV} ${.TARGET}.tmp ${.TARGET}
CLEANFILES+=	saslc.expsym saslc.expsym.tmp

.include <bsd.lib.mk>
