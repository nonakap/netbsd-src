# $NetBSD: Makefile,v 1.19 2025/07/14 10:25:51 kre Exp $

LIB=		fetch
SRCS=		fetch.c common.c ftp.c http.c file.c
DPSRCS= 	ftperr.h httperr.h
INCS=		fetch.h
INCSDIR=	/usr/include
MAN=		fetch.3
CLEANFILES=	ftperr.h httperr.h

.include <bsd.init.mk>

CPPFLAGS+=	-I.
CPPFLAGS+=	-DNETBSD 
CPPFLAGS+=	-DFTP_COMBINE_CWDS
CPPFLAGS+=	-DINET6

CPPFLAGS+=	-DWITH_SSL

LIBDPLIBS+=	ssl	${NETBSDSRCDIR}/crypto/external/${EXTERNAL_OPENSSL_SUBDIR}/lib/libssl \
		crypto	${NETBSDSRCDIR}/crypto/external/${EXTERNAL_OPENSSL_SUBDIR}/lib/libcrypto

CLEANFILES+=	ftperr.h httperr.h

.PATH: ${LIBFETCHDIR}

ftperr.h: ${LIBFETCHDIR}/ftp.errors ${LIBFETCHDIR}/errlist.sh
	${HOST_SH} ${LIBFETCHDIR}/errlist.sh ftp_errlist FTP \
	    ${LIBFETCHDIR}/ftp.errors > ${.TARGET}

httperr.h: ${LIBFETCHDIR}/http.errors ${LIBFETCHDIR}/errlist.sh
	${HOST_SH} ${LIBFETCHDIR}/errlist.sh http_errlist HTTP \
	    ${LIBFETCHDIR}/http.errors > ${.TARGET}

COPTS.http.c+=	${CC_WNO_STRINGOP_TRUNCATION}

.include <bsd.lib.mk>
