#	$NetBSD: Makefile,v 1.11 2025/01/13 07:53:47 skrll Exp $

.include <bsd.own.mk>

PROG=	ntpq
MAN=	ntpq.8
BINDIR=	/usr/sbin

SRCS=	ntpq.c					\
	ntpq-subs.c				\
	ntpq-opts.c

LDADD+=		-L${LIBNTP} -lntp -L${LIBOPTS} -lopts -L${LIBISC} -liscntp -ledit -lterminfo -lm
#DPADD+=		${LIBISC}/libiscntp.a ${LIBOPTS}/libopts.a  ${LIBNTP}/libntp.a ${LIBEDIT} ${LIBTERMINFO} ${LIBM}

.include "${.CURDIR}/../Makefile.inc"

DIST=${IDIST}/ntpq

CPPFLAGS+=-I${IDIST}/include -I${IDIST}/sntp/libopts

.PATH: ${DIST}

COPTS.ntpq.c+=	${CC_WNO_STRINGOP_TRUNCATION}

CLEANFILES+=${MAN}

.include <bsd.prog.mk>
