#	$NetBSD: Makefile,v 1.13 2024/06/30 16:15:03 christos Exp $

.include <bsd.init.mk>

PROG=           gcov
SRCS=		${G_GCOV_OBJS:S/json.o/json.cc/:.o=.cc}

CPPFLAGS+=	-I${GCCARCH} -I${BACKENDOBJ} ${G_ALL_CFLAGS:M-D*} ${G_INCLUDES:M-I*:N-I.*}
DPADD+=		${LIBZ}
LDADD+=		-lz

BINDIR=		/usr/bin

MAN=		gcov.1

.include "../Makefile.prog"

.include "../Makefile.common"
.include "../Makefile.libcpp"
.include "../Makefile.backtrace"
.include "../Makefile.libiberty"
.include "../Makefile.libdecnumber"

COPTS.gcov.cc += -Wno-error=stack-protector

LDADD+=		-lintl
DPADD+=		${LIBINTL}

.PATH: ${DIST}/gcc ${DIST}/gcc/doc
