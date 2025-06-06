#	$NetBSD: Makefile,v 1.16 2024/06/30 16:15:03 christos Exp $

HOSTPROG_CXX=	1
LIBISPRIVATE=	yes

# For ../Makefile.inc and bsd.own.mk
.include <bsd.init.mk>

LIB=		common-target

.include "${.CURDIR}/arch/${GCC_MACHINE_ARCH}.mk"
SRCS=		${G_OBJS-libcommon-target:S/common\///:.o=.cc}

CPPFLAGS+=	-I${GCCARCH} -I${BACKENDOBJ} -I. \
		${G_ALL_CFLAGS:M-D*} ${G_INCLUDES:M-I*:N-I.*} \
		-DPREFIX=\"/usr\" \
		-DDEFAULT_TARGET_VERSION=\"${G_version}\" \
		-DDEFAULT_TARGET_MACHINE=\"${MACHINE_GNU_PLATFORM}\" \
		-DCONFIGURE_SPECS="\"\"" \
		-I${BACKENDOBJ}

COPTS.prefix.cc+=	-Wno-error=stack-protector
COPTS.opts-common.cc+=	-Wno-error=stack-protector
COPTS.rs6000-common.cc+=	-Wno-error=stack-protector
COPTS.arm-common.cc+=	-Wno-error=stack-protector
.if ${MACHINE_CPU} == "sh3"
COPTS.opts.cc+=		${CC_WNO_FORMAT_TRUNCATION}
.endif

GENPROG_ERROR_DEPENDS=errors.lo

.include "../Makefile.options"
.include "../../Makefile.hooks"

${SRCS}: ${GCCARCH}/defs.mk

${G_common_out_file:T:R}.o:  common/common-target-hooks-def.h

DPSRCS+=	options.h

HOST_CPPFLAGS+=	-I${BACKENDOBJ} -I${GCCARCH} -I. -I${DIST}/include -I${DIST}/gcc
HOST_CPPFLAGS+=	-DGENERATOR_FILE

MKPIC:=		no
MKPICLIB:=	no

.include <bsd.lib.mk>

# Force using C++ for this
HOST_CC:=	${HOST_CXX}
HOST_CFLAGS:=	${HOST_CXXFLAGS}
CC:=		${CXX}
CFLAGS:=	${CXXFLAGS}

.PATH: ${DIST}/gcc ${DIST}/gcc/common
.PATH: ${G_common_out_file:H}
