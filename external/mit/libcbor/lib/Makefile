# $NetBSD: Makefile,v 1.5 2024/06/24 18:01:03 riastradh Exp $

NOLINT=
NOMAN=
.include <bsd.own.mk>

DIST = ${.CURDIR}/../dist

.PATH: ${DIST}/src ${DIST}/src/cbor ${DIST}/src/cbor/internal

CPPFLAGS+= -I${DIST}/src -DHAVE_ENDIAN_H -I. -DEIGHT_BYTE_SIZE_T

.if ${MACHINE} == "vax"
# vax does not have NaN (no ieee754, so this code will not work anyway)
CPPFLAGS+=-DNAN=INFINITY
.endif

LIB=    cbor

SRCS+=   cbor.c

# For ldexp
LIBDPLIBS = m ${NETBSDSRCDIR}/lib/libm

VERS_FILE=${DIST}/CMakeLists.txt

.for i in MAJOR MINOR PATCH
CBOR_VERSION_${i} != \
    ${TOOL_SED} -ne '/CBOR_VERSION_${i}/s/.*"\([0-9]*\)")$$/\1/p' ${VERS_FILE}
.endfor

CBOR_VERSION = ${CBOR_VERSION_MAJOR}.${CBOR_VERSION_MINOR}.${CBOR_VERSION_PATCH}

# cbor/
SRCS+= \
arrays.c \
bytestrings.c \
callbacks.c \
common.c \
encoding.c \
floats_ctrls.c \
ints.c \
maps.c \
serialization.c \
streaming.c \
strings.c \
tags.c

# cbor/internal
SRCS+= \
builder_callbacks.c \
encoders.c \
loaders.c \
memory_utils.c \
stack.c \
unicode.c

INCS+= \
cbor.h \
cbor/arrays.h \
cbor/bytestrings.h \
cbor/callbacks.h \
cbor/common.h \
cbor/configuration.h \
cbor/data.h \
cbor/encoding.h \
cbor/floats_ctrls.h \
cbor/ints.h \
cbor/maps.h \
cbor/serialization.h \
cbor/streaming.h \
cbor/strings.h \
cbor/tags.h

INCSDIR=/usr/include

PKGCONFIG=libcbor

.SUFFIXES: .in

.in:
	${TOOL_SED} \
	    -e s@CMAKE_INSTALL_PREFIX@/usr@ \
	    -e s@CMAKE_INSTALL_LIBDIR@/lib@ \
	    -e s@PROJECT_NAME@libcbor@ \
	    -e s@CBOR_VERSION@${CBOR_VERSION}@ ${.ALLSRC} > ${.TARGET}

libcbor.pc: libcbor.pc.in

SHLIB_MAJOR=    0
SHLIB_MINOR=    5

cbor/configuration.h: ${VERS_FILE}
	${_MKTARGET_CREATE}
	mkdir -p cbor && ( \
	echo	'#define CBOR_MAJOR_VERSION ${CBOR_VERSION_MAJOR}' && \
	echo	'#define CBOR_MINOR_VERSION ${CBOR_VERSION_MINOR}' && \
	echo	'#define CBOR_PATCH_VERSION ${CBOR_VERSION_PATCH}' && \
	echo	'#define CBOR_CUSTOM_ALLOC 0' && \
	echo	'#define CBOR_BUFFER_GROWTH 2' && \
	echo	'#define CBOR_PRETTY_PRINTER 1' && \
	echo	'#define CBOR_RESTRICT_SPECIFIER restrict' && \
	echo	'#define CBOR_INLINE_SPECIFIER ') > ${.TARGET}.tmp && \
	${MV} ${.TARGET}.tmp ${.TARGET}

CLEANFILES+= cbor/configuration.h
CLEANFILES+= cbor/configuration.h.tmp

.include <bsd.lib.mk>
