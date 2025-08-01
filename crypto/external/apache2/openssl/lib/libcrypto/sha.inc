#	$NetBSD: sha.inc,v 1.1 2025/07/17 14:25:26 christos Exp $

.PATH.c:	${OPENSSLSRC}/crypto/sha

.if !defined(KECCAKNI)
SHA_SRCS+= keccak1600.c
.endif
SHA_SRCS += \
sha1_one.c \
sha1dgst.c \
sha256.c \
sha3.c \
sha512.c \

SRCS += ${SHA_SRCS}

.for cryptosrc in ${SHA_SRCS}
CPPFLAGS.${cryptosrc} += -I${OPENSSLSRC}/crypto/sha ${SHACPPFLAGS}
.endfor

.if (${MACHINE_ARCH} == "m68k" || ${MACHINE_ARCH} == "m68000") && \
    ${HAVE_GCC:U0} == 12
COPTS.libc-sha2xx.c+=	-fno-stack-protector
.endif
