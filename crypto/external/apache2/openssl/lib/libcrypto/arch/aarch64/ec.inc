.PATH.S: ${.PARSEDIR}
ECCPPFLAGS+=-DECP_NISTZ256_ASM
EC_SRCS += ecp_nistz256-armv8.S ecp_sm2p256-armv8.S sm3-armv8.S sm4-armv8.S
EC_SRCS += vpsm4-armv8.S vpsm4_ex-armv8.S

ECNI = yes
.if ${MACHINE_ARCH} == "aarch64eb"
ECCPPFLAGS+=-DOPENSSL_NO_EC_NISTP_64_GCC_128
.else
EC_SRCS += ecp_nistp384.c
.endif
.include "../../ec.inc"
