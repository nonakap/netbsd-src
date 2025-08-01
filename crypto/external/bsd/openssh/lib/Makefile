#	$NetBSD: Makefile,v 1.42 2025/07/14 10:25:51 kre Exp $

.include <bsd.own.mk>

.include "../Makefile.inc"

CWARNFLAGS.clang+=	-Wno-error=sizeof-array-div
CWARNFLAGS.clang+=	-Wno-error=format-nonliteral
LIB=	ssh
SRCS=\
addr.c \
addrmatch.c \
atomicio.c \
authfd.c \
authfile.c \
bcrypt_pbkdf.c \
bitmap.c \
blowfish.c \
canohost.c \
chacha.c \
channels.c \
cipher-chachapoly.c \
cipher.c \
cleanup.c \
compat.c \
dh.c \
dispatch.c \
dns.c \
ed25519.c \
fatal.c \
freezero.c \
hash.c \
hmac.c \
hostfile.c \
kex.c \
kex-names.c \
kexdh.c \
kexecdh.c \
kexgen.c \
kexgex.c \
kexgexc.c \
kexmlkem768x25519.c \
kexsntrup761x25519.c \
krl.c \
log.c \
mac.c \
match.c \
misc.c \
monitor_fdpass.c \
msg.c \
nchan.c \
packet.c \
poly1305.c \
progressmeter.c \
readpass.c \
recallocarray.c \
smult_curve25519_ref.c \
sntrup761.c \
ssh-ed25519.c \
ssh-ed25519-sk.c \
ssh-pkcs11.c \
ssh-sk-client.c \
ssh-xmss.c \
sshbuf-getput-basic.c \
sshbuf-getput-crypto.c \
sshbuf-misc.c \
sshbuf-io.c \
sshbuf.c \
ssherr.c \
sshkey-xmss.c \
sshkey.c \
ttymodes.c \
uidswap.c \
umac.c \
umac128.c \
utf8.c \
xmalloc.c \
xmss_commons.c \
xmss_fast.c \
xmss_hash.c \
xmss_hash_address.c \
xmss_wots.c

OPENSSL_SRCS=\
digest-openssl.c \
kexc25519.c \
ssh-dss.c \
ssh-ecdsa.c \
ssh-ecdsa-sk.c \
ssh-rsa.c

SRCS+=	fmt_scaled.c
SRCS+=	readpassphrase.c getpeereid.c getrrsetbyname.c
COPTS.monitor_fdpass.c+=-Wno-stack-protector
COPTS.xmss_fast.c+=	-Wno-stack-protector
COPTS.xmss_hash.c+=	-Wno-stack-protector
COPTS.xmss_wots.c+=	-Wno-stack-protector
COPTS.sntrup761.c+=	-Wno-stack-protector

.if WITH_OPENSSL
SRCS+=		${OPENSSL_SRCS}
.else
SRCS+=		digest-libc.c
.endif

CPPFLAGS+= -DHAVE_BLF_H

CPPFLAGS+=	-I${SSHDIST}
.PATH:		${SSHDIST}

LIBDPLIBS+=	crypto	${NETBSDSRCDIR}/crypto/external/${EXTERNAL_OPENSSL_SUBDIR}/lib/libcrypto \
		crypt	${NETBSDSRCDIR}/lib/libcrypt \
		z	${NETBSDSRCDIR}/lib/libz

.for f in dns channels hostfile ssh-pkcs11
COPTS.${f}.c+=	-Wno-pointer-sign
.endfor

# XXX
COPTS.channels.c+=	-fno-strict-aliasing

COPTS.hostfile.c+=	${CC_WNO_FORMAT_TRUNCATION}
COPTS.sshkey.c+=	${CC_WNO_FORMAT_TRUNCATION}
COPTS.cipher.c+=	-Wno-error=deprecated-declarations
COPTS.dh.c+=		-Wno-error=deprecated-declarations
COPTS.kex.c+=		-Wno-error=deprecated-declarations
COPTS.kexdh.c+=		-Wno-error=deprecated-declarations
COPTS.kexecdh.c+=	-Wno-error=deprecated-declarations
COPTS.kexgexc.c+=	-Wno-error=deprecated-declarations
COPTS.ssh-dss.c+=	-Wno-error=deprecated-declarations
COPTS.ssh-ecdsa-sk.c+=	-Wno-error=deprecated-declarations
COPTS.ssh-ecdsa.c+=	-Wno-error=deprecated-declarations
COPTS.ssh-pkcs11.c+=	-Wno-error=deprecated-declarations
COPTS.ssh-rsa.c+=	-Wno-error=deprecated-declarations
COPTS.sshbuf-getput-crypto.c+=	-Wno-error=deprecated-declarations
COPTS.sshkey.c+=	-Wno-error=deprecated-declarations
COPTS.umac.c+=		-Wno-error=deprecated-declarations
COPTS.umac128.c+=	-Wno-error=deprecated-declarations
COPTS.kexmlkem768x25519.c+=${${ACTIVE_CC} == "clang":? -Wno-error=missing-noreturn:}



.include <bsd.lib.mk>
