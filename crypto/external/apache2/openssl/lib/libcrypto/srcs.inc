#	$NetBSD: srcs.inc,v 1.1 2025/07/17 14:25:26 christos Exp $

CRYPTOINCS= \
aes.inc \
aria.inc \
asn1.inc \
async.inc \
bf.inc \
bio.inc \
blake2.inc \
bn.inc \
buffer.inc \
camellia.inc \
cast.inc \
chacha.inc \
cmac.inc \
cmp.inc \
cms.inc \
comp.inc \
conf.inc \
crmf.inc \
crypto.inc \
ct.inc \
curve448.inc \
des.inc \
dh.inc \
dsa.inc \
dso.inc \
ec.inc \
encode_decode.inc \
engine.inc \
err.inc \
ess.inc \
evp.inc \
ffc.inc \
hashtable.inc \
hmac.inc \
hpke.inc \
http.inc \
idea.inc \
kdf.inc \
lhash.inc \
md4.inc \
md5.inc \
mdc2.inc \
ml_dsa.inc \
ml_kem.inc \
modes.inc \
objects.inc \
ocsp.inc \
pem.inc \
pkcs12.inc \
pkcs7.inc \
poly1305.inc \
property.inc \
providers.inc \
rand.inc \
rc2.inc \
rc4.inc \
ripemd.inc \
rsa.inc \
seed.inc \
sha.inc \
siphash.inc \
slh_dsa.inc \
sm2.inc \
sm3.inc \
sm4.inc \
srp.inc \
stack.inc \
store.inc \
thread.inc \
ts.inc \
txt_db.inc \
ui.inc \
whrlpool.inc \
x509.inc \

CRYPTOINCS+=	man.inc

.if exists(${.CURDIR}/arch/${MACHINE_ARCH})
CRYPTO_MACHINE_CPU?=    ${MACHINE_ARCH}
.else
CRYPTO_MACHINE_CPU?=    ${MACHINE_CPU}
.endif

.for cryptoinc in ${CRYPTOINCS}
.if exists(${.CURDIR}/arch/${CRYPTO_MACHINE_CPU}/${cryptoinc})
.include "${.CURDIR}/arch/${CRYPTO_MACHINE_CPU}/${cryptoinc}"
.else
.include "${cryptoinc}"
.endif
.endfor
