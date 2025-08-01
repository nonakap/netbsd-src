# $NetBSD: Makefile,v 1.20 2025/07/19 14:32:41 christos Exp $

.include "${.CURDIR}/../Makefile.inc"


PROG=	hostapd
CPPFLAGS+= -Diphdr=ip

# ap
SRCS+= \
accounting.c \
ap_config.c \
ap_drv_ops.c \
ap_mlme.c \
authsrv.c \
beacon.c \
bss_load.c \
ctrl_iface_ap.c \
dpp.c \
dpp_hostapd.c \
drv_callbacks.c \
eap_user_db.c \
gas.c \
gas_query_ap.c \
gas_serv.c \
hostapd.c \
ieee802_11_auth.c \
ieee802_11_ht.c \
ieee802_11_shared.c \
ieee802_1x.c \
mbo_ap.c \
neighbor_db.c \
pmksa_cache_auth.c \
preauth_auth.c \
rrm.c \
sta_info.c \
tkip_countermeasures.c \
utils.c \
vlan_ifconfig.c \
vlan_init.c \
vlan.c \
wpa_auth.c \
wpa_auth_glue.c \
wpa_auth_ie.c

# common
SRCS+= \
ctrl_iface_common.c \
dpp_auth.c \
dpp_backup.c \
dpp_crypto.c \
dpp_pkex.c \
dpp_reconfig.c \
dpp_tcp.c \
hw_features_common.c \
ieee802_11_common.c \
ptksa_cache.c \
wpa_common.c \
wpa_ctrl.c

# drivers
SRCS+= \
driver_bsd.c \
driver_none.c \
driver_wired.c \
driver_wired_common.c \
driver_common.c \
drivers.c

# radius
SRCS+= \
radius.c \
radius_das.c \
radius_client.c \
radius_server.c

# utils
SRCS+= \
base64.c \
common.c \
crc32.c \
eloop.c \
json.c \
ip_addr.c \
os_unix.c \
wpa_debug.c \
wpabuf.c

# main
SRCS+= \
main.c \
config_file.c \
ctrl_iface.c \
eap_register.c

# l2_packet
SRCS+= \
l2_packet_freebsd.c

# eapol_auth
SRCS+= \
eapol_auth_dump.c \
eapol_auth_sm.c

# eap_server
SRCS+= \
eap_common.c \
eap_server.c \
eap_server_methods.c

# crypto
SRCS+= \
aes-siv.c \
random.c \
sha1-prf.c \
sha256-kdf.c \
sha256-prf.c \
sha384-kdf.c \
sha384-prf.c \
sha512-kdf.c \
sha512-prf.c \

# tls
SRCS+= \
asn1.c

# crypto for non-openssl
NO_SRCS+= \
aes-cbc.c \
aes-omac1.c \
aes-wrap.c \
md5.c


.PATH.c: \
	${HOSTAPD_DISTDIR} \
	${WPA_DISTDIR}/src/eap_server \
	${WPA_DISTDIR}/src/eapol_auth \
	${WPA_DISTDIR}/src/drivers \
	${WPA_DISTDIR}/src/radius \
	${WPA_DISTDIR}/src/tls \
	${COMMON_PATH}

MAN=	hostapd.8 hostapd.conf.5

CPPFLAGS+= -I${.CURDIR} -I${HOSTAPD_DISTDIR}
CPPFLAGS+= -DHOSTAPD
CPPFLAGS+= -DHOSTAPD_DUMP_STATE
CPPFLAGS+= -DALL_DH_GROUPS
CPPFLAGS+= -DRADIUS_SERVER
CPPFLAGS+= -DCONFIG_CTRL_IFACE
CPPFLAGS+= -DCONFIG_CTRL_IFACE_UNIX
CPPFLAGS+= -DCONFIG_DEBUG_SYSLOG
CPPFLAGS+= -DCONFIG_DRIVER_BSD
CPPFLAGS+= -DCONFIG_DRIVER_NONE
CPPFLAGS+= -DCONFIG_DRIVER_WIRED
CPPFLAGS+= -DCONFIG_DRIVER_WPA

.if ${MKINET6} != "no"
CPPFLAGS+= -DCONFIG_IPV6
.endif
CPPFLAGS+= -DCONFIG_PEERKEY
CPPFLAGS+= -DCONFIG_RSN_PREAUTH
CPPFLAGS+= -DCONFIG_DPP
CPPFLAGS+= -DCONFIG_DPP2
CPPFLAGS+= -DCONFIG_ECC
#CPPFLAGS+= -DCONFIG_OWE
#CPPFLAGS+= -DCONFIG_SAE
#CPPFLAGS+= -DCONFIG_AIRTIME_POLICY
#CPPFLAGS+= -DCONFIG_FILS
#CPPFLAGS+= -DCONFIG_OCV
#CPPFLAGS+= -DCONFIG_IEEE80211AX
#CPPFLAGS+= -DCONFIG_IEEE80211R_AP
CPPFLAGS+= -DCONFIG_MBO
#CPPFLAGS+= -DCONFIG_NO_VLAN
#CPPFLAGS+= -DCONFIG_SQLITE
#CPPFLAGS+= -DCONFIG_SHA256 -DCONFIG_SHA484 -DCONFIG_SHA512

DPADD+= ${LIBPCAP}
LDADD+= -lpcap

.if !defined(NO_CRYPT) && !defined(NO_OPENSSL) && !defined(RELEASE_CRUNCH)
CPPFLAGS+= -DEAP_SERVER
CPPFLAGS+= -DEAP_SERVER_AKA
CPPFLAGS+= -DEAP_SERVER_AKA_PRIME
CPPFLAGS+= -DEAP_SERVER_GPSK
CPPFLAGS+= -DEAP_SERVER_GPSK_SHA256
CPPFLAGS+= -DEAP_SERVER_GTC
CPPFLAGS+= -DEAP_SERVER_IDENTITY
CPPFLAGS+= -DEAP_SERVER_IKEV2
CPPFLAGS+= -DEAP_SERVER_MD5
CPPFLAGS+= -DEAP_SERVER_MSCHAPV2
CPPFLAGS+= -DEAP_SERVER_PAX
CPPFLAGS+= -DEAP_SERVER_PEAP
CPPFLAGS+= -DEAP_SERVER_PSK
CPPFLAGS+= -DEAP_SERVER_SAKE
CPPFLAGS+= -DEAP_SERVER_SIM
CPPFLAGS+= -DEAP_SERVER_TLS
CPPFLAGS+= -DEAP_SERVER_TNC
CPPFLAGS+= -DEAP_SERVER_TTLS
CPPFLAGS+= -DEAP_TLS_FUNCS
CPPFLAGS+= -DPKCS12_FUNCS

# crypto
SRCS+= \
aes-ctr.c \
aes-eax.c \
aes-encblock.c \
crypto_openssl.c \
dh_groups.c \
fips_prf_openssl.c \
ms_funcs.c \
sha1-tlsprf.c \
sha256.c \
sha384.c \
sha512.c \
tls_openssl.c

# eap_common
SRCS+= \
chap.c \
eap_gpsk_common.c \
eap_ikev2_common.c \
eap_pax_common.c \
eap_peap_common.c \
eap_psk_common.c \
eap_sake_common.c \
eap_sim_common.c \
ikev2_common.c

# eap_server
SRCS+= \
eap_server_aka.c \
eap_server_gpsk.c \
eap_server_gtc.c \
eap_server_identity.c \
eap_server_ikev2.c \
eap_server_md5.c \
eap_server_mschapv2.c \
eap_server_pax.c \
eap_server_peap.c \
eap_server_psk.c \
eap_server_sake.c \
eap_server_sim.c \
eap_server_tls.c \
eap_server_tls_common.c \
eap_server_tnc.c \
eap_server_ttls.c \
eap_sim_db.c \
ikev2.c \
tncs.c


DPADD+= ${LIBSSL} ${LIBCRYPTO} ${LIBDES} ${LIBPTHREAD}
LDADD+= -lssl -lcrypto -ldes -lpthread
.else
CPPFLAGS+= -DINTERNAL_AES -DINTERNAL_MD5 -DINTERNAL_SHA1 -DCONFIG_NO_PBKDF2
CPPFLAGS+= -DCONFIG_CRYPTO_INTERNAL
SRCS+=  tls_none.c sha1-internal.c md5-internal.c aes-xinternal.c rc4.c
SRCS+= sha1-pbkdf2.c sha1.c md5.c
.endif

CWARNFLAGS.gcc+=	${CC_WNO_ADDRESS_OF_PACKED_MEMBER}
COPTS.dpp.c+= -Wno-error=deprecated-declarations
COPTS.crypto_openssl.c+= -Wno-error=deprecated-declarations
COPTS.fips_prf_openssl.c+= -Wno-error=deprecated-declarations
COPTS.tls_openssl.c+= -Wno-error=deprecated-declarations

.include <bsd.prog.mk>
