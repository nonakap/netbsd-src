#	$NetBSD: Makefile.inc,v 1.2 2025/07/14 10:25:52 kre Exp $

.if !defined(BIND9_MAKEFILE_INC)
BIND9_MAKEFILE_INC=yes

#NAMED_DEBUG=1

USE_FORT?= yes	# network client/server

WARNS?=	1

CWARNFLAGS.clang+=	-Wno-unused-value -Wno-parentheses \
			-Wno-atomic-alignment

.include <bsd.own.mk>

LIBUVDIR=${NETBSDSRCDIR}/external/mit/libuv
LIBUVOBJDIR!=   cd ${LIBUVDIR}/lib && ${PRINTOBJDIR}

NAMED_USE_OPENSSL?=yes

.if exists(${NETBSDSRCDIR}/sys/sys/atomic.h)
NAMED_USE_PTHREADS?=yes
.else
NAMED_USE_PTHREADS?=no
.endif

BIND_SRCDIR:=	${.PARSEDIR}
IDIST=		${BIND_SRCDIR}/dist
BIND_HTMLDIR=	/usr/share/doc/reference/ref8/bind9

VERSIONFILE=${IDIST}/version
.include "${VERSIONFILE}"

VERSION=${MAJORVER}.${MINORVER}.${PATCHVER}${RELEASETYPE}${RELEASEVER}
SYSCONFDIR=/etc
LOCALSTATEDIR=/var

LINTFLAGS+=-Z-include -Z${BIND_SRCDIR}/include/config.h
CPPFLAGS+=-include ${BIND_SRCDIR}/include/config.h
CPPFLAGS+=-I${BIND_SRCDIR}/include \
	-I${IDIST} \
	-I${IDIST}/lib/bind9/include \
	-I${IDIST}/lib/dns/include \
	-I${IDIST}/lib/ns/include \
	-I${IDIST}/lib/irs/include \
	-I${IDIST}/lib/isc/include -I${IDIST}/lib/isc/unix/include \
	-I${IDIST}/lib/isccfg/include \
	-I${IDIST}/lib/isccc/include \
	-DNS_LOCALSTATEDIR=\"${LOCALSTATEDIR}\" \
	-DNS_SYSCONFDIR=\"${SYSCONFDIR}\" \
	-DSESSION_KEYFILE=\"${LOCALSTATEDIR}/run/named/session.key\" \
	-DNAMED_CONFFILE=\"${SYSCONFDIR}/named.conf\" \
	-DVERSION=\"${VERSION}\" -DBIND9

.if (${USE_INET6} != "no")
CPPFLAGS+=	-DWANT_IPV6
CPPFLAGS+=	-DALLOW_FILTER_AAAA
.endif

.if defined(HAVE_GCC)
COPTS+=	-Wno-pointer-sign
.endif

.if defined(NAMED_DEBUG)
DBG=-g3 -gstabs
.endif

.if !defined(LIB) || empty(LIB)
# NOTE: the order of these libraries is important...
.if defined(NAMED_DEBUG)
LDADD+=		-lbind9_g -lisccfg_g -ldns_g -lns_g -lirs_g
LDADD+=		-lisccc_g -lisc_g
LDADD+=		-L${LIBUVOBJDIR} -luv_g
LDADD+=		-lexecinfo_g -lkvm_g -lz_g
.else
LDADD+=		-lbind9 -lisccfg -ldns -lns -lirs
DPADD+=		${LIBBIND9} ${LIBISCCFG} ${LIBDNS} ${LIBNS} ${LIBIRS}
LDADD+=		-lisccc -lisc 
LDADD+=		-L${LIBUVOBJDIR} -luv
LDADD+=		-lexecinfo -lkvm -lz
DPADD+=		${LIBISCCC} ${LIBISC}
DPADD+=		${LIBUVOBJDIR}/libuv.a
DPADD+=		${LIBEXECINFO} ${LIBKVM} ${LIBZ}
.endif
.else
CPPFLAGS+= -DLIBINTERFACE=${LIBINTERFACE} \
	   -DLIBREVISION=${LIBREVISION} -DLIBAGE=${LIBAGE}
.endif
#CPPFLAGS+= -DUSE_MEMIMPREGISTER -DUSE_APPIMPREGISTER -DUSE_SOCKETIMPREGISTER \
#    -DUSE_TIMERIMPREGISTER

LDADD+=-lblocklist
DPADD+=${LIBBLOCKLIST}

.if ${NAMED_USE_PTHREADS} == "yes"
# XXX: Not ready yet
# CPPFLAGS+=	-DISC_PLATFORM_USE_NATIVE_RWLOCKS
CPPFLAGS+=	-DISC_PLATFORM_USETHREADS
.if !defined (LIB) || empty(LIB)
LDADD+= -lpthread
DPADD+= ${LIBPTHREAD}
.else
LIBDPLIBS+=      pthread  ${NETBSDSRCDIR}/lib/libpthread
.endif
.endif

.if ${NAMED_USE_OPENSSL} == "yes"
CPPFLAGS+=-DOPENSSL -DUSE_ISC_SPNEGO
.if ${HAVE_OPENSSL} == 10
CPPFLAGS+=-DHAVE_OPENSSL_GOST
.endif
.if ${MKKERBEROS} != "no"
CPPFLAGS+=-DGSSAPI
.endif
.if ${MKKERBEROS} != "no"
.if !defined (LIB) || empty(LIB)
LDADD+= -lgssapi -lheimntlm ${LIBKRB5_LDADD}
DPADD+= ${LIBGSSAPI} ${LIBHEIMNTLM} ${LIBKRB5_DPADD}
.else
.for L in gssapi krb5 hx509 heimntlm heimbase com_err roken asn1 wind
LIBDPLIBS+=	$L ${NETBSDSRCDIR}/crypto/external/bsd/heimdal/lib/lib$L
.endfor
.endif
.endif
.if !defined (LIB) || empty(LIB)
LDADD+= -lssl -lcrypto -lcrypt
DPADD+= ${LIBSSL} ${LIBCRYPTO} ${LIBCRYPT}
.else
LIBDPLIBS+=	crypto ${NETBSDSRCDIR}/crypto/external/${EXTERNAL_OPENSSL_SUBDIR}/lib/libcrypto
.endif
.endif

.if ${NAMED_USE_PTHREADS} == "yes"
CPPFLAGS+=-DISC_PLATFORM_USETHREADS -I${IDIST}/lib/isc/pthreads/include
.else
CPPFLAGS+=-I${IDIST}/lib/isc/nothreads/include
.endif

.if exists(${.PARSEDIR}/../Makefile.inc)
.include "${.PARSEDIR}/../Makefile.inc"
.endif
.endif

COPTS+=	-fcommon
