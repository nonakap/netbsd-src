#	$NetBSD: Makefile,v 1.78 2024/10/30 18:09:18 christos Exp $

.include <bsd.own.mk>

SUBDIR=	acpica am-utils bc byacc cron dhcpcd elftoolchain/common \
	ekermit elftosb fetch file flex ${EXTERNAL_JEMALLOC_SUBDIR} less \
	libarchive libevent libfido2 liblzf libpcap mdocml \
	ntp openresolv tcpdump tmux top tre wpa zstd

.if (${MKATF} != "no")
SUBDIR+= atf
.endif
SUBDIR+= pkg_install
# IP Filter
.if (${MKIPFILTER} != "no")
SUBDIR+=ipf
.endif
.if (${MKISCSI} != "no")
SUBDIR+= iscsi 
.endif
.if (${MKKYUA} != "no")
SUBDIR+= lutok kyua-testers kyua-cli kyua-atf-compat
.endif
.if (${MKLDAP} != "no")
SUBDIR+= openldap
.endif
.if (${MKLIBCXX} != "no")
SUBDIR+= libc++
.endif
.if (${MKNSD} != "no")
SUBDIR+= nsd
.endif
.if ${MKPAM} != "no"
SUBDIR+= pam-u2f
.endif
.if (${MKPCC} != "no")
SUBDIR+= pcc
.endif
.if (${MKDTRACE} != "no")
SUBDIR+= libproc
SUBDIR+= librtld_db
.endif
.if ${MKUNBOUND} != "no"
SUBDIR+= unbound
.endif

SUBDIR+= blocklist pdisk nvi ppp libnv tradcpp

.include <bsd.subdir.mk>
