# $NetBSD: Makefile,v 1.9 2024/02/17 18:31:19 christos Exp $

.include <bsd.init.mk>

.PATH: \
${UNBOUND}/cachedb \
${UNBOUND}/dns64 \
${UNBOUND}/iterator \
${UNBOUND}/libunbound \
${UNBOUND}/respip \
${UNBOUND}/services \
${UNBOUND}/services/cache \
${UNBOUND}/sldns \
${UNBOUND}/util \
${UNBOUND}/util/data \
${UNBOUND}/util/storage \
${UNBOUND}/validator

CPPFLAGS+=-I${UNBOUND} -I${UNBOUND}/../include

LIB=unbound
SRCS=\
alloc.c \
as112.c \
authzone.c \
autotrust.c \
cachedb.c \
config_file.c \
configlexer.c \
configparser.c \
context.c \
dname.c \
dns.c \
dns64.c \
dnstree.c \
edns.c \
fptr_wlist.c \
infra.c \
iter_delegpt.c \
iter_donotq.c \
iter_fwd.c \
iter_hints.c \
iter_priv.c \
iter_resptype.c \
iter_scrub.c \
iter_utils.c \
iterator.c \
keyraw.c \
libunbound.c \
libworker.c \
listen_dnsport.c \
localzone.c \
locks.c \
log.c \
lookup3.c \
lruhash.c \
mesh.c \
mini_event.c \
modstack.c \
module.c \
msgencode.c \
msgparse.c \
msgreply.c \
net_help.c \
netevent.c \
outbound_list.c \
outside_network.c \
packed_rrset.c \
parse.c \
parseutil.c \
proxy_protocol.c \
random.c \
rbtree.c \
regional.c \
respip.c \
rfc_1982.c \
rpz.c \
rrdef.c \
rrset.c \
rtt.c \
sbuffer.c \
siphash.c \
slabhash.c \
str2wire.c \
tcp_conn_limit.c \
timehist.c \
timeval_func.c \
tube.c \
ub_event_pluggable.c \
val_anchor.c \
val_kcache.c \
val_kentry.c \
val_neg.c \
val_nsec.c \
val_nsec3.c \
val_secalgo.c \
val_sigcrypt.c \
val_utils.c \
validator.c \
view.c \
winsock_event.c \
wire2str.c

LIBDPLIBS+= ${DPLIBS}

INCS=unbound.h
INCSDIR=/usr/include

MAN=libunbound.3
CLEANFILES+=libunbound.3

libunbound.3: libunbound.3.in __subst

COPTS.keyraw.c+= -Wno-error=deprecated-declarations
COPTS.net_help.c+= -Wno-error=deprecated-declarations

.include <bsd.lib.mk>

# Use the generated files
.y.c:
