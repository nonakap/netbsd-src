#	$NetBSD: Makefile,v 1.12 2025/02/25 19:15:53 christos Exp $

LIBISPRIVATE=	yes

.include <bsd.own.mk>

LIB=	util

DIST=	${NETBSDSRCDIR}/external/ibm-public/postfix/dist/src/${LIB}
.PATH:	${DIST}

SRCS= \
allascii.c \
alldig.c \
allprint.c \
allspace.c \
argv.c \
argv_attr_print.c \
argv_attr_scan.c \
argv_split.c \
argv_split_at.c \
argv_splitq.c \
attr_clnt.c \
attr_print0.c \
attr_print64.c \
attr_print_plain.c \
attr_scan0.c \
attr_scan64.c \
attr_scan_plain.c \
auto_clnt.c \
balpar.c \
base32_code.c \
base64_code.c \
basename.c \
binhash.c \
byte_mask.c \
casefold.c \
chroot_uid.c \
cidr_match.c \
clean_ascii_cntrl_space.c \
clean_env.c \
close_on_exec.c \
concatenate.c \
ctable.c \
dict.c \
dict_alloc.c \
dict_cache.c \
dict_cdb.c \
dict_cidr.c \
dict_db.c \
dict_dbm.c \
dict_debug.c \
dict_env.c \
dict_fail.c \
dict_file.c \
dict_ht.c \
dict_inline.c \
dict_lmdb.c \
dict_ni.c \
dict_nis.c \
dict_nisplus.c \
dict_open.c \
dict_pcre.c \
dict_pipe.c \
dict_random.c \
dict_regexp.c \
dict_sdbm.c \
dict_sockmap.c \
dict_static.c \
dict_stream.c \
dict_surrogate.c \
dict_tcp.c \
dict_test.c \
dict_thash.c \
dict_union.c \
dict_unix.c \
dict_utf8.c \
dir_forest.c \
doze.c \
dummy_read.c \
dummy_write.c \
dup2_pass_on_exec.c \
duplex_pipe.c \
edit_file.c \
environ.c \
events.c \
exec_command.c \
extpar.c \
fifo_listen.c \
fifo_open.c \
fifo_rdonly_bug.c \
fifo_rdwr_bug.c \
fifo_trigger.c \
file_limit.c \
find_inet.c \
format_tv.c \
fsspace.c \
fullname.c \
get_domainname.c \
get_hostname.c \
hash_fnv.c \
hex_code.c \
hex_quote.c \
host_port.c \
htable.c \
inet_addr_host.c \
inet_addr_list.c \
inet_addr_local.c \
inet_addr_sizes.c \
inet_connect.c \
inet_listen.c \
inet_prefix_top.c \
inet_proto.c \
inet_trigger.c \
inet_windowsize.c \
ip_match.c \
killme_after.c \
known_tcp_ports.c \
ldseed.c \
line_number.c \
line_wrap.c \
load_file.c \
load_lib.c \
logwriter.c \
lowercase.c \
lstat_as.c \
mac_expand.c \
mac_parse.c \
make_dirs.c \
mask_addr.c \
match_list.c \
match_ops.c \
midna_domain.c \
mkmap_cdb.c \
mkmap_db.c \
mkmap_dbm.c \
mkmap_fail.c \
mkmap_lmdb.c \
mkmap_open.c \
mkmap_sdbm.c \
msg.c \
msg_logger.c \
msg_output.c \
msg_rate_delay.c \
msg_syslog.c \
msg_vstream.c \
mvect.c \
myaddrinfo.c \
myflock.c \
mymalloc.c \
myrand.c \
mystrerror.c \
mystrtok.c \
name_code.c \
name_mask.c \
nbbio.c \
netstring.c \
neuter.c \
non_blocking.c \
normalize_ws.c \
nvtable.c \
open_as.c \
open_limit.c \
open_lock.c \
pass_accept.c \
pass_trigger.c \
peekfd.c \
poll_fd.c \
posix_signals.c \
printable.c \
quote_for_json.c \
rand_sleep.c \
readlline.c \
recv_pass_attr.c \
ring.c \
safe_getenv.c \
safe_open.c \
sane_accept.c \
sane_basename.c \
sane_connect.c \
sane_link.c \
sane_rename.c \
sane_sockaddr_to_hostaddr.c \
sane_socketpair.c \
sane_strtol.c \
sane_time.c \
scan_dir.c \
select_bug.c \
set_eugid.c \
set_ugid.c \
sigdelay.c \
skipblanks.c \
slmdb.c \
sock_addr.c \
spawn_command.c \
split_at.c \
split_nameval.c \
split_qnameval.c \
stat_as.c \
strcasecmp.c \
strcasecmp_utf8.c \
stream_connect.c \
stream_listen.c \
stream_recv_fd.c \
stream_send_fd.c \
stream_test.c \
stream_trigger.c \
sys_compat.c \
timecmp.c \
timed_connect.c \
timed_read.c \
timed_wait.c \
timed_write.c \
translit.c \
trimblanks.c \
unescape.c \
unix_connect.c \
unix_dgram_connect.c \
unix_dgram_listen.c \
unix_listen.c \
unix_pass_fd_fix.c \
unix_recv_fd.c \
unix_send_fd.c \
unix_trigger.c \
unsafe.c \
uppercase.c \
username.c \
valid_hostname.c \
valid_utf8_hostname.c \
valid_utf8_string.c \
vbuf.c \
vbuf_print.c \
vstream.c \
vstream_popen.c \
vstream_tweak.c \
vstring.c \
vstring_vstream.c \
warn_stat.c \
watchdog.c \
write_buf.c

COPTS.unix_recv_fd.c = -Wno-stack-protector
COPTS.unix_send_fd.c = -Wno-stack-protector

.include <bsd.lib.mk>
