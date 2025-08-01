# $NetBSD: Makefile.inc,v 1.6 2025/07/14 10:25:52 kre Exp $

USE_FORT?= yes  # network client/server
UNBOUND:=${.PARSEDIR}/dist

.PATH: ${UNBOUND}/doc

DPLIBS+= ssl ${NETBSDSRCDIR}/crypto/external/${EXTERNAL_OPENSSL_SUBDIR}/lib/libssl
DPLIBS+= crypto ${NETBSDSRCDIR}/crypto/external/${EXTERNAL_OPENSSL_SUBDIR}/lib/libcrypto
DPLIBS+= crypt ${NETBSDSRCDIR}/lib/libcrypt
DPLIBS+= util ${NETBSDSRCDIR}/lib/libutil
DPLIBS+= pthread ${NETBSDSRCDIR}/lib/libpthread
DPLIBS+= event ${NETBSDSRCDIR}/external/bsd/libevent/lib/libevent

__subst: .USE
	${TOOL_SED} \
	    -e s,@ub_conf_dir@,/etc/unbound, \
	    -e s,@ub_conf_file@,/etc/unbound/unbound.conf, \
	    -e s,@UNBOUND_CHROOT_DIR@,/var/chroot/unbound, \
	    -e s,@UNBOUND_PIDFILE@,/var/run/unbound.pid, \
	    -e s,@UNBOUND_ROOTCERT_FILE@,/etc/unbound/icannbundle.pem, \
	    -e s,@UNBOUND_ROOTKEY_FILE@,/etc/unbound/root.key, \
	    -e s,@UNBOUND_RUN_DIR@,/var/chroot/unbound/etc/unbound, \
	    -e s,@UNBOUND_SHARE_DIR@,/etc/unbound, \
	    -e s,@UNBOUND_USERNAME@,_unbound, < ${.ALLSRC} > ${.TARGET}
