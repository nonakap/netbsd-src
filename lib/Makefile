#	$NetBSD: Makefile,v 1.308 2025/07/13 20:15:15 christos Exp $
#	from: @(#)Makefile	5.25.1.1 (Berkeley) 5/7/91

.include <bsd.own.mk>

SUBDIR=		csu .WAIT

.if (${MKGCC} != "no")
SUBDIR+=	../external/gpl3/${EXTERNAL_GCC_SUBDIR}/lib/libgcc .WAIT
.endif

SUBDIR+=	libc
SUBDIR+=	.WAIT

#
# The SUBDIRs above are included here for completeness but should be built
# and installed prior to make(dependall) in this file, as libraries listed
# below will depend on versions from DESTDIR only.
#

SUBDIR+=	i18n_module

SUBDIR+=	libarch \
		libbluetooth libbsdmalloc libbz2 \
		libcompat libcrypt \
		libintl libipsec libkvm libm \
		libossaudio libpci libposix libprop libpthread \
		libpuffs libresolv librmt librpcsvc librt \
		libtelnet libterminfo \
		libusbhid libutil liby libz

.if !defined(BSD_MK_COMPAT_FILE)
SUBDIR+=	libkern
.endif

.if (${MACHINE} == "evbppc" && ${MACHINE_ARCH} == "powerpc")
SUBDIR+=	libc_aligned
.endif
.if (${MACHINE_CPU} == "arm" || ${MACHINE_CPU} == "aarch64")
LIBC_MACHINE_ARCH?=${MACHINE_ARCH}
LIBC_MACHINE_CPU?=${MACHINE_CPU}
.if ${LIBC_MACHINE_CPU} == "arm" && empty(LIBC_MACHINE_ARCH:M*hf*)
SUBDIR+=	libc_vfp
.endif
.endif
.if ${MACHINE_MIPS64}
SUBDIR+=	libc_fp
.endif
.if (${MKRUMP} != "no")
SUBDIR+=	librumpclient
.endif
.if (${MKSKEY} != "no")
SUBDIR+=	libskey
.endif

.if ${HAVE_NVMM:Uno} == "yes" && !defined(MLIBDIR)
SUBDIR+=	libnvmm
.endif

.if (${MKARGON2} != "no")
SUBDIR+=	../external/apache2/argon2/lib/libargon2
.endif

.if (${MKMDNS} != "no")
SUBDIR+=	../external/apache2/mDNSResponder/lib
.endif

SUBDIR+=	../external/bsd/am-utils/lib

SUBDIR+=	../external/bsd/flex/lib
SUBDIR+=	../external/bsd/tre/lib
ELFTOOLCHAINLIB=../external/bsd/elftoolchain/lib/
.include "${ELFTOOLCHAINLIB}Makefile.subdir"
SUBDIR+=	../external/bsd/liblzf/lib
SUBDIR+=	../external/bsd/libpcap/lib

.if ${MKSLJIT} != "no"
SUBDIR+=	../external/bsd/sljit/lib
SUBDIR+=	libbpfjit
.endif

SUBDIR+=	../external/bsd/libnv/lib

.if (${MKZFS} != "no")
SUBDIR+=        ../external/cddl/osnet/lib/libavl
SUBDIR+=        ../external/cddl/osnet/lib/libnvpair
SUBDIR+=        ../external/cddl/osnet/lib/libumem
SUBDIR+=        ../external/cddl/osnet/lib/libuutil
.endif

SUBDIR+=	../external/mit/expat/lib

SUBDIR+=	../external/gpl2/libmalloc

SUBDIR+=	../external/bsd/${EXTERNAL_JEMALLOC_SUBDIR}/lib

.if (${MKGCC} != "no")
SUBDIR+=	../external/gpl3/${EXTERNAL_GCC_SUBDIR}/lib/libobjc
SUBDIR+=	../external/gpl3/${EXTERNAL_GCC_SUBDIR}/lib/libgomp
.endif

# GCC and GDB >= 13 require GMP.
# We don't build compat versions of these
.if !defined(MLIBDIR) && (${MKGCCCMDS} != "no" || ${MKGDB} != "no")
SUBDIR+=	../external/lgpl3/mpfr/lib/libmpfr
SUBDIR+=	../external/lgpl3/mpc/lib/libmpc
SUBDIR+=	../external/lgpl3/gmp/lib/libgmp
.endif

#
# Libraries that depend upon any listed previously
# (and those that depend upon these [and ...])
#
#==================== 1st library dependency barrier ====================
SUBDIR+=	.WAIT

.if ${MKDTRACE} != "no"
SUBDIR+=	../external/bsd/librtld_db/lib		# depends on libutil
.endif

.if ${MKCTF} != "no"
SUBDIR+=        ../external/cddl/osnet/lib/libctf
.endif

SUBDIR+=	../external/public-domain/xz/lib	# depends on libpthread
SUBDIR+=	../crypto/external/bsd/netpgp/libmj
SUBDIR+=	../crypto/external/bsd/netpgp/lib/verify # depends on libz
SUBDIR+=	../external/bsd/blocklist/lib		# depends on libpthread
SUBDIR+=	../external/mit/lua/lib # depends on libm
SUBDIR+=	../external/public-domain/sqlite/lib # depends on libm
SUBDIR+=	libcurses	# depends on libterminfo
SUBDIR+=	libdm		# depends on libprop
SUBDIR+=	libedit		# depends on libterminfo
SUBDIR+=	libexecinfo 	# depends on libelf
SUBDIR+=	libppath	# depends on libprop
SUBDIR+=	libperfuse	# depends on libpuffs
SUBDIR+=	libquota	# depends on libprop and librpcsvc
SUBDIR+=	librefuse	# depends on libpuffs
SUBDIR+=	libisns 	# depends on libpthread
.if (${MKRUMP} != "no")
SUBDIR+=	librumphijack	# depends on librumpclient and libpthread
SUBDIR+=	librumpres	# depends on librumpclient
SUBDIR+=	librumpuser	# depends on libpthread
.endif

.if (${MKNPF} != "no")
SUBDIR+=	libnpf		# depends on libnv
.endif

OSSL=../crypto/external/${EXTERNAL_OPENSSL_SUBDIR}/lib/
.include "${.CURDIR}/${OSSL}Makefile.subdir" # depends on libcrypt

.if (${MKISCSI} != "no")
SUBDIR+=	../external/bsd/iscsi/lib	# depends on libpthread
.endif

.if (${MKZFS} != "no")
SUBDIR+=        ../external/cddl/osnet/lib/libzfs_core
SUBDIR+=        ../external/cddl/osnet/lib/libzpool
.endif

.if (${MKLVM} != "no")
SUBDIR+=	../external/gpl2/lvm2/lib	# depends on libprop
.endif

.if (${MKBINUTILS} != "no")
SUBDIR+=	../external/gpl3/${EXTERNAL_BINUTILS_SUBDIR}/lib	# libbfd depends on libz
.endif

.if (${MKLIBCXX} != "no")
SUBDIR+=	../external/bsd/libc++
.endif

.if (${MKGCC} != "no" && ${MKCXX} != "no" && ${MKLIBSTDCXX} != "no")
SUBDIR+=	../external/gpl3/${EXTERNAL_GCC_SUBDIR}/lib/libstdc++-v3
SUBDIR+=	../external/gpl3/${EXTERNAL_GCC_SUBDIR}/lib/libsupc++
.endif

.if (${MKLLVMRT} != "no" && (!defined(MLIBDIR) || ${MKCOMPATX11} != "no"))
SUBDIR+=	../external/apache2/llvm/include
.endif

SUBDIR+=	../external/mit/libcbor/lib

SUBDIR+=	../external/bsd/zstd/lib
#==================== 2nd library dependency barrier ====================
SUBDIR+=	.WAIT

SUBDIR+=	libwrap

.if (${MKGCC} != "no" && ${MKCXX} != "no" && ${MKLIBSTDCXX} != "no")
.if ${MKGCCCMDS} != "no"
.for sanitizer in asan lsan ubsan
.if exists(../external/gpl3/${EXTERNAL_GCC_SUBDIR}/lib/lib${sanitizer})
SUBDIR+= ../external/gpl3/${EXTERNAL_GCC_SUBDIR}/lib/lib${sanitizer}
.endif
.endfor
.endif
.endif

.if (${MKLLVMRT} != "no" && (!defined(MLIBDIR) || ${MKCOMPATX11} != "no"))
SUBDIR+=	../external/apache2/llvm/librt
.endif

SUBDIR+=	../external/bsd/libarchive/lib	# depends on libxz, zstd

SUBDIR+=	../external/bsd/file/lib	# depends on libz, libbz2, libxz, zstd

.if (${MKNPF} != "no")
SUBDIR+=	npf		# depends on libnpf
.endif

.if (${MKATF} != "no")
ATFLIB=	../external/bsd/atf/lib/
.include "${ATFLIB}Makefile.subdir"		# depends on libstdc++
.endif

.if (${MKKYUA} != "no")
SUBDIR+=	../external/bsd/lutok/lib	# depends on lua and libstdc++
.endif

SUBDIR+=	libform		# depends on libcurses
SUBDIR+=	libmenu		# depends on libcurses
SUBDIR+=	libpanel	# depends on libcurses
SUBDIR+=	libradius	# depends on libcrypto
.if (${MKRUMP} != "no")
SUBDIR+=	librump		# depends on librumpuser
.endif

.if (${MKKERBEROS} != "no")
# heimdal depends on libcrypto, libedit, libterminfo
HEIMDALLIB=	../crypto/external/bsd/heimdal/lib/
.include "${HEIMDALLIB}Makefile.subdir"			# depends on libcrypto
							# libedit, libterminfo,
.endif

SUBDIR+=	../external/bsd/libfido2/lib	# depends on libcbor
NETPGPLIB=	../crypto/external/bsd/netpgp/lib/
.include "${NETPGPLIB}Makefile.subdir"		# depends on libcrypto, ...
LIBEVENTLIB=	../external/bsd/libevent/lib/
.include "${LIBEVENTLIB}Makefile.subdir"	# depends on libcrypto
.if ${MKDTRACE} != "no"
SUBDIR+=	../external/bsd/libproc/lib	# depends on libstdc++, libctf
.endif
SUBDIR+=	../external/bsd/fetch/lib	# depends on libssl

.if (${MKLDAP} != "no")
OPENLDAPLIB=	../external/bsd/openldap/lib/	# depends on libcrypto, ...
.include "${OPENLDAPLIB}Makefile.subdir"
.endif

.if (${MKZFS} != "no")
SUBDIR+=        ../external/cddl/osnet/lib/libzfs
.endif

SUBDIR+= 	../libexec/httpd/libbozohttpd 	# depends on libssl & libcrypto

SUBDIR+=	../external/mit/libuv/lib
SUBDIR+=	../external/lgpl2/userspace-rcu/lib

#==================== 3rd library dependency barrier ====================
SUBDIR+=	.WAIT

SUBDIR+=	../crypto/external/bsd/openssh/lib # depends on libcrypto, libz,
						   # libfido2
SUBDIR+=	../crypto/external/bsd/netpgp/bindings/lua  # depends on netpgp/lib
SUBDIR+=	../external/mpl/bind/lib	# depends on heimdal, libcrypto
						# libuv, userspace-rcu
.if ${MKUNBOUND} != "no"
SUBDIR+=	../external/bsd/unbound/lib	# depends on libcrypto
.endif

.if ${MKDTRACE} != "no"
SUBDIR+=        ../external/cddl/osnet/lib/libdtrace	# depends on libproc
.endif

.if (${MKRUMP} != "no")
SUBDIR+=	librumpdev	# depends on librump
SUBDIR+=	librumpnet	# depends on librump
SUBDIR+=	librumpvfs	# depends on librump
.endif

SUBDIR+=	../crypto/external/bsd/libsaslc	# depends on heimdal, openssl
SUBDIR+=	../external/bsd/mdocml/lib

#==================== 4th library dependency barrier ====================
SUBDIR+=	.WAIT

.if (${MKPAM} != "no")
SUBDIR+=	libpam		# depends on heimdal, libssh
.endif


.if (${MKRUMP} != "no")
SUBDIR+=	libukfs		# depends on librumpvfs, librump
.endif

.if (${MKTPM} != "no")
SUBDIR+=	../crypto/external/cpl/trousers/lib
.endif

#==================== 5th library dependency barrier ====================
SUBDIR+=	.WAIT

.if (${MKPAM} != "no")
SUBDIR+=	../external/bsd/pam-u2f/lib	# depends on libpam
.endif

.if (${MKRUMP} != "no")
SUBDIR+=	libp2k		# depends on libukfs, librumpvfs, libpuffs
.endif

.if (${MKTPM} != "no")
SUBDIR+=	../crypto/external/cpl/tpm-tools/lib	# depends on trousers
.endif

.if (${MKRUMP} != "no")
.if !defined(BSD_MK_COMPAT_FILE)
SUBDIR+=	../sys/rump/dev/lib
SUBDIR+=	../sys/rump/fs/lib
SUBDIR+=	../sys/rump/kern/lib
SUBDIR+=	../sys/rump/net/lib
.endif
.endif

# Lua bindings come last, they might depend on anything
SUBDIR+=	lua

.include <bsd.buildinstall.mk>
.include <bsd.subdir.mk>
