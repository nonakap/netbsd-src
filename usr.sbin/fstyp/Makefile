#	$NetBSD: Makefile,v 1.15 2024/04/26 18:21:25 christos Exp $

.include <bsd.own.mk>

PROG=	fstyp
SRCS=	apfs.c cd9660.c exfat.c ext2fs.c fstyp.c hammer.c hammer2.c hfsplus.c msdosfs.c ntfs.c ufs.c

.if (${MKZFS} != "no")
SRCS+=	zfs.c
.endif

MAN=	fstyp.8

WARNS?=	6

.if (${MKZFS} != "no")
COPTS.zfs.c+=	-Wno-unknown-pragmas
COPTS.zfs.c+=	-Wno-sign-conversion
COPTS.zfs.c+=	-Wno-strict-prototypes
LDADD+=	-lnvpair
DPADD+= ${LIBNVPAIR}

OSNET=${NETBSDSRCDIR}/external/cddl/osnet
CPPFLAGS+=	-DHAVE_ZFS
CPPFLAGS.zfs.c+=	-I${NETBSDSRCDIR}/external
CPPFLAGS.zfs.c+=	-I${OSNET}/include
CPPFLAGS.zfs.c+=	-I${OSNET}/sys
CPPFLAGS.zfs.c+=	-I${OSNET}/dist/head
CPPFLAGS.zfs.c+=	-I${OSNET}/dist/lib/libzpool/common
CPPFLAGS.zfs.c+=	-I${OSNET}/dist/uts/common
CPPFLAGS.zfs.c+=	-I${OSNET}/dist/uts/common/fs/zfs
CPPFLAGS.zfs.c+=	-I${OSNET}/dist/lib/libnvpair
.endif

CWARNFLAGS.clang+=	-Wno-unknown-pragmas
CWARNFLAGS+=        	${CC_WNO_ADDRESS_OF_PACKED_MEMBER}

.include <bsd.prog.mk>
