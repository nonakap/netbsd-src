#	$NetBSD: Makefile.inc,v 1.136 2025/03/22 09:25:14 hgutch Exp $
#
#	etc.evbarm/Makefile.inc -- evbarm-specific etc Makefile targets
#

MKIMAGE= ${NETBSDSRCDIR}/distrib/utils/embedded/mkimage

# If you change the list of distributed kernels, don't forget
# to update the release documentation in distrib/notes/common/contents
EVBARM_BOARDS=
.for i in armv4 xscale armv5t armv6 armv7 arm64
EVBARM_BOARDS.${i}=
.endfor

.if !empty(MACHINE_ARCH:M*eb)
IMAGEENDIAN=	be
# big endian boards
KERNEL_SETS.armv4+=		IXM1200

EVBARM_BOARDS.xscale+=		ADI_BRH
KERNEL_SETS.xscale+=		NSLU2

EVBARM_BOARDS.armv5t+=		KUROBOX_PRO
KERNEL_SETS.armv5t+=		OPENBLOCKS_A6
# Other marvell-based machines may also work but not tested yet.

EVBARM_BOARDS.armv6+=		RPI
EVBARM_BOARDS.armv6hf+=	 	RPI
KERNEL_SETS.armv6+=		RPI2
KERNEL_SETS.armv6hf+=	 	RPI2

KERNEL_SETS.armv7+=		GENERIC
KERNEL_SETS.armv7hf+=		GENERIC

KERNEL_SETS.arm64+=		GENERIC64
KERNEL_SETS.arm64+=		GENERIC64_PMAPMI
.else
IMAGEENDIAN=	le
# little endian boards
EVBARM_BOARDS.armv4+=		GEMINI
EVBARM_BOARDS.armv4+=		INTEGRATOR
EVBARM_BOARDS.armv4+=		INTEGRATOR_CP
KERNEL_SETS.armv4+=		IXM1200
EVBARM_BOARDS.armv4+=		SMDK2410
EVBARM_BOARDS.armv4+=		SMDK2800
EVBARM_BOARDS.armv4+=		TS7200

EVBARM_BOARDS.xscale+=		ADI_BRH
EVBARM_BOARDS.xscale+=		CP3100
EVBARM_BOARDS.xscale+=		GUMSTIX
KERNEL_SETS.xscale+=		HDL_G
EVBARM_BOARDS.xscale+=		IQ80310
EVBARM_BOARDS.xscale+=		IQ80321
EVBARM_BOARDS.xscale+=		TEAMASA_NPWR
EVBARM_BOARDS.xscale+=		TWINTAIL

EVBARM_BOARDS.armv5t+=		KUROBOX_PRO
EVBARM_BOARDS.armv5t+=		MV2120
KERNEL_SETS.armv5t+=		OPENBLOCKS_A6
EVBARM_BOARDS.armv5t+=		OPENRD
EVBARM_BOARDS.armv5t+=		SHEEVAPLUG

EVBARM_BOARDS.armv6+=		RPI
EVBARM_BOARDS.armv6hf+=	 	RPI
KERNEL_SETS.armv6+=		RPI2
KERNEL_SETS.armv6hf+=	 	RPI2

KERNEL_SETS.armv7+=		GENERIC
KERNEL_SETS.armv7hf+=		GENERIC

KERNEL_SETS.arm64+=		GENERIC64
KERNEL_SETS.arm64+=		GENERIC64_PMAPMI
.endif

IMAGE.rel=	${RELEASEDIR}/${RELEASEMACHINEDIR}
IMAGE.dir=	${IMAGE.rel}/binary/gzimg
IMAGE.kern=	${IMAGE.rel}/binary/kernel
IMAGE.instk=	${IMAGE.rel}/installation/instkernel

__mkimage: .USE
	TOOL_MAKE=${MAKE} \
	TOOL_MAKEFS=${TOOL_MAKEFS} \
	TOOL_DISKLABEL=${TOOL_DISKLABEL} \
	TOOL_FDISK=${TOOL_FDISK} \
	TOOL_GPT=${TOOL_GPT} \
	TOOL_GZIP=${TOOL_GZIP} \
	TOOL_MKNOD=${TOOL_MKNOD} \
	TOOL_PAX=${TOOL_PAX} \
	TOOL_MKUBOOTIMAGE=${TOOL_MKUBOOTIMAGE} \
	TOOL_MTREE=${TOOL_MTREE} \
	TOOL_SED=${TOOL_SED} \
	TOOL_PWD_MKDB=${TOOL_PWD_MKDB} \
	HOST_SH=${HOST_SH} \
	KERNOBJDIR=${KERNOBJDIR} \
	MACHINE=${MACHINE} \
	MKDTB=${MKDTB} \
	MKPOSTFIX=${MKPOSTFIX} \
	CKSUM=${CKSUM} \
	IMAGEDIR=${IMAGE.dir} \
	${HOST_SH} ${MKIMAGE} -h ${.TARGET:S/smp_//} -D ${DESTDIR} \
	    -S ${NETBSDSRCDIR} -B ${IMAGEENDIAN} ${MKI_OPTS.${.TARGET}} \
	    ${IMAGE.dir}/${.TARGET:S/smp_//}.img
.for f in ${INSTALLBOOT_BOARDS}
	@echo "===> Making bootable image ${IMAGE.dir:T}/${.TARGET:S/smp_//}-${f}.img.gz"
	@cp ${IMAGE.dir}/${.TARGET:S/smp_//}.img ${IMAGE.dir}/${.TARGET:S/smp_//}-${f}.img
	@${TOOL_INSTALLBOOT} -m ${MACHINE} -o board=${f} \
			${IMAGE.dir}/${.TARGET:S/smp_//}-${f}.img \
		&& ${TOOL_GZIP} -f ${IMAGE.dir}/${.TARGET:S/smp_//}-${f}.img \
		|| rm ${IMAGE.dir}/${.TARGET:S/smp_//}-${f}.img
.endfor
	@echo "===> Compressing image ${IMAGE.dir}/${.TARGET:S/smp_//}.img"
	${TOOL_GZIP} -f ${GZIP_N_FLAG} -9 ${IMAGE.dir}/${.TARGET:S/smp_//}.img

ARCHES.earmv4=		armv4
ARCHES.earmv4eb=	armv4
ARCHES.earmv5=		xscale armv5t
ARCHES.earmv5eb=	xscale armv5t
ARCHES.earmv6=		armv6
ARCHES.earmv6hf=	armv6hf
ARCHES.earmv6eb=	armv6
ARCHES.earmv6hfeb=	armv6hf
ARCHES.earmv7=		armv7
ARCHES.earmv7hf=	armv7hf
ARCHES.earmv7eb=	armv7
ARCHES.earmv7hfeb=	armv7hf
ARCHES.aarch64=		arm64
ARCHES.aarch64eb=	arm64
.for arch in ${ARCHES.${MACHINE_ARCH}}
.for board in ${EVBARM_BOARDS.${arch}}
KERNEL_SETS+=		${board}
BUILD_KERNELS+=		${board}_INSTALL
.endfor
KERNEL_SETS+=		${KERNEL_SETS.${arch}}
.endfor

.if !empty(MACHINE_ARCH:Maarch64*)
smp_efibootaa64:
	cd ${KERNSRCDIR}/stand/efiboot/bootaa64 && ${MAKE} release
SNAP_MD_POST_DEPS+=	smp_efibootaa64
INSTALLATION_DIRS+=	installation/misc
.endif

.if !empty(MACHINE_ARCH:Mearmv7hf)
smp_efibootarm:
	cd ${KERNSRCDIR}/stand/efiboot/bootarm && ${MAKE} release
SNAP_MD_POST_DEPS+=	smp_efibootarm
INSTALLATION_DIRS+=	installation/misc
.endif

.if !empty(MACHINE_ARCH:M*armv7*) && empty(ALL_KERNELS)
smp_armv7: __mkimage
MKI_OPTS.smp_armv7=	-K ${IMAGE.kern} -x
SNAP_MD_POST_DEPS+=	smp_armv7
.endif

.if !empty(MACHINE_ARCH:Maarch64*) && empty(ALL_KERNELS)
smp_arm64: __mkimage
MKI_OPTS.smp_arm64=	-K ${IMAGE.kern} -x
SNAP_MD_POST_DEPS+=	smp_arm64
smp_arm64mbr: __mkimage
MKI_OPTS.smp_arm64mbr=	-K ${IMAGE.kern} -x
SNAP_MD_POST_DEPS+=	smp_arm64mbr
.endif

.if !empty(KERNEL_SETS:MRPI)
smp_rpi: __mkimage
.if empty(ALL_KERNELS) || !empty(ALL_KERNELS:MRPI)
MKI_OPTS.smp_rpi=	-K ${IMAGE.kern}/netbsd-RPI.img.gz -x
SNAP_MD_POST_DEPS+=	smp_rpi
.endif
smp_rpi_inst: ${IMAGE.instk}/netbsd-RPI_INSTALL.img.gz __mkimage
.if empty(ALL_KERNELS) || !empty(ALL_KERNELS:MRPI_INSTALL)
MKI_OPTS.smp_rpi_inst=	-b -K ${IMAGE.instk}/netbsd-RPI_INSTALL.img.gz -x
SNAP_MD_POST_DEPS+=	smp_rpi_inst
.endif
.endif

snap_md_post: check_DESTDIR check_RELEASEDIR snap_post .WAIT ${SNAP_MD_POST_DEPS}

.if !empty(MACHINE_ARCH:Maarch64*)
KERNEL_SUFFIXES=	img
.else
KERNEL_SUFFIXES=	bin img srec ub
.endif

INSTALLATION_DIRS+=	binary/gzimg		\
			installation/instkernel
