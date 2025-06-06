#	$NetBSD: Makefile,v 1.6 2024/08/27 17:07:37 christos Exp $

LIBISPRIVATE=	yes
NOGCCERROR=

.include <bsd.own.mk>
.include "../Makefile.inc"

LIB=	sim
SRCS=	debug.c bits.c sim-endian.c os_emul.c emul_generic.c \
	emul_bugapi.c emul_chirp.c emul_netbsd.c emul_unix.c registers.c vm.c \
	corefile.c model.c spreg.c cpu.c interrupts.c events.c cap.c device.c \
	tree.c device_table.c itable.c mon.c icache.c semantics.c idecode.c \
	support.c psim.c pk_disklabel.c hw_cpu.c hw_memory.c hw_nvram.c \
	hw_iobus.c hw_htab.c hw_disk.c hw_trace.c hw_register.c hw_vm.c \
	hw_init.c hw_core.c hw_pal.c hw_com.c hw_eeprom.c hw_opic.c hw_glue.c \
	hw_phb.c hw_ide.c options.c sim_calls.c callback.c gdb-sim.c
SRCS+=	target-newlib-errno.c target-newlib-open.c target-newlib-signal.c \
	target-newlib-syscall.c

MIC=	${HOST_SH} ${DIST}/move-if-change

HOST_CPPFLAGS+=	-I. \
		-I${DIST}/sim/common \
		-I${DIST}/sim/igen \
		-I${DIST}/sim/ppc -I${DIST}/include \
		-I${.CURDIR}/arch/${GDB_MACHINE_ARCH} \
		-I${.CURDIR}/../libbfd/arch/${GDB_MACHINE_ARCH} \
		-I${.CURDIR}/../libgnulib/arch/${GDB_MACHINE_ARCH} \
		-I${.CURDIR}/../libgdbsupport/arch/${GDB_MACHINE_ARCH} \
		-I${DIST}/bfd \
		-I${DIST}/gdb \
		-I${DIST}/gdb/config \
		-DHAVE_COMMON_FPU \
		-I${.CURDIR}/../arch/${GDB_MACHINE_ARCH} \
		-I${DIST}/gnulib/import
PSIM_DEFINES=	-DHAVE_CONFIG_H \
		-DDEFAULT_INLINE=INLINE_LOCALS \
		-DWITH_HOST_BYTE_ORDER=BYTE_ORDER \
		-DWITH_SMP=5 \
		-DSIM_COMMON_BUILD \
		-DSIM_TOPDIR_BUILD \
		-DHAVE_TERMIOS_STRUCTURE \
		-DHAVE_DEVZERO  \
		-DWITH_TRACE=0 \
		-DWITH_ASSERT=0 \
		-DWITH_STDIO=0 \
		-DWITH_ENVIRONMENT=0 \
		-DWITH_RESERVED_BITS=0 \
		-DREPORT_BUGS_TO=\"gnats@NetBSD.org\" \
		-DPKGVERSION=\"13.2\"

# we need the same -I flags for host / target.
CPPFLAGS+=	${HOST_CPPFLAGS} ${PSIM_DEFINES}

#
# These portions run several programs to generate more code to compile.
#

# igen portion
IGEN_FLAGS=	-E    -F 32,f,o  -CSRI 1024  -N 5 \
	-o ${DIST}/sim/ppc/dc-complex \
	-I ${DIST}/sim/ppc -i ${DIST}/sim/ppc/powerpc.igen \
	-n icache.h    -hc tmp-icache.h \
	-n icache.c    -c  tmp-icache.c \
	-n semantics.h -hs tmp-semantics.h \
	-n semantics.c -s  tmp-semantics.c \
	-n idecode.h   -hd tmp-idecode.h \
	-n idecode.c   -d  tmp-idecode.c \
	-n itable.h    -ht tmp-itable.h \
	-n itable.c    -t  tmp-itable.c \
	-n model.h     -hm tmp-model.h \
	-n model.c     -m  tmp-model.c \
	-n support.h   -hf tmp-support.h \
	-n support.c   -f  tmp-support.c
IGENED_FILES=	icache.h icache.c idecode.h idecode.c semantics.h semantics.c \
		itable.h itable.c model.h model.c support.h support.c
IGENSRCS= igen.c table.c lf.c misc.c filter_host.c ld-decode.c ld-cache.c filter.c ld-insn.c gen-model.c gen-itable.c gen-icache.c gen-semantics.c gen-idecode.c gen-support.c lf-ppc.c dumpf.c filter-ppc.c
IGENOBJS= ${IGENSRCS:S/.c/.lo/}
DPSRCS+= ${IGENED_FILES:M*.h}

${IGENED_FILES}: run-igen
run-igen: igen powerpc.igen
	${_MKMSG_CREATE} ${IGENED_FILES}
	rm -f ${.TARGET}
	./igen ${IGEN_FLAGS}
	${MIC} tmp-icache.h icache.h
	${MIC} tmp-icache.c icache.c
	${MIC} tmp-idecode.h idecode.h
	${MIC} tmp-idecode.c idecode.c
	${MIC} tmp-semantics.h semantics.h
	${MIC} tmp-semantics.c semantics.c
	${MIC} tmp-itable.h itable.h
	${MIC} tmp-itable.c itable.c
	${MIC} tmp-model.h model.h
	${MIC} tmp-model.c model.c
	${MIC} tmp-support.h support.h
	${MIC} tmp-support.c support.c
	touch ${.TARGET}

igen: ${IGENOBJS}
	${HOST_LINK.c} ${IGENOBJS} -o ${.TARGET}

# dgen portion
#DGEN_FLAGS=	-r ${DIST}/sim/ppc/ppc-spr-table \
#	-n spreg.h     -hp tmp-spreg.h \
#	-n spreg.c     -p  tmp-spreg.c
#DGENED_FILES=	spreg.h spreg.c
#DGENSRCS= dgen.c table.c lf.c misc.c filter_host.c
#DGENOBJS= ${DGENSRCS:S/.c/.lo/}
#DPSRCS+= ${DGENED_FILES:M*.h}

#${DGENED_FILES}: run-dgen
#run-dgen: dgen
#	./dgen ${DGEN_FLAGS}
#	${MIC} tmp-spreg.h spreg.h
#	${MIC} tmp-spreg.c spreg.c
#	touch run-dgen
#
#dgen: ${DGENOBJS}
#	${HOST_LINK.c} ${DGENOBJS} -o ${.TARGET}

# hw.c / hw.h portion
HWSRCS=	hw_cpu.c hw_memory.c hw_nvram.c hw_iobus.c hw_htab.c hw_disk.c \
	hw_trace.c hw_register.c hw_vm.c hw_init.c hw_core.c hw_pal.c \
	hw_com.c hw_eeprom.c hw_opic.c hw_glue.c hw_phb.c hw_ide.c

hw.h hw.c: run-hw
run-hw: Makefile
	f=""; \
	for i in ${HWSRCS}; do \
		case " $$f " in \
			*" $$i "*) ;; \
			*) f="$$f $$i" ;; \
		esac ; \
	done ; \
	for hw in $$f; do \
		echo $$hw; \
	done | ${TOOL_SED} -e 's/^.*\(hw_.*\)\.c/\1/' \
		   -e 's/^/extern const device_descriptor /' \
		   -e 's/$$/_device_descriptor\[\];/' \
			> tmp-hw.h
	f=""; \
	for i in ${HWSRCS}; do \
		case " $$f " in \
			*" $$i "*) ;; \
			*) f="$$f $$i" ;; \
		esac ; \
	done ; \
	for hw in $$f; do \
		echo $$hw; \
	done | ${TOOL_SED} -e 's/^.*\(hw_.*\)\.c/\1/' \
		   -e 's/^/    /' \
		   -e 's/$$/_device_descriptor,/' > tmp-hw.c
	${MIC} tmp-hw.h hw.h
	${MIC} tmp-hw.c hw.c
	touch run-hw
DPSRCS+= hw.h

# package portion
PACKAGE_SRC =	pk_disklabel.c
PK_H = 		pk.h

${PK_H}: run-pk
run-pk: $(PACKAGE_SRC)
	f=""; \
	for i in $(PACKAGE_SRC) ; do \
		case " $$f " in \
			*" $$i "*) ;; \
			*) f="$$f $$i" ;; \
		esac ; \
	done ; \
	for pk in $$f; do \
		echo $$pk; \
	done | ${TOOL_SED} -e 's/^.*pk_\(.*\)\.c/\1/' \
		   -e 's/^/extern package_create_instance_callback pk_/' \
		   -e 's/$$/_create_instance;/' > tmp-pk.h
	${MIC} tmp-pk.h pk.h
	touch run-pk
DPSRCS+= ${PK_H}

# defines portion
DEFINES_H=	defines.h
${DEFINES_H}: run-defines
run-defines:
	${TOOL_SED} -n -e '/^#define HAVE_/s/ 1$$/",/' \
	       -e '/^#define HAVE_/s//"HAVE_/p' \
	       < ${.CURDIR}/arch/${GDB_MACHINE_ARCH}/config.h > tmp-defines.h
	${MIC} tmp-defines.h defines.h
	touch run-defines
DPSRCS+= ${DEFINES_H}

# misc. dependencies.
#filter_host.lo: ppc-config.h

#ppc-config.h: ${DIST}/sim/ppc/std-config.h
#	cp -f ${.ALLSRC} ${.TARGET}
#DPSRCS+= ppc-config.h

CLEANFILES+=	igen dgen gentmap *.lo \
		ppc-config.h \
		tmp-icache.h icache.h \
		tmp-icache.c icache.c \
		tmp-idecode.h idecode.h \
		tmp-idecode.c idecode.c \
		tmp-semantics.h semantics.h \
		tmp-semantics.c semantics.c \
		tmp-itable.h itable.h \
		tmp-itable.c itable.c \
		tmp-model.h model.h \
		tmp-model.c model.c \
		tmp-support.h support.h \
		tmp-support.c support.c \
		tmp-spreg.h spreg.h \
		tmp-spreg.c spreg.c \
		tmp-vals.h targ-vals.h \
		hw.c hw.h \
		defines.h pk.h \
		targ-map.c targ-vals.def \
		run-defines run-dgen run-hw run-igen run-pk

.SUFFIXES: .lo
.c.lo:
	${HOST_COMPILE.c} -o ${.TARGET} $<

.PATH: ${DIST}/sim/ppc ${DIST}/sim/common ${DIST}/sim/igen

.include <bsd.lib.mk>
.include "../../Makefile.inc"
