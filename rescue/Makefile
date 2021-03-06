#	$NetBSD: Makefile,v 1.42 2020/04/04 17:57:16 christos Exp $

NOLIBCSANITIZER=	# defined
NOSANITIZER=		# defined

.include <bsd.own.mk>
.include "${NETBSDSRCDIR}/distrib/common/Makefile.distrib"

WARNS=		1
# XXX
.if ${MACHINE_ARCH} != "m68000"
DBG+=		-Os
.endif

CRUNCHGEN_FLAGS+=-V DBG="${DBG}"

.if ${MKSTATICPIE:Uno} == "yes"
CFLAGS+=-fPIE
CRUNCHGEN_FLAGS+=-V LDSTATIC="-static -pie"
.else
CRUNCHGEN_FLAGS+=-V LDSTATIC="-static" -V NOPIE=
.endif

CRUNCHGEN_FLAGS+=-V NOLIBCSANITIZER= -V NOSANITIZER= -V NOMAN=

RESCUEDIR=	/rescue
CRUNCHBIN=	rescue
CRUNCHENV=	RESCUEDIR=${RESCUEDIR}
SMALLPROG=	0
LISTS=		${.CURDIR}/list
TARGETDIR=	${DESTDIR}/rescue
PARSELISTENV+=  TARGETDIR=${TARGETDIR:Q}

.for f in pdisk
PROG_${f}!=	cd ${NETBSDSRCDIR}/external/bsd/${f}/bin && ${MAKE} -V PROG
.if (${PROG_${f}} != "")
LISTS+=		${.CURDIR}/list.${f}
.endif
.endfor

.if ${USE_INET6} != "no"
LISTS+=		${.CURDIR}/list.inet6
.endif

LISTS+=		${.CURDIR}/list.crypto
CRUNCHENV+=	MKKERBEROS=no		# for ssh

LISTS+=		${.CURDIR}/list.ldd
LDD_ELF32DIR!=	cd ${NETBSDSRCDIR}/usr.bin/ldd/elf32 && ${PRINTOBJDIR}
LDD_ELF64DIR!=	cd ${NETBSDSRCDIR}/usr.bin/ldd/elf64 && ${PRINTOBJDIR}
PARSELISTENV+=	LDD_ELF32DIR=${LDD_ELF32DIR} LDD_ELF64DIR=${LDD_ELF64DIR}

#	Specially built objects to override the behaviour of
#	various library functions
#

OVERRIDEOBJS=	rcmd.o
.PATH:	${NETBSDSRCDIR}/lib/libc/net
CPPFLAGS.rcmd.c+=-I${NETBSDSRCDIR}/lib/libc/include -DRESCUEDIR=\"${RESCUEDIR}\"

LIBOVERRIDE=	liboverride.o
${LIBOVERRIDE}: ${OVERRIDEOBJS}
	${_MKTARGET_LINK}
	${LD} -r -o $@ ${OVERRIDEOBJS}

CLEANFILES+=	${OVERRIDEOBJS} ${LIBOVERRIDE}

${CRUNCHBIN}:	${LIBOVERRIDE}


#	The primary target ...
#

CLEANFILES+=	rescue.unstripped

.include "${DISTRIBDIR}/common/Makefile.crunch"

realall: ${CRUNCHBIN}

install: ${CRUNCHBIN}
# XXX this MKMSG doesn't line up
	${_MKMSG} "populate ${TARGETDIR}"
	${PARSELIST} -v mode=install ${LISTS} | ${MAKE} -f - install

.include <bsd.prog.mk>
