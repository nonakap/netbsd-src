# $NetBSD: Makefile,v 1.18 2024/11/30 01:04:14 christos Exp $

INCSDIR= /usr/include/sbmips

# XXXcgd need local: pci_machdep.h
# XXXcgd need export: intr.h

INCS=	ansi.h asm.h \
	bswap.h \
	cdefs.h cpu.h \
	disklabel.h \
	ecoff_machdep.h elf_machdep.h endian.h endian_machdep.h \
	fenv.h float.h \
	ieee.h ieeefp.h \
	int_const.h int_fmtio.h int_limits.h int_mwgwtypes.h int_types.h \
	kcore.h kdbparam.h \
	limits.h lock.h locore.h lwp_private.h \
	math.h mcontext.h mips_opcode.h mutex.h \
	param.h pcb.h pmap.h proc.h profile.h psl.h pte.h ptrace.h \
	reg.h regdef.h regnum.h reloc.h rwlock.h \
	setjmp.h signal.h sljit_machdep.h \
	trap.h types.h \
	vmparam.h \
	wchar_limits.h

.include <bsd.kinc.mk>
