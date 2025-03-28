#	$NetBSD: bsd.sys.mk,v 1.317 2025/01/13 15:40:18 riastradh Exp $
#
# Build definitions used for NetBSD source tree builds.

.if !defined(_BSD_SYS_MK_)
_BSD_SYS_MK_=1

.if !empty(.INCLUDEDFROMFILE:MMakefile*)
error1:
	@(echo "bsd.sys.mk should not be included from Makefiles" >& 2; exit 1)
.endif
.if !defined(_BSD_OWN_MK_)
error2:
	@(echo "bsd.own.mk must be included before bsd.sys.mk" >& 2; exit 1)
.endif

# XXX: LLVM does not support -iremap and -fdebug-*
.if ${MKREPRO:Uno} == "yes" && ${MKLLVM:Uno} != "yes"
.export NETBSDSRCDIR DESTDIR X11SRCDIR

.if !empty(DESTDIR)
CPPFLAGS+=	-Wp,-iremap,${DESTDIR}:
REPROFLAGS+=	-fdebug-prefix-map=\$$DESTDIR=
REPROFLAGS+=	-fmacro-prefix-map=\$$DESTDIR=
.endif

CPPFLAGS+=	-Wp,-fno-canonical-system-headers
CPPFLAGS+=	-Wp,-iremap,${NETBSDSRCDIR}:/usr/src
CPPFLAGS+=	-Wp,-iremap,${X11SRCDIR}:/usr/xsrc

REPROFLAGS+=	-fdebug-prefix-map=\$$NETBSDSRCDIR=/usr/src
REPROFLAGS+=	-fmacro-prefix-map=\$$NETBSDSRCDIR=/usr/src
REPROFLAGS+=	-fdebug-prefix-map=\$$X11SRCDIR=/usr/xsrc
REPROFLAGS+=	-fmacro-prefix-map=\$$X11SRCDIR=/usr/xsrc
.if defined(MAKEOBJDIRPREFIX)
NETBSDOBJDIR=	${MAKEOBJDIRPREFIX}${NETBSDSRCDIR}
.endif

.if defined(NETBSDOBJDIR)
.export NETBSDOBJDIR
REPROFLAGS+=	-fdebug-prefix-map=\$$NETBSDOBJDIR=/usr/obj
REPROFLAGS+=	-fmacro-prefix-map=\$$NETBSDOBJDIR=/usr/obj
.endif

LINTFLAGS+=	-R${NETBSDSRCDIR}=/usr/src -R${X11SRCDIR}=/usr/xsrc
LINTFLAGS+=	-R${DESTDIR}=

# XXX: Cannot handle MAKEOBJDIR, yet.
REPROFLAGS+=	-fdebug-regex-map='/usr/src/(.*)/obj$$=/usr/obj/\1'
REPROFLAGS+=	-fdebug-regex-map='/usr/src/(.*)/obj/(.*)=/usr/obj/\1/\2'
REPROFLAGS+=	-fdebug-regex-map='/usr/src/(.*)/obj\..*=/usr/obj/\1'
REPROFLAGS+=	-fdebug-regex-map='/usr/src/(.*)/obj\..*/(.*)=/usr/obj/\1/\2'

CFLAGS+=	${REPROFLAGS}
CXXFLAGS+=	${REPROFLAGS}
.endif

# NetBSD sources use C99 style, with some GCC extensions.
# Coverity does not like -std=gnu99 (XXX untested but likely not gnu11 either)
#
# XXX Ideally we would not rely on GNU extensions, but currently some
# code uses alloca(3) which -std=c11 compiles broken-at-runtime.  Until
# we fix that (PR toolchain/58969: use of alloca is warning, not error,
# with -std=c11), we have to continue using -std=gnu11 and not
# -std=c11.
.if !defined(COVERITY_TOP_CONFIG) && empty(CFLAGS:M*-std=*)
CFLAGS+=	${${ACTIVE_CC} == "clang":? -std=gnu11 :}
CFLAGS+=	${${ACTIVE_CC} == "gcc":? -std=gnu11 :}
CFLAGS+=	${${ACTIVE_CC} == "pcc":? -std=gnu11 :}
.endif

.if defined(WARNS)
CFLAGS+=	${${ACTIVE_CC} == "clang":? -Wno-sign-compare -Wno-pointer-sign :}
.if ${WARNS} > 0
CFLAGS+=	-Wall -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith
#CFLAGS+=	-Wmissing-declarations -Wredundant-decls -Wnested-externs
# Add -Wno-sign-compare.  -Wsign-compare is included in -Wall as of GCC 3.3,
# but our sources aren't up for it yet. Also, add -Wno-traditional because
# gcc includes #elif in the warnings, which is 'this code will not compile
# in a traditional environment' warning, as opposed to 'this code behaves
# differently in traditional and ansi environments' which is the warning
# we wanted, and now we don't get anymore.
CFLAGS+=	-Wno-sign-compare
# Don't suppress warnings coming from constructs in system headers.
# Our system headers should be clean and we want to warn about things like:
# isdigit((char)1)
CFLAGS+=	${${ACTIVE_CC} == "gcc" :? -Wsystem-headers :}
CFLAGS+=	${${ACTIVE_CC} == "gcc" :? -Wno-traditional :}
.if !defined(NOGCCERROR)
# Set assembler warnings to be fatal
CFLAGS+=	${${ACTIVE_CC} == "gcc" :? -Wa,--fatal-warnings :}
.endif

# Set linker warnings to be fatal
# XXX no proper way to avoid "FOO is a patented algorithm" warnings
# XXX on linking static libs
.if (!defined(MKPIC) || ${MKPIC} != "no") && \
    (!defined(LDSTATIC) || ${LDSTATIC} != "-static")
# XXX there are some strange problems not yet resolved
. if !defined(HAVE_GCC) || defined(HAVE_LLVM)
LDFLAGS+=	-Wl,--fatal-warnings
. endif
.endif
.endif

LDFLAGS+=	-Wl,--warn-shared-textrel

.if ${WARNS} > 1
CFLAGS+=	-Wreturn-type -Wswitch -Wshadow
.endif
.if ${WARNS} > 2
CFLAGS+=	-Wcast-qual -Wwrite-strings
CFLAGS+=	-Wextra -Wno-unused-parameter
# Readd -Wno-sign-compare to override -Wextra with clang
CFLAGS+=	-Wno-sign-compare
.if "${ACTIVE_CC}" == "gcc" && ${HAVE_GCC} < 8
#  XXX: Won't warn about anything.  -Wabi warns about differences from
#  the most up-to-date ABI, which in g++ 8 is used by default.
CXXFLAGS+=	-Wabi
.endif
CXXFLAGS+=	-Wold-style-cast
CXXFLAGS+=	-Wctor-dtor-privacy -Wnon-virtual-dtor -Wreorder \
		-Wno-deprecated -Woverloaded-virtual -Wsign-promo -Wsynth
CXXFLAGS+=	${${ACTIVE_CXX} == "gcc":? -Wno-non-template-friend -Wno-pmf-conversions :}
.endif
.if ${WARNS} > 3 && (defined(HAVE_GCC) || defined(HAVE_LLVM))
.if ${WARNS} > 4
CFLAGS+=	-Wold-style-definition
.endif
.if ${WARNS} > 5
CFLAGS+=	-Wconversion
.endif
CFLAGS+=	-Wsign-compare -Wformat=2
CFLAGS+=	${${ACTIVE_CC} == "gcc":? -Wno-format-zero-length :}
.endif
.if ${WARNS} > 3 && defined(HAVE_LLVM)
CFLAGS+=	${${ACTIVE_CC} == "clang":? -Wpointer-sign -Wmissing-noreturn :}
.endif
.if (defined(HAVE_GCC) \
     && (${MACHINE_ARCH} == "coldfire" || \
	 ${MACHINE_CPU} == "sh3" || \
	 ${MACHINE_CPU} == "m68k"))
# XXX GCC 4.5 for sh3 and m68k (which we compile with -Os) is extra noisy for
# cases it should be better with
CFLAGS+=	-Wno-uninitialized
CFLAGS+=	-Wno-maybe-uninitialized
.endif
.endif

.if ${MKRELRO:Uno} != "no"
LDFLAGS+=	-Wl,-z,relro
.endif

.if ${MKRELRO:Uno} == "full" && ${NOFULLRELRO:Uno} == "no"
LDFLAGS+=	-Wl,-z,now
.endif

.if ${MKSANITIZER:Uno} == "yes"
SANITIZERFLAGS:=	-fsanitize=${USE_SANITIZER} ${SANITIZERFLAGS}
.else
SANITIZERFLAGS=		# empty
.endif

.if ${MKLIBCSANITIZER:Uno} == "yes"
LIBCSANITIZERFLAGS:=	-fsanitize=${USE_LIBCSANITIZER} ${LIBCSANITIZERFLAGS}
LIBCSANITIZERFLAGS+=	-fno-sanitize=vptr	# Unsupported in micro-UBSan
.else
LIBCSANITIZERFLAGS=	# empty
.endif

CWARNFLAGS+=	${CWARNFLAGS.${ACTIVE_CC}}

CPPFLAGS+=	${AUDIT:D-D__AUDIT__}
_NOWERROR=	${defined(NOGCCERROR) || (${ACTIVE_CC} == "clang" && defined(NOCLANGERROR)):?yes:no}
CFLAGS+=	${${_NOWERROR} == "no" :?-Werror:} ${CWARNFLAGS}
.if !empty(DESTDIR)
LINTFLAGS+=	-d ${DESTDIR}
.endif

.if !defined(NOSSP) && (${USE_SSP:Uno} != "no") && (${BINDIR:Ux} != "/usr/mdec")
.   if !defined(KERNSRCDIR) && !defined(KERN) # not for kernels / kern modules
CPPFLAGS+=	-D_FORTIFY_SOURCE=2
.   endif
.   if !defined(COVERITY_TOP_CONFIG)
COPTS+=	-fstack-protector -Wstack-protector 

# GCC 4.8 on m68k erroneously does not protect functions with
# variables needing special alignment, see
#	http://gcc.gnu.org/bugzilla/show_bug.cgi?id=59674
# (the underlying issue for sh and vax may be different, needs more
# investigation, symptoms are similar but for different sources)
# also true for GCC 5, assume GCC 6 too.
.	if "${ACTIVE_CC}" == "gcc" && \
     ( ${HAVE_GCC} == "5" || \
       ${HAVE_GCC} == "6" ) && \
     ( ${MACHINE_CPU} == "sh3" || \
       ${MACHINE_ARCH} == "vax" || \
       ${MACHINE_CPU} == "m68k" || \
       ${MACHINE_CPU} == "or1k" )
COPTS+=	-Wno-error=stack-protector 
.	endif

COPTS+=	${${ACTIVE_CC} == "clang":? --param ssp-buffer-size=1 :}
COPTS+=	${${ACTIVE_CC} == "gcc":? --param ssp-buffer-size=1 :}
.   endif
.endif

.if ${MKSOFTFLOAT:Uno} != "no"
# sh3 defaults to soft-float and specifies hard-float a different way
.if ${MACHINE_CPU} != "sh3"
COPTS+=		${${ACTIVE_CC} == "gcc":? -msoft-float :}
FOPTS+=		-msoft-float
.endif
.elif ${MACHINE_ARCH} == "coldfire"
COPTS+=		-mhard-float
FOPTS+=		-mhard-float
.endif

#.if !empty(MACHINE_ARCH:Mearmv7*)
#COPTS+=		-mthumb
#FOPTS+=		-mthumb
#.endif

.if ${MKIEEEFP:Uno} != "no"
.if ${MACHINE_ARCH} == "alpha"
CFLAGS+=	-mieee
FFLAGS+=	-mieee
.endif
.endif

.if ${MACHINE} == "sparc64" && ${MACHINE_ARCH} == "sparc"
CFLAGS+=	-Wa,-Av8plus
.endif

.if !defined(NOGCCERROR)
.if ${MACHINE_MIPS64}
CPUFLAGS+=	-Wa,--fatal-warnings
.endif
.endif

#.if ${MACHINE} == "sbmips"
#CFLAGS+=	-mips64 -mtune=sb1
#.endif

#.if ${MACHINE_MIPS64} && defined(MKPIC) && ${MKPIC} == "no"
#CPUFLAGS+=	-mno-abicalls -fno-PIC
#.endif
CFLAGS+=	${CPUFLAGS}
AFLAGS+=	${CPUFLAGS}

.if ${KCOV:U0} > 0
KCOVFLAGS=	-fsanitize-coverage=trace-pc,trace-cmp
.for f in subr_kcov.c subr_asan.c subr_csan.c subr_msan.c ubsan.c
KCOVFLAGS.${f}=		# empty
.endfor
CFLAGS+=	${KCOVFLAGS.${.IMPSRC:T}:U${KCOVFLAGS}}
.endif

.if !defined(NOPIE) && (!defined(LDSTATIC) || ${LDSTATIC} != "-static")
# Position Independent Executable flags
PIE_CFLAGS?=        -fPIE
PIE_LDFLAGS?=       -pie ${${ACTIVE_CC} == "gcc":? -shared-libgcc :}
PIE_AFLAGS?=	    -fPIE
.endif

ARM_ELF2AOUT?=	elf2aout
M68K_ELF2AOUT?=	elf2aout
MIPS_ELF2ECOFF?=	elf2ecoff
MKDEP?=		mkdep
MKDEPCXX?=	mkdep
OBJCOPY?=	objcopy
OBJDUMP?=	objdump
PAXCTL?=	paxctl
STRIP?=		strip

.SUFFIXES:	.o .ln .lo .c .cc .cpp .cxx .C .m ${YHEADER:D.h}

# C
.c.o:
	${_MKTARGET_COMPILE}
	${COMPILE.c} ${COPTS.${.IMPSRC:T}} ${CPUFLAGS.${.IMPSRC:T}} ${CPPFLAGS.${.IMPSRC:T}} ${.IMPSRC} ${OBJECT_TARGET}
	${CTFCONVERT_RUN}

.c.ln:
	${_MKTARGET_COMPILE}
	${LINT} ${LINTFLAGS} ${LINTFLAGS.${.IMPSRC:T}} \
	    ${CPPFLAGS:C/-([IDUW])[  ]*/-\1/Wg:M-[IDUW]*} \
	    ${CPPFLAGS.${.IMPSRC:T}:C/-([IDUW])[  ]*/-\1/Wg:M-[IDUW]*} \
	    -i ${.IMPSRC}

# C++
.cc.o .cpp.o .cxx.o .C.o:
	${_MKTARGET_COMPILE}
	${COMPILE.cc} ${COPTS.${.IMPSRC:T}} ${CPUFLAGS.${.IMPSRC:T}} ${CPPFLAGS.${.IMPSRC:T}} ${.IMPSRC}

# Objective C
# (Defined here rather than in <sys.mk> because `.m' is not just
#  used for Objective C source)
.m.o:
	${_MKTARGET_COMPILE}
	${COMPILE.m} ${OBJCOPTS} ${OBJCOPTS.${.IMPSRC:T}} ${.IMPSRC} ${OBJECT_TARGET}
	${CTFCONVERT_RUN}

# Host-compiled C objects
# The intermediate step is necessary for Sun CC, which objects to calling
# object files anything but *.o
.c.lo:
	${_MKTARGET_COMPILE}
	${HOST_COMPILE.c} -o ${.TARGET}.o ${COPTS.${.IMPSRC:T}} ${CPUFLAGS.${.IMPSRC:T}} ${CPPFLAGS.${.IMPSRC:T}} ${.IMPSRC}
	${MV} ${.TARGET}.o ${.TARGET}

# C++
.cc.lo .cpp.lo .cxx.lo .C.lo:
	${_MKTARGET_COMPILE}
	${HOST_COMPILE.cc} -o ${.TARGET}.o ${COPTS.${.IMPSRC:T}} ${CPUFLAGS.${.IMPSRC:T}} ${CPPFLAGS.${.IMPSRC:T}} ${.IMPSRC}
	${MV} ${.TARGET}.o ${.TARGET}

# Assembly
.s.o:
	${_MKTARGET_COMPILE}
	${COMPILE.s} ${COPTS.${.IMPSRC:T}} ${CPUFLAGS.${.IMPSRC:T}} ${CPPFLAGS.${.IMPSRC:T}} ${.IMPSRC} ${OBJECT_TARGET}
	${CTFCONVERT_RUN}

.S.o:
	${_MKTARGET_COMPILE}
	${COMPILE.S} ${COPTS.${.IMPSRC:T}} ${CPUFLAGS.${.IMPSRC:T}} ${CPPFLAGS.${.IMPSRC:T}} ${.IMPSRC} ${OBJECT_TARGET}
	${CTFCONVERT_RUN}

# Lex
LFLAGS+=	${LPREFIX.${.IMPSRC:T}:D-P${LPREFIX.${.IMPSRC:T}}}
LFLAGS+=	${LPREFIX:D-P${LPREFIX}} ${LFLAGS.${.IMPSRC:T}}

.l.c:
	${_MKTARGET_LEX}
	${LEX.l} -o${.TARGET} ${.IMPSRC}

# Yacc
YFLAGS+=	${YPREFIX.${.IMPSRC:T}:D-p${YPREFIX.${.IMPSRC:T}}} ${YHEADER.${.IMPSRC:T}:D-d}
YFLAGS+=	${YPREFIX:D-p${YPREFIX}} ${YHEADER:D-d} ${YFLAGS.${.IMPSRC:T}}

.y.c:
	${_MKTARGET_YACC}
	${YACC.y} -o ${.TARGET} ${.IMPSRC}

.ifdef YHEADER
.if empty(.MAKEFLAGS:M-n)
.y.h: ${.TARGET:.h=.c}
.endif
.endif

# Objcopy
.if ${MACHINE_ARCH} == aarch64eb
# AARCH64 big endian needs to preserve $x/$d symbols for the linker.
OBJCOPYLIBFLAGS_EXTRA=-w -K '[$$][dx]' -K '[$$][dx]\.*'
.elif ${MACHINE_CPU} == "arm"
# ARM big endian needs to preserve $a/$d/$t symbols for the linker.
OBJCOPYLIBFLAGS_EXTRA=-w -K '[$$][adt]' -K '[$$][adt]\.*'
.endif

.if ${MKSTRIPSYM} != "no"
OBJCOPYLIBFLAGS?=${"${.TARGET:M*.po}" != "":?-X:-x} ${OBJCOPYLIBFLAGS_EXTRA}
.else
OBJCOPYLIBFLAGS?=-X ${OBJCOPYLIBFLAGS_EXTRA}
.endif

.endif	# !defined(_BSD_SYS_MK_)
