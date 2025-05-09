#	$NetBSD: Makefile,v 1.56 2024/08/31 10:43:43 rin Exp $

.include <bsd.hostinit.mk>

MODULE=		gdb
GDBDIR=		${.CURDIR}/../../external/gpl3/${EXTERNAL_GDB_SUBDIR}
GNUHOSTDIST=    ${GDBDIR}/dist

FIND_ARGS=	\! \( -type d -name sim -prune \)

CONFIGURE_ARGS=	--target=${MACHINE_GNU_PLATFORM} --disable-nls \
		--program-transform-name="s,^,${MACHINE_GNU_PLATFORM}-," \
		--with-zstd=no \
		--with-mpfr=${TOOLDIR} \
		--with-mpc=${TOOLDIR} \
		--with-gmp=${TOOLDIR}

.if ${MACHINE} == "ia64"
CONFIGURE_ARGS+=--enable-obsolete
.endif

# XXX
# Unfortunately, our in-tree makeinfo(1) (latest GPLv2 release) is
# too old to generate *.info. Use external tool from pkgsrc.
EXTERN_MAKEINFO?=	/usr/pkg/bin/makeinfo
MAKEINFOFLAGS?=		--no-split

MAKE_ARGS=	MACHINE=

ALL_TARGET=	all-gdb
INSTALL_TARGET=	install-gdb

.include "${GDBDIR}/Makefile.gdb_arch"
#GDB_MACHINE_ARCH=       ${MACHINE_ARCH:C/e?armv[4-7]h?f?/arm/}

.include "${.CURDIR}/../Makefile.gmakehost"
BUILD_MAKE=${TOOL_GMAKE}

BINENV=		/usr/bin/env -i

.include "${.CURDIR}/../gcc/lgpl3.mk"

MKNATIVE_ENV=	${BINENV} ${CONFIGURE_ENV:NC*:NLD*:Nam_cv_func_iconv*} \
			CC_FOR_BUILD=${HOST_CC:Q} \
			CXX_FOR_BUILD=${HOST_CXX:Q} \
			CFLAGS_FOR_BUILD="-I${TOOLDIR}/include" \
			CC=${CC:Q}' '${CCADDFLAGS:Q} \
			CXX=${CXX:Q}' '${CCADDFLAGS:Q}' '${CXXADDFLAGS:Q} \
			CPP=${CPP:Q}' '-I${DESTDIR}/usr/include \
			CFLAGS= CPPFLAGS= \
			CXXFLAGS= LDFLAGS='-L${GMPOBJ} -L${MPFROBJ} -L${MPCOBJ}'\
			AS=${AS:Q} AWK=${TOOL_AWK:Q} LD=${LD:Q} \
			MSGFMT=${TOOLDIR}/bin/${_TOOL_PREFIX}msgfmt \
			NM=${NM:Q} OBJDUMP=${OBJDUMP:Q} \
			XGETTEXT=${TOOLDIR}/bin/${_TOOL_PREFIX}xgettext \
			LIBS=-lintl \
			MAKEINFO=${EXTERN_MAKEINFO} \
			MAKEINFOFLAGS=${MAKEINFOFLAGS} \
			${MKNATIVE_CONFIGURE_PRESET}

MKENV_BUILD_MAKE=${MKNATIVE_ENV} ${BUILD_MAKE}

CCADDFLAGS+= --sysroot=${DESTDIR} -B${DESTDIR}/usr/lib/ \
		-I${.OBJDIR}/.native/include \
		-I${.OBJDIR}/.native/gcc/include
LDADDFLAGS+= -L${DESTDIR}/lib -L${DESTDIR}/usr/lib
CXXADDFLAGS+= -D__STDC_FORMAT_MACROS
CXXADDFLAGS+= -D__STDC_LIMIT_MACROS
CXXADDFLAGS+= -D__STDC_CONSTANT_MACROS
HOST_CXXFLAGS+= ${CXXADDFLAGS}
# Since we are using gmake -e the environment overwrites CPPFLAGS
# so we overwrite it again here! (see Makefile.gnuhost)
HOST_CPPFLAGS+= -I${TOOLDIR}/include

NEWCONFIGDIR?=	${.CURDIR}/../..
MKNATIVE?=	${.CURDIR}/mknative-gdb

# Some configure tests require running a test program, which is not
# possible when cross-building.  Provide configure with "cached"
# values in the environment.
MKNATIVE_CONFIGURE_PRESET= \
	ac_cv_prog_cc_cross=yes \
	ac_cv_func_fork_works=yes \
	ac_cv_func_sigprocmask=yes \
	ac_cv_func_strcoll_works=yes \
	ac_cv_func_XML_StopParser=yes \
	ac_cv_libexpat=yes \
	bash_cv_func_ctype_nonascii=yes \
	bash_cv_func_sigsetjmp=present \
	bash_cv_func_strcoll_broken=no \
	bash_cv_must_reinstall_sighandlers=no \
	gl_cv_func_rename_slash_dst_works=yes \
	gl_cv_func_rename_slash_src_works=yes \
	gl_cv_func_rename_link_works=yes \
	gl_cv_func_rename_dest_works=yes

CONFIGURE_ENV+=	am_cv_func_iconv=no

# Recent versions of Solaris have ncurses, but they hide the lib in an
# odd directory. Prevent configure from finding the ncurses headers,
# Solaris curses is sufficient.
.if ${BUILD_OSTYPE} == "SunOS"
CONFIGURE_ENV+=	ac_cv_header_ncurses_h=no \
		ac_cv_header_ncurses_ncurses_h=no \
		ac_cv_header_ncurses_term_h=no
.endif

# Disable sim unless it's known to work (configure's default is to
# enable sim if supported).
CONFIGURE_ARGS_SIM=
#.if \
#    ${MACHINE_CPU} != "powerpc" && \
#    ${MACHINE_CPU} != "powerpc64"
CONFIGURE_ARGS_SIM+= --disable-sim
#.endif

CONFIGURE_ARGS_GDBSERVER=
.if ${MKGDBSERVER} != "no"
CONFIGURE_ARGS_GDBSERVER+= --enable-gdbserver
.endif


native-gdb: .native/.configure_done
	@echo 'Extracting GDB configury for a native toolchain.'
	MAKE=${BUILD_MAKE:Q} ${HOST_SH} ${MKNATIVE} gdb \
		${.OBJDIR}/.native ${NEWCONFIGDIR} ${MACHINE_GNU_PLATFORM} \
		${GDB_MACHINE_ARCH}

.native/.configure_done: ${_GNU_CFGSRC} ${.CURDIR}/Makefile
	mkdir -p ${.OBJDIR}/.native/include
	# we need to make a copy because ${GMPINC} has a config.h
	cp -p ${GMPINC}/gmp.h ${.OBJDIR}/.native/include
	# copy the rest because using --with-foo=${TOOLDIR} breaks with
	# static linking because it picks the tools version of the libraries
	cp -p ${MPFRINC}/mpfr.h ${.OBJDIR}/.native/include
	cp -p ${MPFRINC}/mpf2mpfr.h ${.OBJDIR}/.native/include
	cp -p ${MPCINC}/mpc.h ${.OBJDIR}/.native/include
	PATH=${TOOLDIR}/bin:$$PATH; export PATH; \
		(cd ${.OBJDIR}/.native && \
			${MKNATIVE_ENV} ${HOST_SH} ${GNUHOSTDIST}/configure \
			--prefix=/usr \
			--with-separate-debug-dir=/usr/libdata/debug \
			--with-zstd=no \
			${CONFIGURE_ARGS_SIM} \
			${CONFIGURE_ARGS_GDBSERVER} \
			--build=`${GNUHOSTDIST}/config.guess` \
			--host=${MACHINE_GNU_PLATFORM} \
			--target=${MACHINE_GNU_PLATFORM})
	PATH=${TOOLDIR}/bin:$$PATH; export PATH; \
		(cd ${.OBJDIR}/.native && \
			${MKENV_BUILD_MAKE} configure-host) && \
		(cd ${.OBJDIR}/.native/bfd && \
			${MKENV_BUILD_MAKE} bfd.h bfdver.h) && \
		(cd ${.OBJDIR}/.native/gdb && \
			${MKENV_BUILD_MAKE} xml-builtin.c init.c version.c) && \
		(cd ${.OBJDIR}/.native/libbacktrace && \
			${MKENV_BUILD_MAKE} backtrace-supported.h) && \
		(if [ -d ${.OBJDIR}/.native/gdbserver ]; then \
			cd ${.OBJDIR}/.native/gdbserver && \
			${MKENV_BUILD_MAKE} version-generated.cc; fi) && \
		(cd ${.OBJDIR}/.native/gdb/doc && \
			${MKENV_BUILD_MAKE} NetBSD_DISABLED_info)
	@touch $@

clean: clean.native
clean.native:
	-rm -r -f .native
