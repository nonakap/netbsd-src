#	$NetBSD: Makefile,v 1.128 2025/01/19 10:57:10 rillig Exp $
#	@(#)Makefile	5.2 (Berkeley) 12/28/90

PROG=	make
SRCS=	arch.c
SRCS+=  buf.c
SRCS+=  compat.c
SRCS+=  cond.c
SRCS+=  dir.c
SRCS+=  for.c
SRCS+=  hash.c
SRCS+=  job.c
SRCS+=  lst.c
SRCS+=  main.c
SRCS+=	make.c
SRCS+=  make_malloc.c
SRCS+=  metachar.c
SRCS+=  parse.c
SRCS+=	str.c
SRCS+=  suff.c
SRCS+=  targ.c
SRCS+=  trace.c
SRCS+=  var.c
SRCS+=  util.c
WARNS=	6

# Whether to generate a coverage report after running the tests.
USE_COVERAGE?=	no		# works only with gcc; clang9 fails to link
.if ${USE_COVERAGE} == "yes"
GCOV?=		gcov
CPPFLAGS+=	-DFORK_FUNCTION=fork
COPTS+=		--coverage -O0 -ggdb
GCOV_PERL=	if (/^File '(?:.*\/)?(\S+)'/) {
GCOV_PERL+=		$$file = $$1; $$func = "";
GCOV_PERL+=	} elsif (/^Function '(\S+)'/) {
GCOV_PERL+=		$$func = $$1;
GCOV_PERL+=	} elsif (/^Lines executed:(\d+\.\d+)% of (\d+)/ && defined($$file)) {
GCOV_PERL+=		my ($$percent, $$lines) = ($$1, $$2);
GCOV_PERL+=		my $$uncovered =
GCOV_PERL+=		    $$percent eq '100.00' ? '0'
GCOV_PERL+=		    : $$file =~ /\.h$$/ ? '?'
GCOV_PERL+=		    : `grep -c '\#\#\#\#\#:' < \$$(basename $$file.gcov)`;
GCOV_PERL+=		chomp($$uncovered);
GCOV_PERL+=		printf("%7.2f  %4s/%4d  %s%s\n",
GCOV_PERL+=		    $$percent, $$uncovered, $$lines, $$file, $$func);
GCOV_PERL+=		$$file = undef;
GCOV_PERL+=	}
LDADD+=		--coverage
.endif
CLEANFILES+=	*.gcda *.gcno *.gcov

# Whether to compile using the Undefined Behavior Sanitizer (GCC, Clang).
USE_UBSAN?=	no
.if ${USE_UBSAN} == "yes"
COPTS+=		-fsanitize=undefined
LDADD+=		-fsanitize=undefined
.endif

USE_META?=	yes
.if ${USE_META:tl} != "no"

SRCS+=		meta.c
CPPFLAGS+=	-DUSE_META

USE_FILEMON?=	ktrace
.  if ${USE_FILEMON:tl} != "no"

.PATH:	${.CURDIR}/filemon
SRCS+=		filemon_${USE_FILEMON}.c
CPPFLAGS+=	-DUSE_FILEMON
CPPFLAGS+=	-DUSE_FILEMON_${USE_FILEMON:tu}

.    if ${USE_FILEMON} == "dev"
FILEMON_H?=	/usr/include/dev/filemon/filemon.h
.      if exists(${FILEMON_H}) && ${FILEMON_H:T} == "filemon.h"
COPTS.filemon_dev.c+= \
		-DHAVE_FILEMON_H -I${FILEMON_H:H}
.      endif
.    endif
.  endif
.endif

SUBDIR.roff+=	PSD.doc
.if make(obj) || make(clean) || make(cleandir)
SUBDIR+=	unit-tests
.endif

LINTFLAGS+=	-T	# strict bool mode, available since 2021-01-11
LINTFLAGS+=	-w	# treat warnings as errors
CLEANFILES+=	*.o	# for filemon objects

COPTS.arch.c+=	${CC_WNO_FORMAT_TRUNCATION}
COPTS.dir.c+=	${CC_WNO_FORMAT_TRUNCATION}
COPTS.job.c+=	-Wno-format-nonliteral	# custom shell templates
COPTS.main.c+=	${CC_WNO_FORMAT_TRUNCATION} ${CC_WNO_STRINGOP_TRUNCATION}
COPTS.meta.c+=	${CC_WNO_FORMAT_TRUNCATION}
COPTS.var.c+=	-Wno-format-nonliteral	# strftime

CPPFLAGS+=	-DMAKE_NATIVE

.if defined(TOOLDIR)
# This is a native NetBSD build, use libutil rather than the local emalloc etc.
CPPFLAGS+=	-DUSE_EMALLOC
LDADD+=		-lutil
DPADD+=		${LIBUTIL}
.endif

COPTS+=		-Wdeclaration-after-statement

# A simple unit-test driver to help catch regressions
TEST_MAKE ?= ${.OBJDIR}/${PROG:T}
test: .MAKE
	cd ${.CURDIR}/unit-tests \
	&& MAKEFLAGS= ${TEST_MAKE} -r -m / TEST_MAKE=${TEST_MAKE} ${TESTS:DTESTS=${TESTS:Q}} ${.TARGET}
.if ${USE_COVERAGE} == yes
	${MAKE} report-coverage
.endif

accept sync-mi: .MAKE
	cd ${.CURDIR}/unit-tests && ${.MAKE} ${.TARGET}

retest:
	${.MAKE} -C ${.CURDIR}/unit-tests cleandir
.if ${USE_COVERAGE} == yes
	rm -f *.gcov *.gcda
.endif
	${.MAKE} test

# Just out of curiosity, during development.
.SUFFIXES: .cpre .casm
.c.cpre:
	${COMPILE.c:S,^-c$,-E,} ${COPTS.${.IMPSRC}} ${.IMPSRC} -o ${.TARGET}
.c.casm:
	${COMPILE.c:S,^-c$,-S,} ${COPTS.${.IMPSRC}} ${.IMPSRC} -o ${.TARGET}

test-coverage: .PHONY
	@make -s clean cleandir
	@env USE_COVERAGE=yes COPTS="-O0 -ggdb" USER_CPPFLAGS="-DCLEANUP" \
		sh -c 'make -s all -j8 && make -s test'
	@env USE_COVERAGE=yes make report-coverage > coverage.txt

.if ${USE_COVERAGE} == "yes"
report-coverage: .PHONY
	@echo 'covered  uncovered  file'
	@${GCOV} ${GCOV_OPTS} *.gcda \
	| perl -ne ${GCOV_PERL:Q} \
	| sort -r -k4 \
	| sort -nr -k1
	@sed -i \
	    -e '1d' \
	    -e 's,^\([^:]*\): *[0-9]*:,\1: ,' \
	    -e 's, *$$,,g' \
	    *.gcov
.endif

.include <bsd.prog.mk>
.include <bsd.subdir.mk>

# For -DCLEANUP and similar feature toggles.
CPPFLAGS+=	${USER_CPPFLAGS}
# For overriding -std=gnu99 or similar options.
CFLAGS+=	${USER_CFLAGS}
