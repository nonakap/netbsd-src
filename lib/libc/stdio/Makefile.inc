#	from: @(#)Makefile.inc	5.7 (Berkeley) 6/27/91
#	$NetBSD: Makefile.inc,v 1.51 2025/07/07 20:05:06 rillig Exp $

# stdio sources
.PATH: ${.CURDIR}/stdio

SRCS+=	clrerr.c dprintf.c fclose.c fdopen.c feof.c ferror.c \
	fflush.c fgetc.c fgetln.c fgetpos.c fgets.c fgetstr.c fgetwc.c \
	fgetwln.c fgetws.c fileno.c findfp.c flags.c flockfile.c fopen.c \
	fparseln.c fprintf.c fpurge.c fputc.c fputs.c fputwc.c fputws.c \
	fread.c freopen.c fscanf.c fseek.c fseeko.c fsetpos.c ftell.c ftello.c \
	funopen.c fvwrite.c fwalk.c fwide.c fwprintf.c fwrite.c fwscanf.c \
	getc.c getchar.c getdelim.c getline.c gettemp.c getw.c getwc.c \
	getwchar.c makebuf.c mkdtemp.c mkstemp.c mkstemps.c mkostemp.c \
	mkostemps.c perror.c printf.c putc.c putchar.c puts.c putw.c putwc.c \
	putwchar.c refill.c remove.c rewind.c \
	rget.c scanf.c setbuf.c setbuffer.c setvbuf.c snprintf_ss.c \
	sscanf.c stdio.c swprintf.c swscanf.c tmpfile.c ungetc.c ungetwc.c \
	vasprintf.c vdprintf.c vfprintf.c vfscanf.c vfwprintf.c vfwscanf.c \
	vprintf.c vscanf.c vsnprintf.c vsnprintf_ss.c vsscanf.c vswprintf.c \
	vswscanf.c vwprintf.c vwscanf.c wbuf.c wprintf.c wscanf.c wsetup.c
SRCS+=	fmemopen.c open_memstream.c open_wmemstream.c

.if !defined(AUDIT)
SRCS+=	gets.c vsprintf.c tempnam.c tmpnam.c mktemp.c
.endif

MAN+=	fclose.3 ferror.3 fflush.3 fgetln.3 fgets.3 fgetwln.3 fgetws.3 \
	flockfile.3 fmemopen.3 fopen.3 fparseln.3 fputs.3 fputws.3 fread.3 \
	fseek.3 funopen.3 fwide.3 getc.3 getdelim.3 getwc.3 mktemp.3 printf.3 \
	printf_l.3 putc.3 putwc.3 remove.3 scanf.3 scanf_l.3 setbuf.3 stdio.3 \
	tmpnam.3 ungetc.3 ungetwc.3 wprintf.3 wscanf.3 open_memstream.3

MLINKS+=ferror.3 clearerr.3 ferror.3 feof.3 ferror.3 fileno.3
MLINKS+=fflush.3 fpurge.3
MLINKS+=flockfile.3 ftrylockfile.3 flockfile.3 funlockfile.3
MLINKS+=fgets.3 gets.3
MLINKS+=fopen.3 fdopen.3 fopen.3 freopen.3
MLINKS+=fputs.3 puts.3
MLINKS+=fread.3 fwrite.3
MLINKS+=fseek.3 fgetpos.3 fseek.3 fseeko.3 fseek.3 fsetpos.3 fseek.3 ftell.3 \
	fseek.3 ftello.3 fseek.3 rewind.3
MLINKS+=funopen.3 fropen.3 funopen.3 fwopen.3
MLINKS+=funopen.3 funopen2.3 funopen.3 fropen2.3 funopen.3 fwopen2.3
MLINKS+=getc.3 fgetc.3 getc.3 getc_unlocked.3 getc.3 getchar.3 \
	getc.3 getchar_unlocked.3 getc.3 getw.3
MLINKS+=getdelim.3 getline.3
MLINKS+=mktemp.3 mkdtemp.3 mktemp.3 mkstemp.3
MLINKS+=mktemp.3 mkostemp.3 mktemp.3 mkostemps.3
MLINKS+=mktemp.3 mkstemps.3
MLINKS+=printf.3 asprintf.3 printf.3 fprintf.3 printf.3 snprintf.3 \
	printf.3 snprintf_ss.3 printf.3 sprintf.3 printf.3 vasprintf.3 \
	printf.3 vfprintf.3 printf.3 vprintf.3 printf.3 vsnprintf.3 \
	printf.3 vsprintf.3 printf.3 dprintf.3 printf.3 vdprintf.3 \
	printf.3 vsnprintf_ss.3
MLINKS+=putc.3 fputc.3 putc.3 putc_unlocked.3 putc.3 putchar.3 \
	putc.3 putchar_unlocked.3 putc.3 putw.3
MLINKS+=scanf.3 fscanf.3 scanf.3 sscanf.3 scanf.3 vfscanf.3 scanf.3 vscanf.3 \
	scanf.3 vsscanf.3
MLINKS+=setbuf.3 setbuffer.3 setbuf.3 setlinebuf.3 setbuf.3 setvbuf.3
MLINKS+=tmpnam.3 tempnam.3 tmpnam.3 tmpfile.3
MLINKS+=putwc.3 fputwc.3 putwc.3 putwchar.3
MLINKS+=getwc.3 fgetwc.3 getwc.3 getwchar.3
MLINKS+=wprintf.3 fwprintf.3 wprintf.3 swprintf.3
MLINKS+=wprintf.3 vwprintf.3 wprintf.3 vfwprintf.3 wprintf.3 vswprintf.3
MLINKS+=wscanf.3 fwscanf.3 wscanf.3 swscanf.3 wscanf.3 vwscanf.3
MLINKS+=wscanf.3 vswscanf.3 wscanf.3 vfwscanf.3
MLINKS+=open_memstream.3 open_wmemstream.3
MLINKS+=printf_l.3 asprintf_l.3 printf_l.3 fprintf_l.3 printf_l.3 snprintf_l.3 \
        printf_l.3 sprintf_l.3 printf_l.3 vasprintf_l.3 printf_l.3  \
	vfprintf_l.3 printf_l.3 vprintf_l.3 printf_l.3 vsnprintf_l.3 \
	printf_l.3 vsprintf_l.3
MLINKS+=scanf_l.3 fscanf_l.3 scanf_l.3 sscanf_l.3 scanf_l.3 vfscanf_l.3 \
        scanf_l.3 vscanf_l.3 scanf_l.3 vsscanf_l.3

LINTFLAGS.clrerr.c += -X 309 # XXX: lint bogus warning
LINTFLAGS.rewind.c += -X 309 # XXX: lint bogus warning
LINTFLAGS.ungetwc.c += -X 309 # XXX: lint bogus warning
