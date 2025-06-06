/*	$NetBSD: cerror.S,v 1.18 2025/05/07 16:26:47 uwe Exp $	*/

/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)cerror.s	5.1 (Berkeley) 4/23/90
 */

#include "SYS.h"

/* { r0, r1 } := -1LL */
#ifdef __thumb__
#define MOV_RETVAL_MINUS_1	  \
	movs	r0, #0		; \
	mvns	r0, r0		; \
	movs	r1, r0

#else // !__thumb__
#define MOV_RETVAL_MINUS_1	  \
	mvn	r0, #0		; \
	mov	r1, r0
#endif


/*
 * Set `errno` and return -1.  See SYS.h for syscall stubs that call this.
 */
ENTRY_NP(CERROR)
#ifdef _REENTRANT
	/* __errno() returns the address of a thread local variable */
	.globl	_C_LABEL(__errno)
#if defined(__ARM_EABI__) && defined(__UNWIND_TABLES__)
	.fnstart
	.cfi_startproc
#endif
	push	{r4, lr}
#if defined(__ARM_EABI__) && defined(__UNWIND_TABLES__)
	.save	{r4, lr}
	.cfi_def_cfa_offset 8
	.cfi_offset 14, -4
	.cfi_offset 4, -8
#endif
	movs	r4, r0
	bl	PLT_SYM(_C_LABEL(__errno))
	str	r4, [r0]
	MOV_RETVAL_MINUS_1
	pop	{r4, pc}
#if defined(__ARM_EABI__) && defined(__UNWIND_TABLES__)
	.cfi_endproc
	.fnend
#endif

#else /* !_REENTRANT */
	/* errno is a global variable */
	.globl	_C_LABEL(errno)
#if defined(__ARM_EABI__) && defined(__UNWIND_TABLES__)
	.fnstart
	.cfi_startproc
#endif
0:	GOT_INIT(r3, .Lgot)
	ldr	r1, .Lerrno
#ifdef __PIC__
	ldr	r1, [r3, r1]
#endif /* __PIC__ */
	str	r0, [r1]
	MOV_RETVAL_MINUS_1
	RET
#if defined(__ARM_EABI__) && defined(__UNWIND_TABLES__)
	.cfi_endproc
	.fnend
#endif

	GOT_INITSYM(.Lgot, 0b)
.Lerrno:
	.word	GOT_SYM(_C_LABEL(errno))
#endif /* _REENTRANT */
END(CERROR)
