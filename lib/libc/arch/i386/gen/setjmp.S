/*	$NetBSD: setjmp.S,v 1.19 2025/05/03 19:55:32 riastradh Exp $	*/

/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz.
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
 *	from: @(#)setjmp.s	5.1 (Berkeley) 4/23/90
 */

#include <machine/asm.h>
#if defined(LIBC_SCCS)
	RCSID("$NetBSD: setjmp.S,v 1.19 2025/05/03 19:55:32 riastradh Exp $")
#endif

/*
 * C library -- _setjmp, _longjmp
 *
 *	longjmp(a,v)
 * will generate a "return(v)" from the last call to
 *	setjmp(a)
 * by restoring registers from the stack.
 * The previous signal state is restored.
 */

/*
 * setjmp(jmp_buf env@esp[4,8))
 *
 * ELF symbol: __setjmp14, because the size of jmp_buf changed on some
 * platforms in 1.4.
 */
ENTRY(__setjmp14)
	/*
	 * Save the callee-saves registers: %ebp, %ebx, %edi, %esi,
	 * plus %esp and the return address on the stack since it
	 * will be overwritten if the caller makes any subroutine
	 * calls before longjmp.
	 */
	movl	4(%esp),%ecx		/* ecx := env */
	movl	0(%esp),%edx		/* edx := return address */
	movl	%edx,0(%ecx)
	movl	%ebx,4(%ecx)
	movl	%esp,8(%ecx)
	movl	%ebp,12(%ecx)
	movl	%esi,16(%ecx)
	movl	%edi,20(%ecx)

	/* Get the signal mask. */
	leal	24(%ecx),%edx

	PIC_PROLOGUE
	pushl	%edx			/* oset (signal mask saved to) */
	pushl	$0			/* set := NULL */
	pushl	$0			/* how := 0 (ignored) */
	call	PIC_PLT(_C_LABEL(__sigprocmask14))
	addl	$12,%esp		/* pop sigprocmask args */
	PIC_EPILOGUE

	xorl	%eax,%eax		/* return 0 first time around */
	ret
END(__setjmp14)

/*
 * longjmp(jmp_buf env@esp[4,8), int val@[8,12))
 *
 * ELF symbol: __longjmp14, because the size of jmp_buf changed on some
 * platforms in 1.4.
 */
ENTRY(__longjmp14)
	/*
	 * Restore the callee-saves registers: %ebp, %ebx, %edi, %esi,
	 * plus %esp and the return address on the stack.
	 */
	movl	4(%esp),%edx		/* edx := env */
	movl	8(%esp),%eax		/* eax := val */
	movl	0(%edx),%ecx		/* ecx := return address */
	movl	4(%edx),%ebx
	movl	8(%edx),%esp
	movl	12(%edx),%ebp
	movl	16(%edx),%esi
	movl	20(%edx),%edi
	movl	%ecx,0(%esp)		/* restore return address */

	/* Restore the signal mask. */
	leal	24(%edx),%edx

	pushl	%eax			/* save val@eax */

	PIC_PROLOGUE
	pushl	$0			/* oset := NULL */
	pushl	%edx			/* set (signal mask restored from) */
	pushl	$3			/* how := SIG_SETMASK */
	call	PIC_PLT(_C_LABEL(__sigprocmask14))
	addl	$12,%esp		/* pop sigprocmask args */
	PIC_EPILOGUE

	popl	%eax			/* restore val@eax */

	testl	%eax,%eax		/* val == 0? */
	jz	3f			/* jump if val == 0 */
	ret				/* return val@eax */

3:	incl	%eax			/* val@eax := 1 */
	ret				/* return val@eax */
END(__longjmp14)
