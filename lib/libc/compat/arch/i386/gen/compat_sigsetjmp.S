/*	$NetBSD: compat_sigsetjmp.S,v 1.4 2025/05/03 19:55:32 riastradh Exp $	*/

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
 *	from: @(#)setjmp.s	5.1 (Berkeley) 4/23/90"
 */

#include <machine/asm.h>
#if defined(LIBC_SCCS)
	RCSID("$NetBSD: compat_sigsetjmp.S,v 1.4 2025/05/03 19:55:32 riastradh Exp $")
#endif

ENTRY(sigsetjmp)
	movl	4(%esp),%ecx
	movl	8(%esp),%eax
	movl	%eax,28(%ecx)
	testl	%eax,%eax
	jz	2f

	PIC_PROLOGUE
	pushl	$0
	call	PIC_PLT(_C_LABEL(sigblock))
	addl	$4,%esp
	PIC_EPILOGUE

	movl	4(%esp),%ecx
	movl	%eax,24(%ecx)
2:	movl	0(%esp),%edx
	movl	%edx, 0(%ecx)
	movl	%ebx, 4(%ecx)
	movl	%esp, 8(%ecx)
	movl	%ebp,12(%ecx)
	movl	%esi,16(%ecx)
	movl	%edi,20(%ecx)
	xorl	%eax,%eax
	ret
END(sigsetjmp)

ENTRY(siglongjmp)
	movl	4(%esp),%edx
	cmpl	$0,28(%edx)
	jz	2f

	PIC_PROLOGUE
	pushl	24(%edx)
	call	PIC_PLT(_C_LABEL(sigsetmask))
	addl	$4,%esp
	PIC_EPILOGUE

2:	movl	4(%esp),%edx
	movl	8(%esp),%eax
	movl	0(%edx),%ecx
	movl	4(%edx),%ebx
	movl	8(%edx),%esp
	movl	12(%edx),%ebp
	movl	16(%edx),%esi
	movl	20(%edx),%edi
	testl	%eax,%eax
	jnz	3f
	incl	%eax
3:	movl	%ecx,0(%esp)
	ret
END(siglongjmp)
