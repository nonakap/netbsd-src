/*	$NetBSD: execsp.S,v 1.2 2025/04/21 02:31:22 riastradh Exp $	*/

/*-
 * Copyright (c) 2025 The NetBSD Foundation, Inc.
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define	_LOCORE

#include <machine/asm.h>

RCSID("$NetBSD: execsp.S,v 1.2 2025/04/21 02:31:22 riastradh Exp $")

	.set noat
	.text

/*
 * void execsp_start(void *stackpointer@a0, void (*cleanup@a1)(void),
 *     void *obj_main@a2, struct ps_strings *ps_strings@a3)
 *
 *	ELF entry point.  Saves the stack pointer in startsp and defers
 *	to the usual csu __start routine.
 */
LEAF(execsp_start, 4)
	LDGP(pv)
	ldq	at_reg, startsp(gp)	!literal
	stq	sp, 0(at_reg)
	ldq	pv, __start(gp)		!literal
	jmp	(pv), __start
END(execsp_start)

/*
 * void execsp_ctor(void)
 *
 *	ELF constructor.  Saves the stack pointer in ctorsp and
 *	returns.
 */
LEAF(execsp_ctor, 0)
	LDGP(pv)
	ldq	at_reg, ctorsp(gp)	!literal
	stq	sp, 0(at_reg)
	RET
END(execsp_ctor)

	/* Make execsp_ctor a constructor. */
	.pushsection .ctors,"aw",@progbits
	.p2align 3
	.quad	execsp_ctor
	.popsection

/*
 * int main(int argc@a0, char **argv@a1, ...)
 *
 *	Main function.  Saves the stack pointer in mainsp and returns
 *	zero.  We will call execsp_main in execsp_dtor once dtorsp has
 *	been initialized.
 */
LEAF(main, 2)
	LDGP(pv)
	ldq	at_reg, mainsp(gp)	!literal
	stq	sp, 0(at_reg)
	mov	zero, v0
	RET
END(main)

/*
 * void execsp_dtor(void)
 *
 *	ELF destructor.  Saves the stack pointer in dtorsp and defers
 *	to the C execsp_main in h_execsp.c to report the stack pointers
 *	back to the t_signal_and_sp parent.
 */
LEAF(execsp_dtor, 0)
	LDGP(pv)
	ldq	at_reg, dtorsp(gp)	!literal
	stq	sp, 0(at_reg)
	ldq	pv, execsp_main(gp)	!literal
	jmp	(pv), execsp_main
END(execsp_dtor)

	/* Make execsp_ctor a destructor. */
	.pushsection .dtors,"aw",@progbits
	.p2align 3
	.quad	execsp_dtor
	.popsection
