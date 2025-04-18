/*	$NetBSD: wii_locore.S,v 1.3 2024/10/13 16:21:37 jmcneill Exp $	*/
/*	$OpenBSD: locore.S,v 1.4 1997/01/26 09:06:38 rahnds Exp $	*/

/*
 * Copyright (C) 1995, 1996 Wolfgang Solfrank.
 * Copyright (C) 1995, 1996 TooLs GmbH.
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by TooLs GmbH.
 * 4. The name of TooLs GmbH may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY TOOLS GMBH ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL TOOLS GMBH BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "opt_ddb.h"
#include "opt_kgdb.h"
#include "opt_ppcparam.h"
#include "assym.h"

#include <sys/syscall.h>

#include <machine/param.h>
#include <machine/psl.h>
#include <machine/trap.h>
#include <machine/asm.h>

#include <powerpc/spr.h>
#include <powerpc/oea/spr.h>
#include <powerpc/oea/hid.h>

#include "ksyms.h"

/*
 * Some instructions gas doesn't understand (yet?)
 */
#define	bdneq	bdnzf 2,

/*
 * Globals
 */
GLOBAL(startsym)
	.long	0			/* start symbol table */
GLOBAL(endsym)
	.long	0			/* end symbol table */
/*
 * This symbol is here for the benefit of kvm_mkdb, and is supposed to
 * mark the start of kernel text.
 */
	.text
	.globl	_C_LABEL(kernel_text)
_C_LABEL(kernel_text):

/*
 * Startup entry.  Note, this must be the first thing in the text
 * segment!
 */
	.text
	.globl	__start
__start:
	b	__mmu_init

	/*
	 * Command-line argument protocol supported by HBC.
	 */
	.long	0x5f617267	/* WII_ARGV_MAGIC */
	.globl	_C_LABEL(wii_argv)
_C_LABEL(wii_argv):
	.long	0		/* argv magic, set by loader */
	.long	0		/* command line */
	.long	0		/* command line length */
	.long	0		/* argc */
	.long	0		/* argv */
	.long	0		/* end of argv */

__mmu_init:
	/* reset MMU to a known state */
#include "wii_mmuinit.S"

	/* compute end of kernel memory */
	lis	%r4, _C_LABEL(end)@ha
	addi	%r4, %r4, _C_LABEL(end)@l

#if NKSYMS || defined(DDB) || defined(MODULAR)
	/* If we had symbol table location we'd store it here and would've adjusted r4 here */
	lis	%r7, _C_LABEL(startsym)@ha
	addi	%r7, %r7, _C_LABEL(startsym)@l
	stw	%r4, 0(%r7)
	lis	%r7, _C_LABEL(endsym)@ha
	addi	%r7, %r7,_C_LABEL(endsym)@l
	stw	%r4, 0(%r7)
#endif

	lis	%r1, 0
	INIT_CPUINFO(%r4, %r1, %r9, %r0)

	lis	%r3, __start@ha
	addi	%r3, %r3, __start@l

	xor	%r5, %r5, %r5
	xor	%r6, %r6, %r6
	bl	_C_LABEL(initppc)

	sync
	isync
	mfspr	%r8, SPR_HID0
	ori	%r8, %r8, (HID0_ICE | HID0_DCE)@l
	isync
	mtspr	SPR_HID0, %r8
	sync
	isync

	bl	_C_LABEL(main)

loop:	b	loop			/* XXX not reached */

	.globl	_C_LABEL(enable_intr)
_C_LABEL(enable_intr):
	mfmsr	%r3
	ori	%r3, %r3, PSL_EE@l
	mtmsr	%r3
	blr

	.globl	_C_LABEL(disable_intr)
_C_LABEL(disable_intr):
	mfmsr	%r3
 	andi.	%r3, %r3, ~PSL_EE@l
	mtmsr	%r3
	blr

/*
 * Include common switch / setfault code
 */
#include <powerpc/powerpc/locore_subr.S>

/*
 * Include common trap / exception code
 */
#include <powerpc/powerpc/trap_subr.S>

/*
 * Include PIO routines
 */
#include <powerpc/powerpc/pio_subr.S>
