/*	$NetBSD: locore_el2.S,v 1.10 2025/01/30 08:58:07 jmcneill Exp $	*/

/*-
 * Copyright (c) 2012-2014 Andrew Turner
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: head/sys/arm64/arm64/locore.S 316755 2017-04-13 11:56:27Z andrew $
 */

#include <aarch64/asm.h>
#include <aarch64/hypervisor.h>
#include "assym.h"

RCSID("$NetBSD: locore_el2.S,v 1.10 2025/01/30 08:58:07 jmcneill Exp $")

/*
 * For use in #include "locore_el2.S".
 */

	.global drop_to_el1
	.text

drop_to_el1_inline:
	mov	x8, lr
	bl	drop_to_el1
	mov	lr, x8
	b	drop_to_el1_inline_done

	/*
	 * If we are started in EL2, configure the required hypervisor
	 * registers and drop to EL1.
	 */
drop_to_el1:
	mrs	x1, CurrentEL
	lsr	x1, x1, #2
	cmp	x1, #0x2
	b.eq	in_el2

	/* Not in EL2, nothing to do, leave. */
	ret

in_el2:
	/* Check for EL2 host mode */
	mrs	x2, hcr_el2
	tbz	x2, #34, no_el2_host_mode	/* HCR_E2H not set? */

	/* EL2 host mode supported, nothing to do, leave. */
	ret

no_el2_host_mode:
	/* EL1 will be AArch64. */
	mov	x2, #(HCR_RW)
	msr	hcr_el2, x2

	/* Mirror the Virtualization Process ID Register. */
	mrs	x2, midr_el1
	msr	vpidr_el2, x2

	/* Mirror the Virtualization Multiprocess ID Register. */
	mrs	x2, mpidr_el1
	msr	vmpidr_el2, x2

	/* Set the bits that need to be 1 in SCTLR_EL1. */
	ldr	x2, .Lsctlr_res1
	mrs	x1, sctlr_el1
	and	x1, x1, #(SCTLR_EE | SCTLR_E0E)	/* keep SCTLR_EL1.{EE,E0E} */
	orr	x2, x2, x1
	msr	sctlr_el1, x2

	/* Don't trap to EL2 on FP instructions. */
	mrs	x2, cpacr_el1
	bic	x2, x2, #CPACR_FPEN
	orr	x2, x2, #CPACR_FPEN_ALL
	msr	cpacr_el1, x2
	isb

	/* Don't trap to EL2 on access to various registers. */
	mov	x2, #CPTR_RES1
	msr	cptr_el2, x2

	/* Don't trap to EL2 on CP15 traps. */
	msr	hstr_el2, xzr

	/* Enable access to the physical timers at EL1. */
	mov	x2, #(CNTHCTL_EL1PCTEN | CNTHCTL_EL1PCEN)
	msr	cnthctl_el2, x2

	/* Set the counter offset to a known value. */
	msr	cntvoff_el2, xzr

	/* Set the hypervisor trap vectors. */
	adr	x2, hyp_vectors
	msr	vbar_el2, x2

	mov	x2, #(SPSR_F | SPSR_I | SPSR_A | SPSR_A64_D | SPSR_M_EL1H)
	msr	spsr_el2, x2

	/* Configure GICv3 CPU interface */
	mrs	x2, id_aa64pfr0_el1
	/* Extract GIC bits from the register */
	and	x2, x2, ID_AA64PFR0_EL1_GIC
	lsr	x2, x2, ID_AA64PFR0_EL1_GIC_SHIFT
	/* GIC[3:0] == 0001 - GIC CPU interface via special regs. supported */
	cmp	x2, #ID_AA64PFR0_EL1_GIC_CPUIF_EN
	b.ne	2f
#ifdef __clang__
#define ICC_SRE_EL2 icc_sre_el2
#else
#define ICC_SRE_EL2 S3_4_C12_C9_5
#endif

	mrs	x2, ICC_SRE_EL2
	orr	x2, x2, #ICC_SRE_EL2_EN	/* Enable access from insecure EL1 */
	orr	x2, x2, #ICC_SRE_EL2_SRE	/* Enable system registers */
	msr	ICC_SRE_EL2, x2
2:

	/* Keep the stack pointer. */
	mov	x0, sp
	msr	sp_el1, x0

	/* Set the address to return to. */
	msr	elr_el2, lr
	isb

	eret

	.align 3
.Lsctlr_res1:
	.quad SCTLR_RES1

#define	VECT_EMPTY	\
	.align 7;	\
	1:	b	1b

	.align 11
hyp_vectors:
	VECT_EMPTY	/* Synchronous EL2t */
	VECT_EMPTY	/* IRQ EL2t */
	VECT_EMPTY	/* FIQ EL2t */
	VECT_EMPTY	/* Error EL2t */

	VECT_EMPTY	/* Synchronous EL2h */
	VECT_EMPTY	/* IRQ EL2h */
	VECT_EMPTY	/* FIQ EL2h */
	VECT_EMPTY	/* Error EL2h */

	VECT_EMPTY	/* Synchronous 64-bit EL1 */
	VECT_EMPTY	/* IRQ 64-bit EL1 */
	VECT_EMPTY	/* FIQ 64-bit EL1 */
	VECT_EMPTY	/* Error 64-bit EL1 */

	VECT_EMPTY	/* Synchronous 32-bit EL1 */
	VECT_EMPTY	/* IRQ 32-bit EL1 */
	VECT_EMPTY	/* FIQ 32-bit EL1 */
	VECT_EMPTY	/* Error 32-bit EL1 */

drop_to_el1_inline_done:
	nop
