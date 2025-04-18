/*	$NetBSD: aica_arm_locore.S,v 1.7 2024/02/09 22:08:32 andvar Exp $	*/

/*
 * Copyright (c) 2003 Ryo Shimizu
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

	.text

	b	exp_reset
	b	exp_undef
	b	exp_swi
	b	exp_pabort
	b	exp_dabort
	b	exp_reserved
	b	exp_irq
/*	b	exp_fiq	*/
exp_fiq:
	sub	pc,r14,#4

exp_reset:
	mov	sp,#0xff00	/* setup stack */

	mrs	r0,CPSR		/* disable interrupt */
	bic	r0,r0,#0x80	/* disable IRQ */
	bic	r0,r0,#0x40	/* disable FIQ */
	msr	CPSR_all,r0

	mrc	p15,0,r0,c1,c0,0	/* read control register */
	bic	r0,r0,#0x0004		/* DC disable */
	orr	r0,r0,#0x1000		/* IC enable */
	mcr	p15,0,r0,c1,c0,0	/* write control register */

	bl	aica_main

exp_reserved:
	b	exp_reserved

exp_irq:
	sub	pc,r14,#4

exp_dabort:
	sub	pc,r14,#8

exp_pabort:
	sub	pc,r14,#4

exp_swi:
	mov	pc,r14

exp_undef:
	mov	pc,r14

	.global memset
/* memset(void *b:r0, int c:r1, size_t len:r2) */
memset:
	/* optimized only if c == 0 and b is 4-byte aligned. */
	and	r3,r0,#3	/* r0 is 4byte aligned ? */
	orrs	r3,r3,r1	/* r1 == 0 ? */
	mov	r3,r0		/* p:r3 = b; */
	bne	.memset_byte
	add	r2,r0,r2	/* e:r2 = b + (len & -4); */
	bic	r2,r2,#3
.memset32_zero:
	cmp	r3,r2		/* if (e > p) { */
	bls	.memset_byte
1:				/*  do { */
	str	r1,[r3],#4	/*   *(uint32_t *)p++ = c; */
	cmp	r3,r2		/*  while (e < p); */
	bhi	1b
				/* } */
.memset_byte:
	add	r2,r0,r2	/* e:r2 = b + len; */
	cmp	r0,r2		/* if (e > p) return; */
	movls	pc,lr
1:				/* do { */
	strb	r1,[r3],#1	/*  *(uint8_t *)p++ = c; */
	cmp	r3,r2		/* while (e < p); */
	bhi	1b
	mov	pc,lr		/* return; */
