/*	$NetBSD: vidc.h,v 1.14 2024/02/05 21:39:52 andvar Exp $	*/

/*
 * Copyright (c) 1994,1995 Mark Brinicombe.
 * Copyright (c) 1994,1995 Brini.
 * All rights reserved.
 *
 * This code is derived from software written for Brini by Mark Brinicombe
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
 *	This product includes software developed by Brini.
 * 4. The name of the company nor the name of the author may be used to
 *    endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY BRINI ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL BRINI OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * RiscBSD kernel project
 *
 * vidc.h
 *
 * VIDC20 registers
 *
 * Created      : 18/09/94
 *
 * Based on kate/display/vidc.h
 */

/*
 * This should be private to the vidc directory but there are still dependencies
 * between the vidc and the riscpc virtual console (struct vidc_mode) that
 * means this file must be exported to userland.
 * With the import of the new console code this will go away.
 */

#ifndef	_ARM32_VIDC_H_
#define	_ARM32_VIDC_H_

#include <dev/videomode/videomode.h>
#include <machine/vidc_machdep.h>

/*
 * Current VIDC base set in initarm()
 * since the current code isnt busspaceified, we need to set it manually ...
 * this is to allow the VIDC to be moved.
 */
extern int *vidc_base;


/* Video registers */

#define VIDC_PALETTE 0x00000000
#define VIDC_PALREG  0x10000000

#define VIDC_BCOL    0x40000000
#define VIDC_CP0     0x40000000
#define VIDC_CP1     0x50000000
#define VIDC_CP2     0x60000000
#define VIDC_CP3     0x70000000

#define VIDC_HCR     0x80000000
#define VIDC_HSWR    0x81000000
#define VIDC_HBSR    0x82000000
#define VIDC_HDSR    0x83000000
#define VIDC_HDER    0x84000000
#define VIDC_HBER    0x85000000
#define VIDC_HCSR    0x86000000
#define VIDC_HIR     0x87000000

#define VIDC_VCR     0x90000000
#define VIDC_VSWR    0x91000000
#define VIDC_VBSR    0x92000000
#define VIDC_VDSR    0x93000000
#define VIDC_VDER    0x94000000
#define VIDC_VBER    0x95000000
#define VIDC_VCSR    0x96000000
#define VIDC_VCER    0x97000000

#define VIDC_EREG    0xc0000000
#define VIDC_FSYNREG 0xd0000000
#define VIDC_CONREG  0xe0000000
#define VIDC_DCTL    0xf0000000

/* VIDC palette macros */

#define VIDC_RED(r)   (r)
#define VIDC_GREEN(g) ((g) << 8)
#define VIDC_BLUE(b)  ((b) << 16)
#define VIDC_COL(r, g, b) (VIDC_RED(r) | VIDC_GREEN(g) | VIDC_BLUE(b))


/* Sound registers */

#define VIDC_SIR0    0xa0000000
#define VIDC_SIR1    0xa1000000
#define VIDC_SIR2    0xa2000000
#define VIDC_SIR3    0xa3000000
#define VIDC_SIR4    0xa4000000
#define VIDC_SIR5    0xa5000000
#define VIDC_SIR6    0xa6000000
#define VIDC_SIR7    0xa7000000

#define VIDC_SFR     0xb0000000
#define VIDC_SCR     0xb1000000

#define SIR_LEFT_100  0x01
#define SIR_LEFT_83   0x02
#define SIR_LEFT_67   0x03
#define SIR_CENTRE    0x04
#define SIR_RIGHT_67  0x05
#define SIR_RIGHT_83  0x06
#define SIR_RIGHT_100 0x07

#define SCR_SCLR	0x08
#define SCR_SDAC	0x04
#define SCR_SERIAL	0x02
#define SCR_CLKSEL	0x01

/* Video display addresses */

/* Where the display memory is mapped */
/* note that there's not normally more than 2MB */
#define VMEM_VBASE 0xf7000000
 
/* Where the VRAM will be found */

#define VRAM_BASE  0x02000000

#ifndef _LOCORE

/* Video memory descriptor */

typedef struct
  {
    u_int vidm_vbase;	/* virtual base of video memory */
    u_int vidm_pbase;	/* physical base of video memory */
    u_int vidm_size;	/* video memory size */
    int   vidm_type;	/* video memory type */
  } videomemory_t;

#define VIDEOMEM_TYPE_VRAM 0x01
#define VIDEOMEM_TYPE_DRAM 0x02

/* Structures and prototypes for vidc handling functions */

struct vidc_state {
	int palette[256];
	int palreg;
	int bcol;
	int cp1;
	int cp2;
	int cp3;
	int hcr, hswr, hbsr, hdsr, hder, hber, hcsr; 
	int hir;
	int vcr, vswr, vbsr, vdsr, vder, vber, vcsr, vcer;	
	int ereg;
	int fsynreg;
	int conreg;
	int dctl;
};

extern int vidc_fref;		/* reference frequency of detected VIDC */

extern struct vidc_state vidc_current[];

struct vidc_mode {
	struct	videomode timings;
	int	log2_bpp;
};

#endif	/* !_LOCORE */

#endif	/* !_ARM32_VIDC_H */

/* End of vidc.h */

