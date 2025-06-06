/* $NetBSD: e_acos.S,v 1.8 2024/05/07 22:51:19 riastradh Exp $ */

/*
 * FPLSP wrapper for __ieee754_acos
 * DO NOT EDIT - this file is automatically generated by:
 *
 *	NetBSD: makeas.sh,v 1.16 2024/05/07 22:30:16 riastradh Exp
 */

#include <machine/asm.h>

ENTRY(__ieee754_acos)
#ifdef __SVR4_ABI__
	bral PIC_PLT(_C_LABEL(__fplsp060_0008))
#else
	movel %sp@(8),%sp@-
	movel %sp@(8),%sp@-
	bsrl PIC_PLT(_C_LABEL(__fplsp060_0008))
	fmoved %fp0,%sp@
	movel %sp@+,%d0
	movel %sp@+,%d1
	rts
#endif
END(__ieee754_acos)
