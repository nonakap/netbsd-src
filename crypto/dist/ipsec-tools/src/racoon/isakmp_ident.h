/*	$NetBSD: isakmp_ident.h,v 1.5 2025/03/07 15:55:29 christos Exp $	*/

/* Id: isakmp_ident.h,v 1.3 2004/06/11 16:00:16 ludvigm Exp */

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _ISAKMP_IDENT_H
#define _ISAKMP_IDENT_H

extern int ident_i1send(struct ph1handle *, vchar_t *);
extern int ident_i2recv(struct ph1handle *, vchar_t *);
extern int ident_i2send(struct ph1handle *, vchar_t *);
extern int ident_i3recv(struct ph1handle *, vchar_t *);
extern int ident_i3send(struct ph1handle *, vchar_t *);
extern int ident_i4recv(struct ph1handle *, vchar_t *);
extern int ident_i4send(struct ph1handle *, vchar_t *);

extern int ident_r1recv(struct ph1handle *, vchar_t *);
extern int ident_r1send(struct ph1handle *, vchar_t *);
extern int ident_r2recv(struct ph1handle *, vchar_t *);
extern int ident_r2send(struct ph1handle *, vchar_t *);
extern int ident_r3recv(struct ph1handle *, vchar_t *);
extern int ident_r3send(struct ph1handle *, vchar_t *);

#endif /* _ISAKMP_IDENT_H */
