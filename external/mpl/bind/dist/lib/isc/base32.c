/*	$NetBSD: base32.c,v 1.9 2025/01/26 16:25:36 christos Exp $	*/

/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <stdbool.h>

#include <isc/base32.h>
#include <isc/buffer.h>
#include <isc/lex.h>
#include <isc/region.h>
#include <isc/string.h>
#include <isc/util.h>

#define RETERR(x)                        \
	do {                             \
		isc_result_t _r = (x);   \
		if (_r != ISC_R_SUCCESS) \
			return ((_r));   \
	} while (0)

/*@{*/
/*!
 * These static functions are also present in lib/dns/rdata.c.  I'm not
 * sure where they should go. -- bwelling
 */
static isc_result_t
str_totext(const char *source, isc_buffer_t *target);

static isc_result_t
mem_tobuffer(isc_buffer_t *target, void *base, unsigned int length);

/*@}*/

static const char base32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="
			     "abcdefghijklmnopqrstuvwxyz234567";
static const char base32hex[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV="
				"0123456789abcdefghijklmnopqrstuv";

static isc_result_t
base32_totext(isc_region_t *source, int wordlength, const char *wordbreak,
	      isc_buffer_t *target, const char base[], char pad) {
	char buf[9];
	unsigned int loops = 0;

	if (wordlength >= 0 && wordlength < 8) {
		wordlength = 8;
	}

	memset(buf, 0, sizeof(buf));
	while (source->length > 0) {
		buf[0] = base[((source->base[0] >> 3) & 0x1f)]; /* 5 + */
		if (source->length == 1) {
			buf[1] = base[(source->base[0] << 2) & 0x1c];
			buf[2] = buf[3] = buf[4] = pad;
			buf[5] = buf[6] = buf[7] = pad;
			RETERR(str_totext(buf, target));
			break;
		}
		buf[1] = base[((source->base[0] << 2) & 0x1c) | /* 3 = 8 */
			      ((source->base[1] >> 6) & 0x03)]; /* 2 + */
		buf[2] = base[((source->base[1] >> 1) & 0x1f)]; /* 5 + */
		if (source->length == 2) {
			buf[3] = base[(source->base[1] << 4) & 0x10];
			buf[4] = buf[5] = buf[6] = buf[7] = pad;
			RETERR(str_totext(buf, target));
			break;
		}
		buf[3] = base[((source->base[1] << 4) & 0x10) | /* 1 = 8 */
			      ((source->base[2] >> 4) & 0x0f)]; /* 4 + */
		if (source->length == 3) {
			buf[4] = base[(source->base[2] << 1) & 0x1e];
			buf[5] = buf[6] = buf[7] = pad;
			RETERR(str_totext(buf, target));
			break;
		}
		buf[4] = base[((source->base[2] << 1) & 0x1e) | /* 4 = 8 */
			      ((source->base[3] >> 7) & 0x01)]; /* 1 + */
		buf[5] = base[((source->base[3] >> 2) & 0x1f)]; /* 5 + */
		if (source->length == 4) {
			buf[6] = base[(source->base[3] << 3) & 0x18];
			buf[7] = pad;
			RETERR(str_totext(buf, target));
			break;
		}
		buf[6] = base[((source->base[3] << 3) & 0x18) | /* 2 = 8 */
			      ((source->base[4] >> 5) & 0x07)]; /* 3 + */
		buf[7] = base[source->base[4] & 0x1f];		/* 5 = 8 */
		RETERR(str_totext(buf, target));
		isc_region_consume(source, 5);

		loops++;
		if (source->length != 0 && wordlength >= 0 &&
		    (int)((loops + 1) * 8) >= wordlength)
		{
			loops = 0;
			RETERR(str_totext(wordbreak, target));
		}
	}
	if (source->length > 0) {
		isc_region_consume(source, source->length);
	}
	return ISC_R_SUCCESS;
}

isc_result_t
isc_base32_totext(isc_region_t *source, int wordlength, const char *wordbreak,
		  isc_buffer_t *target) {
	return base32_totext(source, wordlength, wordbreak, target, base32,
			     '=');
}

isc_result_t
isc_base32hex_totext(isc_region_t *source, int wordlength,
		     const char *wordbreak, isc_buffer_t *target) {
	return base32_totext(source, wordlength, wordbreak, target, base32hex,
			     '=');
}

isc_result_t
isc_base32hexnp_totext(isc_region_t *source, int wordlength,
		       const char *wordbreak, isc_buffer_t *target) {
	return base32_totext(source, wordlength, wordbreak, target, base32hex,
			     0);
}

/*%
 * State of a base32 decoding process in progress.
 */
typedef struct {
	int length;	      /*%< Desired length of binary data or -1 */
	isc_buffer_t *target; /*%< Buffer for resulting binary data */
	int digits;	      /*%< Number of buffered base32 digits */
	bool seen_end;	      /*%< True if "=" end marker seen */
	int val[8];
	const char *base; /*%< Which encoding we are using */
	int seen_32;	  /*%< Number of significant bytes if non
			   * zero */
	bool pad;	  /*%< Expect padding */
} base32_decode_ctx_t;

static isc_result_t
base32_decode_char(base32_decode_ctx_t *ctx, int c) {
	const char *s;
	unsigned int last;

	if (ctx->seen_end) {
		return ISC_R_BADBASE32;
	}
	if ((s = strchr(ctx->base, c)) == NULL) {
		return ISC_R_BADBASE32;
	}
	last = (unsigned int)(s - ctx->base);

	/*
	 * Handle lower case.
	 */
	if (last > 32) {
		last -= 33;
	}

	/*
	 * Check that padding is contiguous.
	 */
	if (last != 32 && ctx->seen_32 != 0) {
		return ISC_R_BADBASE32;
	}

	/*
	 * If padding is not permitted flag padding as a error.
	 */
	if (last == 32 && !ctx->pad) {
		return ISC_R_BADBASE32;
	}

	/*
	 * Check that padding starts at the right place and that
	 * bits that should be zero are.
	 * Record how many significant bytes in answer (seen_32).
	 */
	if (last == 32 && ctx->seen_32 == 0) {
		switch (ctx->digits) {
		case 0:
		case 1:
			return ISC_R_BADBASE32;
		case 2:
			if ((ctx->val[1] & 0x03) != 0) {
				return ISC_R_BADBASE32;
			}
			ctx->seen_32 = 1;
			break;
		case 3:
			return ISC_R_BADBASE32;
		case 4:
			if ((ctx->val[3] & 0x0f) != 0) {
				return ISC_R_BADBASE32;
			}
			ctx->seen_32 = 2;
			break;
		case 5:
			if ((ctx->val[4] & 0x01) != 0) {
				return ISC_R_BADBASE32;
			}
			ctx->seen_32 = 3;
			break;
		case 6:
			return ISC_R_BADBASE32;
		case 7:
			if ((ctx->val[6] & 0x07) != 0) {
				return ISC_R_BADBASE32;
			}
			ctx->seen_32 = 4;
			break;
		}
	}

	/*
	 * Zero fill pad values.
	 */
	ctx->val[ctx->digits++] = (last == 32) ? 0 : last;

	if (ctx->digits == 8) {
		int n = 5;
		unsigned char buf[5];

		if (ctx->seen_32 != 0) {
			ctx->seen_end = true;
			n = ctx->seen_32;
		}
		buf[0] = (ctx->val[0] << 3) | (ctx->val[1] >> 2);
		buf[1] = (ctx->val[1] << 6) | (ctx->val[2] << 1) |
			 (ctx->val[3] >> 4);
		buf[2] = (ctx->val[3] << 4) | (ctx->val[4] >> 1);
		buf[3] = (ctx->val[4] << 7) | (ctx->val[5] << 2) |
			 (ctx->val[6] >> 3);
		buf[4] = (ctx->val[6] << 5) | (ctx->val[7]);
		RETERR(mem_tobuffer(ctx->target, buf, n));
		if (ctx->length >= 0) {
			if (n > ctx->length) {
				return ISC_R_BADBASE32;
			} else {
				ctx->length -= n;
			}
		}
		ctx->digits = 0;
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
base32_decode_finish(base32_decode_ctx_t *ctx) {
	if (ctx->length > 0) {
		return ISC_R_UNEXPECTEDEND;
	}
	/*
	 * Add missing padding if required.
	 */
	if (!ctx->pad && ctx->digits != 0) {
		ctx->pad = true;
		do {
			RETERR(base32_decode_char(ctx, '='));
		} while (ctx->digits != 0);
	}
	if (ctx->digits != 0) {
		return ISC_R_BADBASE32;
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
base32_tobuffer(isc_lex_t *lexer, const char base[], bool pad,
		isc_buffer_t *target, int length) {
	unsigned int before, after;
	base32_decode_ctx_t ctx = {
		.length = length, .base = base, .target = target, .pad = pad
	};
	isc_textregion_t *tr;
	isc_token_t token;
	bool eol;

	REQUIRE(length >= -2);

	before = isc_buffer_usedlength(target);
	while (!ctx.seen_end && (ctx.length != 0)) {
		unsigned int i;

		if (length > 0) {
			eol = false;
		} else {
			eol = true;
		}
		RETERR(isc_lex_getmastertoken(lexer, &token,
					      isc_tokentype_string, eol));
		if (token.type != isc_tokentype_string) {
			break;
		}
		tr = &token.value.as_textregion;
		for (i = 0; i < tr->length; i++) {
			RETERR(base32_decode_char(&ctx, tr->base[i]));
		}
	}
	after = isc_buffer_usedlength(target);
	if (ctx.length < 0 && !ctx.seen_end) {
		isc_lex_ungettoken(lexer, &token);
	}
	RETERR(base32_decode_finish(&ctx));
	if (length == -2 && before == after) {
		return ISC_R_UNEXPECTEDEND;
	}
	return ISC_R_SUCCESS;
}

isc_result_t
isc_base32_tobuffer(isc_lex_t *lexer, isc_buffer_t *target, int length) {
	return base32_tobuffer(lexer, base32, true, target, length);
}

isc_result_t
isc_base32hex_tobuffer(isc_lex_t *lexer, isc_buffer_t *target, int length) {
	return base32_tobuffer(lexer, base32hex, true, target, length);
}

isc_result_t
isc_base32hexnp_tobuffer(isc_lex_t *lexer, isc_buffer_t *target, int length) {
	return base32_tobuffer(lexer, base32hex, false, target, length);
}

static isc_result_t
base32_decodestring(const char *cstr, const char base[], bool pad,
		    isc_buffer_t *target) {
	base32_decode_ctx_t ctx = {
		.length = -1, .base = base, .target = target, .pad = pad
	};

	for (;;) {
		int c = *cstr++;
		if (c == '\0') {
			break;
		}
		if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
			continue;
		}
		RETERR(base32_decode_char(&ctx, c));
	}
	RETERR(base32_decode_finish(&ctx));
	return ISC_R_SUCCESS;
}

isc_result_t
isc_base32_decodestring(const char *cstr, isc_buffer_t *target) {
	return base32_decodestring(cstr, base32, true, target);
}

isc_result_t
isc_base32hex_decodestring(const char *cstr, isc_buffer_t *target) {
	return base32_decodestring(cstr, base32hex, true, target);
}

isc_result_t
isc_base32hexnp_decodestring(const char *cstr, isc_buffer_t *target) {
	return base32_decodestring(cstr, base32hex, false, target);
}

static isc_result_t
base32_decoderegion(isc_region_t *source, const char base[], bool pad,
		    isc_buffer_t *target) {
	base32_decode_ctx_t ctx = {
		.length = -1, .base = base, .target = target, .pad = pad
	};

	while (source->length != 0) {
		int c = *source->base;
		RETERR(base32_decode_char(&ctx, c));
		isc_region_consume(source, 1);
	}
	RETERR(base32_decode_finish(&ctx));
	return ISC_R_SUCCESS;
}

isc_result_t
isc_base32_decoderegion(isc_region_t *source, isc_buffer_t *target) {
	return base32_decoderegion(source, base32, true, target);
}

isc_result_t
isc_base32hex_decoderegion(isc_region_t *source, isc_buffer_t *target) {
	return base32_decoderegion(source, base32hex, true, target);
}

isc_result_t
isc_base32hexnp_decoderegion(isc_region_t *source, isc_buffer_t *target) {
	return base32_decoderegion(source, base32hex, false, target);
}

static isc_result_t
str_totext(const char *source, isc_buffer_t *target) {
	unsigned int l;
	isc_region_t region;

	isc_buffer_availableregion(target, &region);
	l = strlen(source);

	if (l > region.length) {
		return ISC_R_NOSPACE;
	}

	memmove(region.base, source, l);
	isc_buffer_add(target, l);
	return ISC_R_SUCCESS;
}

static isc_result_t
mem_tobuffer(isc_buffer_t *target, void *base, unsigned int length) {
	isc_region_t tr;

	isc_buffer_availableregion(target, &tr);
	if (length > tr.length) {
		return ISC_R_NOSPACE;
	}
	memmove(tr.base, base, length);
	isc_buffer_add(target, length);
	return ISC_R_SUCCESS;
}
