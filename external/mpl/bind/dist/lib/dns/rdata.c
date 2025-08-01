/*	$NetBSD: rdata.c,v 1.18 2025/07/17 19:01:45 christos Exp $	*/

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

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>

#include <openssl/err.h>
#include <openssl/objects.h>

#include <isc/ascii.h>
#include <isc/base64.h>
#include <isc/hex.h>
#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/parseint.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/utf8.h>
#include <isc/util.h>

#include <dns/callbacks.h>
#include <dns/cert.h>
#include <dns/compress.h>
#include <dns/db.h>
#include <dns/dsdigest.h>
#include <dns/enumtype.h>
#include <dns/fixedname.h>
#include <dns/keyflags.h>
#include <dns/keyvalues.h>
#include <dns/message.h>
#include <dns/rcode.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdataset.h>
#include <dns/rdatastruct.h>
#include <dns/rdatatype.h>
#include <dns/secalg.h>
#include <dns/secproto.h>
#include <dns/time.h>
#include <dns/ttl.h>

#define RETERR(x)                        \
	do {                             \
		isc_result_t _r = (x);   \
		if (_r != ISC_R_SUCCESS) \
			return ((_r));   \
	} while (0)

#define RETTOK(x)                                          \
	do {                                               \
		isc_result_t _r = (x);                     \
		if (_r != ISC_R_SUCCESS) {                 \
			isc_lex_ungettoken(lexer, &token); \
			return (_r);                       \
		}                                          \
	} while (0)

#define CHECK(op)                            \
	do {                                 \
		result = (op);               \
		if (result != ISC_R_SUCCESS) \
			goto cleanup;        \
	} while (0)

#define CHECKTOK(op)                                       \
	do {                                               \
		result = (op);                             \
		if (result != ISC_R_SUCCESS) {             \
			isc_lex_ungettoken(lexer, &token); \
			goto cleanup;                      \
		}                                          \
	} while (0)

#define DNS_AS_STR(t) ((t).value.as_textregion.base)

#define ARGS_FROMTEXT                                           \
	int rdclass, dns_rdatatype_t type, isc_lex_t *lexer,    \
		const dns_name_t *origin, unsigned int options, \
		isc_buffer_t *target, dns_rdatacallbacks_t *callbacks

#define CALL_FROMTEXT rdclass, type, lexer, origin, options, target, callbacks

#define ARGS_TOTEXT \
	dns_rdata_t *rdata, dns_rdata_textctx_t *tctx, isc_buffer_t *target

#define CALL_TOTEXT rdata, tctx, target

#define ARGS_FROMWIRE                                            \
	int rdclass, dns_rdatatype_t type, isc_buffer_t *source, \
		dns_decompress_t dctx, isc_buffer_t *target

#define CALL_FROMWIRE rdclass, type, source, dctx, target

#define ARGS_TOWIRE \
	dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target

#define CALL_TOWIRE rdata, cctx, target

#define ARGS_COMPARE const dns_rdata_t *rdata1, const dns_rdata_t *rdata2

#define CALL_COMPARE rdata1, rdata2

#define ARGS_FROMSTRUCT \
	int rdclass, dns_rdatatype_t type, void *source, isc_buffer_t *target

#define CALL_FROMSTRUCT rdclass, type, source, target

#define ARGS_TOSTRUCT const dns_rdata_t *rdata, void *target, isc_mem_t *mctx

#define CALL_TOSTRUCT rdata, target, mctx

#define ARGS_FREESTRUCT void *source

#define CALL_FREESTRUCT source

#define ARGS_ADDLDATA                                \
	dns_rdata_t *rdata, const dns_name_t *owner, \
		dns_additionaldatafunc_t add, void *arg

#define CALL_ADDLDATA rdata, owner, add, arg

#define ARGS_DIGEST dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg

#define CALL_DIGEST rdata, digest, arg

#define ARGS_CHECKOWNER                                   \
	const dns_name_t *name, dns_rdataclass_t rdclass, \
		dns_rdatatype_t type, bool wildcard

#define CALL_CHECKOWNER name, rdclass, type, wildcard

#define ARGS_CHECKNAMES \
	dns_rdata_t *rdata, const dns_name_t *owner, dns_name_t *bad

#define CALL_CHECKNAMES rdata, owner, bad

/*%
 * Context structure for the totext_ functions.
 * Contains formatting options for rdata-to-text
 * conversion.
 */
typedef struct dns_rdata_textctx {
	const dns_name_t *origin;      /*%< Current origin, or NULL. */
	dns_masterstyle_flags_t flags; /*%< DNS_STYLEFLAG_*  */
	unsigned int width;	       /*%< Width of rdata column. */
	const char *linebreak;	       /*%< Line break string. */
} dns_rdata_textctx_t;

static isc_result_t
txt_totext(isc_region_t *source, bool quote, isc_buffer_t *target);

static isc_result_t
txt_fromtext(isc_textregion_t *source, isc_buffer_t *target);

static isc_result_t
txt_fromwire(isc_buffer_t *source, isc_buffer_t *target);

static isc_result_t
commatxt_fromtext(isc_textregion_t *source, bool comma, isc_buffer_t *target);

static isc_result_t
commatxt_totext(isc_region_t *source, bool quote, bool comma,
		isc_buffer_t *target);

static isc_result_t
multitxt_totext(isc_region_t *source, isc_buffer_t *target);

static isc_result_t
multitxt_fromtext(isc_textregion_t *source, isc_buffer_t *target);

static bool
name_prefix(dns_name_t *name, const dns_name_t *origin, dns_name_t *target);

static unsigned int
name_length(const dns_name_t *name);

static isc_result_t
str_totext(const char *source, isc_buffer_t *target);

static isc_result_t
inet_totext(int af, uint32_t flags, isc_region_t *src, isc_buffer_t *target);

static bool
buffer_empty(isc_buffer_t *source);

static void
buffer_fromregion(isc_buffer_t *buffer, isc_region_t *region);

static isc_result_t
uint32_tobuffer(uint32_t, isc_buffer_t *target);

static isc_result_t
uint16_tobuffer(uint32_t, isc_buffer_t *target);

static isc_result_t
uint8_tobuffer(uint32_t, isc_buffer_t *target);

static isc_result_t
name_tobuffer(const dns_name_t *name, isc_buffer_t *target);

static uint32_t
uint32_fromregion(isc_region_t *region);

static uint16_t
uint16_fromregion(isc_region_t *region);

static uint8_t
uint8_fromregion(isc_region_t *region);

static uint8_t
uint8_consume_fromregion(isc_region_t *region);

static isc_result_t
mem_tobuffer(isc_buffer_t *target, void *base, unsigned int length);

static int
hexvalue(char value);

static int
decvalue(char value);

static void
default_fromtext_callback(dns_rdatacallbacks_t *callbacks, const char *, ...)
	ISC_FORMAT_PRINTF(2, 3);

static void
fromtext_error(void (*callback)(dns_rdatacallbacks_t *, const char *, ...),
	       dns_rdatacallbacks_t *callbacks, const char *name,
	       unsigned long line, isc_token_t *token, isc_result_t result);

static void
fromtext_warneof(isc_lex_t *lexer, dns_rdatacallbacks_t *callbacks);

static isc_result_t
rdata_totext(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx,
	     isc_buffer_t *target);

static void
warn_badname(const dns_name_t *name, isc_lex_t *lexer,
	     dns_rdatacallbacks_t *callbacks);

static void
warn_badmx(isc_token_t *token, isc_lex_t *lexer,
	   dns_rdatacallbacks_t *callbacks);

static uint16_t
uint16_consume_fromregion(isc_region_t *region);

static isc_result_t
unknown_totext(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx,
	       isc_buffer_t *target);

static isc_result_t generic_fromtext_key(ARGS_FROMTEXT);

static isc_result_t generic_totext_key(ARGS_TOTEXT);

static isc_result_t generic_fromwire_key(ARGS_FROMWIRE);

static isc_result_t generic_fromstruct_key(ARGS_FROMSTRUCT);

static isc_result_t generic_tostruct_key(ARGS_TOSTRUCT);

static void generic_freestruct_key(ARGS_FREESTRUCT);

static isc_result_t generic_fromtext_txt(ARGS_FROMTEXT);

static isc_result_t generic_totext_txt(ARGS_TOTEXT);

static isc_result_t generic_fromwire_txt(ARGS_FROMWIRE);

static isc_result_t generic_fromstruct_txt(ARGS_FROMSTRUCT);

static isc_result_t generic_tostruct_txt(ARGS_TOSTRUCT);

static void generic_freestruct_txt(ARGS_FREESTRUCT);

static isc_result_t
generic_txt_first(dns_rdata_txt_t *txt);

static isc_result_t
generic_txt_next(dns_rdata_txt_t *txt);

static isc_result_t
generic_txt_current(dns_rdata_txt_t *txt, dns_rdata_txt_string_t *string);

static isc_result_t generic_totext_ds(ARGS_TOTEXT);

static isc_result_t generic_tostruct_ds(ARGS_TOSTRUCT);

static isc_result_t generic_fromtext_ds(ARGS_FROMTEXT);

static isc_result_t generic_fromwire_ds(ARGS_FROMWIRE);

static isc_result_t generic_fromstruct_ds(ARGS_FROMSTRUCT);

static isc_result_t generic_fromtext_tlsa(ARGS_FROMTEXT);

static isc_result_t generic_totext_tlsa(ARGS_TOTEXT);

static isc_result_t generic_fromwire_tlsa(ARGS_FROMWIRE);

static isc_result_t generic_fromstruct_tlsa(ARGS_FROMSTRUCT);

static isc_result_t generic_tostruct_tlsa(ARGS_TOSTRUCT);

static void generic_freestruct_tlsa(ARGS_FREESTRUCT);

static isc_result_t generic_fromtext_in_svcb(ARGS_FROMTEXT);
static isc_result_t generic_totext_in_svcb(ARGS_TOTEXT);
static isc_result_t generic_fromwire_in_svcb(ARGS_FROMWIRE);
static isc_result_t generic_towire_in_svcb(ARGS_TOWIRE);
static isc_result_t generic_fromstruct_in_svcb(ARGS_FROMSTRUCT);
static isc_result_t generic_tostruct_in_svcb(ARGS_TOSTRUCT);
static void generic_freestruct_in_svcb(ARGS_FREESTRUCT);
static isc_result_t generic_additionaldata_in_svcb(ARGS_ADDLDATA);
static bool generic_checknames_in_svcb(ARGS_CHECKNAMES);
static isc_result_t
generic_rdata_in_svcb_first(dns_rdata_in_svcb_t *);
static isc_result_t
generic_rdata_in_svcb_next(dns_rdata_in_svcb_t *);
static void
generic_rdata_in_svcb_current(dns_rdata_in_svcb_t *, isc_region_t *);

/*% INT16 Size */
#define NS_INT16SZ 2
/*% IPv6 Address Size */
#define NS_LOCATORSZ 8

/*
 * Active Directory gc._msdcs.<forest> prefix.
 */
static unsigned char gc_msdcs_data[] = "\002gc\006_msdcs";
static unsigned char gc_msdcs_offset[] = { 0, 3 };

static dns_name_t const gc_msdcs = DNS_NAME_INITNONABSOLUTE(gc_msdcs_data,
							    gc_msdcs_offset);

/*%
 *	convert presentation level address to network order binary form.
 * \return
 *	1 if `src' is a valid [RFC1884 2.2] address, else 0.
 * \note
 *	(1) does not touch `dst' unless it's returning 1.
 */
static int
locator_pton(const char *src, unsigned char *dst) {
	unsigned char tmp[NS_LOCATORSZ];
	unsigned char *tp = tmp, *endp;
	int ch, seen_xdigits;
	unsigned int val, hexval;

	memset(tp, '\0', NS_LOCATORSZ);
	endp = tp + NS_LOCATORSZ;
	seen_xdigits = 0;
	val = 0;
	while ((ch = *src++) != '\0') {
		hexval = isc_hex_char(ch);
		if (hexval != 0) {
			val <<= 4;
			val |= (ch - hexval);
			if (++seen_xdigits > 4) {
				return 0;
			}
			continue;
		}
		if (ch == ':') {
			if (!seen_xdigits) {
				return 0;
			}
			if (tp + NS_INT16SZ > endp) {
				return 0;
			}
			*tp++ = (unsigned char)(val >> 8) & 0xff;
			*tp++ = (unsigned char)val & 0xff;
			seen_xdigits = 0;
			val = 0;
			continue;
		}
		return 0;
	}
	if (seen_xdigits) {
		if (tp + NS_INT16SZ > endp) {
			return 0;
		}
		*tp++ = (unsigned char)(val >> 8) & 0xff;
		*tp++ = (unsigned char)val & 0xff;
	}
	if (tp != endp) {
		return 0;
	}
	memmove(dst, tmp, NS_LOCATORSZ);
	return 1;
}

static void
name_duporclone(const dns_name_t *source, isc_mem_t *mctx, dns_name_t *target) {
	if (mctx != NULL) {
		dns_name_dup(source, mctx, target);
	} else {
		dns_name_clone(source, target);
	}
}

static void *
mem_maybedup(isc_mem_t *mctx, void *source, size_t length) {
	void *copy = NULL;

	REQUIRE(source != NULL);

	if (mctx == NULL) {
		return source;
	}

	copy = isc_mem_allocate(mctx, length);
	memmove(copy, source, length);

	return copy;
}

static isc_result_t
typemap_fromtext(isc_lex_t *lexer, isc_buffer_t *target, bool allow_empty) {
	isc_token_t token;
	unsigned char bm[8 * 1024]; /* 64k bits */
	dns_rdatatype_t covered, max_used;
	int octet;
	unsigned int max_octet, newend, end;
	int window;
	bool first = true;

	max_used = 0;
	bm[0] = 0;
	end = 0;

	do {
		RETERR(isc_lex_getmastertoken(lexer, &token,
					      isc_tokentype_string, true));
		if (token.type != isc_tokentype_string) {
			break;
		}
		RETTOK(dns_rdatatype_fromtext(&covered,
					      &token.value.as_textregion));
		if (covered > max_used) {
			newend = covered / 8;
			if (newend > end) {
				memset(&bm[end + 1], 0, newend - end);
				end = newend;
			}
			max_used = covered;
		}
		bm[covered / 8] |= (0x80 >> (covered % 8));
		first = false;
	} while (1);
	isc_lex_ungettoken(lexer, &token);
	if (!allow_empty && first) {
		return DNS_R_FORMERR;
	}

	for (window = 0; window < 256; window++) {
		if (max_used < window * 256) {
			break;
		}

		max_octet = max_used - (window * 256);
		if (max_octet >= 256) {
			max_octet = 31;
		} else {
			max_octet /= 8;
		}

		/*
		 * Find if we have a type in this window.
		 */
		for (octet = max_octet; octet >= 0; octet--) {
			if (bm[window * 32 + octet] != 0) {
				break;
			}
		}
		if (octet < 0) {
			continue;
		}
		RETERR(uint8_tobuffer(window, target));
		RETERR(uint8_tobuffer(octet + 1, target));
		RETERR(mem_tobuffer(target, &bm[window * 32], octet + 1));
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
typemap_totext(isc_region_t *sr, dns_rdata_textctx_t *tctx,
	       isc_buffer_t *target) {
	unsigned int i, j, k;
	unsigned int window, len;
	bool first = true;

	for (i = 0; i < sr->length; i += len) {
		if (tctx != NULL &&
		    (tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0)
		{
			RETERR(str_totext(tctx->linebreak, target));
			first = true;
		}
		INSIST(i + 2 <= sr->length);
		window = sr->base[i];
		len = sr->base[i + 1];
		INSIST(len > 0 && len <= 32);
		i += 2;
		INSIST(i + len <= sr->length);
		for (j = 0; j < len; j++) {
			dns_rdatatype_t t;
			if (sr->base[i + j] == 0) {
				continue;
			}
			for (k = 0; k < 8; k++) {
				if ((sr->base[i + j] & (0x80 >> k)) == 0) {
					continue;
				}
				t = window * 256 + j * 8 + k;
				if (!first) {
					RETERR(str_totext(" ", target));
				}
				first = false;
				if (dns_rdatatype_isknown(t)) {
					RETERR(dns_rdatatype_totext(t, target));
				} else {
					char buf[sizeof("TYPE65535")];
					snprintf(buf, sizeof(buf), "TYPE%u", t);
					RETERR(str_totext(buf, target));
				}
			}
		}
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
typemap_test(isc_region_t *sr, bool allow_empty) {
	unsigned int window, lastwindow = 0;
	unsigned int len;
	bool first = true;
	unsigned int i;

	for (i = 0; i < sr->length; i += len) {
		/*
		 * Check for overflow.
		 */
		if (i + 2 > sr->length) {
			RETERR(DNS_R_FORMERR);
		}
		window = sr->base[i];
		len = sr->base[i + 1];
		i += 2;
		/*
		 * Check that bitmap windows are in the correct order.
		 */
		if (!first && window <= lastwindow) {
			RETERR(DNS_R_FORMERR);
		}
		/*
		 * Check for legal lengths.
		 */
		if (len < 1 || len > 32) {
			RETERR(DNS_R_FORMERR);
		}
		/*
		 * Check for overflow.
		 */
		if (i + len > sr->length) {
			RETERR(DNS_R_FORMERR);
		}
		/*
		 * The last octet of the bitmap must be non zero.
		 */
		if (sr->base[i + len - 1] == 0) {
			RETERR(DNS_R_FORMERR);
		}
		lastwindow = window;
		first = false;
	}
	if (i != sr->length) {
		return DNS_R_EXTRADATA;
	}
	if (!allow_empty && first) {
		RETERR(DNS_R_FORMERR);
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
check_private(isc_buffer_t *source, dns_secalg_t alg) {
	isc_region_t sr;
	if (alg == DNS_KEYALG_PRIVATEDNS) {
		dns_fixedname_t fixed;

		RETERR(dns_name_fromwire(dns_fixedname_initname(&fixed), source,
					 DNS_DECOMPRESS_DEFAULT, NULL));
	} else if (alg == DNS_KEYALG_PRIVATEOID) {
		/*
		 * Check that we can extract the OID from the start of the
		 * key data. We have a length byte followed by the OID BER
		 * encoded.
		 */
		const unsigned char *in = NULL;
		ASN1_OBJECT *obj = NULL;

		isc_buffer_activeregion(source, &sr);
		if (sr.length < 1 || (unsigned int)*sr.base + 1 > sr.length) {
			RETERR(DNS_R_FORMERR);
		}
		in = sr.base + 1;
		obj = d2i_ASN1_OBJECT(NULL, &in, *sr.base);
		if (obj == NULL) {
			ERR_clear_error();
			RETERR(DNS_R_FORMERR);
		}
		ASN1_OBJECT_free(obj);
		if ((in - sr.base) != (*sr.base + 1)) {
			RETERR(DNS_R_FORMERR);
		}
	}
	return ISC_R_SUCCESS;
}

/*
 * A relative URI template that has a "dns" variable.
 */
static bool
validate_dohpath(isc_region_t *region) {
	const unsigned char *p;
	const unsigned char *v = NULL;
	const unsigned char *n = NULL;
	unsigned char c;
	bool dns = false;
	bool wasop = false;
	enum {
		path,
		variable,
		percent1,
		percent2,
		variable_percent1,
		variable_percent2,
		prefix,
		explode
	} state = path;

	if (region->length == 0 || *region->base != '/' ||
	    !isc_utf8_valid(region->base, region->length))
	{
		return false;
	}

	/*
	 * RFC 6570 URI Template check + "dns" variable.
	 */
	p = region->base;
	while (p < region->base + region->length) {
		switch (state) {
		case path:
			switch (*p++) {
			case '{': /*}*/
				state = variable;
				wasop = false;
				v = p;
				break;
			case '%':
				state = percent1;
				break;
			default:
				break;
			}
			break;
		case variable:
			c = *p++;
			switch (c) {
			case '+':
			case '#':
			case '.':
			case '/':
			case ';':
			case '?':
			case '&':
				/* Operators. */
				if (p != v + 1 || wasop) {
					return false;
				}
				wasop = true;
				v = p;
				break;
			case '=':
			case '!':
			case '@':
			case '|':
				/* Reserved operators. */
				return false;
			case '*':
			case ':':
			case '}':
			case ',':
				/* Found the end of the variable name. */
				if (p == (v + 1)) {
					return false;
				}
				/* 'p' has been incremented so 4 not 3 */
				if ((p - v) == 4 && memcmp(v, "dns", 3) == 0) {
					dns = true;
				}
				switch (c) {
				case ':':
					state = prefix;
					n = p;
					break;
				case /*{*/ '}':
					state = path;
					break;
				case '*':
					state = explode;
					break;
				case ',':
					wasop = false;
					v = p;
					break;
				}
				break;
			case '%':
				/* Percent encoded variable name. */
				state = variable_percent1;
				break;
			default:
				/* Valid variable name character? */
				if (c != '_' && !isalnum(c)) {
					return false;
				}
				break;
			}
			break;
		case explode:
			switch (*p++) {
			case ',':
				state = variable;
				wasop = false;
				v = p;
				break;
			case /*}*/ '}':
				state = path;
				break;
			default:
				return false;
			}
			break;
		/* Check % encoding */
		case percent1:
		case percent2:
		case variable_percent1:
		case variable_percent2:
			/* bad percent encoding? */
			if (!isxdigit(*p++)) {
				return false;
			}
			if (state == percent1) {
				state = percent2;
			} else if (state == percent2) {
				state = path;
			} else if (state == variable_percent1) {
				state = variable_percent2;
			} else {
				state = variable;
			}
			break;
		case prefix:
			c = *p++;
			if (!isdigit(c)) {
				/* valid number range [1..9999] */
				if ((p == n + 1) || (p - n) > 5 || *n == '0') {
					return false;
				}
				switch (c) {
				case ',':
					state = variable;
					wasop = false;
					break;
				case /*{*/ '}':
					state = path;
					break;
				default:
					return false;
				}
			}
			break;
		}
	}
	return state == path && dns;
}

#include "code.h"

#define META	 0x0001
#define RESERVED 0x0002

/***
 *** Initialization
 ***/

void
dns_rdata_init(dns_rdata_t *rdata) {
	REQUIRE(rdata != NULL);

	rdata->data = NULL;
	rdata->length = 0;
	rdata->rdclass = 0;
	rdata->type = 0;
	rdata->flags = 0;
	ISC_LINK_INIT(rdata, link);
	/* ISC_LIST_INIT(rdata->list); */
}

void
dns_rdata_reset(dns_rdata_t *rdata) {
	REQUIRE(rdata != NULL);

	REQUIRE(!ISC_LINK_LINKED(rdata, link));
	REQUIRE(DNS_RDATA_VALIDFLAGS(rdata));

	rdata->data = NULL;
	rdata->length = 0;
	rdata->rdclass = 0;
	rdata->type = 0;
	rdata->flags = 0;
}

/***
 ***
 ***/

void
dns_rdata_clone(const dns_rdata_t *src, dns_rdata_t *target) {
	REQUIRE(src != NULL);
	REQUIRE(target != NULL);

	REQUIRE(DNS_RDATA_INITIALIZED(target));

	REQUIRE(DNS_RDATA_VALIDFLAGS(src));
	REQUIRE(DNS_RDATA_VALIDFLAGS(target));

	target->data = src->data;
	target->length = src->length;
	target->rdclass = src->rdclass;
	target->type = src->type;
	target->flags = src->flags;
}

/***
 *** Comparisons
 ***/

int
dns_rdata_compare(const dns_rdata_t *rdata1, const dns_rdata_t *rdata2) {
	int result = 0;
	bool use_default = false;

	REQUIRE(rdata1 != NULL);
	REQUIRE(rdata2 != NULL);
	REQUIRE(rdata1->length == 0 || rdata1->data != NULL);
	REQUIRE(rdata2->length == 0 || rdata2->data != NULL);
	REQUIRE(DNS_RDATA_VALIDFLAGS(rdata1));
	REQUIRE(DNS_RDATA_VALIDFLAGS(rdata2));

	if (rdata1->rdclass != rdata2->rdclass) {
		return rdata1->rdclass < rdata2->rdclass ? -1 : 1;
	}

	if (rdata1->type != rdata2->type) {
		return rdata1->type < rdata2->type ? -1 : 1;
	}

	COMPARESWITCH

	if (use_default) {
		isc_region_t r1;
		isc_region_t r2;

		dns_rdata_toregion(rdata1, &r1);
		dns_rdata_toregion(rdata2, &r2);
		result = isc_region_compare(&r1, &r2);
	}
	return result;
}

int
dns_rdata_casecompare(const dns_rdata_t *rdata1, const dns_rdata_t *rdata2) {
	int result = 0;
	bool use_default = false;

	REQUIRE(rdata1 != NULL);
	REQUIRE(rdata2 != NULL);
	REQUIRE(rdata1->length == 0 || rdata1->data != NULL);
	REQUIRE(rdata2->length == 0 || rdata2->data != NULL);
	REQUIRE(DNS_RDATA_VALIDFLAGS(rdata1));
	REQUIRE(DNS_RDATA_VALIDFLAGS(rdata2));

	if (rdata1->rdclass != rdata2->rdclass) {
		return rdata1->rdclass < rdata2->rdclass ? -1 : 1;
	}

	if (rdata1->type != rdata2->type) {
		return rdata1->type < rdata2->type ? -1 : 1;
	}

	CASECOMPARESWITCH

	if (use_default) {
		isc_region_t r1;
		isc_region_t r2;

		dns_rdata_toregion(rdata1, &r1);
		dns_rdata_toregion(rdata2, &r2);
		result = isc_region_compare(&r1, &r2);
	}
	return result;
}

/***
 *** Conversions
 ***/

void
dns_rdata_fromregion(dns_rdata_t *rdata, dns_rdataclass_t rdclass,
		     dns_rdatatype_t type, isc_region_t *r) {
	REQUIRE(rdata != NULL);
	REQUIRE(DNS_RDATA_INITIALIZED(rdata));
	REQUIRE(r != NULL);

	REQUIRE(DNS_RDATA_VALIDFLAGS(rdata));

	rdata->data = r->base;
	rdata->length = r->length;
	rdata->rdclass = rdclass;
	rdata->type = type;
	rdata->flags = 0;
}

void
dns_rdata_toregion(const dns_rdata_t *rdata, isc_region_t *r) {
	REQUIRE(rdata != NULL);
	REQUIRE(r != NULL);
	REQUIRE(DNS_RDATA_VALIDFLAGS(rdata));

	r->base = rdata->data;
	r->length = rdata->length;
}

isc_result_t
dns_rdata_fromwire(dns_rdata_t *rdata, dns_rdataclass_t rdclass,
		   dns_rdatatype_t type, isc_buffer_t *source,
		   dns_decompress_t dctx, isc_buffer_t *target) {
	isc_result_t result = ISC_R_NOTIMPLEMENTED;
	isc_region_t region;
	isc_buffer_t ss;
	isc_buffer_t st;
	bool use_default = false;
	uint32_t activelength;
	unsigned int length;

	if (rdata != NULL) {
		REQUIRE(DNS_RDATA_INITIALIZED(rdata));
		REQUIRE(DNS_RDATA_VALIDFLAGS(rdata));
	}
	REQUIRE(source != NULL);
	REQUIRE(target != NULL);

	if (type == 0) {
		return DNS_R_FORMERR;
	}

	ss = *source;
	st = *target;

	activelength = isc_buffer_activelength(source);
	INSIST(activelength < 65536);

	FROMWIRESWITCH

	if (use_default) {
		if (activelength > isc_buffer_availablelength(target)) {
			result = ISC_R_NOSPACE;
		} else {
			isc_buffer_putmem(target, isc_buffer_current(source),
					  activelength);
			isc_buffer_forward(source, activelength);
			result = ISC_R_SUCCESS;
		}
	}

	/*
	 * Reject any rdata that expands out to more than DNS_RDATA_MAXLENGTH
	 * as we cannot transmit it.
	 */
	length = isc_buffer_usedlength(target) - isc_buffer_usedlength(&st);
	if (result == ISC_R_SUCCESS && length > DNS_RDATA_MAXLENGTH) {
		result = DNS_R_FORMERR;
	}

	/*
	 * We should have consumed all of our buffer.
	 */
	if (result == ISC_R_SUCCESS && !buffer_empty(source)) {
		result = DNS_R_EXTRADATA;
	}

	if (rdata != NULL && result == ISC_R_SUCCESS) {
		region.base = isc_buffer_used(&st);
		region.length = length;
		dns_rdata_fromregion(rdata, rdclass, type, &region);
	}

	if (result != ISC_R_SUCCESS) {
		*source = ss;
		*target = st;
	}
	return result;
}

isc_result_t
dns_rdata_towire(dns_rdata_t *rdata, dns_compress_t *cctx,
		 isc_buffer_t *target) {
	isc_result_t result = ISC_R_NOTIMPLEMENTED;
	bool use_default = false;
	isc_region_t tr;
	isc_buffer_t st;

	REQUIRE(rdata != NULL);
	REQUIRE(DNS_RDATA_VALIDFLAGS(rdata));

	/*
	 * Some DynDNS meta-RRs have empty rdata.
	 */
	if ((rdata->flags & DNS_RDATA_UPDATE) != 0) {
		INSIST(rdata->length == 0);
		return ISC_R_SUCCESS;
	}

	st = *target;

	TOWIRESWITCH

	if (use_default) {
		isc_buffer_availableregion(target, &tr);
		if (tr.length < rdata->length) {
			return ISC_R_NOSPACE;
		}
		memmove(tr.base, rdata->data, rdata->length);
		isc_buffer_add(target, rdata->length);
		return ISC_R_SUCCESS;
	}
	if (result != ISC_R_SUCCESS) {
		*target = st;
		dns_compress_rollback(cctx, target->used);
	}
	return result;
}

/*
 * If the binary data in 'src' is valid uncompressed wire format
 * rdata of class 'rdclass' and type 'type', return ISC_R_SUCCESS
 * and copy the validated rdata to 'dest'.  Otherwise return an error.
 */
static isc_result_t
rdata_validate(isc_buffer_t *src, isc_buffer_t *dest, dns_rdataclass_t rdclass,
	       dns_rdatatype_t type) {
	isc_result_t result;

	isc_buffer_setactive(src, isc_buffer_usedlength(src));
	result = dns_rdata_fromwire(NULL, rdclass, type, src,
				    DNS_DECOMPRESS_NEVER, dest);

	return result;
}

static isc_result_t
unknown_fromtext(dns_rdataclass_t rdclass, dns_rdatatype_t type,
		 isc_lex_t *lexer, isc_mem_t *mctx, isc_buffer_t *target) {
	isc_result_t result;
	isc_buffer_t *buf = NULL;
	isc_token_t token;

	if (type == 0 || dns_rdatatype_ismeta(type)) {
		return DNS_R_METATYPE;
	}

	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_number,
				      false));
	if (token.value.as_ulong > 65535U) {
		return ISC_R_RANGE;
	}
	isc_buffer_allocate(mctx, &buf, token.value.as_ulong);

	if (token.value.as_ulong != 0U) {
		result = isc_hex_tobuffer(lexer, buf,
					  (unsigned int)token.value.as_ulong);
		if (result != ISC_R_SUCCESS) {
			goto failure;
		}
		if (isc_buffer_usedlength(buf) != token.value.as_ulong) {
			result = ISC_R_UNEXPECTEDEND;
			goto failure;
		}
	}

	if (dns_rdatatype_isknown(type)) {
		result = rdata_validate(buf, target, rdclass, type);
	} else {
		isc_region_t r;
		isc_buffer_usedregion(buf, &r);
		result = isc_buffer_copyregion(target, &r);
	}
	if (result != ISC_R_SUCCESS) {
		goto failure;
	}

	isc_buffer_free(&buf);
	return ISC_R_SUCCESS;

failure:
	isc_buffer_free(&buf);
	return result;
}

isc_result_t
dns_rdata_fromtext(dns_rdata_t *rdata, dns_rdataclass_t rdclass,
		   dns_rdatatype_t type, isc_lex_t *lexer,
		   const dns_name_t *origin, unsigned int options,
		   isc_mem_t *mctx, isc_buffer_t *target,
		   dns_rdatacallbacks_t *callbacks) {
	isc_result_t result = ISC_R_NOTIMPLEMENTED;
	isc_region_t region;
	isc_buffer_t st;
	isc_token_t token;
	unsigned int lexoptions = ISC_LEXOPT_EOL | ISC_LEXOPT_EOF |
				  ISC_LEXOPT_DNSMULTILINE | ISC_LEXOPT_ESCAPE;
	char *name;
	unsigned long line;
	void (*callback)(dns_rdatacallbacks_t *, const char *, ...);
	isc_result_t tresult;
	unsigned int length;
	bool unknown;

	REQUIRE(origin == NULL || dns_name_isabsolute(origin));
	if (rdata != NULL) {
		REQUIRE(DNS_RDATA_INITIALIZED(rdata));
		REQUIRE(DNS_RDATA_VALIDFLAGS(rdata));
	}
	if (callbacks != NULL) {
		REQUIRE(callbacks->warn != NULL);
		REQUIRE(callbacks->error != NULL);
	}

	st = *target;

	if (callbacks != NULL) {
		callback = callbacks->error;
	} else {
		callback = default_fromtext_callback;
	}

	result = isc_lex_getmastertoken(lexer, &token, isc_tokentype_qstring,
					true);
	if (result != ISC_R_SUCCESS) {
		name = isc_lex_getsourcename(lexer);
		line = isc_lex_getsourceline(lexer);
		fromtext_error(callback, callbacks, name, line, NULL, result);
		return result;
	}

	unknown = false;
	if (token.type == isc_tokentype_string &&
	    strcmp(DNS_AS_STR(token), "\\#") == 0)
	{
		/*
		 * If this is a TXT record '\#' could be a escaped '#'.
		 * Look to see if the next token is a number and if so
		 * treat it as a unknown record format.
		 */
		if (type == dns_rdatatype_txt) {
			result = isc_lex_getmastertoken(
				lexer, &token, isc_tokentype_number, false);
			if (result == ISC_R_SUCCESS) {
				isc_lex_ungettoken(lexer, &token);
			}
		}

		if (result == ISC_R_SUCCESS) {
			unknown = true;
			result = unknown_fromtext(rdclass, type, lexer, mctx,
						  target);
		} else {
			options |= DNS_RDATA_UNKNOWNESCAPE;
		}
	} else {
		isc_lex_ungettoken(lexer, &token);
	}

	if (!unknown) {
		FROMTEXTSWITCH

		/*
		 * Consume to end of line / file.
		 * If not at end of line initially set error code.
		 * Call callback via fromtext_error once if there was an error.
		 */
	}
	do {
		name = isc_lex_getsourcename(lexer);
		line = isc_lex_getsourceline(lexer);
		tresult = isc_lex_gettoken(lexer, lexoptions, &token);
		if (tresult != ISC_R_SUCCESS) {
			if (result == ISC_R_SUCCESS) {
				result = tresult;
			}
			if (callback != NULL) {
				fromtext_error(callback, callbacks, name, line,
					       NULL, result);
			}
			break;
		} else if (token.type != isc_tokentype_eol &&
			   token.type != isc_tokentype_eof)
		{
			if (result == ISC_R_SUCCESS) {
				result = DNS_R_EXTRATOKEN;
			}
			if (callback != NULL) {
				fromtext_error(callback, callbacks, name, line,
					       &token, result);
				callback = NULL;
			}
		} else if (result != ISC_R_SUCCESS && callback != NULL) {
			fromtext_error(callback, callbacks, name, line, &token,
				       result);
			break;
		} else {
			if (token.type == isc_tokentype_eof) {
				fromtext_warneof(lexer, callbacks);
			}
			break;
		}
	} while (1);

	length = isc_buffer_usedlength(target) - isc_buffer_usedlength(&st);
	if (result == ISC_R_SUCCESS && length > DNS_RDATA_MAXLENGTH) {
		result = ISC_R_NOSPACE;
	}

	if (rdata != NULL && result == ISC_R_SUCCESS) {
		region.base = isc_buffer_used(&st);
		region.length = length;
		dns_rdata_fromregion(rdata, rdclass, type, &region);
	}
	if (result != ISC_R_SUCCESS) {
		*target = st;
	}
	return result;
}

static isc_result_t
unknown_totext(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx,
	       isc_buffer_t *target) {
	isc_result_t result;
	char buf[sizeof("65535")];
	isc_region_t sr;

	strlcpy(buf, "\\# ", sizeof(buf));
	result = str_totext(buf, target);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	dns_rdata_toregion(rdata, &sr);
	INSIST(sr.length < 65536);
	snprintf(buf, sizeof(buf), "%u", sr.length);
	result = str_totext(buf, target);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	if (sr.length != 0U) {
		if ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0) {
			result = str_totext(" ( ", target);
		} else {
			result = str_totext(" ", target);
		}

		if (result != ISC_R_SUCCESS) {
			return result;
		}

		if (tctx->width == 0) { /* No splitting */
			result = isc_hex_totext(&sr, 0, "", target);
		} else {
			result = isc_hex_totext(&sr, tctx->width - 2,
						tctx->linebreak, target);
		}
		if (result == ISC_R_SUCCESS &&
		    (tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0)
		{
			result = str_totext(" )", target);
		}
	}
	return result;
}

static isc_result_t
rdata_totext(dns_rdata_t *rdata, dns_rdata_textctx_t *tctx,
	     isc_buffer_t *target) {
	isc_result_t result = ISC_R_NOTIMPLEMENTED;
	bool use_default = false;
	unsigned int cur;

	REQUIRE(rdata != NULL);
	REQUIRE(tctx->origin == NULL || dns_name_isabsolute(tctx->origin));

	/*
	 * Some DynDNS meta-RRs have empty rdata.
	 */
	if ((rdata->flags & DNS_RDATA_UPDATE) != 0) {
		INSIST(rdata->length == 0);
		return ISC_R_SUCCESS;
	}

	if ((tctx->flags & DNS_STYLEFLAG_UNKNOWNFORMAT) != 0) {
		return unknown_totext(rdata, tctx, target);
	}

	cur = isc_buffer_usedlength(target);

	TOTEXTSWITCH

	if (use_default || (result == ISC_R_NOTIMPLEMENTED)) {
		unsigned int u = isc_buffer_usedlength(target);

		INSIST(u >= cur);
		isc_buffer_subtract(target, u - cur);
		result = unknown_totext(rdata, tctx, target);
	}

	return result;
}

isc_result_t
dns_rdata_totext(dns_rdata_t *rdata, const dns_name_t *origin,
		 isc_buffer_t *target) {
	dns_rdata_textctx_t tctx;

	REQUIRE(DNS_RDATA_VALIDFLAGS(rdata));

	/*
	 * Set up formatting options for single-line output.
	 */
	tctx.origin = origin;
	tctx.flags = 0;
	tctx.width = 60;
	tctx.linebreak = " ";
	return rdata_totext(rdata, &tctx, target);
}

isc_result_t
dns_rdata_tofmttext(dns_rdata_t *rdata, const dns_name_t *origin,
		    dns_masterstyle_flags_t flags, unsigned int width,
		    unsigned int split_width, const char *linebreak,
		    isc_buffer_t *target) {
	dns_rdata_textctx_t tctx;

	REQUIRE(DNS_RDATA_VALIDFLAGS(rdata));

	/*
	 * Set up formatting options for formatted output.
	 */
	tctx.origin = origin;
	tctx.flags = flags;
	if (split_width == 0xffffffff) {
		tctx.width = width;
	} else {
		tctx.width = split_width;
	}

	if ((flags & DNS_STYLEFLAG_MULTILINE) != 0) {
		tctx.linebreak = linebreak;
	} else {
		if (split_width == 0xffffffff) {
			tctx.width = 60; /* Used for hex word length only. */
		}
		tctx.linebreak = " ";
	}
	return rdata_totext(rdata, &tctx, target);
}

isc_result_t
dns_rdata_fromstruct(dns_rdata_t *rdata, dns_rdataclass_t rdclass,
		     dns_rdatatype_t type, void *source, isc_buffer_t *target) {
	isc_result_t result = ISC_R_NOTIMPLEMENTED;
	isc_buffer_t st;
	isc_region_t region;
	bool use_default = false;
	unsigned int length;

	REQUIRE(source != NULL);
	if (rdata != NULL) {
		REQUIRE(DNS_RDATA_INITIALIZED(rdata));
		REQUIRE(DNS_RDATA_VALIDFLAGS(rdata));
	}

	st = *target;

	FROMSTRUCTSWITCH

	if (use_default) {
		(void)NULL;
	}

	length = isc_buffer_usedlength(target) - isc_buffer_usedlength(&st);
	if (result == ISC_R_SUCCESS && length > DNS_RDATA_MAXLENGTH) {
		result = ISC_R_NOSPACE;
	}

	if (rdata != NULL && result == ISC_R_SUCCESS) {
		region.base = isc_buffer_used(&st);
		region.length = length;
		dns_rdata_fromregion(rdata, rdclass, type, &region);
	}
	if (result != ISC_R_SUCCESS) {
		*target = st;
	}
	return result;
}

isc_result_t
dns_rdata_tostruct(const dns_rdata_t *rdata, void *target, isc_mem_t *mctx) {
	isc_result_t result = ISC_R_NOTIMPLEMENTED;
	bool use_default = false;

	REQUIRE(rdata != NULL);
	REQUIRE(DNS_RDATA_VALIDFLAGS(rdata));
	REQUIRE((rdata->flags & DNS_RDATA_UPDATE) == 0);

	TOSTRUCTSWITCH

	if (use_default) {
		(void)NULL;
	}

	return result;
}

void
dns_rdata_freestruct(void *source) {
	dns_rdatacommon_t *common = source;
	REQUIRE(common != NULL);

	FREESTRUCTSWITCH
}

isc_result_t
dns_rdata_additionaldata(dns_rdata_t *rdata, const dns_name_t *owner,
			 dns_additionaldatafunc_t add, void *arg) {
	isc_result_t result = ISC_R_NOTIMPLEMENTED;
	bool use_default = false;

	/*
	 * Call 'add' for each name and type from 'rdata' which is subject to
	 * additional section processing.
	 */

	REQUIRE(rdata != NULL);
	REQUIRE(add != NULL);
	REQUIRE(DNS_RDATA_VALIDFLAGS(rdata));

	ADDITIONALDATASWITCH

	/* No additional processing for unknown types */
	if (use_default) {
		result = ISC_R_SUCCESS;
	}

	return result;
}

isc_result_t
dns_rdata_digest(dns_rdata_t *rdata, dns_digestfunc_t digest, void *arg) {
	isc_result_t result = ISC_R_NOTIMPLEMENTED;
	bool use_default = false;
	isc_region_t r;

	/*
	 * Send 'rdata' in DNSSEC canonical form to 'digest'.
	 */

	REQUIRE(rdata != NULL);
	REQUIRE(digest != NULL);
	REQUIRE(DNS_RDATA_VALIDFLAGS(rdata));

	DIGESTSWITCH

	if (use_default) {
		dns_rdata_toregion(rdata, &r);
		result = (digest)(arg, &r);
	}

	return result;
}

bool
dns_rdata_checkowner(const dns_name_t *name, dns_rdataclass_t rdclass,
		     dns_rdatatype_t type, bool wildcard) {
	bool result;

	CHECKOWNERSWITCH
	return result;
}

bool
dns_rdata_checknames(dns_rdata_t *rdata, const dns_name_t *owner,
		     dns_name_t *bad) {
	bool result;

	CHECKNAMESSWITCH
	return result;
}

unsigned int
dns_rdatatype_attributes(dns_rdatatype_t type) {
	RDATATYPE_ATTRIBUTE_SW
	if (type >= (dns_rdatatype_t)128 && type <= (dns_rdatatype_t)255) {
		return DNS_RDATATYPEATTR_UNKNOWN | DNS_RDATATYPEATTR_META;
	}
	return DNS_RDATATYPEATTR_UNKNOWN;
}

isc_result_t
dns_rdatatype_fromtext(dns_rdatatype_t *typep, isc_textregion_t *source) {
	unsigned int hash;
	unsigned int n;
	unsigned char a, b;

	n = source->length;

	if (n == 0) {
		return DNS_R_UNKNOWN;
	}

	a = isc_ascii_tolower(source->base[0]);
	b = isc_ascii_tolower(source->base[n - 1]);

	hash = ((a + n) * b) % 256;

	/*
	 * This switch block is inlined via \#define, and will use "return"
	 * to return a result to the caller if it is a valid (known)
	 * rdatatype name.
	 */
	RDATATYPE_FROMTEXT_SW(hash, source->base, n, typep);

	if (source->length > 4 && source->length < (4 + sizeof("65000")) &&
	    strncasecmp("type", source->base, 4) == 0)
	{
		char buf[sizeof("65000")];
		char *endp;
		unsigned int val;

		/*
		 * source->base is not required to be NUL terminated.
		 * Copy up to remaining bytes and NUL terminate.
		 */
		snprintf(buf, sizeof(buf), "%.*s", (int)(source->length - 4),
			 source->base + 4);
		val = strtoul(buf, &endp, 10);
		if (*endp == '\0' && val <= 0xffff) {
			*typep = (dns_rdatatype_t)val;
			return ISC_R_SUCCESS;
		}
	}

	return DNS_R_UNKNOWN;
}

isc_result_t
dns_rdatatype_totext(dns_rdatatype_t type, isc_buffer_t *target) {
	RDATATYPE_TOTEXT_SW

	return dns_rdatatype_tounknowntext(type, target);
}

isc_result_t
dns_rdatatype_tounknowntext(dns_rdatatype_t type, isc_buffer_t *target) {
	char buf[sizeof("TYPE65535")];

	snprintf(buf, sizeof(buf), "TYPE%u", type);
	return str_totext(buf, target);
}

void
dns_rdatatype_format(dns_rdatatype_t rdtype, char *array, unsigned int size) {
	isc_result_t result;
	isc_buffer_t buf;

	if (size == 0U) {
		return;
	}

	isc_buffer_init(&buf, array, size);
	result = dns_rdatatype_totext(rdtype, &buf);
	/*
	 * Null terminate.
	 */
	if (result == ISC_R_SUCCESS) {
		if (isc_buffer_availablelength(&buf) >= 1) {
			isc_buffer_putuint8(&buf, 0);
		} else {
			result = ISC_R_NOSPACE;
		}
	}
	if (result != ISC_R_SUCCESS) {
		strlcpy(array, "<unknown>", size);
	}
}

/*
 * Private function.
 */

static unsigned int
name_length(const dns_name_t *name) {
	return name->length;
}

static isc_result_t
commatxt_totext(isc_region_t *source, bool quote, bool comma,
		isc_buffer_t *target) {
	unsigned int tl;
	unsigned int n;
	unsigned char *sp;
	char *tp;
	isc_region_t region;

	isc_buffer_availableregion(target, &region);
	sp = source->base;
	tp = (char *)region.base;
	tl = region.length;

	n = *sp++;

	REQUIRE(n + 1 <= source->length);
	if (n == 0U) {
		REQUIRE(quote);
	}

	if (quote) {
		if (tl < 1) {
			return ISC_R_NOSPACE;
		}
		*tp++ = '"';
		tl--;
	}
	while (n--) {
		/*
		 * \DDD space (0x20) if not quoting.
		 */
		if (*sp < (quote ? ' ' : '!') || *sp >= 0x7f) {
			if (tl < 4) {
				return ISC_R_NOSPACE;
			}
			*tp++ = '\\';
			*tp++ = '0' + ((*sp / 100) % 10);
			*tp++ = '0' + ((*sp / 10) % 10);
			*tp++ = '0' + (*sp % 10);
			sp++;
			tl -= 4;
			continue;
		}
		/*
		 * Escape double quote and backslash.  If we are not
		 * enclosing the string in double quotes, also escape
		 * at sign (@) and semicolon (;) unless comma is set.
		 * If comma is set, then only escape commas (,).
		 */
		if (*sp == '"' || *sp == '\\' || (comma && *sp == ',') ||
		    (!comma && !quote && (*sp == '@' || *sp == ';')))
		{
			if (tl < 2) {
				return ISC_R_NOSPACE;
			}
			*tp++ = '\\';
			tl--;
			/*
			 * Perform comma escape processing.
			 * ',' => '\\,'
			 * '\' => '\\\\'
			 */
			if (comma && (*sp == ',' || *sp == '\\')) {
				if (tl < ((*sp == '\\') ? 3 : 2)) {
					return ISC_R_NOSPACE;
				}
				*tp++ = '\\';
				tl--;
				if (*sp == '\\') {
					*tp++ = '\\';
					tl--;
				}
			}
		}
		if (tl < 1) {
			return ISC_R_NOSPACE;
		}
		*tp++ = *sp++;
		tl--;
	}
	if (quote) {
		if (tl < 1) {
			return ISC_R_NOSPACE;
		}
		*tp++ = '"';
		tl--;
		POST(tl);
	}
	isc_buffer_add(target, (unsigned int)(tp - (char *)region.base));
	isc_region_consume(source, *source->base + 1);
	return ISC_R_SUCCESS;
}

static isc_result_t
txt_totext(isc_region_t *source, bool quote, isc_buffer_t *target) {
	return commatxt_totext(source, quote, false, target);
}

static isc_result_t
commatxt_fromtext(isc_textregion_t *source, bool comma, isc_buffer_t *target) {
	isc_region_t tregion;
	bool escape = false, comma_escape = false, seen_comma = false;
	unsigned int n, nrem;
	char *s;
	unsigned char *t;
	int d;
	int c;

	isc_buffer_availableregion(target, &tregion);
	s = source->base;
	n = source->length;
	t = tregion.base;
	nrem = tregion.length;
	if (nrem < 1) {
		return ISC_R_NOSPACE;
	}
	/*
	 * Length byte.
	 */
	nrem--;
	t++;
	/*
	 * Maximum text string length.
	 */
	if (nrem > 255) {
		nrem = 255;
	}
	while (n-- != 0) {
		c = (*s++) & 0xff;
		if (escape && (d = decvalue((char)c)) != -1) {
			c = d;
			if (n == 0) {
				return DNS_R_SYNTAX;
			}
			n--;
			if ((d = decvalue(*s++)) != -1) {
				c = c * 10 + d;
			} else {
				return DNS_R_SYNTAX;
			}
			if (n == 0) {
				return DNS_R_SYNTAX;
			}
			n--;
			if ((d = decvalue(*s++)) != -1) {
				c = c * 10 + d;
			} else {
				return DNS_R_SYNTAX;
			}
			if (c > 255) {
				return DNS_R_SYNTAX;
			}
		} else if (!escape && c == '\\') {
			escape = true;
			continue;
		}
		escape = false;
		/*
		 * Level 1 escape processing complete.
		 * If comma is set perform comma escape processing.
		 *
		 * Level 1	Level 2		ALPN's
		 * h1\,h2   =>	h1,h2   =>	h1 and h2
		 * h1\\,h2  =>	h1\,h2  =>	h1,h2
		 * h1\\h2   =>	h1\h2   =>	h1h2
		 * h1\\\\h2 =>	h1\\h2  =>	h1\h2
		 */
		if (comma && !comma_escape && c == ',') {
			seen_comma = true;
			break;
		}
		if (comma && !comma_escape && c == '\\') {
			comma_escape = true;
			continue;
		}
		comma_escape = false;
		if (nrem == 0) {
			return (tregion.length <= 256U) ? ISC_R_NOSPACE
							: DNS_R_SYNTAX;
		}
		*t++ = c;
		nrem--;
	}

	/*
	 * Incomplete escape processing?
	 */
	if (escape || (comma && comma_escape)) {
		return DNS_R_SYNTAX;
	}

	if (comma) {
		/*
		 * Disallow empty ALPN at start (",h1" or "\,h1") or
		 * in the middle ("h1,,h2" or "h1\,\,h2").
		 */
		if ((t - tregion.base - 1) == 0) {
			return DNS_R_SYNTAX;
		}

		/*
		 * Consume this ALPN and possible ending comma.
		 */
		isc_textregion_consume(source, s - source->base);

		/*
		 * Disallow empty ALPN at end ("h1," or "h1\,").
		 */
		if (seen_comma && source->length == 0) {
			return DNS_R_SYNTAX;
		}
	}

	*tregion.base = (unsigned char)(t - tregion.base - 1);
	isc_buffer_add(target, *tregion.base + 1);
	return ISC_R_SUCCESS;
}

static isc_result_t
txt_fromtext(isc_textregion_t *source, isc_buffer_t *target) {
	return commatxt_fromtext(source, false, target);
}

static isc_result_t
txt_fromwire(isc_buffer_t *source, isc_buffer_t *target) {
	unsigned int n;
	isc_region_t sregion;
	isc_region_t tregion;

	isc_buffer_activeregion(source, &sregion);
	if (sregion.length == 0) {
		return ISC_R_UNEXPECTEDEND;
	}
	n = *sregion.base + 1;
	if (n > sregion.length) {
		return ISC_R_UNEXPECTEDEND;
	}

	isc_buffer_availableregion(target, &tregion);
	if (n > tregion.length) {
		return ISC_R_NOSPACE;
	}

	if (tregion.base != sregion.base) {
		memmove(tregion.base, sregion.base, n);
	}
	isc_buffer_forward(source, n);
	isc_buffer_add(target, n);
	return ISC_R_SUCCESS;
}

/*
 * Conversion of TXT-like rdata fields without length limits.
 */
static isc_result_t
multitxt_totext(isc_region_t *source, isc_buffer_t *target) {
	unsigned int tl;
	unsigned int n0, n;
	unsigned char *sp;
	char *tp;
	isc_region_t region;

	isc_buffer_availableregion(target, &region);
	sp = source->base;
	tp = (char *)region.base;
	tl = region.length;

	if (tl < 1) {
		return ISC_R_NOSPACE;
	}
	*tp++ = '"';
	tl--;
	do {
		n = source->length;
		n0 = source->length - 1;

		while (n--) {
			if (*sp < ' ' || *sp >= 0x7f) {
				if (tl < 4) {
					return ISC_R_NOSPACE;
				}
				*tp++ = '\\';
				*tp++ = '0' + ((*sp / 100) % 10);
				*tp++ = '0' + ((*sp / 10) % 10);
				*tp++ = '0' + (*sp % 10);
				sp++;
				tl -= 4;
				continue;
			}
			/* double quote, backslash */
			if (*sp == '"' || *sp == '\\') {
				if (tl < 2) {
					return ISC_R_NOSPACE;
				}
				*tp++ = '\\';
				tl--;
			}
			if (tl < 1) {
				return ISC_R_NOSPACE;
			}
			*tp++ = *sp++;
			tl--;
		}
		isc_region_consume(source, n0 + 1);
	} while (source->length != 0);
	if (tl < 1) {
		return ISC_R_NOSPACE;
	}
	*tp++ = '"';
	tl--;
	POST(tl);
	isc_buffer_add(target, (unsigned int)(tp - (char *)region.base));
	return ISC_R_SUCCESS;
}

static isc_result_t
multitxt_fromtext(isc_textregion_t *source, isc_buffer_t *target) {
	isc_region_t tregion;
	bool escape;
	unsigned int n, nrem;
	char *s;
	unsigned char *t0, *t;
	int d;
	int c;

	s = source->base;
	n = source->length;
	escape = false;

	do {
		isc_buffer_availableregion(target, &tregion);
		t0 = t = tregion.base;
		nrem = tregion.length;
		if (nrem < 1) {
			return ISC_R_NOSPACE;
		}

		while (n != 0) {
			--n;
			c = (*s++) & 0xff;
			if (escape && (d = decvalue((char)c)) != -1) {
				c = d;
				if (n == 0) {
					return DNS_R_SYNTAX;
				}
				n--;
				if ((d = decvalue(*s++)) != -1) {
					c = c * 10 + d;
				} else {
					return DNS_R_SYNTAX;
				}
				if (n == 0) {
					return DNS_R_SYNTAX;
				}
				n--;
				if ((d = decvalue(*s++)) != -1) {
					c = c * 10 + d;
				} else {
					return DNS_R_SYNTAX;
				}
				if (c > 255) {
					return DNS_R_SYNTAX;
				}
			} else if (!escape && c == '\\') {
				escape = true;
				continue;
			}
			escape = false;
			*t++ = c;
			nrem--;
			if (nrem == 0) {
				break;
			}
		}
		if (escape) {
			return DNS_R_SYNTAX;
		}

		isc_buffer_add(target, (unsigned int)(t - t0));
	} while (n != 0);
	return ISC_R_SUCCESS;
}

static bool
name_prefix(dns_name_t *name, const dns_name_t *origin, dns_name_t *target) {
	int l1, l2;

	if (origin == NULL) {
		goto return_false;
	}

	if (dns_name_compare(origin, dns_rootname) == 0) {
		goto return_false;
	}

	if (!dns_name_issubdomain(name, origin)) {
		goto return_false;
	}

	l1 = dns_name_countlabels(name);
	l2 = dns_name_countlabels(origin);

	if (l1 == l2) {
		goto return_false;
	}

	/* Master files should be case preserving. */
	dns_name_getlabelsequence(name, l1 - l2, l2, target);
	if (!dns_name_caseequal(origin, target)) {
		goto return_false;
	}

	dns_name_getlabelsequence(name, 0, l1 - l2, target);
	return true;

return_false:
	*target = *name;
	return false;
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
inet_totext(int af, uint32_t flags, isc_region_t *src, isc_buffer_t *target) {
	char tmpbuf[64];

	/* Note - inet_ntop doesn't do size checking on its input. */
	if (inet_ntop(af, src->base, tmpbuf, sizeof(tmpbuf)) == NULL) {
		return ISC_R_NOSPACE;
	}
	if (strlen(tmpbuf) > isc_buffer_availablelength(target)) {
		return ISC_R_NOSPACE;
	}
	isc_buffer_putstr(target, tmpbuf);

	/*
	 * An IPv6 address ending in "::" breaks YAML
	 * parsing, so append 0 in that case.
	 */
	if (af == AF_INET6 && (flags & DNS_STYLEFLAG_YAML) != 0) {
		isc_region_t r;
		isc_buffer_usedregion(target, &r);
		if (r.length > 0 && r.base[r.length - 1] == ':') {
			if (isc_buffer_availablelength(target) == 0) {
				return ISC_R_NOSPACE;
			}
			isc_buffer_putmem(target, (const unsigned char *)"0",
					  1);
		}
	}

	return ISC_R_SUCCESS;
}

static bool
buffer_empty(isc_buffer_t *source) {
	return (source->current == source->active) ? true : false;
}

static void
buffer_fromregion(isc_buffer_t *buffer, isc_region_t *region) {
	isc_buffer_init(buffer, region->base, region->length);
	isc_buffer_add(buffer, region->length);
	isc_buffer_setactive(buffer, region->length);
}

static isc_result_t
uint32_tobuffer(uint32_t value, isc_buffer_t *target) {
	isc_region_t region;

	isc_buffer_availableregion(target, &region);
	if (region.length < 4) {
		return ISC_R_NOSPACE;
	}
	isc_buffer_putuint32(target, value);
	return ISC_R_SUCCESS;
}

static isc_result_t
uint16_tobuffer(uint32_t value, isc_buffer_t *target) {
	isc_region_t region;

	if (value > 0xffff) {
		return ISC_R_RANGE;
	}
	isc_buffer_availableregion(target, &region);
	if (region.length < 2) {
		return ISC_R_NOSPACE;
	}
	isc_buffer_putuint16(target, (uint16_t)value);
	return ISC_R_SUCCESS;
}

static isc_result_t
uint8_tobuffer(uint32_t value, isc_buffer_t *target) {
	isc_region_t region;

	if (value > 0xff) {
		return ISC_R_RANGE;
	}
	isc_buffer_availableregion(target, &region);
	if (region.length < 1) {
		return ISC_R_NOSPACE;
	}
	isc_buffer_putuint8(target, (uint8_t)value);
	return ISC_R_SUCCESS;
}

static isc_result_t
name_tobuffer(const dns_name_t *name, isc_buffer_t *target) {
	isc_region_t r;
	dns_name_toregion(name, &r);
	return isc_buffer_copyregion(target, &r);
}

static uint32_t
uint32_fromregion(isc_region_t *region) {
	uint32_t value;

	REQUIRE(region->length >= 4);
	value = (uint32_t)region->base[0] << 24;
	value |= (uint32_t)region->base[1] << 16;
	value |= (uint32_t)region->base[2] << 8;
	value |= (uint32_t)region->base[3];
	return value;
}

static uint16_t
uint16_consume_fromregion(isc_region_t *region) {
	uint16_t r = uint16_fromregion(region);

	isc_region_consume(region, 2);
	return r;
}

static uint16_t
uint16_fromregion(isc_region_t *region) {
	REQUIRE(region->length >= 2);

	return (region->base[0] << 8) | region->base[1];
}

static uint8_t
uint8_fromregion(isc_region_t *region) {
	REQUIRE(region->length >= 1);

	return region->base[0];
}

static uint8_t
uint8_consume_fromregion(isc_region_t *region) {
	uint8_t r = uint8_fromregion(region);

	isc_region_consume(region, 1);
	return r;
}

static isc_result_t
mem_tobuffer(isc_buffer_t *target, void *base, unsigned int length) {
	isc_region_t tr;

	if (length == 0U) {
		return ISC_R_SUCCESS;
	}

	isc_buffer_availableregion(target, &tr);
	if (length > tr.length) {
		return ISC_R_NOSPACE;
	}
	if (tr.base != base) {
		memmove(tr.base, base, length);
	}
	isc_buffer_add(target, length);
	return ISC_R_SUCCESS;
}

static int
hexvalue(char value) {
	int hexval = isc_hex_char(value);
	if (hexval == 0) {
		return -1;
	} else {
		return value - hexval;
	}
}

static int
decvalue(char value) {
	if (isdigit((unsigned char)value)) {
		return value - '0';
	} else {
		return -1;
	}
}

static void
default_fromtext_callback(dns_rdatacallbacks_t *callbacks, const char *fmt,
			  ...) {
	va_list ap;

	UNUSED(callbacks);

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

static void
fromtext_warneof(isc_lex_t *lexer, dns_rdatacallbacks_t *callbacks) {
	if (isc_lex_isfile(lexer) && callbacks != NULL) {
		const char *name = isc_lex_getsourcename(lexer);
		if (name == NULL) {
			name = "UNKNOWN";
		}
		(*callbacks->warn)(callbacks,
				   "%s:%lu: file does not end with newline",
				   name, isc_lex_getsourceline(lexer));
	}
}

static void
warn_badmx(isc_token_t *token, isc_lex_t *lexer,
	   dns_rdatacallbacks_t *callbacks) {
	const char *file;
	unsigned long line;

	if (lexer != NULL) {
		file = isc_lex_getsourcename(lexer);
		line = isc_lex_getsourceline(lexer);
		(*callbacks->warn)(callbacks, "%s:%u: warning: '%s': %s", file,
				   line, DNS_AS_STR(*token),
				   isc_result_totext(DNS_R_MXISADDRESS));
	}
}

static void
warn_badname(const dns_name_t *name, isc_lex_t *lexer,
	     dns_rdatacallbacks_t *callbacks) {
	const char *file;
	unsigned long line;
	char namebuf[DNS_NAME_FORMATSIZE];

	if (lexer != NULL) {
		file = isc_lex_getsourcename(lexer);
		line = isc_lex_getsourceline(lexer);
		dns_name_format(name, namebuf, sizeof(namebuf));
		(*callbacks->warn)(callbacks, "%s:%u: warning: %s: %s", file,
				   line, namebuf,
				   isc_result_totext(DNS_R_BADNAME));
	}
}

static void
fromtext_error(void (*callback)(dns_rdatacallbacks_t *, const char *, ...),
	       dns_rdatacallbacks_t *callbacks, const char *name,
	       unsigned long line, isc_token_t *token, isc_result_t result) {
	if (name == NULL) {
		name = "UNKNOWN";
	}

	if (token != NULL) {
		switch (token->type) {
		case isc_tokentype_eol:
			(*callback)(callbacks, "%s: %s:%lu: near eol: %s",
				    "dns_rdata_fromtext", name, line,
				    isc_result_totext(result));
			break;
		case isc_tokentype_eof:
			(*callback)(callbacks, "%s: %s:%lu: near eof: %s",
				    "dns_rdata_fromtext", name, line,
				    isc_result_totext(result));
			break;
		case isc_tokentype_number:
			(*callback)(callbacks, "%s: %s:%lu: near %lu: %s",
				    "dns_rdata_fromtext", name, line,
				    token->value.as_ulong,
				    isc_result_totext(result));
			break;
		case isc_tokentype_string:
		case isc_tokentype_qstring:
			(*callback)(callbacks, "%s: %s:%lu: near '%s': %s",
				    "dns_rdata_fromtext", name, line,
				    DNS_AS_STR(*token),
				    isc_result_totext(result));
			break;
		default:
			(*callback)(callbacks, "%s: %s:%lu: %s",
				    "dns_rdata_fromtext", name, line,
				    isc_result_totext(result));
			break;
		}
	} else {
		(*callback)(callbacks, "dns_rdata_fromtext: %s:%lu: %s", name,
			    line, isc_result_totext(result));
	}
}

dns_rdatatype_t
dns_rdata_covers(dns_rdata_t *rdata) {
	if (rdata->type == dns_rdatatype_rrsig) {
		return covers_rrsig(rdata);
	}
	return covers_sig(rdata);
}

bool
dns_rdatatype_ismeta(dns_rdatatype_t type) {
	if ((dns_rdatatype_attributes(type) & DNS_RDATATYPEATTR_META) != 0) {
		return true;
	}
	return false;
}

bool
dns_rdatatype_issingleton(dns_rdatatype_t type) {
	if ((dns_rdatatype_attributes(type) & DNS_RDATATYPEATTR_SINGLETON) != 0)
	{
		return true;
	}
	return false;
}

bool
dns_rdatatype_notquestion(dns_rdatatype_t type) {
	if ((dns_rdatatype_attributes(type) & DNS_RDATATYPEATTR_NOTQUESTION) !=
	    0)
	{
		return true;
	}
	return false;
}

bool
dns_rdatatype_questiononly(dns_rdatatype_t type) {
	if ((dns_rdatatype_attributes(type) & DNS_RDATATYPEATTR_QUESTIONONLY) !=
	    0)
	{
		return true;
	}
	return false;
}

bool
dns_rdatatype_atcname(dns_rdatatype_t type) {
	if ((dns_rdatatype_attributes(type) & DNS_RDATATYPEATTR_ATCNAME) != 0) {
		return true;
	}
	return false;
}

bool
dns_rdatatype_atparent(dns_rdatatype_t type) {
	if ((dns_rdatatype_attributes(type) & DNS_RDATATYPEATTR_ATPARENT) != 0)
	{
		return true;
	}
	return false;
}

bool
dns_rdatatype_followadditional(dns_rdatatype_t type) {
	if ((dns_rdatatype_attributes(type) &
	     DNS_RDATATYPEATTR_FOLLOWADDITIONAL) != 0)
	{
		return true;
	}
	return false;
}

bool
dns_rdataclass_ismeta(dns_rdataclass_t rdclass) {
	if (rdclass == dns_rdataclass_reserved0 ||
	    rdclass == dns_rdataclass_none || rdclass == dns_rdataclass_any)
	{
		return true;
	}

	return false; /* Assume it is not a meta class. */
}

bool
dns_rdatatype_isdnssec(dns_rdatatype_t type) {
	if ((dns_rdatatype_attributes(type) & DNS_RDATATYPEATTR_DNSSEC) != 0) {
		return true;
	}
	return false;
}

bool
dns_rdatatype_iskeymaterial(dns_rdatatype_t type) {
	return type == dns_rdatatype_dnskey || type == dns_rdatatype_cdnskey ||
	       type == dns_rdatatype_cds;
}

bool
dns_rdatatype_iszonecutauth(dns_rdatatype_t type) {
	if ((dns_rdatatype_attributes(type) & DNS_RDATATYPEATTR_ZONECUTAUTH) !=
	    0)
	{
		return true;
	}
	return false;
}

bool
dns_rdatatype_isknown(dns_rdatatype_t type) {
	if ((dns_rdatatype_attributes(type) & DNS_RDATATYPEATTR_UNKNOWN) == 0) {
		return true;
	}
	return false;
}

void
dns_rdata_exists(dns_rdata_t *rdata, dns_rdatatype_t type) {
	REQUIRE(rdata != NULL);
	REQUIRE(DNS_RDATA_INITIALIZED(rdata));

	rdata->data = NULL;
	rdata->length = 0;
	rdata->flags = DNS_RDATA_UPDATE;
	rdata->type = type;
	rdata->rdclass = dns_rdataclass_any;
}

void
dns_rdata_notexist(dns_rdata_t *rdata, dns_rdatatype_t type) {
	REQUIRE(rdata != NULL);
	REQUIRE(DNS_RDATA_INITIALIZED(rdata));

	rdata->data = NULL;
	rdata->length = 0;
	rdata->flags = DNS_RDATA_UPDATE;
	rdata->type = type;
	rdata->rdclass = dns_rdataclass_none;
}

void
dns_rdata_deleterrset(dns_rdata_t *rdata, dns_rdatatype_t type) {
	REQUIRE(rdata != NULL);
	REQUIRE(DNS_RDATA_INITIALIZED(rdata));

	rdata->data = NULL;
	rdata->length = 0;
	rdata->flags = DNS_RDATA_UPDATE;
	rdata->type = type;
	rdata->rdclass = dns_rdataclass_any;
}

void
dns_rdata_makedelete(dns_rdata_t *rdata) {
	REQUIRE(rdata != NULL);

	rdata->rdclass = dns_rdataclass_none;
}

const char *
dns_rdata_updateop(dns_rdata_t *rdata, dns_section_t section) {
	REQUIRE(rdata != NULL);
	REQUIRE(DNS_RDATA_INITIALIZED(rdata));

	switch (section) {
	case DNS_SECTION_PREREQUISITE:
		switch (rdata->rdclass) {
		case dns_rdataclass_none:
			switch (rdata->type) {
			case dns_rdatatype_any:
				return "domain doesn't exist";
			default:
				return "rrset doesn't exist";
			}
		case dns_rdataclass_any:
			switch (rdata->type) {
			case dns_rdatatype_any:
				return "domain exists";
			default:
				return "rrset exists (value independent)";
			}
		default:
			return "rrset exists (value dependent)";
		}
	case DNS_SECTION_UPDATE:
		switch (rdata->rdclass) {
		case dns_rdataclass_none:
			return "delete";
		case dns_rdataclass_any:
			switch (rdata->type) {
			case dns_rdatatype_any:
				return "delete all rrsets";
			default:
				return "delete rrset";
			}
		default:
			return "add";
		}
	}
	return "invalid";
}

static bool
svcb_ishttp(const char *s, size_t len) {
	/*
	 * HTTP entries from:
	 *
	 * https://www.iana.org/assignments/tls-extensiontype-values/\
	 * tls-extensiontype-values.xhtml#alpn-protocol-ids
	 */
	struct {
		size_t len;
		const char *value;
	} http[] = { { 8, "http/0.9" }, { 8, "http/1.0" }, { 8, "http/1.1" },
		     { 2, "h2" },	{ 3, "h2c" },	   { 2, "h3" } };

	for (size_t i = 0; i < ARRAY_SIZE(http); i++) {
		if (len == http[i].len && memcmp(s, http[i].value, len) == 0) {
			return true;
		}
	}
	return false;
}

static bool
svcb_hashttp(isc_textregion_t *alpn) {
	while (alpn->length > 0) {
		char c, *s;
		unsigned char len = *alpn->base;

		isc_textregion_consume(alpn, 1);

		/*
		 * This has to detect "http/1.1", "h2" and "h3", etc.
		 * in a comma list.
		 */
		s = alpn->base;
		while (len-- > 0) {
			c = *alpn->base;
			isc_textregion_consume(alpn, 1);
			if (c == ',') {
				if (svcb_ishttp(s, (alpn->base - s) - 1)) {
					return true;
				}
				s = alpn->base;
			}
		}
		if (svcb_ishttp(s, alpn->base - s)) {
			return true;
		}
	}
	return false;
}

isc_result_t
dns_rdata_checksvcb(const dns_name_t *owner, const dns_rdata_t *rdata) {
	dns_rdata_in_svcb_t svcb;
	isc_result_t result;

	REQUIRE(owner != NULL);
	REQUIRE(rdata != NULL);
	REQUIRE(rdata->type == dns_rdatatype_svcb);
	REQUIRE(DNS_RDATA_VALIDFLAGS(rdata));

	result = dns_rdata_tostruct(rdata, &svcb, NULL);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);

	/*
	 * Check that Alias Mode records don't have SvcParamKeys.
	 */
	if (svcb.priority == 0 && svcb.svclen != 0) {
		return DNS_R_HAVEPARMKEYS;
	}

	if (dns_name_isdnssvcb(owner)) {
		isc_region_t r = { .base = svcb.svc, .length = svcb.svclen };
		isc_textregion_t alpn;
		uint16_t key = 0, len = 0;

		/* Check for ALPN (key1) */
		while (r.length > 0) {
			key = uint16_fromregion(&r);
			isc_region_consume(&r, 2);
			len = uint16_fromregion(&r);
			isc_region_consume(&r, 2);
			if (key >= SVCB_ALPN_KEY) {
				break;
			}
			isc_region_consume(&r, len);
		}
		if (key != SVCB_ALPN_KEY) {
			return DNS_R_NOALPN;
		}
		alpn = (isc_textregion_t){ .base = (char *)r.base,
					   .length = len };
		isc_region_consume(&r, len);
		if (svcb_hashttp(&alpn)) {
			/* Check for DOHPATH (key7) */
			while (r.length > 0) {
				key = uint16_fromregion(&r);
				isc_region_consume(&r, 2);
				len = uint16_fromregion(&r);
				isc_region_consume(&r, 2);
				if (key >= SVCB_DOHPATH_KEY) {
					break;
				}
				isc_region_consume(&r, len);
			}
			if (key != SVCB_DOHPATH_KEY) {
				return DNS_R_NODOHPATH;
			}
		}
	}
	return ISC_R_SUCCESS;
}
