/*	$NetBSD: dst_internal.h,v 1.10 2025/01/26 16:25:22 christos Exp $	*/

/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0 AND ISC
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*
 * Portions Copyright (C) Network Associates, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC AND NETWORK ASSOCIATES DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE
 * FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 * IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#pragma once

#include <inttypes.h>
#include <stdbool.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>

#include <isc/buffer.h>
#include <isc/hmac.h>
#include <isc/lang.h>
#include <isc/magic.h>
#include <isc/md.h>
#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/stdtime.h>
#include <isc/types.h>

#include <dns/time.h>

#include <dst/dst.h>

ISC_LANG_BEGINDECLS

#define KEY_MAGIC ISC_MAGIC('D', 'S', 'T', 'K')
#define CTX_MAGIC ISC_MAGIC('D', 'S', 'T', 'C')

#define VALID_KEY(x) ISC_MAGIC_VALID(x, KEY_MAGIC)
#define VALID_CTX(x) ISC_MAGIC_VALID(x, CTX_MAGIC)

/***
 *** Types
 ***/

typedef struct dst_func dst_func_t;

typedef struct dst_hmac_key dst_hmac_key_t;

/*%
 * Indicate whether a DST context will be used for signing
 * or for verification
 */
typedef enum { DO_SIGN, DO_VERIFY } dst_use_t;

/*% DST Key Structure */
struct dst_key {
	unsigned int magic;
	isc_refcount_t refs;
	isc_mutex_t mdlock;	    /*%< lock for read/write metadata */
	dns_name_t *key_name;	    /*%< name of the key */
	unsigned int key_size;	    /*%< size of the key in bits */
	unsigned int key_proto;	    /*%< protocols this key is used for
				     * */
	unsigned int key_alg;	    /*%< algorithm of the key */
	uint32_t key_flags;	    /*%< flags of the public key */
	uint16_t key_id;	    /*%< identifier of the key */
	uint16_t key_rid;	    /*%< identifier of the key when
				     *   revoked */
	uint16_t key_bits;	    /*%< hmac digest bits */
	dns_rdataclass_t key_class; /*%< class of the key record */
	dns_ttl_t key_ttl;	    /*%< default/initial dnskey ttl */
	isc_mem_t *mctx;	    /*%< memory context */
	char *directory;	    /*%< key directory */
	char *engine;		    /*%< engine name (HSM) */
	char *label;		    /*%< engine label (HSM) */
	union {
		void *generic;
		dns_gss_ctx_id_t gssctx;
		dst_hmac_key_t *hmac_key;
		struct {
			EVP_PKEY *pub;
			EVP_PKEY *priv;
		} pkeypair;
	} keydata; /*%< pointer to key in crypto pkg fmt */

	isc_stdtime_t times[DST_MAX_TIMES + 1]; /*%< timing metadata */
	bool timeset[DST_MAX_TIMES + 1];	/*%< data set? */

	uint32_t nums[DST_MAX_NUMERIC + 1]; /*%< numeric metadata
					     * */
	bool numset[DST_MAX_NUMERIC + 1];   /*%< data set? */

	bool bools[DST_MAX_BOOLEAN + 1];   /*%< boolean metadata
					    * */
	bool boolset[DST_MAX_BOOLEAN + 1]; /*%< data set? */

	dst_key_state_t keystates[DST_MAX_KEYSTATES + 1]; /*%< key states
							   * */
	bool keystateset[DST_MAX_KEYSTATES + 1];	  /*%< data
							   * set? */

	bool kasp;     /*%< key has kasp state */
	bool inactive; /*%< private key not present as it is
			* inactive */
	bool external; /*%< external key */
	bool modified; /*%< set to true if key file metadata has changed */

	int fmt_major; /*%< private key format, major version
			* */
	int fmt_minor; /*%< private key format, minor version
			* */

	dst_func_t *func;	     /*%< crypto package specific functions */
	isc_buffer_t *key_tkeytoken; /*%< TKEY token data */
};

struct dst_context {
	unsigned int magic;
	dst_use_t use;
	dst_key_t *key;
	isc_mem_t *mctx;
	isc_logcategory_t *category;
	union {
		void *generic;
		dst_gssapi_signverifyctx_t *gssctx;
		isc_hmac_t *hmac_ctx;
		EVP_MD_CTX *evp_md_ctx;
	} ctxdata;
};

struct dst_func {
	/*
	 * Context functions
	 */
	isc_result_t (*createctx)(dst_key_t *key, dst_context_t *dctx);
	isc_result_t (*createctx2)(dst_key_t *key, int maxbits,
				   dst_context_t *dctx);
	void (*destroyctx)(dst_context_t *dctx);
	isc_result_t (*adddata)(dst_context_t *dctx, const isc_region_t *data);

	/*
	 * Key operations
	 */
	isc_result_t (*sign)(dst_context_t *dctx, isc_buffer_t *sig);
	isc_result_t (*verify)(dst_context_t *dctx, const isc_region_t *sig);
	isc_result_t (*verify2)(dst_context_t *dctx, int maxbits,
				const isc_region_t *sig);
	isc_result_t (*computesecret)(const dst_key_t *pub,
				      const dst_key_t *priv,
				      isc_buffer_t *secret);
	bool (*compare)(const dst_key_t *key1, const dst_key_t *key2);
	bool (*paramcompare)(const dst_key_t *key1, const dst_key_t *key2);
	isc_result_t (*generate)(dst_key_t *key, int parms,
				 void (*callback)(int));
	bool (*isprivate)(const dst_key_t *key);
	void (*destroy)(dst_key_t *key);

	/* conversion functions */
	isc_result_t (*todns)(const dst_key_t *key, isc_buffer_t *data);
	isc_result_t (*fromdns)(dst_key_t *key, isc_buffer_t *data);
	isc_result_t (*tofile)(const dst_key_t *key, const char *directory);
	isc_result_t (*parse)(dst_key_t *key, isc_lex_t *lexer, dst_key_t *pub);

	/* cleanup */
	void (*cleanup)(void);

	isc_result_t (*fromlabel)(dst_key_t *key, const char *engine,
				  const char *label, const char *pin);
	isc_result_t (*dump)(dst_key_t *key, isc_mem_t *mctx, char **buffer,
			     int *length);
	isc_result_t (*restore)(dst_key_t *key, const char *keystr);
};

/*%
 * Initializers
 */
isc_result_t
dst__openssl_init(const char *engine);

isc_result_t
dst__hmacmd5_init(struct dst_func **funcp);
isc_result_t
dst__hmacsha1_init(struct dst_func **funcp);
isc_result_t
dst__hmacsha224_init(struct dst_func **funcp);
isc_result_t
dst__hmacsha256_init(struct dst_func **funcp);
isc_result_t
dst__hmacsha384_init(struct dst_func **funcp);
isc_result_t
dst__hmacsha512_init(struct dst_func **funcp);
isc_result_t
dst__opensslrsa_init(struct dst_func **funcp, unsigned char algorithm);
isc_result_t
dst__opensslecdsa_init(struct dst_func **funcp);
#if HAVE_OPENSSL_ED25519 || HAVE_OPENSSL_ED448
isc_result_t
dst__openssleddsa_init(struct dst_func **funcp, unsigned char algorithm);
#endif /* HAVE_OPENSSL_ED25519 || HAVE_OPENSSL_ED448 */
#if HAVE_GSSAPI
isc_result_t
dst__gssapi_init(struct dst_func **funcp);
#endif /* HAVE_GSSAPI*/

/*%
 * Destructors
 */
void
dst__openssl_destroy(void);

/*%
 * Memory allocators using the DST memory pool.
 */
void *
dst__mem_alloc(size_t size);
void
dst__mem_free(void *ptr);
void *
dst__mem_realloc(void *ptr, size_t size);

/*%
 * Secure private file handling
 */
FILE *
dst_key_open(char *tmpname, mode_t mode);
isc_result_t
dst_key_close(char *tmpname, FILE *fp, char *filename);
isc_result_t
dst_key_cleanup(char *tmpname, FILE *fp);

ISC_LANG_ENDDECLS

/*! \file */
