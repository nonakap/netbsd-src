/*	$NetBSD: nsec3.h,v 1.9 2025/01/26 16:25:28 christos Exp $	*/

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

#pragma once

#include <stdbool.h>

#include <isc/iterated_hash.h>
#include <isc/lang.h>
#include <isc/log.h>

#include <dns/db.h>
#include <dns/diff.h>
#include <dns/name.h>
#include <dns/rdatastruct.h>
#include <dns/types.h>

#define DNS_NSEC3_SALTSIZE	255
#define DNS_NSEC3_MAXITERATIONS 50U

/*
 * hash = 1, flags =1, iterations = 2, salt length = 1, salt = 255 (max)
 * hash length = 1, hash = 255 (max), bitmap = 8192 + 512 (max)
 */
#define DNS_NSEC3_BUFFERSIZE (6 + 255 + 255 + 8192 + 512)
/*
 * hash = 1, flags = 1, iterations = 2, salt length = 1, salt = 255 (max)
 */
#define DNS_NSEC3PARAM_BUFFERSIZE (5 + 255)

/*
 * Test "unknown" algorithm.  Is mapped to dns_hash_sha1.
 */
#define DNS_NSEC3_UNKNOWNALG ((dns_hash_t)245U)

ISC_LANG_BEGINDECLS

isc_result_t
dns_nsec3_buildrdata(dns_db_t *db, dns_dbversion_t *version, dns_dbnode_t *node,
		     unsigned int hashalg, unsigned int optin,
		     unsigned int iterations, const unsigned char *salt,
		     size_t salt_length, const unsigned char *nexthash,
		     size_t hash_length, unsigned char *buffer,
		     dns_rdata_t *rdata);
/*%<
 * Build the rdata of a NSEC3 record for the data at 'node'.
 * Note: 'node' is not the node where the NSEC3 record will be stored.
 *
 * Requires:
 *	buffer	Points to a temporary buffer of at least
 * 		DNS_NSEC_BUFFERSIZE bytes.
 *	rdata	Points to an initialized dns_rdata_t.
 *
 * Ensures:
 *      *rdata	Contains a valid NSEC3 rdata.  The 'data' member refers
 *		to 'buffer'.
 */

bool
dns_nsec3_typepresent(dns_rdata_t *nsec, dns_rdatatype_t type);
/*%<
 * Determine if a type is marked as present in an NSEC3 record.
 *
 * Requires:
 *	'nsec' points to a valid rdataset of type NSEC3
 */

isc_result_t
dns_nsec3_generate_salt(unsigned char *salt, size_t saltlen);
/*%<
 * Generate a salt with the given salt length.
 */

isc_result_t
dns_nsec3_hashname(dns_fixedname_t *result,
		   unsigned char    rethash[NSEC3_MAX_HASH_LENGTH],
		   size_t *hash_length, const dns_name_t *name,
		   const dns_name_t *origin, dns_hash_t hashalg,
		   unsigned int iterations, const unsigned char *salt,
		   size_t saltlength);
/*%<
 * Make a hashed domain name from an unhashed one. If rethash is not NULL
 * the raw hash is stored there.
 */

unsigned int
dns_nsec3_hashlength(dns_hash_t hash);
/*%<
 * Return the length of the hash produced by the specified algorithm
 * or zero when unknown.
 */

bool
dns_nsec3_supportedhash(dns_hash_t hash);
/*%<
 * Return whether we support this hash algorithm or not.
 */

isc_result_t
dns_nsec3_addnsec3(dns_db_t *db, dns_dbversion_t *version,
		   const dns_name_t		*name,
		   const dns_rdata_nsec3param_t *nsec3param, dns_ttl_t nsecttl,
		   bool unsecure, dns_diff_t *diff);

isc_result_t
dns_nsec3_addnsec3s(dns_db_t *db, dns_dbversion_t *version,
		    const dns_name_t *name, dns_ttl_t nsecttl, bool unsecure,
		    dns_diff_t *diff);

isc_result_t
dns_nsec3_addnsec3sx(dns_db_t *db, dns_dbversion_t *version,
		     const dns_name_t *name, dns_ttl_t nsecttl, bool unsecure,
		     dns_rdatatype_t private, dns_diff_t *diff);
/*%<
 * Add NSEC3 records for 'name', recording the change in 'diff'.
 * Adjust previous NSEC3 records, if any, to reflect the addition.
 * The existing NSEC3 records are removed.
 *
 * dns_nsec3_addnsec3() will only add records to the chain identified by
 * 'nsec3param'.
 *
 * 'unsecure' should be set to reflect if this is a potentially
 * unsecure delegation (no DS record).
 *
 * dns_nsec3_addnsec3s() will examine the NSEC3PARAM RRset to determine which
 * chains to be updated.  NSEC3PARAM records with the DNS_NSEC3FLAG_CREATE
 * will be preferentially chosen over NSEC3PARAM records without
 * DNS_NSEC3FLAG_CREATE set.  NSEC3PARAM records with DNS_NSEC3FLAG_REMOVE
 * set will be ignored by dns_nsec3_addnsec3s().  If DNS_NSEC3FLAG_CREATE
 * is set then the new NSEC3 will have OPTOUT set to match the that in the
 * NSEC3PARAM record otherwise OPTOUT will be inherited from the previous
 * record in the chain.
 *
 * dns_nsec3_addnsec3sx() is similar to dns_nsec3_addnsec3s() but 'private'
 * specifies the type of the private rdataset to be checked in addition to
 * the nsec3param rdataset at the zone apex.
 *
 * Requires:
 *	'db' to be valid.
 *	'version' to be valid or NULL.
 *	'name' to be valid.
 *	'nsec3param' to be valid.
 *	'diff' to be valid.
 */

isc_result_t
dns_nsec3_delnsec3(dns_db_t *db, dns_dbversion_t *version,
		   const dns_name_t		*name,
		   const dns_rdata_nsec3param_t *nsec3param, dns_diff_t *diff);

isc_result_t
dns_nsec3_delnsec3s(dns_db_t *db, dns_dbversion_t *version,
		    const dns_name_t *name, dns_diff_t *diff);

isc_result_t
dns_nsec3_delnsec3sx(dns_db_t *db, dns_dbversion_t *version,
		     const dns_name_t *name, dns_rdatatype_t private,
		     dns_diff_t	      *diff);
/*%<
 * Remove NSEC3 records for 'name', recording the change in 'diff'.
 * Adjust previous NSEC3 records, if any, to reflect the removal.
 *
 * dns_nsec3_delnsec3() performs the above for the chain identified by
 * 'nsec3param'.
 *
 * dns_nsec3_delnsec3s() examines the NSEC3PARAM RRset in a similar manner
 * to dns_nsec3_addnsec3s().  Unlike dns_nsec3_addnsec3s() updated NSEC3
 * records have the OPTOUT flag preserved.
 *
 * dns_nsec3_delnsec3sx() is similar to dns_nsec3_delnsec3s() but 'private'
 * specifies the type of the private rdataset to be checked in addition to
 * the nsec3param rdataset at the zone apex.
 *
 * Requires:
 *	'db' to be valid.
 *	'version' to be valid or NULL.
 *	'name' to be valid.
 *	'nsec3param' to be valid.
 *	'diff' to be valid.
 */

isc_result_t
dns_nsec3_active(dns_db_t *db, dns_dbversion_t *version, bool complete,
		 bool *answer);

isc_result_t
dns_nsec3_activex(dns_db_t *db, dns_dbversion_t *version, bool complete,
		  dns_rdatatype_t private, bool *answer);
/*%<
 * Check if there are any complete/to be built NSEC3 chains.
 * If 'complete' is true only complete chains will be recognized.
 *
 * dns_nsec3_activex() is similar to dns_nsec3_active() but 'private'
 * specifies the type of the private rdataset to be checked in addition to
 * the nsec3param rdataset at the zone apex.
 *
 * Requires:
 *	'db' to be valid.
 *	'version' to be valid or NULL.
 *	'answer' to be non NULL.
 */

unsigned int
dns_nsec3_maxiterations(void);
/*%<
 * Return the maximum permissible number of NSEC3 iterations.
 */

bool
dns_nsec3param_fromprivate(dns_rdata_t *src, dns_rdata_t *target,
			   unsigned char *buf, size_t buflen);
/*%<
 * Convert a private rdata to a nsec3param rdata.
 *
 * Return true if 'src' could be successfully converted.
 *
 * 'buf' should be at least DNS_NSEC3PARAM_BUFFERSIZE in size.
 */

void
dns_nsec3param_toprivate(dns_rdata_t *src, dns_rdata_t *target,
			 dns_rdatatype_t privatetype, unsigned char *buf,
			 size_t buflen);
/*%<
 * Convert a nsec3param rdata to a private rdata.
 *
 * 'buf' should be at least src->length + 1 in size.
 */

isc_result_t
dns_nsec3param_salttotext(dns_rdata_nsec3param_t *nsec3param, char *dst,
			  size_t dstlen);
/*%<
 * Convert the salt of given NSEC3PARAM RDATA into hex-encoded, NULL-terminated
 * text stored at "dst".
 *
 * Requires:
 *
 *\li 	"dst" to have enough space (as indicated by "dstlen") to hold the
 * 	resulting text and its NULL-terminating byte.
 */

isc_result_t
dns_nsec3param_deletechains(dns_db_t *db, dns_dbversion_t *ver,
			    dns_zone_t *zone, bool nonsec, dns_diff_t *diff);

/*%<
 * Mark NSEC3PARAM for deletion.
 */

isc_result_t
dns_nsec3_noexistnodata(dns_rdatatype_t type, const dns_name_t *name,
			const dns_name_t *nsec3name, dns_rdataset_t *nsec3set,
			dns_name_t *zonename, bool *exists, bool *data,
			bool *optout, bool *unknown, bool *setclosest,
			bool *setnearest, dns_name_t *closest,
			dns_name_t *nearest, dns_nseclog_t logit, void *arg);

ISC_LANG_ENDDECLS
