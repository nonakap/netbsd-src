/*	$NetBSD: server.h,v 1.11 2025/05/21 14:48:06 christos Exp $	*/

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

/*! \file */

#include <inttypes.h>
#include <stdbool.h>

#include <isc/fuzz.h>
#include <isc/histo.h>
#include <isc/log.h>
#include <isc/magic.h>
#include <isc/quota.h>
#include <isc/random.h>
#include <isc/sockaddr.h>
#include <isc/types.h>

#include <dns/acl.h>
#include <dns/types.h>

#include <ns/types.h>

#define NS_SERVER_LOGQUERIES	    0x00000001U /*%< log queries */
#define NS_SERVER_NOAA		    0x00000002U /*%< -T noaa */
#define NS_SERVER_NOSOA		    0x00000004U /*%< -T nosoa */
#define NS_SERVER_NONEAREST	    0x00000008U /*%< -T nonearest */
#define NS_SERVER_NOEDNS	    0x00000020U /*%< -T noedns */
#define NS_SERVER_DROPEDNS	    0x00000040U /*%< -T dropedns */
#define NS_SERVER_NOTCP		    0x00000080U /*%< -T notcp */
#define NS_SERVER_DISABLE4	    0x00000100U /*%< -6 */
#define NS_SERVER_DISABLE6	    0x00000200U /*%< -4 */
#define NS_SERVER_FIXEDLOCAL	    0x00000400U /*%< -T fixedlocal */
#define NS_SERVER_SIGVALINSECS	    0x00000800U /*%< -T sigvalinsecs */
#define NS_SERVER_EDNSFORMERR	    0x00001000U /*%< -T ednsformerr (STD13) */
#define NS_SERVER_EDNSNOTIMP	    0x00002000U /*%< -T ednsnotimp */
#define NS_SERVER_EDNSREFUSED	    0x00004000U /*%< -T ednsrefused */
#define NS_SERVER_TRANSFERINSECS    0x00008000U /*%< -T transferinsecs */
#define NS_SERVER_TRANSFERSLOWLY    0x00010000U /*%< -T transferslowly */
#define NS_SERVER_TRANSFERSTUCK	    0x00020000U /*%< -T transferstuck */
#define NS_SERVER_LOGRESPONSES	    0x00040000U /*%< log responses */
#define NS_SERVER_COOKIEALWAYSVALID 0x00080000U /*%< -T cookiealwaysvalid */

/*%
 * Type for callback function to get hostname.
 */
typedef isc_result_t (*ns_hostnamecb_t)(char *buf, size_t len);

/*%
 * Type for callback function to signal the fuzzer thread
 * when built with AFL.
 */
typedef void (*ns_fuzzcb_t)(void);

/*%
 * Type for callback function to get the view that can answer a query.
 */
typedef isc_result_t (*ns_matchview_t)(
	isc_netaddr_t *srcaddr, isc_netaddr_t *destaddr, dns_message_t *message,
	dns_aclenv_t *env, ns_server_t *sctx, isc_loop_t *loop, isc_job_cb cb,
	void *cbarg, isc_result_t *sigresultp, isc_result_t *viewmatchresult,
	dns_view_t **viewp);

/*%
 * Server context.
 */
struct ns_server {
	unsigned int magic;
	isc_mem_t   *mctx;

	isc_refcount_t references;

	/*% Server cookie secret and algorithm */
	unsigned char	   secret[32];
	ns_cookiealg_t	   cookiealg;
	ns_altsecretlist_t altsecrets;
	bool		   answercookie;

	/*% Quotas */
	isc_quota_t recursionquota;
	isc_quota_t tcpquota;
	isc_quota_t xfroutquota;
	isc_quota_t updquota;
	isc_quota_t sig0checksquota;
	dns_acl_t  *sig0checksquota_exempt;
	ISC_LIST(isc_quota_t) http_quotas;
	isc_mutex_t http_quotas_lock;

	/*% Test options and other configurables */
	uint32_t options;

	dns_acl_t     *blackholeacl;
	uint16_t       udpsize;
	uint16_t       transfer_tcp_message_size;
	bool	       interface_auto;
	dns_tkeyctx_t *tkeyctx;
	uint8_t	       max_restarts;

	/*% Server id for NSID */
	char *server_id;
	bool  usehostname;

	/*% Fuzzer callback */
	isc_fuzztype_t fuzztype;
	ns_fuzzcb_t    fuzznotify;

	/*% Callback to find a matching view for a query */
	ns_matchview_t matchingview;

	/*% Stats counters */
	ns_stats_t  *nsstats;
	dns_stats_t *rcvquerystats;
	dns_stats_t *opcodestats;
	dns_stats_t *rcodestats;

	isc_histomulti_t *udpinstats4;
	isc_histomulti_t *udpoutstats4;
	isc_histomulti_t *udpinstats6;
	isc_histomulti_t *udpoutstats6;

	isc_histomulti_t *tcpinstats4;
	isc_histomulti_t *tcpoutstats4;
	isc_histomulti_t *tcpinstats6;
	isc_histomulti_t *tcpoutstats6;
};

struct ns_altsecret {
	ISC_LINK(ns_altsecret_t) link;
	unsigned char secret[32];
};

void
ns_server_create(isc_mem_t *mctx, ns_matchview_t matchingview,
		 ns_server_t **sctxp);
/*%<
 * Create a server context object with default settings.
 */

void
ns_server_attach(ns_server_t *src, ns_server_t **dest);
/*%<
 * Attach a server context.
 *
 * Requires:
 *\li	'src' is valid.
 */

void
ns_server_detach(ns_server_t **sctxp);
/*%<
 * Detach from a server context.  If its reference count drops to zero, destroy
 * it, freeing its memory.
 *
 * Requires:
 *\li	'*sctxp' is valid.
 * Ensures:
 *\li	'*sctxp' is NULL on return.
 */

isc_result_t
ns_server_setserverid(ns_server_t *sctx, const char *serverid);
/*%<
 * Set sctx->server_id to 'serverid'. If it was set previously, free the memory.
 *
 * Requires:
 *\li	'sctx' is valid.
 */

void
ns_server_setoption(ns_server_t *sctx, unsigned int option, bool value);
/*%<
 *	Set the given options on (if 'value' == #true)
 *	or off (if 'value' == #false).
 *
 * Requires:
 *\li	'sctx' is valid
 */

bool
ns_server_getoption(ns_server_t *sctx, unsigned int option);
/*%<
 *	Returns the current value of the specified server option.
 *
 * Requires:
 *\li	'sctx' is valid.
 */

void
ns_server_append_http_quota(ns_server_t *sctx, isc_quota_t *http_quota);
/*%<
 *	Add a quota to the list of HTTP quotas to destroy it safely later.
 *
 * Requires:
 *\li	'sctx' is valid;
 *\li	'http_quota' is not 'NULL'.
 */
