/*	$NetBSD: log.h,v 1.8 2025/01/26 16:25:46 christos Exp $	*/

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

#include <isc/log.h>
#include <isc/types.h>

extern isc_log_t	*ns_lctx;
extern isc_logcategory_t ns_categories[];
extern isc_logmodule_t	 ns_modules[];

#define NS_LOGCATEGORY_CLIENT	       (&ns_categories[0])
#define NS_LOGCATEGORY_NETWORK	       (&ns_categories[1])
#define NS_LOGCATEGORY_UPDATE	       (&ns_categories[2])
#define NS_LOGCATEGORY_QUERIES	       (&ns_categories[3])
#define NS_LOGCATEGORY_UPDATE_SECURITY (&ns_categories[4])
#define NS_LOGCATEGORY_QUERY_ERRORS    (&ns_categories[5])
#define NS_LOGCATEGORY_TAT	       (&ns_categories[6])
#define NS_LOGCATEGORY_SERVE_STALE     (&ns_categories[7])
#define NS_LOGCATEGORY_RESPONSES       (&ns_categories[8])

/*
 * Backwards compatibility.
 */
#define NS_LOGCATEGORY_GENERAL ISC_LOGCATEGORY_GENERAL

#define NS_LOGMODULE_CLIENT	  (&ns_modules[0])
#define NS_LOGMODULE_QUERY	  (&ns_modules[1])
#define NS_LOGMODULE_INTERFACEMGR (&ns_modules[2])
#define NS_LOGMODULE_UPDATE	  (&ns_modules[3])
#define NS_LOGMODULE_XFER_IN	  (&ns_modules[4])
#define NS_LOGMODULE_XFER_OUT	  (&ns_modules[5])
#define NS_LOGMODULE_NOTIFY	  (&ns_modules[6])
#define NS_LOGMODULE_HOOKS	  (&ns_modules[7])

void
ns_log_init(isc_log_t *lctx);
/*%<
 * Make the libns categories and modules available for use with the
 * ISC logging library.
 *
 * Requires:
 *\li	lctx is a valid logging context.
 *
 *\li	ns_log_init() is called only once.
 *
 * Ensures:
 *\li	The categories and modules defined above are available for
 * 	use by isc_log_usechannnel() and isc_log_write().
 */

void
ns_log_setcontext(isc_log_t *lctx);
/*%<
 * Make the libns library use the provided context for logging internal
 * messages.
 *
 * Requires:
 *\li	lctx is a valid logging context.
 */
