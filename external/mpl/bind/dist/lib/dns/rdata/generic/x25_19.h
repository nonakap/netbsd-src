/*	$NetBSD: x25_19.h,v 1.8 2025/01/26 16:25:34 christos Exp $	*/

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

/*!
 *  \brief Per RFC1183 */

typedef struct dns_rdata_x25 {
	dns_rdatacommon_t common;
	isc_mem_t *mctx;
	unsigned char *x25;
	uint8_t x25_len;
} dns_rdata_x25_t;
