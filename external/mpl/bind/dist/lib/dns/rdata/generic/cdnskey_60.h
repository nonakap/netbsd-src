/*	$NetBSD: cdnskey_60.h,v 1.6 2025/01/26 16:25:30 christos Exp $	*/

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

/* CDNSKEY records have the same RDATA fields as DNSKEY records. */
typedef struct dns_rdata_key dns_rdata_cdnskey_t;
