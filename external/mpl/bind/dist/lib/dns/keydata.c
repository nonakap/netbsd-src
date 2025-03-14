/*	$NetBSD: keydata.c,v 1.7 2025/01/26 16:25:23 christos Exp $	*/

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

#include <inttypes.h>

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/keydata.h>
#include <dns/rdata.h>
#include <dns/rdatastruct.h>

isc_result_t
dns_keydata_todnskey(dns_rdata_keydata_t *keydata, dns_rdata_dnskey_t *dnskey,
		     isc_mem_t *mctx) {
	REQUIRE(keydata != NULL && dnskey != NULL);

	dnskey->common.rdtype = dns_rdatatype_dnskey;
	dnskey->common.rdclass = keydata->common.rdclass;
	dnskey->mctx = mctx;
	dnskey->flags = keydata->flags;
	dnskey->protocol = keydata->protocol;
	dnskey->algorithm = keydata->algorithm;

	dnskey->datalen = keydata->datalen;

	if (mctx == NULL) {
		dnskey->data = keydata->data;
	} else {
		dnskey->data = isc_mem_allocate(mctx, dnskey->datalen);
		memmove(dnskey->data, keydata->data, dnskey->datalen);
	}

	return ISC_R_SUCCESS;
}

isc_result_t
dns_keydata_fromdnskey(dns_rdata_keydata_t *keydata, dns_rdata_dnskey_t *dnskey,
		       uint32_t refresh, uint32_t addhd, uint32_t removehd,
		       isc_mem_t *mctx) {
	REQUIRE(keydata != NULL && dnskey != NULL);

	keydata->common.rdtype = dns_rdatatype_keydata;
	keydata->common.rdclass = dnskey->common.rdclass;
	keydata->mctx = mctx;
	keydata->refresh = refresh;
	keydata->addhd = addhd;
	keydata->removehd = removehd;
	keydata->flags = dnskey->flags;
	keydata->protocol = dnskey->protocol;
	keydata->algorithm = dnskey->algorithm;

	keydata->datalen = dnskey->datalen;
	if (mctx == NULL) {
		keydata->data = dnskey->data;
	} else {
		keydata->data = isc_mem_allocate(mctx, keydata->datalen);
		memmove(keydata->data, dnskey->data, keydata->datalen);
	}

	return ISC_R_SUCCESS;
}
