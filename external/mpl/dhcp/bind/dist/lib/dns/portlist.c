/*	$NetBSD: portlist.c,v 1.1 2024/02/18 20:57:33 christos Exp $	*/

/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0.  If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/net.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/types.h>
#include <isc/util.h>

#include <dns/portlist.h>
#include <dns/types.h>

#define DNS_PORTLIST_MAGIC    ISC_MAGIC('P', 'L', 'S', 'T')
#define DNS_VALID_PORTLIST(p) ISC_MAGIC_VALID(p, DNS_PORTLIST_MAGIC)

typedef struct dns_element {
	in_port_t port;
	uint16_t flags;
} dns_element_t;

struct dns_portlist {
	unsigned int magic;
	isc_mem_t *mctx;
	isc_refcount_t refcount;
	isc_mutex_t lock;
	dns_element_t *list;
	unsigned int allocated;
	unsigned int active;
};

#define DNS_PL_INET	0x0001
#define DNS_PL_INET6	0x0002
#define DNS_PL_ALLOCATE 16

static int
compare(const void *arg1, const void *arg2) {
	const dns_element_t *e1 = (const dns_element_t *)arg1;
	const dns_element_t *e2 = (const dns_element_t *)arg2;

	if (e1->port < e2->port) {
		return (-1);
	}
	if (e1->port > e2->port) {
		return (1);
	}
	return (0);
}

isc_result_t
dns_portlist_create(isc_mem_t *mctx, dns_portlist_t **portlistp) {
	dns_portlist_t *portlist;

	REQUIRE(portlistp != NULL && *portlistp == NULL);

	portlist = isc_mem_get(mctx, sizeof(*portlist));
	isc_mutex_init(&portlist->lock);
	isc_refcount_init(&portlist->refcount, 1);
	portlist->list = NULL;
	portlist->allocated = 0;
	portlist->active = 0;
	portlist->mctx = NULL;
	isc_mem_attach(mctx, &portlist->mctx);
	portlist->magic = DNS_PORTLIST_MAGIC;
	*portlistp = portlist;
	return (ISC_R_SUCCESS);
}

static dns_element_t *
find_port(dns_element_t *list, unsigned int len, in_port_t port) {
	unsigned int xtry = len / 2;
	unsigned int min = 0;
	unsigned int max = len - 1;
	unsigned int last = len;

	for (;;) {
		if (list[xtry].port == port) {
			return (&list[xtry]);
		}
		if (port > list[xtry].port) {
			if (xtry == max) {
				break;
			}
			min = xtry;
			xtry = xtry + (max - xtry + 1) / 2;
			INSIST(xtry <= max);
			if (xtry == last) {
				break;
			}
			last = min;
		} else {
			if (xtry == min) {
				break;
			}
			max = xtry;
			xtry = xtry - (xtry - min + 1) / 2;
			INSIST(xtry >= min);
			if (xtry == last) {
				break;
			}
			last = max;
		}
	}
	return (NULL);
}

isc_result_t
dns_portlist_add(dns_portlist_t *portlist, int af, in_port_t port) {
	dns_element_t *el;
	isc_result_t result;

	REQUIRE(DNS_VALID_PORTLIST(portlist));
	REQUIRE(af == AF_INET || af == AF_INET6);

	LOCK(&portlist->lock);
	if (portlist->active != 0) {
		el = find_port(portlist->list, portlist->active, port);
		if (el != NULL) {
			if (af == AF_INET) {
				el->flags |= DNS_PL_INET;
			} else {
				el->flags |= DNS_PL_INET6;
			}
			result = ISC_R_SUCCESS;
			goto unlock;
		}
	}

	if (portlist->allocated <= portlist->active) {
		unsigned int allocated;
		allocated = portlist->allocated + DNS_PL_ALLOCATE;
		el = isc_mem_get(portlist->mctx, sizeof(*el) * allocated);
		if (portlist->list != NULL) {
			memmove(el, portlist->list,
				portlist->allocated * sizeof(*el));
			isc_mem_put(portlist->mctx, portlist->list,
				    portlist->allocated * sizeof(*el));
		}
		portlist->list = el;
		portlist->allocated = allocated;
	}
	portlist->list[portlist->active].port = port;
	if (af == AF_INET) {
		portlist->list[portlist->active].flags = DNS_PL_INET;
	} else {
		portlist->list[portlist->active].flags = DNS_PL_INET6;
	}
	portlist->active++;
	qsort(portlist->list, portlist->active, sizeof(*el), compare);
	result = ISC_R_SUCCESS;
unlock:
	UNLOCK(&portlist->lock);
	return (result);
}

void
dns_portlist_remove(dns_portlist_t *portlist, int af, in_port_t port) {
	dns_element_t *el;

	REQUIRE(DNS_VALID_PORTLIST(portlist));
	REQUIRE(af == AF_INET || af == AF_INET6);

	LOCK(&portlist->lock);
	if (portlist->active != 0) {
		el = find_port(portlist->list, portlist->active, port);
		if (el != NULL) {
			if (af == AF_INET) {
				el->flags &= ~DNS_PL_INET;
			} else {
				el->flags &= ~DNS_PL_INET6;
			}
			if (el->flags == 0) {
				*el = portlist->list[portlist->active];
				portlist->active--;
				qsort(portlist->list, portlist->active,
				      sizeof(*el), compare);
			}
		}
	}
	UNLOCK(&portlist->lock);
}

bool
dns_portlist_match(dns_portlist_t *portlist, int af, in_port_t port) {
	dns_element_t *el;
	bool result = false;

	REQUIRE(DNS_VALID_PORTLIST(portlist));
	REQUIRE(af == AF_INET || af == AF_INET6);
	LOCK(&portlist->lock);
	if (portlist->active != 0) {
		el = find_port(portlist->list, portlist->active, port);
		if (el != NULL) {
			if (af == AF_INET && (el->flags & DNS_PL_INET) != 0) {
				result = true;
			}
			if (af == AF_INET6 && (el->flags & DNS_PL_INET6) != 0) {
				result = true;
			}
		}
	}
	UNLOCK(&portlist->lock);
	return (result);
}

void
dns_portlist_attach(dns_portlist_t *portlist, dns_portlist_t **portlistp) {
	REQUIRE(DNS_VALID_PORTLIST(portlist));
	REQUIRE(portlistp != NULL && *portlistp == NULL);

	isc_refcount_increment(&portlist->refcount);
	*portlistp = portlist;
}

void
dns_portlist_detach(dns_portlist_t **portlistp) {
	REQUIRE(portlistp != NULL && DNS_VALID_PORTLIST(*portlistp));
	dns_portlist_t *portlist = *portlistp;
	*portlistp = NULL;

	if (isc_refcount_decrement(&portlist->refcount) == 1) {
		portlist->magic = 0;
		isc_refcount_destroy(&portlist->refcount);
		if (portlist->list != NULL) {
			isc_mem_put(portlist->mctx, portlist->list,
				    portlist->allocated *
					    sizeof(*portlist->list));
		}
		isc_mutex_destroy(&portlist->lock);
		isc_mem_putanddetach(&portlist->mctx, portlist,
				     sizeof(*portlist));
	}
}
