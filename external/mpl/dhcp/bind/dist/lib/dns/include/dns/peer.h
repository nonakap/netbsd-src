/*	$NetBSD: peer.h,v 1.1 2024/02/18 20:57:37 christos Exp $	*/

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

#ifndef DNS_PEER_H
#define DNS_PEER_H 1

/*****
***** Module Info
*****/

/*! \file dns/peer.h
 * \brief
 * Data structures for peers (e.g. a 'server' config file statement)
 */

/***
 *** Imports
 ***/

#include <inttypes.h>
#include <stdbool.h>

#include <isc/lang.h>
#include <isc/magic.h>
#include <isc/netaddr.h>
#include <isc/refcount.h>

#include <dns/types.h>

#define DNS_PEERLIST_MAGIC ISC_MAGIC('s', 'e', 'R', 'L')
#define DNS_PEER_MAGIC	   ISC_MAGIC('S', 'E', 'r', 'v')

#define DNS_PEERLIST_VALID(ptr) ISC_MAGIC_VALID(ptr, DNS_PEERLIST_MAGIC)
#define DNS_PEER_VALID(ptr)	ISC_MAGIC_VALID(ptr, DNS_PEER_MAGIC)

/***
 *** Types
 ***/

struct dns_peerlist {
	unsigned int   magic;
	isc_refcount_t refs;

	isc_mem_t *mem;

	ISC_LIST(dns_peer_t) elements;
};

struct dns_peer {
	unsigned int   magic;
	isc_refcount_t refs;

	isc_mem_t *mem;

	isc_netaddr_t	      address;
	unsigned int	      prefixlen;
	bool		      bogus;
	dns_transfer_format_t transfer_format;
	uint32_t	      transfers;
	bool		      support_ixfr;
	bool		      provide_ixfr;
	bool		      request_ixfr;
	bool		      support_edns;
	bool		      request_nsid;
	bool		      send_cookie;
	bool		      request_expire;
	bool		      force_tcp;
	bool		      tcp_keepalive;
	dns_name_t	     *key;
	isc_sockaddr_t	     *transfer_source;
	isc_dscp_t	      transfer_dscp;
	isc_sockaddr_t	     *notify_source;
	isc_dscp_t	      notify_dscp;
	isc_sockaddr_t	     *query_source;
	isc_dscp_t	      query_dscp;
	uint16_t	      udpsize;	   /* receive size */
	uint16_t	      maxudp;	   /* transmit size */
	uint16_t	      padding;	   /* pad block size */
	uint8_t		      ednsversion; /* edns version */

	uint32_t bitflags;

	ISC_LINK(dns_peer_t) next;
};

/***
 *** Functions
 ***/

ISC_LANG_BEGINDECLS

isc_result_t
dns_peerlist_new(isc_mem_t *mem, dns_peerlist_t **list);

void
dns_peerlist_attach(dns_peerlist_t *source, dns_peerlist_t **target);

void
dns_peerlist_detach(dns_peerlist_t **list);

/*
 * After return caller still holds a reference to peer.
 */
void
dns_peerlist_addpeer(dns_peerlist_t *peers, dns_peer_t *peer);

/*
 * Ditto. */
isc_result_t
dns_peerlist_peerbyaddr(dns_peerlist_t *peers, const isc_netaddr_t *addr,
			dns_peer_t **retval);

/*
 * What he said.
 */
isc_result_t
dns_peerlist_currpeer(dns_peerlist_t *peers, dns_peer_t **retval);

isc_result_t
dns_peer_new(isc_mem_t *mem, const isc_netaddr_t *ipaddr, dns_peer_t **peer);

isc_result_t
dns_peer_newprefix(isc_mem_t *mem, const isc_netaddr_t *ipaddr,
		   unsigned int prefixlen, dns_peer_t **peer);

void
dns_peer_attach(dns_peer_t *source, dns_peer_t **target);

void
dns_peer_detach(dns_peer_t **list);

isc_result_t
dns_peer_setbogus(dns_peer_t *peer, bool newval);

isc_result_t
dns_peer_getbogus(dns_peer_t *peer, bool *retval);

isc_result_t
dns_peer_setrequestixfr(dns_peer_t *peer, bool newval);

isc_result_t
dns_peer_getrequestixfr(dns_peer_t *peer, bool *retval);

isc_result_t
dns_peer_setprovideixfr(dns_peer_t *peer, bool newval);

isc_result_t
dns_peer_getprovideixfr(dns_peer_t *peer, bool *retval);

isc_result_t
dns_peer_setrequestnsid(dns_peer_t *peer, bool newval);

isc_result_t
dns_peer_getrequestnsid(dns_peer_t *peer, bool *retval);

isc_result_t
dns_peer_setsendcookie(dns_peer_t *peer, bool newval);

isc_result_t
dns_peer_getsendcookie(dns_peer_t *peer, bool *retval);

isc_result_t
dns_peer_setrequestexpire(dns_peer_t *peer, bool newval);

isc_result_t
dns_peer_getrequestexpire(dns_peer_t *peer, bool *retval);

isc_result_t
dns_peer_setsupportedns(dns_peer_t *peer, bool newval);

isc_result_t
dns_peer_getforcetcp(dns_peer_t *peer, bool *retval);

isc_result_t
dns_peer_setforcetcp(dns_peer_t *peer, bool newval);

isc_result_t
dns_peer_gettcpkeepalive(dns_peer_t *peer, bool *retval);

isc_result_t
dns_peer_settcpkeepalive(dns_peer_t *peer, bool newval);

isc_result_t
dns_peer_getsupportedns(dns_peer_t *peer, bool *retval);

isc_result_t
dns_peer_settransfers(dns_peer_t *peer, uint32_t newval);

isc_result_t
dns_peer_gettransfers(dns_peer_t *peer, uint32_t *retval);

isc_result_t
dns_peer_settransferformat(dns_peer_t *peer, dns_transfer_format_t newval);

isc_result_t
dns_peer_gettransferformat(dns_peer_t *peer, dns_transfer_format_t *retval);

isc_result_t
dns_peer_setkeybycharp(dns_peer_t *peer, const char *keyval);

isc_result_t
dns_peer_getkey(dns_peer_t *peer, dns_name_t **retval);

isc_result_t
dns_peer_setkey(dns_peer_t *peer, dns_name_t **keyval);

isc_result_t
dns_peer_settransfersource(dns_peer_t		*peer,
			   const isc_sockaddr_t *transfer_source);

isc_result_t
dns_peer_gettransfersource(dns_peer_t *peer, isc_sockaddr_t *transfer_source);

isc_result_t
dns_peer_setudpsize(dns_peer_t *peer, uint16_t udpsize);

isc_result_t
dns_peer_getudpsize(dns_peer_t *peer, uint16_t *udpsize);

isc_result_t
dns_peer_setmaxudp(dns_peer_t *peer, uint16_t maxudp);

isc_result_t
dns_peer_getmaxudp(dns_peer_t *peer, uint16_t *maxudp);

isc_result_t
dns_peer_setpadding(dns_peer_t *peer, uint16_t padding);

isc_result_t
dns_peer_getpadding(dns_peer_t *peer, uint16_t *padding);

isc_result_t
dns_peer_setnotifysource(dns_peer_t *peer, const isc_sockaddr_t *notify_source);

isc_result_t
dns_peer_getnotifysource(dns_peer_t *peer, isc_sockaddr_t *notify_source);

isc_result_t
dns_peer_setquerysource(dns_peer_t *peer, const isc_sockaddr_t *query_source);

isc_result_t
dns_peer_getquerysource(dns_peer_t *peer, isc_sockaddr_t *query_source);

isc_result_t
dns_peer_setnotifydscp(dns_peer_t *peer, isc_dscp_t dscp);

isc_result_t
dns_peer_getnotifydscp(dns_peer_t *peer, isc_dscp_t *dscpp);

isc_result_t
dns_peer_settransferdscp(dns_peer_t *peer, isc_dscp_t dscp);

isc_result_t
dns_peer_gettransferdscp(dns_peer_t *peer, isc_dscp_t *dscpp);

isc_result_t
dns_peer_setquerydscp(dns_peer_t *peer, isc_dscp_t dscp);

isc_result_t
dns_peer_getquerydscp(dns_peer_t *peer, isc_dscp_t *dscpp);

isc_result_t
dns_peer_setednsversion(dns_peer_t *peer, uint8_t ednsversion);

isc_result_t
dns_peer_getednsversion(dns_peer_t *peer, uint8_t *ednsversion);
ISC_LANG_ENDDECLS

#endif /* DNS_PEER_H */
