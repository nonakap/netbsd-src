/*	$NetBSD: dig.c,v 1.14 2025/07/17 19:01:43 christos Exp $	*/

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
#include <stdlib.h>
#include <time.h>

#include <isc/attributes.h>
#include <isc/dir.h>
#include <isc/loop.h>
#include <isc/netaddr.h>
#include <isc/parseint.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/util.h>

#include <dns/byaddr.h>
#include <dns/dns64.h>
#include <dns/fixedname.h>
#include <dns/masterdump.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rcode.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdataset.h>
#include <dns/rdatatype.h>
#include <dns/tsig.h>

#include "dighost.h"

#define ADD_STRING(b, s)                                          \
	{                                                         \
		if (strlen(s) >= isc_buffer_availablelength(b)) { \
			return ((((ISC_R_NOSPACE))));             \
		} else {                                          \
			isc_buffer_putstr(b, s);                  \
		}                                                 \
	}

#define DIG_MAX_ADDRESSES 20

dig_lookup_t *default_lookup = NULL;

static char *batchname = NULL;
static FILE *batchfp = NULL;
static char *argv0;
static int addresscount = 0;

static char domainopt[DNS_NAME_MAXTEXT];
static char hexcookie[81];

static bool short_form = false, printcmd = true, plusquest = false,
	    pluscomm = false, ipv4only = false, ipv6only = false, digrc = true;
static uint32_t splitwidth = 0xffffffff;

/*% opcode text */
static const char *const opcodetext[] = {
	"QUERY",      "IQUERY",	    "STATUS",	  "RESERVED3",
	"NOTIFY",     "UPDATE",	    "RESERVED6",  "RESERVED7",
	"RESERVED8",  "RESERVED9",  "RESERVED10", "RESERVED11",
	"RESERVED12", "RESERVED13", "RESERVED14", "RESERVED15"
};

static const char *
rcode_totext(dns_rcode_t rcode) {
	static char buf[64];
	isc_buffer_t b;
	isc_result_t result;

	memset(buf, 0, sizeof(buf));
	isc_buffer_init(&b, buf + 1, sizeof(buf) - 2);
	result = dns_rcode_totext(rcode, &b);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
	if (strspn(buf + 1, "0123456789") == strlen(buf + 1)) {
		buf[0] = '?';
		return buf;
	}
	return buf + 1;
}

/*% print usage */
static void
print_usage(FILE *fp) {
	fprintf(fp,
		"Usage:  dig [@global-server] [domain] [q-type] [q-class] "
		"{q-opt}\n"
		"            {global-d-opt} host [@local-server] "
		"{local-d-opt}\n"
		"            [ host [@local-server] {local-d-opt} [...]]\n");
}

#if TARGET_OS_IPHONE
static void
usage(void) {
	fprintf(stderr, "Press <Help> for complete list of options\n");
}
#else  /* if TARGET_OS_IPHONE */
noreturn static void
usage(void);

static void
usage(void) {
	print_usage(stderr);
	fprintf(stderr, "\nUse \"dig -h\" (or \"dig -h | more\") "
			"for complete list of options\n");
	exit(EXIT_FAILURE);
}
#endif /* if TARGET_OS_IPHONE */

/*% help */
static void
help(void) {
	print_usage(stdout);
	printf("Where:  domain	  is in the Domain Name System\n"
	       "        q-class  is one of (in,hs,ch,...) [default: in]\n"
	       "        q-type   is one of "
	       "(a,any,mx,ns,soa,hinfo,axfr,txt,...) "
	       "[default:a]\n"
	       "                 (Use ixfr=version for type ixfr)\n"
	       "        q-opt    is one of:\n"
	       "                 -4                  (use IPv4 query transport "
	       "only)\n"
	       "                 -6                  (use IPv6 query transport "
	       "only)\n"
	       "                 -b address[#port]   (bind to source "
	       "address/port)\n"
	       "                 -c class            (specify query class)\n"
	       "                 -f filename         (batch mode)\n"
	       "                 -k keyfile          (specify tsig key file)\n"
	       "                 -m                  (enable memory usage "
	       "debugging)\n"
	       "                 -p port             (specify port number)\n"
	       "                 -q name             (specify query name)\n"
	       "                 -r                  (do not read ~/.digrc)\n"
	       "                 -t type             (specify query type)\n"
	       "                 -u                  (display times in usec "
	       "instead of msec)\n"
	       "                 -x dot-notation     (shortcut for reverse "
	       "lookups)\n"
	       "                 -y [hmac:]name:key  (specify named base64 "
	       "tsig "
	       "key)\n"
	       "        d-opt    is of the form +keyword[=value], where "
	       "keyword "
	       "is:\n"
	       "                 +[no]aaflag         (Set AA flag in query "
	       "(+[no]aaflag))\n"
	       "                 +[no]aaonly         (Set AA flag in query "
	       "(+[no]aaflag))\n"
	       "                 +[no]additional     (Control display of "
	       "additional section)\n"
	       "                 +[no]adflag         (Set AD flag in query "
	       "(default on))\n"
	       "                 +[no]all            (Set or clear all display "
	       "flags)\n"
	       "                 +[no]answer         (Control display of "
	       "answer "
	       "section)\n"
	       "                 +[no]authority      (Control display of "
	       "authority section)\n"
	       "                 +[no]badcookie      (Retry BADCOOKIE "
	       "responses)\n"
	       "                 +[no]besteffort     (Try to parse even "
	       "illegal "
	       "messages)\n"
	       "                 +bufsize[=###]      (Set EDNS0 Max UDP packet "
	       "size)\n"
	       "                 +[no]cdflag         (Set checking disabled "
	       "flag in query)\n"
	       "                 +[no]class          (Control display of class "
	       "in records)\n"
	       "                 +[no]cmd            (Control display of "
	       "command line -\n"
	       "                                      global option)\n"
	       "                 +[no]coflag         (Set compact denial of "
	       "existence ok flag)\n"
	       "                                      in query)\n"
	       "                 +[no]comments       (Control display of "
	       "packet "
	       "header\n"
	       "                                      and section name "
	       "comments)\n"
	       "                 +[no]cookie         (Add a COOKIE option to "
	       "the request)\n"
	       "                 +[no]crypto         (Control display of "
	       "cryptographic\n"
	       "                                      fields in records)\n"
	       "                 +[no]defname        (Use search list "
	       "(+[no]search))\n"
	       "                 +[no]dns64prefix    (Get the DNS64 prefixes "
	       "from ipv4only.arpa)\n"
	       "                 +[no]dnssec         (Request DNSSEC records)\n"
	       "                 +domain=###         (Set default domainname)\n"
	       "                 +[no]edns[=###]     (Set EDNS version) [0]\n"
	       "                 +ednsflags=###      (Set undefined EDNS flag "
	       "bits)\n"
	       "                 +[no]ednsnegotiation (Set EDNS version "
	       "negotiation)\n"
	       "                 +ednsopt=###[:value] (Send specified EDNS "
	       "option)\n"
	       "                 +noednsopt          (Clear list of +ednsopt "
	       "options)\n"
	       "                 +[no]expandaaaa     (Expand AAAA records)\n"
	       "                 +[no]expire         (Request time to expire)\n"
	       "                 +[no]fail           (Don't try next server on "
	       "SERVFAIL)\n"
	       "                 +[no]header-only    (Send query without a "
	       "question section)\n"
	       "                 +[no]https[=###]    (DNS-over-HTTPS mode) "
	       "[/]\n"
	       "                 +[no]https-get      (Use GET instead of "
	       "default POST method\n"
	       "                                      while using HTTPS)\n"
	       "                 +[no]http-plain[=###] (DNS over plain HTTP "
	       "mode) [/]\n"
	       "                 +[no]http-plain-get (Use GET instead of "
	       "default POST "
	       "method\n"
	       "                                      while using plain HTTP)\n"
	       "                 +[no]identify       (ID responders in short "
	       "answers)\n"
#ifdef HAVE_LIBIDN2
	       "                 +[no]idn            (convert international "
	       "domain names)\n"
#endif /* ifdef HAVE_LIBIDN2 */
	       "                 +[no]ignore         (Don't revert to TCP for "
	       "TC responses.)\n"
	       "                 +[no]keepalive      (Request EDNS TCP "
	       "keepalive)\n"
	       "                 +[no]keepopen       (Keep the TCP socket open "
	       "between "
	       "queries)\n"
	       "                 +[no]multiline      (Print records in an "
	       "expanded format)\n"
	       "                 +ndots=###          (Set search NDOTS value)\n"
	       "                 +[no]nsid           (Request Name Server ID)\n"
	       "                 +[no]nssearch       (Search all authoritative "
	       "nameservers)\n"
	       "                 +[no]onesoa         (AXFR prints only one soa "
	       "record)\n"
	       "                 +[no]opcode=###     (Set the opcode of the "
	       "request)\n"
	       "                 +padding=###        (Set padding block size "
	       "[0])\n"
	       "                 "
	       "+[no]proxy[=src_addr[#src_port]-dst_addr[#dst_port]]\n"
	       "                                     (Add PROXYv2 headers to "
	       "the queries. If\n"
	       "                                      addresses are omitted, "
	       "LOCAL PROXYv2\n"
	       "                                      headers are added)\n"
	       "                 "
	       "+[no]proxy-plain[=src_addr[#src_port]-dst_addr[#dst_port]]\n"
	       "                                     (The same as'+[no]proxy', "
	       "but send PROXYv2\n"
	       "                                      headers ahead of any "
	       "encryption if an\n"
	       "                                      encrypted transport is "
	       "used)\n"
	       "                 +qid=###            (Specify the query ID to "
	       "use when sending\n"
	       "                                      queries)\n"
	       "                 +[no]qr             (Print question before "
	       "sending)\n"
	       "                 +[no]question       (Control display of "
	       "question section)\n"
	       "                 +[no]raflag         (Set RA flag in query "
	       "(+[no]raflag))\n"
	       "                 +[no]rdflag         (Recursive mode "
	       "(+[no]recurse))\n"
	       "                 +[no]recurse        (Recursive mode "
	       "(+[no]rdflag))\n"
	       "                 +retry=###          (Set number of UDP "
	       "retries) [2]\n"
	       "                 +[no]rrcomments     (Control display of "
	       "per-record "
	       "comments)\n"
	       "                 +[no]search         (Set whether to use "
	       "searchlist)\n"
	       "                 +[no]short          (Display nothing except "
	       "short\n"
	       "                                      form of answers - global "
	       "option)\n"
	       "                 +[no]showbadcookie  (Show BADCOOKIE message)\n"
	       "                 +[no]showbadvers    (Show BADVERS message)\n"
	       "                 +[no]showsearch     (Search with intermediate "
	       "results)\n"
	       "                 +[no]split=##       (Split hex/base64 fields "
	       "into chunks)\n"
	       "                 +[no]stats          (Control display of "
	       "statistics)\n"
	       "                 +subnet=addr        (Set edns-client-subnet "
	       "option)\n"
	       "                 +[no]tcflag         (Set TC flag in query "
	       "(+[no]tcflag))\n"
	       "                 +[no]tcp            (TCP mode (+[no]vc))\n"
	       "                 +timeout=###        (Set query timeout) [5]\n"
	       "                 +[no]tls            (DNS-over-TLS mode)\n"
	       "                 +[no]tls-ca[=file]  (Enable remote server's "
	       "TLS certificate\n"
	       "                                      validation)\n"
	       "                 +[no]tls-hostname=hostname (Explicitly set "
	       "the expected TLS\n"
	       "                                      hostname)\n"
	       "                 +[no]tls-certfile=file (Load client TLS "
	       "certificate chain from\n"
	       "                                      file)\n"
	       "                 +[no]tls-keyfile=file (Load client TLS "
	       "private key from file)\n"
	       "                 +[no]trace          (Trace delegation down "
	       "from root [implies\n"
	       "                                      +dnssec])\n"
	       "                 +tries=###          (Set number of UDP "
	       "attempts) [3]\n"
	       "                 +[no]ttlid          (Control display of ttls "
	       "in records)\n"
	       "                 +[no]ttlunits       (Display TTLs in "
	       "human-readable units)\n"
	       "                 +[no]unknownformat  (Print RDATA in RFC 3597 "
	       "\"unknown\" "
	       "format)\n"
	       "                 +[no]vc             (TCP mode (+[no]tcp))\n"
	       "                 +[no]yaml           (Present the results as "
	       "YAML)\n"
	       "                 +[no]zflag          (Set Z flag in query)\n"
	       "        global d-opts and servers (before host name) affect "
	       "all "
	       "queries.\n"
	       "        local d-opts and servers (after host name) affect only "
	       "that lookup.\n"
	       "        -h                           (print help and exit)\n"
	       "        -v                           (print version "
	       "and exit)\n");
}

/*%
 * Callback from dighost.c to print the received message.
 */
static void
received(unsigned int bytes, isc_sockaddr_t *from, dig_query_t *query) {
	uint64_t diff;
	time_t tnow;
	struct tm tmnow;
	char time_str[100];
	char fromtext[ISC_SOCKADDR_FORMATSIZE];

	isc_sockaddr_format(from, fromtext, sizeof(fromtext));

	if (short_form || yaml) {
		return;
	}

	if (query->lookup->stats) {
		const char *proto;
		diff = isc_time_microdiff(&query->time_recv, &query->time_sent);
		if (query->lookup->use_usec) {
			printf(";; Query time: %ld usec\n", (long)diff);
		} else {
			printf(";; Query time: %ld msec\n", (long)diff / 1000);
		}
		if (dig_lookup_is_tls(query->lookup)) {
			proto = "TLS";
		} else if (query->lookup->https_mode) {
			if (query->lookup->http_plain) {
				proto = query->lookup->https_get ? "HTTP-GET"
								 : "HTTP";
			} else {
				proto = query->lookup->https_get ? "HTTPS-GET"
								 : "HTTPS";
			}
		} else if (query->lookup->tcp_mode) {
			proto = "TCP";
		} else {
			proto = "UDP";
		}
		printf(";; SERVER: %s(%s) (%s)\n", fromtext, query->userarg,
		       proto);

		if (query->lookup->proxy_mode) {
			printf(";; CLIENT PROXY HEADER");

			if ((dig_lookup_is_tls(query->lookup) ||
			     (query->lookup->https_mode &&
			      !query->lookup->http_plain)) &&
			    query->lookup->proxy_plain)
			{
				printf(" (plain)");
			}

			printf(": ");

			if (!query->lookup->proxy_local) {
				char src_buf[ISC_SOCKADDR_FORMATSIZE] = { 0 };
				char dst_buf[ISC_SOCKADDR_FORMATSIZE] = { 0 };

				isc_sockaddr_format(
					&query->lookup->proxy_src_addr, src_buf,
					sizeof(src_buf));

				isc_sockaddr_format(
					&query->lookup->proxy_dst_addr, dst_buf,
					sizeof(dst_buf));
				printf("source: %s, destination: %s", src_buf,
				       dst_buf);
			} else {
				printf("LOCAL");
			}

			printf("\n");
		}
		time(&tnow);
		(void)localtime_r(&tnow, &tmnow);

		if (strftime(time_str, sizeof(time_str),
			     "%a %b %d %H:%M:%S %Z %Y", &tmnow) > 0U)
		{
			printf(";; WHEN: %s\n", time_str);
		}
		if (query->lookup->doing_xfr) {
			printf(";; XFR size: %u records (messages %u, "
			       "bytes %" PRIu64 ")\n",
			       query->rr_count, query->msg_count,
			       query->byte_count);
		} else {
			printf(";; MSG SIZE  rcvd: %u\n", bytes);
		}
		if (tsigkey != NULL) {
			if (!validated) {
				puts(";; WARNING -- Some TSIG could not "
				     "be validated");
			}
		}
		if ((tsigkey == NULL) && (keysecret[0] != 0)) {
			puts(";; WARNING -- TSIG key was not used.");
		}
		puts("");
	} else if (query->lookup->identify) {
		diff = isc_time_microdiff(&query->time_recv, &query->time_sent);
		if (query->lookup->use_usec) {
			printf(";; Received %" PRIu64 " bytes "
			       "from %s(%s) in %ld us\n\n",
			       query->lookup->doing_xfr ? query->byte_count
							: (uint64_t)bytes,
			       fromtext, query->userarg, (long)diff);
		} else {
			printf(";; Received %" PRIu64 " bytes "
			       "from %s(%s) in %ld ms\n\n",
			       query->lookup->doing_xfr ? query->byte_count
							: (uint64_t)bytes,
			       fromtext, query->userarg, (long)diff / 1000);
		}
	}
}

/*
 * Callback from dighost.c to print that it is trying a server.
 * Not used in dig.
 * XXX print_trying
 */
static void
trying(char *frm, dig_lookup_t *lookup) {
	UNUSED(frm);
	UNUSED(lookup);
}

/*%
 * Internal print routine used to print short form replies.
 */
static isc_result_t
say_message(dns_rdata_t *rdata, dig_query_t *query, isc_buffer_t *buf) {
	isc_result_t result;
	uint64_t diff;
	char store[sizeof(" in 18446744073709551616 us.")];
	unsigned int styleflags = 0;

	if (query->lookup->trace || query->lookup->ns_search_only) {
		result = dns_rdatatype_totext(rdata->type, buf);
		if (result != ISC_R_SUCCESS) {
			return result;
		}
		ADD_STRING(buf, " ");
	}

	/* Turn on rrcomments if explicitly enabled */
	if (query->lookup->rrcomments > 0) {
		styleflags |= DNS_STYLEFLAG_RRCOMMENT;
	}
	if (query->lookup->nocrypto) {
		styleflags |= DNS_STYLEFLAG_NOCRYPTO;
	}
	if (query->lookup->print_unknown_format) {
		styleflags |= DNS_STYLEFLAG_UNKNOWNFORMAT;
	}
	if (query->lookup->expandaaaa) {
		styleflags |= DNS_STYLEFLAG_EXPANDAAAA;
	}
	result = dns_rdata_tofmttext(rdata, NULL, styleflags, 0, splitwidth,
				     " ", buf);
	if (result == ISC_R_NOSPACE) {
		return result;
	}
	check_result(result, "dns_rdata_totext");
	if (query->lookup->identify) {
		diff = isc_time_microdiff(&query->time_recv, &query->time_sent);
		ADD_STRING(buf, " from server ");
		ADD_STRING(buf, query->servname);
		if (query->lookup->use_usec) {
			snprintf(store, sizeof(store), " in %" PRIu64 " us.",
				 diff);
		} else {
			snprintf(store, sizeof(store), " in %" PRIu64 " ms.",
				 diff / 1000);
		}
		ADD_STRING(buf, store);
	}
	ADD_STRING(buf, "\n");
	return ISC_R_SUCCESS;
}

/*%
 * short_form message print handler.  Calls above say_message()
 */
static isc_result_t
dns64prefix_answer(dns_message_t *msg, isc_buffer_t *buf) {
	dns_rdataset_t *rdataset = NULL;
	dns_fixedname_t fixed;
	dns_name_t *name;
	isc_result_t result;
	isc_netprefix_t prefix[10];
	size_t i, count = 10;

	name = dns_fixedname_initname(&fixed);
	result = dns_name_fromstring(name, "ipv4only.arpa", dns_rootname, 0,
				     NULL);
	check_result(result, "dns_name_fromstring");

	result = dns_message_findname(msg, DNS_SECTION_ANSWER, name,
				      dns_rdatatype_aaaa, dns_rdatatype_none,
				      NULL, &rdataset);
	if (result == DNS_R_NXDOMAIN || result == DNS_R_NXRRSET) {
		return ISC_R_SUCCESS;
	} else if (result != ISC_R_SUCCESS) {
		return result;
	}

	result = dns_dns64_findprefix(rdataset, prefix, &count);
	if (result == ISC_R_NOTFOUND) {
		return ISC_R_SUCCESS;
	}
	if (count > 10) {
		count = 10;
	}
	for (i = 0; i < count; i++) {
		result = isc_netaddr_totext(&prefix[i].addr, buf);
		if (result != ISC_R_SUCCESS) {
			return result;
		}
		result = isc_buffer_printf(buf, "/%u\n", prefix[i].prefixlen);
		if (result != ISC_R_SUCCESS) {
			return result;
		}
	}

	return ISC_R_SUCCESS;
}

/*%
 * short_form message print handler.  Calls above say_message()
 */
static isc_result_t
short_answer(dns_message_t *msg, dns_messagetextflag_t flags, isc_buffer_t *buf,
	     dig_query_t *query) {
	dns_name_t *name;
	dns_rdataset_t *rdataset;
	isc_result_t result, loopresult;
	dns_name_t empty_name;
	dns_rdata_t rdata = DNS_RDATA_INIT;

	UNUSED(flags);

	dns_name_init(&empty_name, NULL);
	result = dns_message_firstname(msg, DNS_SECTION_ANSWER);
	if (result == ISC_R_NOMORE) {
		return ISC_R_SUCCESS;
	} else if (result != ISC_R_SUCCESS) {
		return result;
	}

	for (;;) {
		name = NULL;
		dns_message_currentname(msg, DNS_SECTION_ANSWER, &name);

		for (rdataset = ISC_LIST_HEAD(name->list); rdataset != NULL;
		     rdataset = ISC_LIST_NEXT(rdataset, link))
		{
			loopresult = dns_rdataset_first(rdataset);
			while (loopresult == ISC_R_SUCCESS) {
				dns_rdataset_current(rdataset, &rdata);
				result = say_message(&rdata, query, buf);
				if (result == ISC_R_NOSPACE) {
					return result;
				}
				check_result(result, "say_message");
				loopresult = dns_rdataset_next(rdataset);
				dns_rdata_reset(&rdata);
			}
		}
		result = dns_message_nextname(msg, DNS_SECTION_ANSWER);
		if (result == ISC_R_NOMORE) {
			break;
		} else if (result != ISC_R_SUCCESS) {
			return result;
		}
	}

	return ISC_R_SUCCESS;
}

static bool
isdotlocal(dns_message_t *msg) {
	isc_result_t result;
	static unsigned char local_ndata[] = { "\005local" };
	static unsigned char local_offsets[] = { 0, 6 };
	static dns_name_t local = DNS_NAME_INITABSOLUTE(local_ndata,
							local_offsets);

	for (result = dns_message_firstname(msg, DNS_SECTION_QUESTION);
	     result == ISC_R_SUCCESS;
	     result = dns_message_nextname(msg, DNS_SECTION_QUESTION))
	{
		dns_name_t *name = NULL;
		dns_message_currentname(msg, DNS_SECTION_QUESTION, &name);
		if (dns_name_issubdomain(name, &local)) {
			return true;
		}
	}
	return false;
}

/*
 * Callback from dighost.c to print the reply from a server
 */
static isc_result_t
printmessage(dig_query_t *query, const isc_buffer_t *msgbuf, dns_message_t *msg,
	     bool headers) {
	isc_result_t result;
	dns_messagetextflag_t flags;
	isc_buffer_t *buf = NULL;
	unsigned int len = OUTPUTBUF;
	dns_master_style_t *style = NULL;
	unsigned int styleflags = 0;
	bool isquery = (msg == query->lookup->sendmsg);
	bool dns64prefix = query->lookup->dns64prefix;

	UNUSED(msgbuf);

	dig_idnsetup(query->lookup, true);

	styleflags |= DNS_STYLEFLAG_REL_OWNER;
	if (yaml) {
		msg->indent.string = "  ";
		msg->indent.count = 3;
		styleflags |= DNS_STYLEFLAG_YAML;
	} else {
		if (query->lookup->comments) {
			styleflags |= DNS_STYLEFLAG_COMMENT;
		}
		if (query->lookup->print_unknown_format) {
			styleflags |= DNS_STYLEFLAG_UNKNOWNFORMAT;
		}
		/* Turn on rrcomments if explicitly enabled */
		if (query->lookup->rrcomments > 0) {
			styleflags |= DNS_STYLEFLAG_RRCOMMENT;
		}
		if (query->lookup->ttlunits) {
			styleflags |= DNS_STYLEFLAG_TTL_UNITS;
		}
		if (query->lookup->nottl) {
			styleflags |= DNS_STYLEFLAG_NO_TTL;
		}
		if (query->lookup->noclass) {
			styleflags |= DNS_STYLEFLAG_NO_CLASS;
		}
		if (query->lookup->nocrypto) {
			styleflags |= DNS_STYLEFLAG_NOCRYPTO;
		}
		if (query->lookup->expandaaaa) {
			styleflags |= DNS_STYLEFLAG_EXPANDAAAA;
		}
		if (query->lookup->multiline) {
			styleflags |= DNS_STYLEFLAG_OMIT_OWNER;
			styleflags |= DNS_STYLEFLAG_OMIT_CLASS;
			styleflags |= DNS_STYLEFLAG_REL_DATA;
			styleflags |= DNS_STYLEFLAG_OMIT_TTL;
			styleflags |= DNS_STYLEFLAG_TTL;
			styleflags |= DNS_STYLEFLAG_MULTILINE;
			/* Turn on rrcomments unless explicitly disabled */
			if (query->lookup->rrcomments >= 0) {
				styleflags |= DNS_STYLEFLAG_RRCOMMENT;
			}
		}
	}
	if (query->lookup->multiline ||
	    (query->lookup->nottl && query->lookup->noclass))
	{
		result = dns_master_stylecreate(&style, styleflags, 24, 24, 24,
						32, 80, 8, splitwidth, mctx);
	} else if (query->lookup->nottl || query->lookup->noclass) {
		result = dns_master_stylecreate(&style, styleflags, 24, 24, 32,
						40, 80, 8, splitwidth, mctx);
	} else {
		result = dns_master_stylecreate(&style, styleflags, 24, 32, 40,
						48, 80, 8, splitwidth, mctx);
	}
	check_result(result, "dns_master_stylecreate");

	if (query->lookup->cmdline[0] != 0) {
		if (!short_form && !dns64prefix && printcmd) {
			printf("%s", query->lookup->cmdline);
		}
		query->lookup->cmdline[0] = '\0';
	}
	debug("printmessage(%s %s %s)", headers ? "headers" : "noheaders",
	      query->lookup->comments ? "comments" : "nocomments",
	      short_form    ? "short_form"
	      : dns64prefix ? "dns64prefix_form"
			    : "long_form");

	flags = 0;
	if (!headers) {
		flags |= DNS_MESSAGETEXTFLAG_NOHEADERS;
		flags |= DNS_MESSAGETEXTFLAG_NOCOMMENTS;
	}
	if (query->lookup->onesoa &&
	    query->lookup->rdtype == dns_rdatatype_axfr)
	{
		flags |= (query->msg_count == 0) ? DNS_MESSAGETEXTFLAG_ONESOA
						 : DNS_MESSAGETEXTFLAG_OMITSOA;
	}
	if (!query->lookup->comments) {
		flags |= DNS_MESSAGETEXTFLAG_NOCOMMENTS;
	}

	isc_buffer_allocate(mctx, &buf, len);

	if (yaml) {
		enum { Q = 0x1, R = 0x2 }; /* Q:query; R:ecursive */
		unsigned int tflag = 0;
		char sockstr[ISC_SOCKADDR_FORMATSIZE];
		uint16_t sport;
		char *hash;
		int pf;

		printf("- type: MESSAGE\n");
		printf("  message:\n");

		if (isquery) {
			tflag |= Q;
			if ((msg->flags & DNS_MESSAGEFLAG_RD) != 0) {
				tflag |= R;
			}
		} else if (((msg->flags & DNS_MESSAGEFLAG_RD) != 0) &&
			   ((msg->flags & DNS_MESSAGEFLAG_RA) != 0))
		{
			tflag |= R;
		}

		if (tflag == (Q | R)) {
			printf("    type: RECURSIVE_QUERY\n");
		} else if (tflag == Q) {
			printf("    type: AUTH_QUERY\n");
		} else if (tflag == R) {
			printf("    type: RECURSIVE_RESPONSE\n");
		} else {
			printf("    type: AUTH_RESPONSE\n");
		}

		if (!isc_time_isepoch(&query->time_sent)) {
			char tbuf[100];
			if (query->lookup->use_usec) {
				isc_time_formatISO8601us(&query->time_sent,
							 tbuf, sizeof(tbuf));
			} else {
				isc_time_formatISO8601ms(&query->time_sent,
							 tbuf, sizeof(tbuf));
			}
			printf("    query_time: !!timestamp %s\n", tbuf);
		}

		if (!isquery && !isc_time_isepoch(&query->time_recv)) {
			char tbuf[100];
			if (query->lookup->use_usec) {
				isc_time_formatISO8601us(&query->time_recv,
							 tbuf, sizeof(tbuf));
			} else {
				isc_time_formatISO8601ms(&query->time_recv,
							 tbuf, sizeof(tbuf));
			}
			printf("    response_time: !!timestamp %s\n", tbuf);
		}

		printf("    message_size: %ub\n",
		       isc_buffer_usedlength(msgbuf));

		pf = isc_sockaddr_pf(&query->sockaddr);
		if (pf == PF_INET || pf == PF_INET6) {
			printf("    socket_family: %s\n",
			       pf == PF_INET ? "INET" : "INET6");

			printf("    socket_protocol: %s\n",
			       query->lookup->tcp_mode ? "TCP" : "UDP");

			sport = isc_sockaddr_getport(&query->sockaddr);
			isc_sockaddr_format(&query->sockaddr, sockstr,
					    sizeof(sockstr));
			hash = strchr(sockstr, '#');
			if (hash != NULL) {
				*hash = '\0';
			}
			if (strcmp(sockstr, "::") == 0) {
				strlcat(sockstr, "0", sizeof(sockstr));
			}

			printf("    response_address: \"%s\"\n", sockstr);
			printf("    response_port: %u\n", sport);
		}

		if (query->handle != NULL) {
			isc_sockaddr_t saddr =
				isc_nmhandle_localaddr(query->handle);
			sport = isc_sockaddr_getport(&saddr);
			isc_sockaddr_format(&saddr, sockstr, sizeof(sockstr));
			hash = strchr(sockstr, '#');
			if (hash != NULL) {
				*hash = '\0';
			}
			if (strcmp(sockstr, "::") == 0) {
				strlcat(sockstr, "0", sizeof(sockstr));
			}

			printf("    query_address: \"%s\"\n", sockstr);
			printf("    query_port: %u\n", sport);
		}

		printf("    %s:\n", isquery ? "query_message_data"
					    : "response_message_data");
		result = dns_message_headertotext(msg, style, flags, buf);
	} else if (query->lookup->comments && !short_form && !dns64prefix) {
		if (query->lookup->cmdline[0] != '\0' && printcmd) {
			printf("; %s\n", query->lookup->cmdline);
		}
		if (msg == query->lookup->sendmsg) {
			printf(";; Sending:\n");
		} else {
			printf(";; Got answer:\n");
		}

		if (headers) {
			if (isdotlocal(msg)) {
				printf(";; WARNING: .local is reserved for "
				       "Multicast DNS\n;; You are currently "
				       "testing what happens when an mDNS "
				       "query is leaked to DNS\n");
			}
			printf(";; ->>HEADER<<- opcode: %s, status: %s, "
			       "id: %u\n",
			       opcodetext[msg->opcode],
			       rcode_totext(msg->rcode), msg->id);
			printf(";; flags:");
			if ((msg->flags & DNS_MESSAGEFLAG_QR) != 0) {
				printf(" qr");
			}
			if ((msg->flags & DNS_MESSAGEFLAG_AA) != 0) {
				printf(" aa");
			}
			if ((msg->flags & DNS_MESSAGEFLAG_TC) != 0) {
				printf(" tc");
			}
			if ((msg->flags & DNS_MESSAGEFLAG_RD) != 0) {
				printf(" rd");
			}
			if ((msg->flags & DNS_MESSAGEFLAG_RA) != 0) {
				printf(" ra");
			}
			if ((msg->flags & DNS_MESSAGEFLAG_AD) != 0) {
				printf(" ad");
			}
			if ((msg->flags & DNS_MESSAGEFLAG_CD) != 0) {
				printf(" cd");
			}
			if ((msg->flags & 0x0040U) != 0) {
				printf("; MBZ: 0x4");
			}

			printf("; QUERY: %u, ANSWER: %u, "
			       "AUTHORITY: %u, ADDITIONAL: %u\n",
			       msg->counts[DNS_SECTION_QUESTION],
			       msg->counts[DNS_SECTION_ANSWER],
			       msg->counts[DNS_SECTION_AUTHORITY],
			       msg->counts[DNS_SECTION_ADDITIONAL]);

			if (msg != query->lookup->sendmsg &&
			    (msg->flags & DNS_MESSAGEFLAG_RD) != 0 &&
			    (msg->flags & DNS_MESSAGEFLAG_RA) == 0)
			{
				printf(";; WARNING: recursion requested "
				       "but not available\n");
			}
		}
		if (msg != query->lookup->sendmsg &&
		    query->lookup->edns != -1 && msg->opt == NULL &&
		    (msg->rcode == dns_rcode_formerr ||
		     msg->rcode == dns_rcode_notimp))
		{
			printf("\n;; WARNING: EDNS query returned status "
			       "%s - retry with '%s+noedns'\n",
			       rcode_totext(msg->rcode),
			       query->lookup->dnssec ? "+nodnssec " : "");
		}
		if (msg != query->lookup->sendmsg && extrabytes != 0U) {
			printf(";; WARNING: Message has %u extra byte%s at "
			       "end\n",
			       extrabytes, extrabytes != 0 ? "s" : "");
		}
	}

repopulate_buffer:

	if (query->lookup->comments && headers && !short_form && !dns64prefix) {
		result = dns_message_pseudosectiontotext(
			msg, DNS_PSEUDOSECTION_OPT, style, flags, buf);
		if (result == ISC_R_NOSPACE) {
		buftoosmall:
			len += OUTPUTBUF;
			isc_buffer_free(&buf);
			isc_buffer_allocate(mctx, &buf, len);
			goto repopulate_buffer;
		}
		check_result(result, "dns_message_pseudosectiontotext");
	}

	if (query->lookup->section_question && headers) {
		if (!short_form && !dns64prefix) {
			result = dns_message_sectiontotext(
				msg, DNS_SECTION_QUESTION, style, flags, buf);
			if (result == ISC_R_NOSPACE) {
				goto buftoosmall;
			}
			check_result(result, "dns_message_sectiontotext");
		}
	}
	if (query->lookup->section_answer) {
		if (!short_form && !dns64prefix) {
			result = dns_message_sectiontotext(
				msg, DNS_SECTION_ANSWER, style, flags, buf);
			if (result == ISC_R_NOSPACE) {
				goto buftoosmall;
			}
			check_result(result, "dns_message_sectiontotext");
		} else if (dns64prefix) {
			result = dns64prefix_answer(msg, buf);
			if (result == ISC_R_NOSPACE) {
				goto buftoosmall;
			}
			check_result(result, "dns64prefix_answer");
		} else {
			result = short_answer(msg, flags, buf, query);
			if (result == ISC_R_NOSPACE) {
				goto buftoosmall;
			}
			check_result(result, "short_answer");
		}
	}
	if (query->lookup->section_authority) {
		if (!short_form && !dns64prefix) {
			result = dns_message_sectiontotext(
				msg, DNS_SECTION_AUTHORITY, style, flags, buf);
			if (result == ISC_R_NOSPACE) {
				goto buftoosmall;
			}
			check_result(result, "dns_message_sectiontotext");
		}
	}
	if (query->lookup->section_additional) {
		if (!short_form && !dns64prefix) {
			result = dns_message_sectiontotext(
				msg, DNS_SECTION_ADDITIONAL, style, flags, buf);
			if (result == ISC_R_NOSPACE) {
				goto buftoosmall;
			}
			check_result(result, "dns_message_sectiontotext");
			/*
			 * Only print the signature on the first record.
			 */
			if (headers) {
				result = dns_message_pseudosectiontotext(
					msg, DNS_PSEUDOSECTION_TSIG, style,
					flags, buf);
				if (result == ISC_R_NOSPACE) {
					goto buftoosmall;
				}
				check_result(result, "dns_message_"
						     "pseudosectiontotext");
				result = dns_message_pseudosectiontotext(
					msg, DNS_PSEUDOSECTION_SIG0, style,
					flags, buf);
				if (result == ISC_R_NOSPACE) {
					goto buftoosmall;
				}
				check_result(result, "dns_message_"
						     "pseudosectiontotext");
			}
		}
	}

	if (headers && query->lookup->comments && !short_form && !yaml) {
		printf("\n");
	}

	printf("%.*s", (int)isc_buffer_usedlength(buf),
	       (char *)isc_buffer_base(buf));
	isc_buffer_free(&buf);

	if (style != NULL) {
		dns_master_styledestroy(&style, mctx);
	}

	dig_idnsetup(query->lookup, false);

	return result;
}

/*%
 * print the greeting message when the program first starts up.
 */
static void
printgreeting(int argc, char **argv, dig_lookup_t *lookup) {
	int i;
	static bool first = true;
	char append[MXNAME];

	if (printcmd) {
		snprintf(lookup->cmdline, sizeof(lookup->cmdline),
			 "%s; <<>> DiG %s <<>>", first ? "\n" : "",
			 PACKAGE_VERSION);
		i = 1;
		while (i < argc) {
			snprintf(append, sizeof(append), " %s", argv[i++]);
			strlcat(lookup->cmdline, append,
				sizeof(lookup->cmdline));
		}
		strlcat(lookup->cmdline, "\n", sizeof(lookup->cmdline));
		if (first && addresscount != 0) {
			snprintf(append, sizeof(append),
				 "; (%d server%s found)\n", addresscount,
				 addresscount > 1 ? "s" : "");
			strlcat(lookup->cmdline, append,
				sizeof(lookup->cmdline));
		}
		if (first) {
			snprintf(append, sizeof(append),
				 ";; global options:%s%s\n",
				 short_form ? " +short" : "",
				 printcmd ? " +cmd" : "");
			first = false;
			strlcat(lookup->cmdline, append,
				sizeof(lookup->cmdline));
		}
	}
}

#define FULLCHECK(A)                                                 \
	do {                                                         \
		size_t _l = strlen(cmd);                             \
		if (_l >= sizeof(A) || strncasecmp(cmd, A, _l) != 0) \
			goto invalid_option;                         \
	} while (0)
#define FULLCHECK2(A, B)                                                 \
	do {                                                             \
		size_t _l = strlen(cmd);                                 \
		if ((_l >= sizeof(A) || strncasecmp(cmd, A, _l) != 0) && \
		    (_l >= sizeof(B) || strncasecmp(cmd, B, _l) != 0))   \
			goto invalid_option;                             \
	} while (0)
#define FULLCHECK6(A, B, C, D, E, F)                                     \
	do {                                                             \
		size_t _l = strlen(cmd);                                 \
		if ((_l >= sizeof(A) || strncasecmp(cmd, A, _l) != 0) && \
		    (_l >= sizeof(B) || strncasecmp(cmd, B, _l) != 0) && \
		    (_l >= sizeof(C) || strncasecmp(cmd, C, _l) != 0) && \
		    (_l >= sizeof(D) || strncasecmp(cmd, D, _l) != 0) && \
		    (_l >= sizeof(E) || strncasecmp(cmd, E, _l) != 0) && \
		    (_l >= sizeof(F) || strncasecmp(cmd, F, _l) != 0))   \
			goto invalid_option;                             \
	} while (0)

/*
 * Parse source and destination addresses in the same format as used by "kdig":
 *
 * SRC_ADDR[#SRC_PORT]-DST_ADDR[#DST_PORT]
 *
 * This can be described (pretty closely for our purpose) using the
 * following EBNF grammar:
 *
 * S = proxy-addrs. (* start rule *)
 * proxy-addrs = addr "-" addr EOF.
 * addr = addr-char { addr-char } ["#" port ].
 * port = digit { digit }.
 * addr-char = <aby but "#", "-", EOF >.
 * EOF = '\0'.
 */
#define MATCH(ch)     (st->str[0] == (ch))
#define MATCH_DIGIT() isdigit((unsigned char)(st->str[0]))
#define ADVANCE()     st->str++
#define GETP()	      (st->str)

typedef struct isc_proxy_addrs_parser_state {
	const char *str;

	const char *last_addr_start;
	size_t last_addr_len;

	const char *last_port_start;
	size_t last_port_len;

	const char *src_addr_start;
	size_t src_addr_len;

	const char *src_port_start;
	size_t src_port_len;

	const char *dst_addr_start;
	size_t dst_addr_len;

	const char *dst_port_start;
	size_t dst_port_len;
} isc_proxy_addrs_parser_state_t;

static bool
rule_proxy_addrs(isc_proxy_addrs_parser_state_t *st);

static bool
rule_addr(isc_proxy_addrs_parser_state_t *st);

static bool
rule_port(isc_proxy_addrs_parser_state_t *st);

static bool
rule_addr_char(isc_proxy_addrs_parser_state_t *st);

static void
proxy_handle_port_string(const char *port_start, const size_t port_len,
			 in_port_t *pport) {
	char buf[512] = { 0 }; /* max */
	size_t string_size = 0, max_string_bytes = 0;
	unsigned int tmp;
	isc_result_t result;

	string_size = port_len + 1;
	max_string_bytes = string_size > sizeof(buf) ? sizeof(buf)
						     : string_size;

	(void)strlcpy(buf, port_start, max_string_bytes);
	result = parse_uint(&tmp, buf, MAXPORT, "port number");
	if (result != ISC_R_SUCCESS) {
		fatal("Couldn't parse port number");
	}
	*pport = tmp;
}

static isc_result_t
proxy_handle_addr_string(const char *addr_start, const size_t addr_len,
			 const in_port_t addr_port, isc_sockaddr_t *addr) {
	isc_result_t result = ISC_R_FAILURE;
	char buf[512] = { 0 }; /* max */
	size_t string_size = 0, max_string_bytes = 0;
	struct in_addr ipv4 = { 0 };
	struct in6_addr ipv6 = { 0 };
	int ret = 0;

	string_size = addr_len + 1;
	max_string_bytes = string_size > sizeof(buf) ? sizeof(buf)
						     : string_size;

	(void)strlcpy(buf, addr_start, max_string_bytes);

	ret = inet_pton(AF_INET, buf, &ipv4);
	if (ret == 1) {
		isc_sockaddr_fromin(addr, &ipv4, addr_port);
		result = ISC_R_SUCCESS;
	} else {
		ret = inet_pton(AF_INET6, buf, &ipv6);
		if (ret == 1) {
			isc_sockaddr_fromin6(addr, &ipv6, addr_port);
			result = ISC_R_SUCCESS;
		}
	}

	return result;
}

static bool
parse_proxy_addresses(const char *addrs, isc_sockaddr_t *psrc,
		      isc_sockaddr_t *pdst) {
	isc_result_t result = ISC_R_FAILURE;
	isc_sockaddr_t src = { 0 }, dst = { 0 };
	isc_proxy_addrs_parser_state_t st = { 0 };
	in_port_t src_port = 0, dst_port = 53; /* Follow kdig footsteps */

	REQUIRE(addrs != NULL && *addrs != '\0');
	REQUIRE(psrc != NULL);
	REQUIRE(pdst != NULL);

	st.str = addrs;

	/* start syntax analysis and verification */
	if (!rule_proxy_addrs(&st)) {
		warn("PROXY source and destination addresses cannot be parsed");
		return false;
	}

	/* get port numeric values */
	if (st.src_port_len > 0) {
		INSIST(st.src_port_start != NULL);
		proxy_handle_port_string(st.src_port_start, st.src_port_len,
					 &src_port);
	}

	if (st.dst_port_len > 0) {
		INSIST(st.dst_port_start != NULL);
		proxy_handle_port_string(st.dst_port_start, st.dst_port_len,
					 &dst_port);
	}

	/* get addresses */
	INSIST(st.src_addr_len > 0);
	INSIST(st.src_addr_start != NULL);
	INSIST(st.dst_addr_len > 0);
	INSIST(st.dst_addr_start != NULL);

	result = proxy_handle_addr_string(st.src_addr_start, st.src_addr_len,
					  src_port, &src);
	if (result != ISC_R_SUCCESS) {
		warn("Cannot get PROXY source address: %s",
		     isc_result_totext(result));
		return false;
	}

	result = proxy_handle_addr_string(st.dst_addr_start, st.dst_addr_len,
					  dst_port, &dst);
	if (result != ISC_R_SUCCESS) {
		warn("Cannot get PROXY destination address: %s",
		     isc_result_totext(result));
		return false;
	}

	/* addresses should be of the same type */
	if (isc_sockaddr_pf(&src) != isc_sockaddr_pf(&dst)) {
		warn("PROXY source and destination addresses must be of the "
		     "same type");
		return false;
	}

	*psrc = src;
	*pdst = dst;

	return true;
}

static bool
rule_proxy_addrs(isc_proxy_addrs_parser_state_t *st) {
	if (!rule_addr(st)) {
		return false;
	}

	st->src_addr_start = st->last_addr_start;
	st->src_addr_len = st->last_addr_len;
	st->src_port_start = st->last_port_start;
	st->src_port_len = st->last_port_len;

	if (!MATCH('-')) {
		return false;
	}

	ADVANCE();

	if (!rule_addr(st)) {
		return false;
	}

	st->dst_addr_start = st->last_addr_start;
	st->dst_addr_len = st->last_addr_len;
	st->dst_port_start = st->last_port_start;
	st->dst_port_len = st->last_port_len;

	if (!MATCH('\0')) {
		return false;
	}

	return true;
}

static bool
rule_addr(isc_proxy_addrs_parser_state_t *st) {
	const char *start = GETP();
	if (!rule_addr_char(st)) {
		return false;
	}

	while (rule_addr_char(st)) {
		/* skip */
	}

	st->last_addr_start = start;
	st->last_addr_len = GETP() - start;

	if (MATCH('#')) {
		ADVANCE();

		if (!rule_port(st)) {
			return false;
		}
	}

	return true;
}

static bool
rule_port(isc_proxy_addrs_parser_state_t *st) {
	const char *start = GETP();
	if (!MATCH_DIGIT()) {
		return false;
	}

	ADVANCE();

	while (MATCH_DIGIT()) {
		ADVANCE();
	}

	st->last_port_start = start;
	st->last_port_len = GETP() - start;

	return true;
}

static bool
rule_addr_char(isc_proxy_addrs_parser_state_t *st) {
	if (MATCH('#') || MATCH('-') || MATCH('\0')) {
		return false;
	}

	ADVANCE();

	return true;
}

#undef GETP
#undef ADVANCE
#undef MATCH_DIGIT
#undef MATCH

static bool
plus_proxy_handle_addresses(const char *value, const bool state,
			    dig_lookup_t *lookup) {
	lookup->proxy_mode = state;
	if (!state) {
		/*
		 * We are not interested in the option value in that
		 * case
		 */
		return true;
	}

	if (value == NULL || *value == '\0') {
		lookup->proxy_local = true;
		return true;
	}

	if (!parse_proxy_addresses(value, &lookup->proxy_src_addr,
				   &lookup->proxy_dst_addr))
	{
		return false;
	}
	return true;
}

static bool
plus_proxy_options(const char *cmd, const char *value, const bool state,
		   dig_lookup_t *lookup) {
	switch (cmd[5]) {
	case '-':
		FULLCHECK("proxy-plain");
		lookup->proxy_plain = state;
		if (!plus_proxy_handle_addresses(value, state, lookup)) {
			goto invalid_option;
		}
		break;
	case '\0':
		FULLCHECK("proxy");
		if (!plus_proxy_handle_addresses(value, state, lookup)) {
			goto invalid_option;
		}
		break;
	default:
		goto invalid_option;
	}
	return true;

invalid_option:
	return false;
}

static bool
plus_tls_options(const char *cmd, const char *value, const bool state,
		 dig_lookup_t *lookup) {
	/*
	 * Using TLS implies "TCP-like" mode.
	 */
	if (!lookup->tcp_mode_set) {
		lookup->tcp_mode = state;
	}
	switch (cmd[3]) {
	case '-':
		/*
		 * Assume that if any of the +tls-* options are set, then we
		 * need to verify the remote certificate (compatibility with
		 * kdig).
		 */
		if (state) {
			lookup->tls_ca_set = state;
		}
		switch (cmd[4]) {
		case 'c':
			switch (cmd[5]) {
			case 'a':
				FULLCHECK("tls-ca");
				lookup->tls_ca_set = state;
				if (state && value != NULL) {
					lookup->tls_ca_file =
						isc_mem_strdup(mctx, value);
				}
				break;
			case 'e':
				FULLCHECK("tls-certfile");
				lookup->tls_cert_file_set = state;
				if (state) {
					if (value != NULL && *value != '\0') {
						lookup->tls_cert_file =
							isc_mem_strdup(mctx,
								       value);
					} else {
						fprintf(stderr,
							";; TLS certificate "
							"file is "
							"not specified\n");
						goto invalid_option;
					}
				}
				break;
			default:
				goto invalid_option;
			}
			break;
		case 'h':
			FULLCHECK("tls-hostname");
			lookup->tls_hostname_set = state;
			if (state) {
				if (value != NULL && *value != '\0') {
					lookup->tls_hostname =
						isc_mem_strdup(mctx, value);
				} else {
					fprintf(stderr, ";; TLS hostname is "
							"not specified\n");
					goto invalid_option;
				}
			}
			break;
		case 'k':
			FULLCHECK("tls-keyfile");
			lookup->tls_key_file_set = state;
			if (state) {
				if (value != NULL && *value != '\0') {
					lookup->tls_key_file =
						isc_mem_strdup(mctx, value);
				} else {
					fprintf(stderr,
						";; TLS private key file is "
						"not specified\n");
					goto invalid_option;
				}
			}
			break;
		default:
			goto invalid_option;
		}
		break;
	case '\0':
		FULLCHECK("tls");
		lookup->tls_mode = state;
		break;
	default:
		goto invalid_option;
	}

	return true;
invalid_option:
	return false;
}

/*%
 * We're not using isc_commandline_parse() here since the command line
 * syntax of dig is quite a bit different from that which can be described
 * by that routine.
 * XXX doc options
 */

static dig_lookup_t *
plus_option(char *option, bool is_batchfile, bool *need_clone,
	    dig_lookup_t *lookup) {
	isc_result_t result;
	char *cmd, *value, *last = NULL, *code, *extra;
	uint32_t num;
	bool state = true;
	size_t n;

	INSIST(option != NULL);

	if ((cmd = strtok_r(option, "=", &last)) == NULL) {
		printf(";; Invalid option %s\n", option);
		return lookup;
	}
	if (strncasecmp(cmd, "no", 2) == 0) {
		cmd += 2;
		state = false;
	}
	/* parse the rest of the string */
	value = strtok_r(NULL, "", &last);

	switch (cmd[0]) {
	case 'a':
		switch (cmd[1]) {
		case 'a': /* aaonly / aaflag */
			FULLCHECK2("aaonly", "aaflag");
			lookup->aaonly = state;
			break;
		case 'd':
			switch (cmd[2]) {
			case 'd': /* additional */
				FULLCHECK("additional");
				lookup->section_additional = state;
				break;
			case 'f':  /* adflag */
			case '\0': /* +ad is a synonym for +adflag */
				FULLCHECK("adflag");
				lookup->adflag = state;
				break;
			default:
				goto invalid_option;
			}
			break;
		case 'l': /* all */
			FULLCHECK("all");
			lookup->section_question = state;
			lookup->section_authority = state;
			lookup->section_answer = state;
			lookup->section_additional = state;
			lookup->comments = state;
			lookup->stats = state;
			printcmd = state;
			break;
		case 'n': /* answer */
			FULLCHECK("answer");
			lookup->section_answer = state;
			break;
		case 'u': /* authority */
			FULLCHECK("authority");
			lookup->section_authority = state;
			break;
		default:
			goto invalid_option;
		}
		break;
	case 'b':
		switch (cmd[1]) {
		case 'a': /* badcookie */
			FULLCHECK("badcookie");
			lookup->badcookie = state;
			break;
		case 'e': /* besteffort */
			FULLCHECK("besteffort");
			lookup->besteffort = state;
			break;
		case 'u': /* bufsize */
			FULLCHECK("bufsize");
			if (!state) {
				goto invalid_option;
			}
			if (value == NULL) {
				lookup->udpsize = DEFAULT_EDNS_BUFSIZE;
				break;
			}
			result = parse_uint(&num, value, COMMSIZE,
					    "buffer size");
			if (result != ISC_R_SUCCESS) {
				warn("Couldn't parse buffer size");
				goto exit_or_usage;
			}
			lookup->udpsize = num;
			break;
		default:
			goto invalid_option;
		}
		break;
	case 'c':
		switch (cmd[1]) {
		case 'd': /* cdflag */
			switch (cmd[2]) {
			case 'f':  /* cdflag */
			case '\0': /* +cd is a synonym for +cdflag */
				FULLCHECK("cdflag");
				lookup->cdflag = state;
				break;
			default:
				goto invalid_option;
			}
			break;
		case 'l': /* class */
			/* keep +cl for backwards compatibility */
			FULLCHECK2("cl", "class");
			lookup->noclass = !state;
			break;
		case 'm': /* cmd */
			FULLCHECK("cmd");
			printcmd = state;
			break;
		case 'o': /* comments */
			switch (cmd[2]) {
			case 'f':
			case '\0': /* +co is a synonym for +coflag */
				FULLCHECK("coflag");
				lookup->coflag = state;
				break;
			case 'm':
				FULLCHECK("comments");
				lookup->comments = state;
				if (lookup == default_lookup) {
					pluscomm = state;
				}
				break;
			case 'o': /* cookie */
				FULLCHECK("cookie");
				if (state && lookup->edns == -1) {
					lookup->edns = DEFAULT_EDNS_VERSION;
				}
				lookup->sendcookie = state;
				if (value != NULL) {
					n = strlcpy(hexcookie, value,
						    sizeof(hexcookie));
					if (n >= sizeof(hexcookie)) {
						warn("COOKIE data too large");
						goto exit_or_usage;
					}
					lookup->cookie = hexcookie;
				} else {
					lookup->cookie = NULL;
				}
				break;
			default:
				goto invalid_option;
			}
			break;
		case 'r':
			FULLCHECK("crypto");
			lookup->nocrypto = !state;
			break;
		default:
			goto invalid_option;
		}
		break;
	case 'd':
		switch (cmd[1]) {
		case 'e': /* defname */
			FULLCHECK("defname");
			fprintf(stderr, ";; +[no]defname option is "
					"deprecated; use +[no]search\n");
			if (!lookup->trace) {
				usesearch = state;
			}
			break;
		case 'n':
			switch (cmd[2]) {
			case 's':
				switch (cmd[3]) {
				case '6': /* dns64prefix */
					FULLCHECK("dns64prefix");
					if (state) {
						if (*need_clone) {
							lookup = clone_lookup(
								default_lookup,
								true);
						}
						*need_clone = true;
						lookup->dns64prefix = state;
						strlcpy(lookup->textname,
							"ipv4only.arpa",
							sizeof(lookup->textname));
						printcmd = false;
						lookup->section_additional =
							false;
						lookup->section_answer = true;
						lookup->section_authority =
							false;
						lookup->section_question =
							false;
						lookup->comments = false;
						lookup->stats = false;
						lookup->rrcomments = -1;
						lookup->rdtype =
							dns_rdatatype_aaaa;
						lookup->rdtypeset = true;
						ISC_LIST_APPEND(lookup_list,
								lookup, link);
					}
					break;
				case 's': /* dnssec */
					FULLCHECK("dnssec");
				dnssec:
					if (state && lookup->edns == -1) {
						lookup->edns =
							DEFAULT_EDNS_VERSION;
					}
					lookup->dnssec = state;
					break;
				default:
					goto invalid_option;
				}
				break;
			default:
				goto invalid_option;
			}
			break;
		case 'o': /* domain ... but treat "do" as synonym for dnssec */
			if (cmd[2] == '\0') {
				goto dnssec;
			}
			FULLCHECK("domain");
			if (value == NULL) {
				goto need_value;
			}
			if (!state) {
				goto invalid_option;
			}
			strlcpy(domainopt, value, sizeof(domainopt));
			break;
		default:
			goto invalid_option;
		}
		break;
	case 'e':
		switch (cmd[1]) {
		case 'd':
			switch (cmd[2]) {
			case 'n':
				switch (cmd[3]) {
				case 's':
					switch (cmd[4]) {
					case 0:
						FULLCHECK("edns");
						if (!state) {
							lookup->edns = -1;
							lookup->original_edns =
								-1;
							break;
						}
						if (value == NULL) {
							lookup->edns =
								DEFAULT_EDNS_VERSION;
							break;
						}
						result = parse_uint(&num, value,
								    255,
								    "edns");
						if (result != ISC_R_SUCCESS) {
							warn("Couldn't parse "
							     "edns");
							goto exit_or_usage;
						}
						lookup->edns = num;
						lookup->original_edns = num;
						break;
					case 'f':
						FULLCHECK("ednsflags");
						if (!state) {
							lookup->ednsflags = 0;
							break;
						}
						if (value == NULL) {
							lookup->ednsflags = 0;
							break;
						}
						result = parse_xint(
							&num, value, 0xffff,
							"ednsflags");
						if (result != ISC_R_SUCCESS) {
							warn("Couldn't parse "
							     "ednsflags");
							goto exit_or_usage;
						}
						if (lookup->edns == -1) {
							lookup->edns =
								DEFAULT_EDNS_VERSION;
						}
						lookup->ednsflags = num;
						break;
					case 'n':
						FULLCHECK("ednsnegotiation");
						lookup->ednsneg = state;
						break;
					case 'o':
						FULLCHECK("ednsopt");
						if (!state) {
							lookup->ednsoptscnt = 0;
							break;
						}
						code = NULL;
						if (value != NULL) {
							code = strtok_r(value,
									":",
									&last);
						}
						if (code == NULL) {
							warn("ednsopt no "
							     "code point "
							     "specified");
							goto exit_or_usage;
						}
						extra = strtok_r(NULL, "",
								 &last);
						save_opt(lookup, code, extra);
						if (extra != NULL) {
							extra[-1] = ':';
						}
						break;
					default:
						goto invalid_option;
					}
					break;
				default:
					goto invalid_option;
				}
				break;
			default:
				goto invalid_option;
			}
			break;
		case 'x':
			switch (cmd[2]) {
			case 'p':
				switch (cmd[3]) {
				case 'a':
					FULLCHECK("expandaaaa");
					lookup->expandaaaa = state;
					break;
				case 'i':
					FULLCHECK("expire");
					lookup->expire = state;
					break;
				default:
					goto invalid_option;
				}
				break;
			default:
				goto invalid_option;
			}
			break;
		default:
			goto invalid_option;
		}
		break;
	case 'f': /* fail */
		switch (cmd[1]) {
		case 'a':
			FULLCHECK("fail");
			lookup->servfail_stops = state;
			break;
		case 'u':
			FULLCHECK("fuzztime");
			lookup->fuzzing = state;
			if (lookup->fuzzing) {
				if (value == NULL) {
					lookup->fuzztime = 0x622acce1;
					break;
				}
				result = parse_uint(&num, value, 0xffffffff,
						    "fuzztime");
				if (result != ISC_R_SUCCESS) {
					warn("Couldn't parse fuzztime");
					goto exit_or_usage;
				}
				lookup->fuzztime = num;
			}
			break;
		default:
			goto invalid_option;
		}
		break;
	case 'h':
		switch (cmd[1]) {
		case 'e': /* header-only */
			FULLCHECK("header-only");
			lookup->header_only = state;
			break;
		case 't':
			FULLCHECK6("https", "https-get", "https-post",
				   "http-plain", "http-plain-get",
				   "http-plain-post");
#if HAVE_LIBNGHTTP2
			if (lookup->https_path != NULL) {
				isc_mem_free(mctx, lookup->https_path);
				lookup->https_path = NULL;
			}
			if (!state) {
				lookup->https_mode = false;
				break;
			}
			lookup->https_mode = true;
			if (cmd[4] == '-') {
				lookup->http_plain = true;
				switch (cmd[10]) {
				case '\0':
					FULLCHECK("http-plain");
					break;
				case '-':
					switch (cmd[11]) {
					case 'p':
						FULLCHECK("http-plain-post");
						break;
					case 'g':
						FULLCHECK("http-plain-get");
						lookup->https_get = true;
						break;
					}
					break;
				default:
					goto invalid_option;
				}
			} else {
				switch (cmd[5]) {
				case '\0':
					FULLCHECK("https");
					break;
				case '-':
					switch (cmd[6]) {
					case 'p':
						FULLCHECK("https-post");
						break;
					case 'g':
						FULLCHECK("https-get");
						lookup->https_get = true;
						break;
					}
					break;
				default:
					goto invalid_option;
				}
			}
			if (!lookup->tcp_mode_set) {
				lookup->tcp_mode = state;
			}
			if (value == NULL) {
				lookup->https_path = isc_mem_strdup(
					mctx, ISC_NM_HTTP_DEFAULT_PATH);
			} else {
				if (!isc_nm_http_path_isvalid(value)) {
					fprintf(stderr,
						";; The given HTTP path \"%s\" "
						"is not "
						"a valid absolute path\n",
						value);
					goto invalid_option;
				}
				lookup->https_path = isc_mem_strdup(mctx,
								    value);
			}
#else
			fprintf(stderr, ";; DoH support not enabled\n");
#endif
			break;
		default:
			goto invalid_option;
		}
		break;
	case 'i':
		switch (cmd[1]) {
		case 'd':
			switch (cmd[2]) {
			case 'e':
				FULLCHECK("identify");
				lookup->identify = state;
				break;
			case 'n':
				switch (cmd[3]) {
				case '\0':
					FULLCHECK("idn");
					lookup->idnin = state;
					lookup->idnout = state;
					break;
				case 'i': /* (compat) */
					FULLCHECK("idnin");
					lookup->idnin = state;
					break;
				case 'o': /* (compat) */
					FULLCHECK("idnout");
					lookup->idnout = state;
					break;
				default:
					goto invalid_option;
				}
#ifndef HAVE_LIBIDN2
				if (state) {
					printf(";; IDN support "
					       "is not available\n");
				}
#endif /* ifndef HAVE_LIBIDN2 */
				break;
			default:
				goto invalid_option;
			}
			break;
		case 'g': /* ignore */
		default:  /*
			   * Inherits default for compatibility (+[no]i*).
			   */
			FULLCHECK("ignore");
			lookup->ignore = state;
		}
		break;
	case 'k':
		switch (cmd[1]) {
		case 'e':
			switch (cmd[2]) {
			case 'e':
				switch (cmd[3]) {
				case 'p':
					switch (cmd[4]) {
					case 'a':
						FULLCHECK("keepalive");
						lookup->tcp_keepalive = state;
						break;
					case 'o':
						FULLCHECK("keepopen");
						keep_open = state;
						break;
					default:
						goto invalid_option;
					}
					break;
				default:
					goto invalid_option;
				}
				break;
			default:
				goto invalid_option;
			}
			break;
		default:
			goto invalid_option;
		}
		break;
	case 'm':
		switch (cmd[1]) {
		case 'a':
			FULLCHECK("mapped");
			fatal("+mapped option no longer supported");
		case 'u':
			FULLCHECK("multiline");
			lookup->multiline = state;
			break;
		default:
			goto invalid_option;
		}
		break;
	case 'n':
		switch (cmd[1]) {
		case 'd': /* ndots */
			FULLCHECK("ndots");
			if (value == NULL) {
				goto need_value;
			}
			if (!state) {
				goto invalid_option;
			}
			result = parse_uint(&num, value, MAXNDOTS, "ndots");
			if (result != ISC_R_SUCCESS) {
				warn("Couldn't parse ndots");
				goto exit_or_usage;
			}
			ndots = num;
			break;
		case 's':
			switch (cmd[2]) {
			case 'i': /* nsid */
				FULLCHECK("nsid");
				if (state && lookup->edns == -1) {
					lookup->edns = DEFAULT_EDNS_VERSION;
				}
				lookup->nsid = state;
				break;
			case 's': /* nssearch */
				FULLCHECK("nssearch");
				lookup->ns_search_only = state;
				if (state) {
					lookup->trace_root = true;
					lookup->recurse = true;
					lookup->identify = true;
					lookup->stats = false;
					lookup->comments = false;
					lookup->section_additional = false;
					lookup->section_authority = false;
					lookup->section_question = false;
					lookup->rdtype = dns_rdatatype_ns;
					lookup->rdtypeset = true;
					short_form = true;
					lookup->rrcomments = 0;
				}
				break;
			default:
				goto invalid_option;
			}
			break;
		default:
			goto invalid_option;
		}
		break;
	case 'o':
		switch (cmd[1]) {
		case 'n':
			FULLCHECK("onesoa");
			lookup->onesoa = state;
			break;
		case 'p':
			FULLCHECK("opcode");
			if (!state) {
				lookup->opcode = 0; /* default - query */
				break;
			}
			if (value == NULL) {
				goto need_value;
			}
			for (num = 0;
			     num < sizeof(opcodetext) / sizeof(opcodetext[0]);
			     num++)
			{
				if (strcasecmp(opcodetext[num], value) == 0) {
					break;
				}
			}
			if (num < 16) {
				lookup->opcode = (dns_opcode_t)num;
				break;
			}
			result = parse_uint(&num, value, 15, "opcode");
			if (result != ISC_R_SUCCESS) {
				warn("Couldn't parse opcode");
				goto exit_or_usage;
			}
			lookup->opcode = (dns_opcode_t)num;
			break;
		default:
			goto invalid_option;
		}
		break;
	case 'p':
		switch (cmd[1]) {
		case 'a':
			FULLCHECK("padding");
			if (state && lookup->edns == -1) {
				lookup->edns = DEFAULT_EDNS_VERSION;
			}
			if (value == NULL) {
				goto need_value;
			}
			result = parse_uint(&num, value, 512, "padding");
			if (result != ISC_R_SUCCESS) {
				warn("Couldn't parse padding");
				goto exit_or_usage;
			}
			lookup->padding = (uint16_t)num;
			break;
		case 'r':
			if (!plus_proxy_options(cmd, value, state, lookup)) {
				goto invalid_option;
			}
			break;
		default:
			goto invalid_option;
		}
		break;
	case 'q':
		switch (cmd[1]) {
		case 'i': /* qid */
			FULLCHECK("qid");
			if (!state) {
				lookup->setqid = false;
				lookup->qid = 0;
				break;
			}
			if (value == NULL) {
				goto need_value;
			}
			result = parse_uint(&num, value, MAXQID, "qid");
			if (result != ISC_R_SUCCESS) {
				warn("Couldn't parse qid");
				goto exit_or_usage;
			}
			lookup->setqid = true;
			lookup->qid = num;
			break;
		case 'r': /* qr */
			FULLCHECK("qr");
			lookup->qr = state;
			break;
		case 'u': /* question */
			FULLCHECK("question");
			lookup->section_question = state;
			if (lookup == default_lookup) {
				plusquest = state;
			}
			break;
		default:
			goto invalid_option;
		}
		break;
	case 'r':
		switch (cmd[1]) {
		case 'a': /* raflag */
			FULLCHECK("raflag");
			lookup->raflag = state;
			break;
		case 'd': /* rdflag */
			FULLCHECK("rdflag");
			lookup->recurse = state;
			break;
		case 'e':
			switch (cmd[2]) {
			case 'c': /* recurse */
				FULLCHECK("recurse");
				lookup->recurse = state;
				break;
			case 't': /* retry / retries */
				FULLCHECK2("retry", "retries");
				if (value == NULL) {
					goto need_value;
				}
				if (!state) {
					goto invalid_option;
				}
				result = parse_uint(&lookup->retries, value,
						    MAXTRIES - 1, "retries");
				if (result != ISC_R_SUCCESS) {
					warn("Couldn't parse retries");
					goto exit_or_usage;
				}
				lookup->retries++;
				break;
			default:
				goto invalid_option;
			}
			break;
		case 'r': /* rrcomments */
			FULLCHECK("rrcomments");
			lookup->rrcomments = state ? 1 : -1;
			break;
		default:
			goto invalid_option;
		}
		break;
	case 's':
		switch (cmd[1]) {
		case 'e': /* search */
			FULLCHECK("search");
			if (!lookup->trace) {
				usesearch = state;
			}
			break;
		case 'h':
			if (cmd[2] != 'o') {
				goto invalid_option;
			}
			switch (cmd[3]) {
			case 'r': /* short */
				FULLCHECK("short");
				short_form = state;
				if (state) {
					printcmd = false;
					lookup->section_additional = false;
					lookup->section_answer = true;
					lookup->section_authority = false;
					lookup->section_question = false;
					lookup->comments = false;
					lookup->stats = false;
					lookup->rrcomments = -1;
				}
				break;
			case 'w': /* showsearch */
				switch (cmd[4]) {
				case 'b':
					switch (cmd[7]) {
					case 'c':
						FULLCHECK("showbadcookie");
						lookup->showbadcookie = state;
						break;
					case 'v':
						FULLCHECK("showbadvers");
						lookup->showbadvers = state;
						break;
					default:
						goto invalid_option;
					}
					break;
				case 's':
					FULLCHECK("showsearch");
					if (!lookup->trace) {
						showsearch = state;
						usesearch = state;
					}
					break;
				default:
					goto invalid_option;
				}
				break;
			default:
				goto invalid_option;
			}
			break;
		case 'i': /* sigchase */
			FULLCHECK("sigchase");
			fatal("+sigchase option no longer supported");
		case 'p': /* split */
			FULLCHECK("split");
			if (value != NULL && !state) {
				goto invalid_option;
			}
			if (!state) {
				splitwidth = 0;
				break;
			} else if (value == NULL) {
				break;
			}

			result = parse_uint(&splitwidth, value, 1023, "split");
			if ((splitwidth % 4) != 0U) {
				splitwidth = ((splitwidth + 3) / 4) * 4;
				fprintf(stderr,
					";; Warning, split must be "
					"a multiple of 4; adjusting "
					"to %u\n",
					splitwidth);
			}
			/*
			 * There is an adjustment done in the
			 * totext_<rrtype>() functions which causes
			 * splitwidth to shrink.  This is okay when we're
			 * using the default width but incorrect in this
			 * case, so we correct for it
			 */
			if (splitwidth) {
				splitwidth += 3;
			}
			if (result != ISC_R_SUCCESS) {
				warn("Couldn't parse split");
				goto exit_or_usage;
			}
			break;
		case 't': /* stats */
			FULLCHECK("stats");
			lookup->stats = state;
			break;
		case 'u': /* subnet */
			FULLCHECK("subnet");
			if (state && value == NULL) {
				goto need_value;
			}
			if (!state) {
				if (lookup->ecs_addr != NULL) {
					isc_mem_put(mctx, lookup->ecs_addr,
						    sizeof(*lookup->ecs_addr));
					lookup->ecs_addr = NULL;
				}
				break;
			}
			if (lookup->edns == -1) {
				lookup->edns = DEFAULT_EDNS_VERSION;
			}
			if (lookup->ecs_addr != NULL) {
				isc_mem_put(mctx, lookup->ecs_addr,
					    sizeof(*lookup->ecs_addr));
				lookup->ecs_addr = NULL;
			}
			result = parse_netprefix(&lookup->ecs_addr, value);
			if (result != ISC_R_SUCCESS) {
				warn("Couldn't parse client");
				goto exit_or_usage;
			}
			break;
		default:
			goto invalid_option;
		}
		break;
	case 't':
		switch (cmd[1]) {
		case 'c': /* tcp */
			switch (cmd[2]) {
			case 'f':
				FULLCHECK("tcflag");
				lookup->tcflag = state;
				break;
			case 'p':
				FULLCHECK("tcp");
				if (!is_batchfile) {
					lookup->tcp_mode = state;
					lookup->tcp_mode_set = true;
				}
				break;
			default:
				goto invalid_option;
			}
			break;
		case 'i': /* timeout */
			FULLCHECK("timeout");
			if (value == NULL) {
				goto need_value;
			}
			if (!state) {
				goto invalid_option;
			}
			result = parse_uint(&timeout, value, MAXTIMEOUT,
					    "timeout");
			if (result != ISC_R_SUCCESS) {
				warn("Couldn't parse timeout");
				goto exit_or_usage;
			}
			if (timeout == 0) {
				timeout = 1;
			}
			break;
		case 'l':
			switch (cmd[2]) {
			case 's':
				if (!plus_tls_options(cmd, value, state,
						      lookup))
				{
					goto invalid_option;
				}
				break;
			default:
				goto invalid_option;
			}
			break;
		case 'o':
			FULLCHECK("topdown");
			fatal("+topdown option no longer supported");
		case 'r':
			switch (cmd[2]) {
			case 'a': /* trace */
				FULLCHECK("trace");
				lookup->trace = state;
				lookup->trace_root = state;
				if (state) {
					lookup->recurse = true;
					lookup->identify = true;
					lookup->comments = false;
					lookup->rrcomments = 0;
					lookup->stats = false;
					lookup->section_additional = false;
					lookup->section_authority = true;
					lookup->section_question = false;
					lookup->dnssec = true;
					lookup->sendcookie = true;
					usesearch = false;
				}
				break;
			case 'i': /* tries */
				FULLCHECK("tries");
				if (value == NULL) {
					goto need_value;
				}
				if (!state) {
					goto invalid_option;
				}
				result = parse_uint(&lookup->retries, value,
						    MAXTRIES, "tries");
				if (result != ISC_R_SUCCESS) {
					warn("Couldn't parse tries");
					goto exit_or_usage;
				}
				if (lookup->retries == 0) {
					lookup->retries = 1;
				}
				break;
			case 'u': /* trusted-key */
				FULLCHECK("trusted-key");
				fatal("+trusted-key option "
				      "no longer supported");
			default:
				goto invalid_option;
			}
			break;
		case 't':
			switch (cmd[2]) {
			case 'l':
				switch (cmd[3]) {
				case 0:
				case 'i': /* ttlid */
					FULLCHECK2("ttl", "ttlid");
					lookup->nottl = !state;
					break;
				case 'u': /* ttlunits */
					FULLCHECK("ttlunits");
					lookup->nottl = false;
					lookup->ttlunits = state;
					break;
				default:
					goto invalid_option;
				}
				break;
			default:
				goto invalid_option;
			}
			break;
		default:
			goto invalid_option;
		}
		break;
	case 'u':
		switch (cmd[1]) {
		case 'n':
			switch (cmd[2]) {
			case 'e':
				FULLCHECK("unexpected");
				fatal("+unexpected option "
				      "no longer supported");
			case 'k':
				FULLCHECK("unknownformat");
				lookup->print_unknown_format = state;
				break;
			default:
				goto invalid_option;
			}
		}
		break;
	case 'v':
		FULLCHECK("vc");
		if (!is_batchfile) {
			lookup->tcp_mode = state;
			lookup->tcp_mode_set = true;
		}
		break;
	case 'y': /* yaml */
		FULLCHECK("yaml");
		yaml = state;
		if (state) {
			printcmd = false;
			lookup->stats = false;
			lookup->rrcomments = -1;
		}
		break;
	case 'z': /* zflag */
		FULLCHECK("zflag");
		lookup->zflag = state;
		break;
	default:
	invalid_option:
	need_value:
#if TARGET_OS_IPHONE
	exit_or_usage:
#endif /* if TARGET_OS_IPHONE */
		fprintf(stderr, "Invalid option: +%s\n", option);
		usage();
	}
	if (value != NULL) {
		value[-1] = '=';
	}
	return lookup;

#if !TARGET_OS_IPHONE
exit_or_usage:
	cleanup_openssl_refs();
	digexit();
#endif /* if !TARGET_OS_IPHONE */
}

/*%
 * #true returned if value was used
 */
static const char *single_dash_opts = "46dhimnruv";
static const char *dash_opts = "46bcdfhikmnpqrtvyx";
static bool
dash_option(char *option, char *next, dig_lookup_t **lookup,
	    bool *open_type_class, bool *need_clone, bool config_only, int argc,
	    char **argv, bool *firstarg) {
	char opt, *value, *ptr, *ptr2, *ptr3, *last;
	isc_result_t result;
	bool value_from_next;
	isc_textregion_t tr;
	dns_rdatatype_t rdtype;
	dns_rdataclass_t rdclass;
	char textname[MXNAME];
	struct in_addr in4;
	struct in6_addr in6;
	in_port_t srcport;
	char *hash, *cmd;
	uint32_t num;

	while (strpbrk(option, single_dash_opts) == &option[0]) {
		/*
		 * Since the -[46dhimnuv] options do not take an argument,
		 * account for them (in any number and/or combination)
		 * if they appear as the first character(s) of a q-opt.
		 */
		opt = option[0];
		switch (opt) {
		case '4':
			if (have_ipv4) {
				isc_net_disableipv6();
				have_ipv6 = false;
			} else {
				fatal("can't find IPv4 networking");
				UNREACHABLE();
				return false;
			}
			break;
		case '6':
			if (have_ipv6) {
				isc_net_disableipv4();
				have_ipv4 = false;
			} else {
				fatal("can't find IPv6 networking");
				UNREACHABLE();
				return false;
			}
			break;
		case 'd':
			ptr = strpbrk(&option[1], dash_opts);
			if (ptr != &option[1]) {
				cmd = option;
				FULLCHECK("debug");
				debugging = true;
				return false;
			} else {
				debugging = true;
			}
			break;
		case 'h':
			help();
			exit(EXIT_SUCCESS);
			break;
		case 'i':
			fatal("-%c removed", option[0]);
		case 'm': /* memdebug */
			/* memdebug is handled in preparse_args() */
			break;
		case 'n':
			fatal("-%c removed", option[0]);
		case 'r':
			debug("digrc (late)");
			digrc = false;
			break;
		case 'u':
			(*lookup)->use_usec = true;
			break;
		case 'v':
			printf("DiG %s\n", PACKAGE_VERSION);
			exit(EXIT_SUCCESS);
			break;
		}
		if (strlen(option) > 1U) {
			option = &option[1];
		} else {
			return false;
		}
	}
	opt = option[0];
	if (strlen(option) > 1U) {
		value_from_next = false;
		value = &option[1];
	} else {
		value_from_next = true;
		value = next;
	}
	if (value == NULL) {
		goto invalid_option;
	}
	switch (opt) {
	case 'b':
		hash = strchr(value, '#');
		if (hash != NULL) {
			result = parse_uint(&num, hash + 1, MAXPORT,
					    "port number");
			if (result != ISC_R_SUCCESS) {
				fatal("Couldn't parse port number");
			}
			srcport = num;
			*hash = '\0';
		} else {
			srcport = 0;
		}
		if (have_ipv6 && inet_pton(AF_INET6, value, &in6) == 1) {
			isc_sockaddr_fromin6(&localaddr, &in6, srcport);
			isc_net_disableipv4();
		} else if (have_ipv4 && inet_pton(AF_INET, value, &in4) == 1) {
			isc_sockaddr_fromin(&localaddr, &in4, srcport);
			isc_net_disableipv6();
		} else {
			if (hash != NULL) {
				*hash = '#';
			}
			fatal("invalid address %s", value);
		}
		if (hash != NULL) {
			*hash = '#';
		}
		specified_source = true;
		return value_from_next;
	case 'c':
		if ((*lookup)->rdclassset) {
			fprintf(stderr, ";; Warning, extra class option\n");
		}
		*open_type_class = false;
		tr.base = value;
		tr.length = (unsigned int)strlen(value);
		result = dns_rdataclass_fromtext(&rdclass,
						 (isc_textregion_t *)&tr);
		if (result == ISC_R_SUCCESS) {
			(*lookup)->rdclass = rdclass;
			(*lookup)->rdclassset = true;
		} else {
			fprintf(stderr,
				";; Warning, ignoring "
				"invalid class %s\n",
				value);
		}
		return value_from_next;
	case 'f':
		batchname = value;
		return value_from_next;
	case 'k':
		strlcpy(keyfile, value, sizeof(keyfile));
		return value_from_next;
	case 'p':
		result = parse_uint(&num, value, MAXPORT, "port number");
		if (result != ISC_R_SUCCESS) {
			fatal("Couldn't parse port number");
		}
		port = num;
		port_set = true;
		return value_from_next;
	case 'q':
		if (!config_only) {
			if (*need_clone) {
				(*lookup) = clone_lookup(default_lookup, true);
			}
			*need_clone = true;
			strlcpy((*lookup)->textname, value,
				sizeof((*lookup)->textname));
			(*lookup)->trace_root = ((*lookup)->trace ||
						 (*lookup)->ns_search_only);
			(*lookup)->new_search = true;
			if (*firstarg) {
				printgreeting(argc, argv, *lookup);
				*firstarg = false;
			}
			ISC_LIST_APPEND(lookup_list, *lookup, link);
			debug("looking up %s", (*lookup)->textname);
		}
		return value_from_next;
	case 't':
		*open_type_class = false;
		if (strncasecmp(value, "ixfr=", 5) == 0) {
			rdtype = dns_rdatatype_ixfr;
			result = ISC_R_SUCCESS;
		} else {
			tr.base = value;
			tr.length = (unsigned int)strlen(value);
			result = dns_rdatatype_fromtext(
				&rdtype, (isc_textregion_t *)&tr);
			if (result == ISC_R_SUCCESS &&
			    rdtype == dns_rdatatype_ixfr)
			{
				result = DNS_R_UNKNOWN;
			}
		}
		if (result == ISC_R_SUCCESS) {
			if ((*lookup)->rdtypeset) {
				fprintf(stderr, ";; Warning, "
						"extra type option\n");
			}
			if (rdtype == dns_rdatatype_ixfr) {
				uint32_t serial;
				(*lookup)->rdtype = dns_rdatatype_ixfr;
				(*lookup)->rdtypeset = true;
				result = parse_uint(&serial, &value[5],
						    MAXSERIAL, "serial number");
				if (result != ISC_R_SUCCESS) {
					fatal("Couldn't parse serial number");
				}
				(*lookup)->ixfr_serial = serial;
				(*lookup)->section_question = plusquest;
				(*lookup)->comments = pluscomm;
				if (!(*lookup)->tcp_mode_set) {
					(*lookup)->tcp_mode = true;
				}
			} else {
				(*lookup)->rdtype = rdtype;
				if (!config_only) {
					(*lookup)->rdtypeset = true;
				}
				if (rdtype == dns_rdatatype_axfr) {
					(*lookup)->section_question = plusquest;
					(*lookup)->comments = pluscomm;
				} else if (rdtype == dns_rdatatype_any) {
					if (!(*lookup)->tcp_mode_set) {
						(*lookup)->tcp_mode = true;
					}
				}
				(*lookup)->ixfr_serial = false;
			}
		} else {
			fprintf(stderr,
				";; Warning, ignoring "
				"invalid type %s\n",
				value);
		}
		return value_from_next;
	case 'y':
		if ((ptr = strtok_r(value, ":", &last)) == NULL) {
			usage();
		}
		if ((ptr2 = strtok_r(NULL, ":", &last)) == NULL) { /* name or
								    * secret */
			usage();
		}
		if ((ptr3 = strtok_r(NULL, "", &last)) != NULL) { /* secret or
								   * NULL */
			parse_hmac(ptr);
			ptr = ptr2;
			ptr2 = ptr3;
		} else {
			hmac_alg = DST_ALG_HMACMD5;
			digestbits = 0;
		}
		/* XXXONDREJ: FIXME */
		strlcpy(keynametext, ptr, sizeof(keynametext));
		strlcpy(keysecret, ptr2, sizeof(keysecret));
		if (ptr3 != NULL) {
			ptr[-1] = ':';
		}
		ptr2[-1] = ':';
		return value_from_next;
	case 'x':
		if (*need_clone) {
			*lookup = clone_lookup(default_lookup, true);
		}
		*need_clone = true;
		if (get_reverse(textname, sizeof(textname), value, false) ==
		    ISC_R_SUCCESS)
		{
			strlcpy((*lookup)->textname, textname,
				sizeof((*lookup)->textname));
			debug("looking up %s", (*lookup)->textname);
			(*lookup)->trace_root = ((*lookup)->trace ||
						 (*lookup)->ns_search_only);
			if (!(*lookup)->rdtypeset) {
				(*lookup)->rdtype = dns_rdatatype_ptr;
			}
			if (!(*lookup)->rdclassset) {
				(*lookup)->rdclass = dns_rdataclass_in;
			}
			(*lookup)->new_search = true;
			if (*firstarg) {
				printgreeting(argc, argv, *lookup);
				*firstarg = false;
			}
			ISC_LIST_APPEND(lookup_list, *lookup, link);
		} else {
			fprintf(stderr, "Invalid IP address %s\n", value);
			exit(EXIT_FAILURE);
		}
		return value_from_next;
	invalid_option:
	default:
		fprintf(stderr, "Invalid option: -%s\n", option);
		usage();
	}
	UNREACHABLE();
	return false;
}

/*%
 * Because we may be trying to do memory allocation recording, we're going
 * to need to parse the arguments for the -m *before* we start the main
 * argument parsing routine.
 *
 * I'd prefer not to have to do this, but I am not quite sure how else to
 * fix the problem.  Argument parsing in dig involves memory allocation
 * by its nature, so it can't be done in the main argument parser.
 */
static void
preparse_args(int argc, char **argv) {
	int rc;
	char **rv;
	char *option;

	rc = argc;
	rv = argv;
	for (rc--, rv++; rc > 0; rc--, rv++) {
		if (rv[0][0] != '-') {
			continue;
		}
		option = &rv[0][1];
		while (strpbrk(option, single_dash_opts) == &option[0]) {
			switch (option[0]) {
			case 'd':
				/* For debugging early startup */
				debugging = true;
				break;
			case 'm':
				memdebugging = true;
				isc_mem_debugging = ISC_MEM_DEBUGTRACE |
						    ISC_MEM_DEBUGRECORD;
				break;
			case 'r':
				/*
				 * Must be done early, because ~/.digrc
				 * is read before command line parsing
				 */
				debug("digrc (early)");
				digrc = false;
				break;
			case '4':
				if (ipv6only) {
					fatal("only one of -4 and -6 allowed");
				}
				ipv4only = true;
				break;
			case '6':
				if (ipv4only) {
					fatal("only one of -4 and -6 allowed");
				}
				ipv6only = true;
				break;
			}
			option = &option[1];
		}
		if (strlen(option) == 0U) {
			continue;
		}
		/* Look for dash value option. */
		if (strpbrk(option, dash_opts) != &option[0]) {
			goto invalid_option;
		}
		if (strlen(option) > 1U) {
			/* value in option. */
			continue;
		}
		/* Dash value is next argument so we need to skip it. */
		rc--, rv++;
		/* Handle missing argument */
		if (rc == 0) {
		invalid_option:
			fprintf(stderr, "Invalid option: -%s\n", option);
			usage();
		}
	}
}

static int
split_batchline(char *batchline, char **bargv, int len, const char *msg) {
	int bargc;
	char *last = NULL;

	REQUIRE(batchline != NULL);

	for (bargc = 1, bargv[bargc] = strtok_r(batchline, " \t\r\n", &last);
	     bargc < len && bargv[bargc];
	     bargv[++bargc] = strtok_r(NULL, " \t\r\n", &last))
	{
		debug("%s %d: %s", msg, bargc, bargv[bargc]);
	}
	return bargc;
}

static void
parse_args(bool is_batchfile, bool config_only, int argc, char **argv) {
	isc_result_t result;
	isc_textregion_t tr;
	bool firstarg = true;
	dig_lookup_t *lookup = NULL;
	dns_rdatatype_t rdtype;
	dns_rdataclass_t rdclass;
	bool open_type_class = true;
	char batchline[MXNAME];
	int bargc;
	char *bargv[64];
	int rc;
	char **rv;
#ifndef NOPOSIX
	char *homedir;
	char rcfile[PATH_MAX];
#endif /* ifndef NOPOSIX */
	bool need_clone = true;

	/*
	 * The semantics for parsing the args is a bit complex; if
	 * we don't have a host yet, make the arg apply globally,
	 * otherwise make it apply to the latest host.  This is
	 * a bit different than the previous versions, but should
	 * form a consistent user interface.
	 *
	 * First, create a "default lookup" which won't actually be used
	 * anywhere, except for cloning into new lookups
	 */

	debug("parse_args()");
	if (!is_batchfile) {
		debug("making new lookup");
		default_lookup = make_empty_lookup();
		default_lookup->adflag = true;
		default_lookup->edns = DEFAULT_EDNS_VERSION;
		default_lookup->sendcookie = true;

#ifndef NOPOSIX
		/*
		 * Treat ${HOME}/.digrc as a special batchfile
		 */
		INSIST(batchfp == NULL);
		homedir = getenv("HOME");
		if (homedir != NULL && digrc) {
			unsigned int n;
			debug("digrc (open)");
			n = snprintf(rcfile, sizeof(rcfile), "%s/.digrc",
				     homedir);
			if (n < sizeof(rcfile)) {
				batchfp = fopen(rcfile, "r");
			}
		}
		if (batchfp != NULL) {
			while (fgets(batchline, sizeof(batchline), batchfp) !=
			       0)
			{
				debug("config line %s", batchline);
				bargc = split_batchline(batchline, bargv, 62,
							".digrc argv");
				bargv[0] = argv[0];
				argv0 = argv[0];
				parse_args(true, true, bargc, (char **)bargv);
			}
			fclose(batchfp);
		}
#endif /* ifndef NOPOSIX */
	}

	if (is_batchfile && !config_only) {
		/* Processing '-f batchfile'. */
		lookup = clone_lookup(default_lookup, true);
		need_clone = false;
	} else {
		lookup = default_lookup;
	}

	rc = argc;
	rv = argv;
	for (rc--, rv++; rc > 0; rc--, rv++) {
		debug("main parsing %s", rv[0]);
		if (strncmp(rv[0], "%", 1) == 0) {
			break;
		}
		if (rv[0][0] == '@') {
			if (is_batchfile && !config_only) {
				addresscount = getaddresses(lookup, &rv[0][1],
							    &result);
				if (addresscount == 0) {
					fprintf(stderr,
						"couldn't get address "
						"for '%s': %s: skipping "
						"lookup\n",
						&rv[0][1],
						isc_result_totext(result));
					if (ISC_LINK_LINKED(lookup, link)) {
						ISC_LIST_DEQUEUE(lookup_list,
								 lookup, link);
					}
					destroy_lookup(lookup);
					return;
				}
			} else {
				addresscount = getaddresses(lookup, &rv[0][1],
							    NULL);
				if (addresscount == 0) {
					fatal("no valid addresses for '%s'\n",
					      &rv[0][1]);
				}
			}
		} else if (rv[0][0] == '+') {
			lookup = plus_option(&rv[0][1], is_batchfile,
					     &need_clone, lookup);
		} else if (rv[0][0] == '-') {
			if (rc <= 1) {
				if (dash_option(&rv[0][1], NULL, &lookup,
						&open_type_class, &need_clone,
						config_only, argc, argv,
						&firstarg))
				{
					rc--;
					rv++;
				}
			} else {
				if (dash_option(&rv[0][1], rv[1], &lookup,
						&open_type_class, &need_clone,
						config_only, argc, argv,
						&firstarg))
				{
					rc--;
					rv++;
				}
			}
		} else {
			/*
			 * Anything which isn't an option
			 */
			if (open_type_class) {
				if (strncasecmp(rv[0], "ixfr=", 5) == 0) {
					rdtype = dns_rdatatype_ixfr;
					result = ISC_R_SUCCESS;
				} else {
					tr.base = rv[0];
					tr.length = (unsigned int)strlen(rv[0]);
					result = dns_rdatatype_fromtext(
						&rdtype,
						(isc_textregion_t *)&tr);
					if (result == ISC_R_SUCCESS &&
					    rdtype == dns_rdatatype_ixfr)
					{
						fprintf(stderr, ";; Warning, "
								"ixfr requires "
								"a "
								"serial "
								"number\n");
						continue;
					}
				}
				if (result == ISC_R_SUCCESS) {
					if (lookup->rdtypeset) {
						fprintf(stderr, ";; Warning, "
								"extra type "
								"option\n");
					}
					if (rdtype == dns_rdatatype_ixfr) {
						uint32_t serial;
						lookup->rdtype =
							dns_rdatatype_ixfr;
						lookup->rdtypeset = true;
						result = parse_uint(&serial,
								    &rv[0][5],
								    MAXSERIAL,
								    "serial "
								    "number");
						if (result != ISC_R_SUCCESS) {
							fatal("Couldn't parse "
							      "serial number");
						}
						lookup->ixfr_serial = serial;
						lookup->section_question =
							plusquest;
						lookup->comments = pluscomm;
						if (!lookup->tcp_mode_set) {
							lookup->tcp_mode = true;
						}
					} else {
						lookup->rdtype = rdtype;
						lookup->rdtypeset = true;
						if (rdtype ==
						    dns_rdatatype_axfr)
						{
							lookup->section_question =
								plusquest;
							lookup->comments =
								pluscomm;
						}
						if (rdtype ==
							    dns_rdatatype_any &&
						    !lookup->tcp_mode_set)
						{
							lookup->tcp_mode = true;
						}
						lookup->ixfr_serial = false;
					}
					continue;
				}
				result = dns_rdataclass_fromtext(
					&rdclass, (isc_textregion_t *)&tr);
				if (result == ISC_R_SUCCESS) {
					if (lookup->rdclassset) {
						fprintf(stderr, ";; Warning, "
								"extra class "
								"option\n");
					}
					lookup->rdclass = rdclass;
					lookup->rdclassset = true;
					continue;
				}
			}

			if (!config_only) {
				if (need_clone) {
					lookup = clone_lookup(default_lookup,
							      true);
				}
				need_clone = true;
				strlcpy(lookup->textname, rv[0],
					sizeof(lookup->textname));
				lookup->trace_root = (lookup->trace ||
						      lookup->ns_search_only);
				lookup->new_search = true;
				if (firstarg) {
					printgreeting(argc, argv, lookup);
					firstarg = false;
				}
				ISC_LIST_APPEND(lookup_list, lookup, link);
				debug("looking up %s", lookup->textname);
			}
			/* XXX Error message */
		}
	}

	/*
	 * If we have a batchfile, seed the lookup list with the
	 * first entry, then trust the callback in dighost_shutdown
	 * to get the rest
	 */
	char *filename = batchname;
	if ((filename != NULL) && !(is_batchfile)) {
		if (strcmp(filename, "-") == 0) {
			batchfp = stdin;
		} else {
			batchfp = fopen(filename, "r");
		}
		if (batchfp == NULL) {
			perror(filename);
			if (exitcode < 8) {
				exitcode = 8;
			}
			fatal("couldn't open specified batch file");
		}
		/* XXX Remove code dup from shutdown code */
	next_line:
		if (fgets(batchline, sizeof(batchline), batchfp) != 0) {
			debug("batch line %s", batchline);
			if (batchline[0] == '\r' || batchline[0] == '\n' ||
			    batchline[0] == '#' || batchline[0] == ';')
			{
				goto next_line;
			}
			bargc = split_batchline(batchline, bargv, 14,
						"batch argv");
			bargv[0] = argv[0];
			argv0 = argv[0];
			parse_args(true, false, bargc, (char **)bargv);
			return;
		}
		return;
	}
	/*
	 * If no lookup specified, search for root
	 */
	if ((lookup_list.head == NULL) && !config_only) {
		if (need_clone) {
			lookup = clone_lookup(default_lookup, true);
		}
		need_clone = true;
		lookup->trace_root = (lookup->trace || lookup->ns_search_only);
		lookup->new_search = true;
		strlcpy(lookup->textname, ".", sizeof(lookup->textname));
		lookup->rdtype = dns_rdatatype_ns;
		lookup->rdtypeset = true;
		if (firstarg) {
			printgreeting(argc, argv, lookup);
			firstarg = false;
		}
		ISC_LIST_APPEND(lookup_list, lookup, link);
	}
	if (!need_clone) {
		destroy_lookup(lookup);
	}
}

/*
 * Callback from dighost.c to allow program-specific shutdown code.
 * Here, we're possibly reading from a batch file, then shutting down
 * for real if there's nothing in the batch file to read.
 */
static void
query_finished(void) {
	char batchline[MXNAME];

	fflush(stdout);

	if (batchname != NULL && !feof(batchfp) &&
	    fgets(batchline, sizeof(batchline), batchfp) != NULL)
	{
		int bargc;
		char *bargv[16];
		debug("batch line %s", batchline);
		bargc = split_batchline(batchline, bargv, 14, "batch argv");
		bargv[0] = argv0;
		parse_args(true, false, bargc, (char **)bargv);
		start_lookup();
		return;
	}

	debug("shutdown");

	/* We are done */
	if (batchname != NULL) {
		if (batchfp != stdin) {
			fclose(batchfp);
		}
		batchname = NULL;
	}
	isc_loopmgr_shutdown(loopmgr);
}

static void
dig_error(const char *format, ...) {
	va_list args;

	if (yaml) {
		printf("- type: DIG_ERROR\n");

		/*
		 * Print an indent before a literal block quote.
		 * Note: this will break if used to print more than
		 * one line of text as only the first line would be
		 * indented.
		 */
		printf("  message: |\n");
		printf("    ");
	} else {
		printf(";; ");
	}

	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	printf("\n"); /* We get the error without a newline */
}

static void
dig_warning(const char *format, ...) {
	va_list args;

	if (!yaml) {
		printf(";; ");

		va_start(args, format);
		vprintf(format, args);
		va_end(args);

		printf("\n");
	}
}

static void
dig_comments(dig_lookup_t *lookup, const char *format, ...) {
	va_list args;

	if (lookup->comments && !yaml) {
		printf(";; ");

		va_start(args, format);
		vprintf(format, args);
		va_end(args);

		printf("\n");
	}
}

void
dig_setup(int argc, char **argv) {
	ISC_LIST_INIT(lookup_list);
	ISC_LIST_INIT(server_list);
	ISC_LIST_INIT(search_list);

	debug("dig_setup()");

	/* setup dighost callbacks */
	dighost_printmessage = printmessage;
	dighost_received = received;
	dighost_trying = trying;
	dighost_shutdown = query_finished;
	dighost_error = dig_error;
	dighost_warning = dig_warning;
	dighost_comments = dig_comments;

	progname = argv[0];
	preparse_args(argc, argv);

	setup_libs();
	setup_system(ipv4only, ipv6only);
}

void
dig_query_setup(bool is_batchfile, bool config_only, int argc, char **argv) {
	debug("dig_query_setup");

	parse_args(is_batchfile, config_only, argc, argv);
	if (keyfile[0] != 0) {
		setup_file_key();
	} else if (keysecret[0] != 0) {
		setup_text_key();
	}
	if (domainopt[0] != '\0') {
		set_search_domain(domainopt);
		usesearch = true;
	}
}

void
dig_startup(void) {
	debug("dig_startup()");

	isc_loopmgr_setup(loopmgr, run_loop, NULL);
	isc_loopmgr_run(loopmgr);
}

void
dig_shutdown(void) {
	destroy_lookup(default_lookup);
	cancel_all();
	destroy_libs();
}

/*% Main processing routine for dig */
int
main(int argc, char **argv) {
	dig_setup(argc, argv);
	dig_query_setup(false, false, argc, argv);
	dig_startup();
	dig_shutdown();

	return exitcode;
}
