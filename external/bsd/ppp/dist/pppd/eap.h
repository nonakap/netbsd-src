/*	$NetBSD: eap.h,v 1.6 2025/01/08 19:59:39 christos Exp $	*/

/*
 * eap.h - Extensible Authentication Protocol for PPP (RFC 2284)
 *
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Non-exclusive rights to redistribute, modify, translate, and use
 * this software in source and binary forms, in whole or in part, is
 * hereby granted, provided that the above copyright notice is
 * duplicated in any source form, and that neither the name of the
 * copyright holder nor the author is used to endorse or promote
 * products derived from this software.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Original version by James Carlson
 */

#ifndef PPP_EAP_H
#define	PPP_EAP_H

#include "pppdconf.h"

#ifdef	__cplusplus
extern "C" {
#endif


#ifndef PPP_EAP
#define PPP_EAP 0xc227
#endif


/*
 * Packet header = Code, id, length.
 */
#define	EAP_HEADERLEN	4


/* EAP message codes. */
#define	EAP_REQUEST	1
#define	EAP_RESPONSE	2
#define	EAP_SUCCESS	3
#define	EAP_FAILURE	4

/* EAP types */
#define	EAPT_IDENTITY		1
#define	EAPT_NOTIFICATION	2
#define	EAPT_NAK		3	/* (response only) */
#define	EAPT_MD5CHAP		4
#define	EAPT_OTP		5	/* One-Time Password; RFC 1938 */
#define	EAPT_TOKEN		6	/* Generic Token Card */
/* 7 and 8 are unassigned. */
#define	EAPT_RSA		9	/* RSA Public Key Authentication */
#define	EAPT_DSS		10	/* DSS Unilateral */
#define	EAPT_KEA		11	/* KEA */
#define	EAPT_KEA_VALIDATE	12	/* KEA-VALIDATE	*/
#define	EAPT_TLS		13	/* EAP-TLS */
#define	EAPT_DEFENDER		14	/* Defender Token (AXENT) */
#define	EAPT_W2K		15	/* Windows 2000 EAP */
#define	EAPT_ARCOT		16	/* Arcot Systems */
#define	EAPT_CISCOWIRELESS	17	/* Cisco Wireless */
#define	EAPT_NOKIACARD		18	/* Nokia IP smart card */
#define	EAPT_SRP		19	/* Secure Remote Password */
/* 20 is deprecated */
#define	EAPT_TTLS		21	/* EAP Tunneled TLS Authentication Protocol RFC5281 */
#define	EAPT_RAS		22	/* Remote Access Service */
#define	EAPT_AKA		23	/* EAP method for 3rd Generation Authentication and Key Agreement RFC4187 */
#define	EAPT_3COM		24	/* EAP-3Com Wireless */
#define	EAPT_PEAP		25	/* Protected EAP */
#define	EAPT_MSCHAPV2		26	/* EAP-MSCHAPv2 RFC-draft-kamath-pppext-eap-mschapv2-02 */

/* OpCodes for MSCHAPv2 */
#define CHAP_CHALLENGE		1
#define CHAP_RESPONSE		2
#define CHAP_SUCCESS		3
#define CHAP_FAILURE		4

/* EAP SRP-SHA1 Subtypes */
#define	EAPSRP_CHALLENGE	1	/* Request 1 - Challenge */
#define	EAPSRP_CKEY		1	/* Response 1 - Client Key */
#define	EAPSRP_SKEY		2	/* Request 2 - Server Key */
#define	EAPSRP_CVALIDATOR	2	/* Response 2 - Client Validator */
#define	EAPSRP_SVALIDATOR	3	/* Request 3 - Server Validator */
#define	EAPSRP_ACK		3	/* Response 3 - final ack */
#define	EAPSRP_LWRECHALLENGE	4	/* Req/resp 4 - Lightweight rechal */

#define	SRPVAL_EBIT	0x00000001	/* Use shared key for ECP */

#define	SRP_PSEUDO_ID	"pseudo_"
#define	SRP_PSEUDO_LEN	7

#define MIN_CHALLENGE_LENGTH	16
#define MAX_CHALLENGE_LENGTH	24

enum eap_state_code {
	eapInitial = 0,	/* No EAP authentication yet requested */
	eapPending,	/* Waiting for LCP (no timer) */
	eapClosed,	/* Authentication not in use */
	eapListen,	/* Client ready (and timer running) */
	eapIdentify,	/* EAP Identify sent */
	eapTlsStart,	/* Send EAP-TLS start packet */
	eapTlsRecv,	/* Receive EAP-TLS tls data */
	eapTlsSendAck,	/* Send EAP-TLS ack */
	eapTlsSend,	/* Send EAP-TLS tls data */
	eapTlsRecvAck,	/* Receive EAP-TLS ack */
	eapTlsRecvClient, 	/* Receive EAP-TLS auth response from client*/
	eapTlsSendAlert,	/* Send EAP-TLS tls alert (server)*/
	eapTlsRecvAlertAck,	/* Receive EAP-TLS ack after sending alert */
	eapTlsRecvSuccess,	/* Receive EAP success */
	eapTlsRecvFailure,	/* Receive EAP failure */
	eapSRP1,	/* Sent EAP SRP-SHA1 Subtype 1 */
	eapSRP2,	/* Sent EAP SRP-SHA1 Subtype 2 */
	eapSRP3,	/* Sent EAP SRP-SHA1 Subtype 3 */
	eapMD5Chall,	/* Sent MD5-Challenge */
	eapMSCHAPv2Chall,	/* Sent MSCHAPv2-Challenge */
	eapOpen,	/* Completed authentication */
	eapSRP4,	/* Sent EAP SRP-SHA1 Subtype 4 */
	eapBadAuth	/* Failed authentication */
};

#define	EAP_STATES	\
	"Initial", "Pending", "Closed", "Listen", "Identify", \
	"TlsStart", "TlsRecv", "TlsSendAck", "TlsSend", "TlsRecvAck", "TlsRecvClient",\
	"TlsSendAlert", "TlsRecvAlertAck" , "TlsRecvSuccess", "TlsRecvFailure", \
	"SRP1", "SRP2", "SRP3", "MD5Chall", "MSCHAPv2Chall", "Open", "SRP4", "BadAuth"

#ifdef PPP_WITH_EAPTLS
#define	eap_client_active(esp)	((esp)->es_client.ea_state != eapInitial &&\
				 (esp)->es_client.ea_state != eapPending &&\
				 (esp)->es_client.ea_state != eapClosed)
#else
#define eap_client_active(esp)	((esp)->es_client.ea_state == eapListen)
#endif /* PPP_WITH_EAPTLS */

#define	eap_server_active(esp)	\
	((esp)->es_server.ea_state >= eapIdentify && \
	 (esp)->es_server.ea_state <= eapMD5Chall)

struct eap_auth {
	char *ea_name;		/* Our name */
	char *ea_peer;		/* Peer's name */
	void *ea_session;	/* Authentication library linkage */
	unsigned char *ea_skey;	/* Shared encryption key */
	int ea_timeout;		/* Time to wait (for retransmit/fail) */
	int ea_maxrequests;	/* Max Requests allowed */
	unsigned short ea_namelen;	/* Length of our name */
	unsigned short ea_peerlen;	/* Length of peer's name */
	enum eap_state_code ea_state;
#ifdef PPP_WITH_EAPTLS
	enum eap_state_code ea_prev_state;
#endif
#ifdef PPP_WITH_CHAPMS
        struct chap_digest_type *digest;
#endif
	unsigned char ea_id;		/* Current id */
	unsigned char ea_requests;	/* Number of Requests sent/received */
	unsigned char ea_responses;	/* Number of Responses */
	unsigned char ea_type;		/* One of EAPT_* */
	uint32_t ea_keyflags;	/* SRP shared key usage flags */
#ifdef PPP_WITH_EAPTLS
	bool ea_using_eaptls;
#endif
};

/*
 * Complete EAP state for one PPP session.
 */
typedef struct eap_state {
	int es_unit;			/* Interface unit number */
	struct eap_auth es_client;	/* Client (authenticatee) data */
	struct eap_auth es_server;	/* Server (authenticator) data */
#ifdef PPP_WITH_PEAP
	struct peap_state *ea_peap;	/* Client PEAP (authenticator) data */
#endif
	int es_savedtime;		/* Saved timeout */
	int es_rechallenge;		/* EAP rechallenge interval */
	int es_lwrechallenge;		/* SRP lightweight rechallenge inter */
	bool es_usepseudo;		/* Use SRP Pseudonym if offered one */
	int es_usedpseudo;		/* Set if we already sent PN */
	int es_challen;			/* Length of challenge string */
	unsigned char es_challenge[MAX_CHALLENGE_LENGTH];
} eap_state;

/*
 * Timeouts.
 */
#define	EAP_DEFTIMEOUT		3	/* Timeout (seconds) for rexmit */
#ifdef PPP_WITH_EAPTLS
#define	EAP_DEFTRANSMITS	30	/* max # times to transmit */
					/* certificates can be long ... */
#else
#define	EAP_DEFTRANSMITS	10	/* max # times to transmit */
#endif /* PPP_WITH_EAPTLS */
#define	EAP_DEFREQTIME		20	/* Time to wait for peer request */
#define	EAP_DEFALLOWREQ		20	/* max # times to accept requests */

extern eap_state eap_states[];

void eap_authwithpeer (int unit, char *localname);
void eap_authpeer (int unit, char *localname);

extern struct protent eap_protent;

#ifdef PPP_WITH_EAPTLS
typedef int (eaptls_passwd_hook_fn)(char *user, char *passwd);
extern eaptls_passwd_hook_fn *eaptls_passwd_hook;
#endif

#ifdef	__cplusplus
}
#endif

#endif /* PPP_EAP_H */

