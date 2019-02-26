/*	$NetBSD: vmbusicreg.h,v 1.2 2019/03/01 10:02:33 nonaka Exp $	*/
/*	$OpenBSD: hypervicreg.h,v 1.6 2017/11/07 16:49:42 mikeb Exp $	*/

/*-
 * Copyright (c) 2016 Microsoft Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: head/sys/dev/hyperv/utilities/vmbus_icreg.h 305281 2016-09-02 06:23:28Z sephe $
 */

#ifndef _VMBUSICREG_H_
#define _VMBUSICREG_H_

#include <dev/hyperv/hypervio.h>

#define VMBUS_ICMSG_TYPE_NEGOTIATE	0
#define VMBUS_ICMSG_TYPE_HEARTBEAT	1
#define VMBUS_ICMSG_TYPE_KVP		2
#define VMBUS_ICMSG_TYPE_SHUTDOWN	3
#define VMBUS_ICMSG_TYPE_TIMESYNC	4
#define VMBUS_ICMSG_TYPE_VSS		5

#define VMBUS_IC_VERSION(major, minor)	((major) | (((uint32_t)(minor)) << 16))
#define VMBUS_ICVER_MAJOR(ver)		((ver) & 0xffff)
#define VMBUS_ICVER_MINOR(ver)		(((ver) & 0xffff0000) >> 16)
#define VMBUS_ICVER_SWAP(ver)		\
            ((VMBUS_ICVER_MAJOR((ver)) << 16) | VMBUS_ICVER_MINOR((ver)))
#define VMBUS_ICVER_LE(v1, v2)		\
            (VMBUS_ICVER_SWAP((v1)) <= VMBUS_ICVER_SWAP((v2)))
#define VMBUS_ICVER_GT(v1, v2)		\
            (VMBUS_ICVER_SWAP((v1)) > VMBUS_ICVER_SWAP((v2)))

struct vmbus_pipe_hdr {
	uint32_t		ph_flags;
	uint32_t		ph_msgsz;
} __packed;

struct vmbus_icmsg_hdr {
	struct vmbus_pipe_hdr	ic_pipe;
	uint32_t		ic_fwver;	/* framework version */
	uint16_t		ic_type;
	uint32_t		ic_msgver;	/* message version */
	uint16_t		ic_dsize;	/* data size */
	uint32_t		ic_status;	/* HV_S_OK, ... */
	uint8_t			ic_tid;
	uint8_t			ic_flags;	/* VMBUS_ICMSG_FLAG_ */
	uint8_t			ic_rsvd[2];
} __packed;

#define VMBUS_ICMSG_FLAG_TRANSACTION	1
#define VMBUS_ICMSG_FLAG_REQUEST	2
#define VMBUS_ICMSG_FLAG_RESPONSE	4

/* VMBUS_ICMSG_TYPE_NEGOTIATE */
struct vmbus_icmsg_negotiate {
	struct vmbus_icmsg_hdr	ic_hdr;
	uint16_t		ic_fwver_cnt;
	uint16_t		ic_msgver_cnt;
	uint32_t		ic_rsvd;
	/*
	 * This version array contains two set of supported
	 * versions:
	 * - The first set consists of #ic_fwver_cnt supported framework
	 *   versions.
	 * - The second set consists of #ic_msgver_cnt supported message
	 *   versions.
	 */
	uint32_t		ic_ver[0];
} __packed;

/* VMBUS_ICMSG_TYPE_HEARTBEAT */
struct vmbus_icmsg_heartbeat {
	struct vmbus_icmsg_hdr	ic_hdr;
	uint64_t		ic_seq;
	uint32_t		ic_rsvd[8];
} __packed;

#define VMBUS_ICMSG_HEARTBEAT_SIZE_MIN	\
	    offsetof(struct vmbus_icmsg_heartbeat, ic_rsvd[0])

/* VMBUS_ICMSG_TYPE_SHUTDOWN */
struct vmbus_icmsg_shutdown {
	struct vmbus_icmsg_hdr	ic_hdr;
	uint32_t		ic_code;
	uint32_t		ic_timeo;
	uint32_t 		ic_haltflags;
	uint8_t			ic_msg[2048];
} __packed;

#define VMBUS_ICMSG_SHUTDOWN_SIZE_MIN	\
	    offsetof(struct vmbus_icmsg_shutdown, ic_msg[0])

/* VMBUS_ICMSG_TYPE_TIMESYNC */
struct vmbus_icmsg_timesync {
	struct vmbus_icmsg_hdr	ic_hdr;
	uint64_t		ic_hvtime;
	uint64_t		ic_vmtime;
	uint64_t		ic_rtt;
	uint8_t			ic_tsflags;	/* VMBUS_ICMSG_TS_FLAG_ */
} __packed;

/* VMBUS_ICMSG_TYPE_TIMESYNC, MSGVER4 */
struct vmbus_icmsg_timesync4 {
	struct vmbus_icmsg_hdr	ic_hdr;
	uint64_t		ic_hvtime;
	uint64_t		ic_sent_tc;
	uint8_t			ic_tsflags;	/* VMBUS_ICMSG_TS_FLAG_ */
	uint8_t			ic_rsvd[5];
} __packed;

#define VMBUS_ICMSG_TS_FLAG_SYNC	0x01
#define VMBUS_ICMSG_TS_FLAG_SAMPLE	0x02

#define VMBUS_ICMSG_TS_BASE		116444736000000000ULL

/* VMBUS_ICMSG_TYPE_KVP */
#define VMBUS_KVP_MAX_VAL_SIZE		1024
#define VMBUS_KVP_MAX_KEY_SIZE		256

union vmbus_kvp_hdr {
	struct {
		uint8_t		kvu_op;
		uint8_t		kvu_pool;
		uint16_t	kvu_pad;
	} req;
	struct {
		uint32_t	kvu_err;
	} rsp;
#define kvh_op			req.kvu_op
#define kvh_pool		req.kvu_pool
#define kvh_err			rsp.kvu_err
} __packed;

struct vmbus_kvp_msg_val {
	uint32_t		kvm_valtype;
	uint32_t		kvm_keylen;
	uint32_t		kvm_vallen;
	uint16_t		kvm_key[VMBUS_KVP_MAX_KEY_SIZE];
	uint16_t		kvm_val[VMBUS_KVP_MAX_VAL_SIZE];
} __packed;

struct vmbus_kvp_msg_enum {
	uint32_t		kvm_index;
	uint32_t		kvm_valtype;
	uint32_t		kvm_keylen;
	uint32_t		kvm_vallen;
	uint16_t		kvm_key[VMBUS_KVP_MAX_KEY_SIZE];
	uint16_t		kvm_val[VMBUS_KVP_MAX_VAL_SIZE];
} __packed;

struct vmbus_kvp_msg_del {
	uint32_t		kvm_keylen;
	uint16_t		kvm_key[VMBUS_KVP_MAX_KEY_SIZE];
} __packed;

#define VMBUS_KVP_MAX_ADAPTER_ID_SIZE	128
#define VMBUS_KVP_MAX_IP_ADDR_SIZE	1024
#define VMBUS_KVP_MAX_GATEWAY_SIZE	512

struct vmbus_kvp_msg_addr {
	uint16_t		kvm_adapter_id[VMBUS_KVP_MAX_ADAPTER_ID_SIZE];
	uint8_t			kvm_family;
	uint8_t			kvm_dhcp;
	uint16_t		kvm_addr[VMBUS_KVP_MAX_IP_ADDR_SIZE];
	uint16_t		kvm_netmask[VMBUS_KVP_MAX_IP_ADDR_SIZE];
	uint16_t		kvm_gateway[VMBUS_KVP_MAX_GATEWAY_SIZE];
	uint16_t		kvm_dns[VMBUS_KVP_MAX_IP_ADDR_SIZE];
} __packed;

union vmbus_kvp_msg {
	struct vmbus_kvp_msg_val	kvm_val;
	struct vmbus_kvp_msg_enum	kvm_enum;
	struct vmbus_kvp_msg_del	kvm_del;
};

struct vmbus_icmsg_kvp {
	struct vmbus_icmsg_hdr		ic_hdr;
	union vmbus_kvp_hdr		ic_kvh;
	union vmbus_kvp_msg		ic_kvm;
} __packed;

struct vmbus_icmsg_kvp_addr {
	struct vmbus_icmsg_hdr		ic_hdr;
	struct {
		struct {
			uint8_t	kvu_op;
			uint8_t	kvu_pool;
		} req;
	}				ic_kvh;
	struct vmbus_kvp_msg_addr	ic_kvm;
} __packed;

#endif	/* _VMBUSICREG_H_ */
