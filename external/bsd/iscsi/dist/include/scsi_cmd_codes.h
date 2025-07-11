/* $NetBSD: scsi_cmd_codes.h,v 1.4 2025/07/05 06:50:12 mlelstv Exp $ */

/*
 * Copyright � 2006 Alistair Crooks.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef SCSI_CMD_CODES_H_
#define SCSI_CMD_CODES_H_

/* information taken from SPC3, T10/1416-D Revision 23, from www.t10.org */

enum {
	TEST_UNIT_READY = 0x00,
	READ_6 = 0x08,
	WRITE_6 = 0x0a,
	INQUIRY = 0x12,
	MODE_SELECT_6 = 0x15,
	RESERVE_6 = 0x16,
	RELEASE_6 = 0x17,
	MODE_SENSE_6 = 0x1a,
	STOP_START_UNIT = 0x1b,
	READ_CAPACITY = 0x25,
	READ_CAPACITY_16 = 0x9e,
	READ_10 = 0x28,
	WRITE_10 = 0x2a,
	WRITE_VERIFY = 0x2e,
	READ_16 = 0x88,
	WRITE_16 = 0x8a,
	WRITE_VERIFY_16 = 0x8e,
	VERIFY = 0x2f,
	SYNC_CACHE = 0x35,
	LOG_SENSE = 0x4d,
	MODE_SELECT_10 = 0x55,
	RESERVE_10 = 0x56,
	RELEASE_10 = 0x57,
	MODE_SENSE_10 = 0x5a,
	PERSISTENT_RESERVE_IN = 0x5e,
	PERSISTENT_RESERVE_OUT = 0x5f,
	REPORT_LUNS = 0xa0
};

#define SIX_BYTE_COMMAND(op)	((op) <= 0x1f)
#define TEN_BYTE_COMMAND(op)	((op) > 0x1f && (op) <= 0x5f)

enum {
	ISCSI_MODE_SENSE_LEN = 	11
};

/* miscellaneous definitions */
enum {
	DISK_PERIPHERAL_DEVICE = 0x0,

	INQUIRY_EVPD_BIT = 0x01,

	INQUIRY_UNIT_SERIAL_NUMBER_VPD = 0x80,
	INQUIRY_DEVICE_IDENTIFICATION_VPD = 0x83,
	INQUIRY_SUPPORTED_VPD_PAGES = 0x0,
		INQUIRY_DEVICE_PIV = 0x1,

		INQUIRY_IDENTIFIER_TYPE_T10 = 0x1,
		INQUIRY_IDENTIFIER_TYPE_EUI64 = 0x2,
		INQUIRY_IDENTIFIER_TYPE_NAA = 0x3,

		INQUIRY_DEVICE_ASSOCIATION_LOGICAL_UNIT = 0x0,
		INQUIRY_DEVICE_ASSOCIATION_TARGET_PORT = 0x1,
		INQUIRY_DEVICE_ASSOCIATION_TARGET_DEVICE = 0x2,

		INQUIRY_DEVICE_CODESET_UTF8 = 0x3,
		INQUIRY_DEVICE_ISCSI_PROTOCOL = 0x5,
		INQUIRY_DEVICE_T10_VENDOR = 0x1,
		INQUIRY_DEVICE_IDENTIFIER_SCSI_NAME = 0x8,

	EXTENDED_INQUIRY_DATA_VPD = 0x86,
		EXTENDED_INQUIRY_REF_TAG_OWNER = 0x08,
		EXTENDED_INQUIRY_GUARD_CHECK = 0x04,
		EXTENDED_INQUIRY_APPLICATION_CHECK = 0x02,
		EXTENDED_INQUIRY_REFERENCE_CHECK = 0x01,

		EXTENDED_INQUIRY_GROUP_SUPPORT = 0x10,
		EXTENDED_INQUIRY_PRIORITY_SUPPORT = 0x8,
		EXTENDED_INQUIRY_QUEUE_HEAD_SUPPORT = 0x4,
		EXTENDED_INQUIRY_ORDERED_SUPPORT = 0x2,
		EXTENDED_INQUIRY_SIMPLE_SUPPORT = 0x1,

	PERSISTENT_RESERVE_IN_SERVICE_ACTION_MASK = 0x1f,
		PERSISTENT_RESERVE_IN_READ_KEYS = 0x0,
		PERSISTENT_RESERVE_IN_READ_RESERVATION = 0x1,
		PERSISTENT_RESERVE_IN_REPORT_CAPABILITIES = 0x2,
		PERSISTENT_RESERVE_IN_READ_FULL_STATUS = 0x3,

	PERSISTENT_RESERVE_IN_CRH = 0x10,
	PERSISTENT_RESERVE_IN_SIP_C = 0x8,
	PERSISTENT_RESERVE_IN_ATP_C = 0x4,
	PERSISTENT_RESERVE_IN_PTPL_C = 0x1, /* persistence through power loss */
	PERSISTENT_RESERVE_IN_TMV = 0x80, /* Type Mask Valid */
	PERSISTENT_RESERVE_IN_PTPL_A = 0x01, /* persistence through power loss activated */

	PERSISTENT_RESERVE_IN_WR_EX_AR = 0x80,
	PERSISTENT_RESERVE_IN_EX_AC_RD = 0x40,
	PERSISTENT_RESERVE_IN_WR_AC_RD = 0x20,
	PERSISTENT_RESERVE_IN_EX_AC = 0x08,
	PERSISTENT_RESERVE_IN_WR_EX = 0x02,
	PERSISTENT_RESERVE_IN_EX_AC_AR = 0x01,

	WIDE_BUS_16 = 0x20,
	WIDE_BUS_32 = 0x40,

	SCSI_VERSION_SPC = 0x03,
	SCSI_VERSION_SPC2 = 0x04,
	SCSI_VERSION_SPC3 = 0x05,

	/* used in MODE_SENSE_10 */
	DISABLE_BLOCK_DESCRIPTORS = 0x08,
	LONG_LBA_ACCEPTED = 0x10,
	PAGE_CONTROL_MASK = 0xc0,
		PAGE_CONTROL_CURRENT_VALUES = 0x0,
		PAGE_CONTROL_CHANGEABLE_VALUES = 0x40,
		PAGE_CONTROL_DEFAULT_VALUES = 0x80,
		PAGE_CONTROL_SAVAED_VALUES = 0xc0,
	PAGE_CODE_MASK = 0x3f,

		ASC_LUN_UNSUPPORTED = 0x25,
		ASCQ_LUN_UNSUPPORTED = 0x0,

		SCSI_SKEY_ILLEGAL_REQUEST = 0x05
};

/* device return codes */
enum {
	SCSI_SUCCESS = 0x0,
	SCSI_CHECK_CONDITION = 0x02
};

#endif /* !SCSI_CMD_CODES_H_ */
