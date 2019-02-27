/*	$NetBSD$	*/

/*-
 * Copyright (c) 2014,2016-2017 Microsoft Corp.
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
 */

/*
 *	Author:	Sainath Varanasi.
 *	Date:	4/2012
 *	Email:	bsdic@microsoft.com
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>
#include <sys/endian.h>
#include <sys/module.h>
#include <sys/pmf.h>

#include <dev/hyperv/vmbusvar.h>
#include <dev/hyperv/vmbusicreg.h>
#include <dev/hyperv/vmbusicvar.h>

#define VMBUS_KVP_FWVER_MAJOR	3
#define VMBUS_KVP_FWVER		\
	    VMBUS_IC_VERSION(VMBUS_KVP_FWVER_MAJOR, 0)

#define VMBUS_KVP_MSGVER_MAJOR	4
#define VMBUS_KVP_MSGVER		\
	    VMBUS_IC_VERSION(VMBUS_KVP_MSGVER_MAJOR, 0)

struct hvkvp_softc {
	struct vmbusic_softc	 sc_vmbusic;
};

/* ProcessorArchitecture */
/* https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/ns-sysinfoapi-_system_info */
#define	PROCESSOR_ARCHITECTURE_INTEL	0	/* x86 */
#define	PROCESSOR_ARCHITECTURE_ARM	5	/* ARM */
#define	PROCESSOR_ARCHITECTURE_IA64	6	/* Intel Itanium-based */
#define	PROCESSOR_ARCHITECTURE_AMD64	9	/* x64 (AMD or Intel) */
#define	PROCESSOR_ARCHITECTURE_ARM64	12	/* ARM64 */
#define	PROCESSOR_ARCHITECTURE_UNKNOWN	0xffff	/* Unknown architecture */

#if defined(__i386__)
#define	PROCESSOR_ARCHITECTURE	PROCESSOR_ARCHITECTURE_INTEL
#elif defined(__x86_64__)
#define	PROCESSOR_ARCHITECTURE	PROCESSOR_ARCHITECTURE_AMD64
#elif defined(__aarch64__)
#define	PROCESSOR_ARCHITECTURE	PROCESSOR_ARCHITECTURE_ARM64
#else
#error	Unknown ProcessorArchitecture
#endif

static const char hvkvp_version[] /*XXX*/ __unused = "1.0";

static int	hvkvp_match(device_t, cfdata_t, void *);
static void	hvkvp_attach(device_t, device_t, void *);
static int	hvkvp_detach(device_t, int);

static void	hvkvp_channel_cb(void *);

static ssize_t	ucs2utf8(const uint16_t *, size_t, uint8_t *, size_t);
static ssize_t	utf8ucs2(const uint8_t *, size_t, uint16_t *, size_t);
static size_t	ucs2utf8str(const uint16_t *, size_t, uint8_t *, size_t);
static size_t	utf8ucs2str(const uint8_t *, size_t, uint16_t *, size_t);

CFATTACH_DECL_NEW(hvkvp, sizeof(struct hvkvp_softc),
    hvkvp_match, hvkvp_attach, hvkvp_detach, NULL);

static int
hvkvp_match(device_t parent, cfdata_t cf, void *aux)
{
	struct vmbus_attach_args *aa = aux;

	return vmbusic_probe(aa, &hyperv_guid_kvp);
}

static void
hvkvp_attach(device_t parent, device_t self, void *aux)
{
	struct hvkvp_softc *sc = device_private(self);
	struct vmbusic_softc *vsc = &sc->sc_vmbusic;
	struct vmbus_attach_args *aa = aux;
	int error;

	aprint_naive("\n");
	aprint_normal(": Hyper-V Data Exchange Service\n");

	error = vmbusic_attach(self, aa, hvkvp_channel_cb);
	if (error) {
		aprint_error_dev(vsc->sc_dev, "vmbusic_attach failed: %u\n",
		    error);
		return;
	}

	(void) pmf_device_register(self, NULL, NULL);
}

static int
hvkvp_detach(device_t self, int flags)
{

	pmf_device_deregister(self);

	return vmbusic_detach(self, flags);
}

static void
hvkvp_channel_cb(void *arg)
{
	struct hvkvp_softc *sc = arg;
	struct vmbusic_softc *vsc = &sc->sc_vmbusic;
	struct vmbus_channel *ch = vsc->sc_chan;
	struct vmbus_icmsg_hdr *hdr;
	uint64_t rid;
	uint32_t rlen, fwver, msgver;
	int error;

	for (;;) {
		error = vmbus_channel_recv(ch, vsc->sc_buf, vsc->sc_buflen,
		    &rlen, &rid, 0);
		if (error || rlen == 0) {
			if (error != EAGAIN) {
				DPRINTF("%s: KVP error=%d len=%u\n",
				    device_xname(vsc->sc_dev), error, rlen);
			}
			return;
		}
		if (rlen < sizeof(*hdr)) {
			DPRINTF("%s: KVP short read len=%u\n",
			    device_xname(vsc->sc_dev), rlen);
			return;
		}

		hdr = (struct vmbus_icmsg_hdr *)vsc->sc_buf;
		switch (hdr->ic_type) {
		case VMBUS_ICMSG_TYPE_NEGOTIATE:
			switch (ch->ch_sc->sc_proto) {
			case VMBUS_VERSION_WS2008:
				fwver = VMBUS_IC_VERSION(1, 0);
				msgver = VMBUS_IC_VERSION(1, 0);
				break;
			case VMBUS_VERSION_WIN7:
				fwver = VMBUS_IC_VERSION(3, 0);
				msgver = VMBUS_IC_VERSION(3, 0);
				break;
			default:
				fwver = VMBUS_KVP_FWVER;
				msgver = VMBUS_KVP_MSGVER;
			}
			error = vmbusic_negotiate(vsc, hdr, &rlen,
			    fwver, msgver);
			if (error == 0)
				hdr->ic_status = HV_S_OK;
			else
				hdr->ic_status = HV_E_FAIL;
			break;

		case VMBUS_ICMSG_TYPE_KVP:
			if (rlen < sizeof(struct vmbus_icmsg_kvp)) {
				device_printf(vsc->sc_dev,
				    "message too short: %u\n", hdr->ic_dsize);
				continue;
			}

			/* XXX */
			break;

		default:
			device_printf(vsc->sc_dev,
			    "unhandled KVP message type %u\n", hdr->ic_type);
			continue;
		}

		(void) vmbusic_sendresp(vsc, ch, vsc->sc_buf, rlen, rid);
	}
}

/*
 * Convert UCS-2 character into UTF-8
 * return number of output bytes or 0 if output
 * buffer is too short and -1 if input is invalid
 */
static ssize_t
ucs2utf8(const uint16_t *in, size_t n, uint8_t *out, size_t m)
{
	uint16_t inch;

	inch = le16toh(in[0]);
	if (inch <= 0x007f) {
		if (m < 1) return 0;
		if (out)
			*out++ = inch;
		return 1;
	} else if (inch <= 0x07ff) {
		if (m < 2) return 0;
		if (out) {
			*out++ = 0xc0 | (inch >> 6);
			*out++ = 0x80 | (inch & 0x3f);
		}
		return 2;
	} else if (inch >= 0xd800 && inch <= 0xdbff) {
		uint16_t low;
		if (m < 4) return 0;
		if (n < 2) return -1;
		low = le16toh(in[1]);
		if (low >= 0xdc00 && low <= 0xdfff) {
			if (out) {
				inch = 0x40 + (inch - 0xd800);
				low -= 0xdc00;

				*out++ = 0xf0 | ((inch >> 8) & 0x07);
				*out++ = 0x80 | ((inch >> 2) & 0x3f);
				*out++ = 0x80 | ((inch << 6) & 0x30) | ((low >> 6) & 0x0f);
				*out++ = 0x80 | (low & 0x3f);
			}
			return 4;
		}
		return -1;
	} else {
		if (m < 3) return 0;
		if (out) {
			*out++ = 0xe0 | (inch >> 12);
			*out++ = 0x80 | ((inch >> 6) & 0x3f);
			*out++ = 0x80 | (inch & 0x3f);
		}
		return 3;
	}
}

/*
 * Convert UTF-8 bytes into UCS-2 character
 * return number of input bytes, 0 if input
 * is too short and -1 if input is invalid
 */
static ssize_t
utf8ucs2(const uint8_t *in, size_t n, uint16_t *out, size_t m)
{
	uint16_t outch;

	if (n < 1) return 0;

	if (in[0] <= 0x7f) {
		outch = in[0];
		if (out)
			*out = htole16(outch);
		return 1;
	} else if (in[0] <= 0xdf) {
		if (n < 2) return 0;
		outch = (in[0] & 0x1f) << 6 | (in[1] & 0x3f);
		if (out)
			*out = htole16(outch);
		return 2;
	} else if (in[0] <= 0xef) {
		if (n < 3) return 0;
		outch = (in[0] & 0x1f) << 12 | (in[1] & 0x3f) << 6 | (in[2] & 0x3f);
		if (out)
			*out = htole16(outch);
		return 3;
	} else if (in[0] <= 0xf7) {
		if (n < 4) return 0;
		if (m < 2) return -1;
		outch = (in[0] & 0x7) << 8 | (in[1] & 0x3f) << 2 | (in[2] & 0x30) >> 4;
		if (out)
			*out++ = htole16(0xd800 + 0x40 - outch);
		outch = (in[2] & 0x0f) << 6 | (in[3] & 0x3f);
		if (out)
			*out = htole16(0xdc00 + outch);
		return 4;
	}

	return -1;
}

/*
 * Convert UCS-2 string into UTF-8 string
 * return total number of output bytes
 */
static size_t	/* XXX */ __unused
ucs2utf8str(const uint16_t *in, size_t n, uint8_t *out, size_t m)
{
	uint8_t *p;
	ssize_t outlen;

	p = out;
	while (n > 0 && *in != 0) {
		outlen = ucs2utf8(in, n, out ? p : out, m);
		if (outlen <= 0)
			break;
		p += outlen;
		m -= outlen;
		in += (outlen == 4) ? 2 : 1;
		n -= (outlen == 4) ? 2 : 1;
	}

	return p - out;
}

/*
 * Convert UTF8 string into UCS-2 string
 * return total number of output chacters
 */
static size_t	/* XXX */ __unused
utf8ucs2str(const uint8_t *in, size_t n, uint16_t *out, size_t m)
{
	uint16_t *p;
	ssize_t inlen;

	p = out;
	while (n > 0 && *in != 0) {
		if (m < 1)
			break;
		inlen = utf8ucs2(in, n, out ? p : out, m);
		if (inlen <= 0)
			break;
		in += inlen;
		n -= inlen;
		p += (inlen == 4) ? 2 : 1;
		m -= (inlen == 4) ? 2 : 1;
	}

	return p - out;
}

MODULE(MODULE_CLASS_DRIVER, hvkvp, "vmbus");

#ifdef _MODULE
#include "ioconf.c"
#endif

static int
hvkvp_modcmd(modcmd_t cmd, void *aux)
{
	int error = 0;

	switch (cmd) {
	case MODULE_CMD_INIT:
#ifdef _MODULE
		error = config_init_component(cfdriver_ioconf_hvkvp,
		    cfattach_ioconf_hvkvp, cfdata_ioconf_hvkvp);
#endif
		break;

	case MODULE_CMD_FINI:
#ifdef _MODULE
		error = config_fini_component(cfdriver_ioconf_hvkvp,
		    cfattach_ioconf_hvkvp, cfdata_ioconf_hvkvp);
#endif
		break;

	case MODULE_CMD_AUTOUNLOAD:
		error = EBUSY;
		break;

	default:
		error = ENOTTY;
		break;
	}

	return error;
}
