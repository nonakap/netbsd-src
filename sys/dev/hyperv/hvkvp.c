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

/*-
 * Copyright (c) 2009-2016 Microsoft Corp.
 * Copyright (c) 2012 NetApp Inc.
 * Copyright (c) 2012 Citrix Inc.
 * Copyright (c) 2016 Mike Belopuhov <mike@esdenera.com>
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
 * The OpenBSD port was done under funding by Esdenera Networks GmbH.
 */

#include "opt_inet.h"

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/once.h>
#include <sys/pmf.h>
#include <sys/pool.h>
#include <sys/queue.h>
#include <sys/workqueue.h>

#include <net/if_dl.h>
#include <net/if_ether.h>
#include <netinet/in.h>
#include <netinet6/in6.h>

#include <dev/hyperv/vmbusvar.h>
#include <dev/hyperv/vmbusicreg.h>
#include <dev/hyperv/vmbusicvar.h>

#define VMBUS_KVP_FWVER_MAJOR	3
#define VMBUS_KVP_FWVER		\
	    VMBUS_IC_VERSION(VMBUS_KVP_FWVER_MAJOR, 0)

#define VMBUS_KVP_MSGVER_MAJOR	4
#define VMBUS_KVP_MSGVER		\
	    VMBUS_IC_VERSION(VMBUS_KVP_MSGVER_MAJOR, 0)

struct hvkvp_entry {
	TAILQ_ENTRY(hvkvp_entry)	kpe_entry;
	int				kpe_index;
	uint32_t			kpe_valtype;
	uint8_t				kpe_key[HV_KVP_EXCHANGE_MAX_KEY_SIZE];
	uint8_t				kpe_val[HV_KVP_EXCHANGE_MAX_VALUE_SIZE];
};
TAILQ_HEAD(hvkvp_list, hvkvp_entry);

struct hvkvp_pool {
	struct hvkvp_list		kvp_entries;
	kmutex_t			kvp_lock;
	u_int				kvp_index;
};

struct hvkvp_softc {
	struct vmbusic_softc	 sc_vmbusic;

	struct workqueue	*sc_channel_wq;

	struct pool		 sc_entry_pool;
	struct hvkvp_pool	 sc_pools[HV_KVP_POOL_COUNT];

	u_int			 sc_dying;
	u_int			 sc_flags;
#define HVKVP_FLAG_ATTACHED	__BIT(0)
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

static const char hvkvp_version[] = "1.0";
static char hvkvp_osbuildnumber[20], hvkvp_osmajor[20], hvkvp_osminor[20];
static char hvkvp_ipv4addr[INET_ADDRSTRLEN] = "127.0.0.1";
static char hvkvp_ipv6addr[INET6_ADDRSTRLEN] = "::1";

/*static XXX*/ const struct {
	int				 idx;
	const char			*key;
	const char			*value;
} kvp_pool_auto[] = {
	{  0, "FullyQualifiedDomainName",	hostname },
	{  1, "IntegrationServicesVersion",	hvkvp_version },
	{  2, "NetworkAddressIPv4",		hvkvp_ipv4addr },
	{  3, "NetworkAddressIPv6",		hvkvp_ipv6addr },
	{  4, "OSBuildNumber",			hvkvp_osbuildnumber },
	{  5, "OSName",				ostype },
	{  6, "OSMajorVersion",			hvkvp_osmajor },
	{  7, "OSMinorVersion",			hvkvp_osminor },
	{  8, "OSVersion",			osrelease },
	{  9, "ProcessorArchitecture",
		___STRING(PROCESSOR_ARCHITECTURE) },
};

static ONCE_DECL(hvkvp_once);

static int	hvkvp_match(device_t, cfdata_t, void *);
static void	hvkvp_attach(device_t, device_t, void *);
static int	hvkvp_detach(device_t, int);

static int	hvkvp_attach_once(void);
static void	hvkvp_process(struct hvkvp_softc *, struct vmbus_icmsg_kvp *);
static void	hvkvp_channel_work(struct work *, void *);
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

	RUN_ONCE(&hvkvp_once, hvkvp_attach_once);

	pool_init(&sc->sc_entry_pool, sizeof(struct hvkvp_entry), 0, 0, 0,
	    "hvkvpl", NULL, IPL_SOFTNET);

	error = workqueue_create(&sc->sc_channel_wq, "hvkvpwq",
	    hvkvp_channel_work, sc, PRI_SOFTNET, IPL_SOFTNET,
	    WQ_MPSAFE /*| WQ_PERCPU*/);
	if (error) {
		aprint_error_dev(vsc->sc_dev, "workqueue_create failed: %u\n",
		    error);
		goto fail1;
	}

	error = vmbusic_attach(self, aa, hvkvp_channel_cb);
	if (error) {
		aprint_error_dev(vsc->sc_dev, "vmbusic_attach failed: %u\n",
		    error);
		goto fail2;
	}

	(void) pmf_device_register(self, NULL, NULL);

	SET(sc->sc_flags, HVKVP_FLAG_ATTACHED);
	return;

fail2:
	workqueue_destroy(sc->sc_channel_wq);
	sc->sc_channel_wq = NULL;
fail1:
	pool_destroy(&sc->sc_entry_pool);
	sc->sc_dying = 1;
}

static int
hvkvp_detach(device_t self, int flags)
{
	struct hvkvp_softc *sc = device_private(self);
	int error;

	if (!ISSET(sc->sc_flags, HVKVP_FLAG_ATTACHED))
		return 0;

	pmf_device_deregister(self);

	sc->sc_dying = 1;

	error = vmbusic_detach(self, flags);
	if (error)
		return error;

	if (sc->sc_channel_wq != NULL) {
		workqueue_destroy(sc->sc_channel_wq);
		sc->sc_channel_wq = NULL;
	}

	pool_destroy(&sc->sc_entry_pool);

	return 0;
}

static int
hvkvp_attach_once(void)
{
	const char *p, *q;

	/*
	 * OSBuildNumber
	 *
	 * version: "NetBSD <osrelease> (<kernel_ident>) #\d+: <build time>\n"
	 *          "\t<build host>:<kernel build path>\n"
	 */
	for (p = version; *p != '\0'; ) {
		while (*p == ' ')
			p++;

		if (*p == '#') {
			q = ++p;
			while (*q >= '0' && *q <= '9')
				q++;
			if (*q == ':' && q > p)
				break;

			p = q;
		}

		while (*p != ' ' && *p != '\0')
			p++;
	}
	if (*p != '\0') {
		ptrdiff_t len = q - p;
		if (len > sizeof(hvkvp_osbuildnumber) - 1)
			len = sizeof(hvkvp_osbuildnumber) - 1;
		memcpy(hvkvp_osbuildnumber, p, len);
		hvkvp_osbuildnumber[len] = '\0';
	} else {
		hvkvp_osbuildnumber[0] = '0';
		hvkvp_osbuildnumber[1] = '\0';
	}

	/* OSMajorVersion */
	snprintf(hvkvp_osmajor, sizeof(hvkvp_osmajor), "%d",
	    __NetBSD_Version__ / 100000000);

	/* OSMinorVersion */
	snprintf(hvkvp_osminor, sizeof(hvkvp_osminor), "%d",
	    (__NetBSD_Version__ % 100000000) / 1000000);

	return 0;
}

static int
nibble(int ch)
{

	if (ch >= '0' && ch <= '9')
		return ch - '0';
	if (ch >= 'A' && ch <= 'F')
		return 10 + ch - 'A';
	if (ch >= 'a' && ch <= 'f')
		return 10 + ch - 'a';
	return -1;
}

static int
hvkvp_get_ip_info(struct hvkvp_softc *sc, const uint16_t *mac, uint8_t *family,
    uint16_t *addr, uint16_t *netmask, size_t addrlen)
{
	struct ifnet *ifp;
	struct ifaddr *ifa, *ifa6, *ifa6ll;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6, sa6;
	uint8_t	enaddr[ETHER_ADDR_LEN];
	uint8_t ipaddr[INET6_ADDRSTRLEN];
	int i, j, lo, hi, s, af;
#if defined(INET) || defined(INET6)
	size_t len;
#endif

	/* Convert from the UTF-16LE string format to binary */
	for (i = 0, j = 0; j < ETHER_ADDR_LEN; i += 3) {
		if ((hi = nibble(le16toh(mac[i]))) == -1 ||
		    (lo = nibble(le16toh(mac[i+1]))) == -1)
			return EINVAL;
		enaddr[j++] = (hi << 4) | lo;
	}

	switch (*family) {
	case ADDR_FAMILY_NONE:
		af = AF_UNSPEC;
		break;
	case ADDR_FAMILY_IPV4:
		af = AF_INET;
		break;
	case ADDR_FAMILY_IPV6:
		af = AF_INET6;
		break;
	default:
		return -1;
	}

	/* FIXME check GUID? */
	/* chan->ch_inst: GUID? adapter_id? */

	s = pserialize_read_enter();
	IFNET_READER_FOREACH(ifp) {
		if (!memcmp(CLLADDR(ifp->if_sadl), enaddr, ETHER_ADDR_LEN))
			break;
	}
	if (ifp == NULL) {
		pserialize_read_exit(s);
		return -1;
	}

	ifa6 = ifa6ll = NULL;

	/* Try to find a best matching address, preferring IPv4 */
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
		/*
		 * First IPv4 address is always a best match unless
		 * we were asked for for an IPv6 address.
		 */
		if ((af == AF_INET || af == AF_UNSPEC) &&
		    (ifa->ifa_addr->sa_family == AF_INET)) {
			af = AF_INET;
			goto found;
		}
		if ((af == AF_INET6 || af == AF_UNSPEC) &&
		    (ifa->ifa_addr->sa_family == AF_INET6)) {
			if (!IN6_IS_ADDR_LINKLOCAL(
			    &satosin6(ifa->ifa_addr)->sin6_addr)) {
				/* Done if we're looking for an IPv6 address */
				if (af == AF_INET6)
					goto found;
				/* Stick to the first one */
				if (ifa6 == NULL)
					ifa6 = ifa;
			} else	/* Pick the last one */
				ifa6ll = ifa;
		}
	}
	/* If we haven't found any IPv4 or IPv6 direct matches... */
	if (ifa == NULL) {
		/* ... try the last global IPv6 address... */
		if (ifa6 != NULL)
			ifa = ifa6;
		/* ... or the last link-local...  */
		else if (ifa6ll != NULL)
			ifa = ifa6ll;
		else {
			pserialize_read_exit(s);
			return -1;
		}
	}
 found:
	switch (af) {
#ifdef INET
	case AF_INET:
		sin = satosin(ifa->ifa_addr);
		sin_print(ipaddr, sizeof(ipaddr), sin);
		len = utf8ucs2str(ipaddr, sizeof(ipaddr), addr, addrlen);
		if (len < addrlen)
			addr[len] = '\0';

		sin = satosin(ifa->ifa_netmask);
		sin_print(ipaddr, sizeof(ipaddr), sin);
		len = utf8ucs2str(ipaddr, sizeof(ipaddr), netmask, addrlen);
		if (len < addrlen)
			netmask[len] = '\0';

		*family = ADDR_FAMILY_IPV4;
		break;
#endif
	case AF_UNSPEC:
#ifdef INET6
	case AF_INET6:
		sin6 = satosin6(ifa->ifa_addr);
		if (IN6_IS_SCOPE_EMBEDDABLE(&sin6->sin6_addr)) {
			sa6 = *satosin6(ifa->ifa_addr);
			sa6.sin6_addr.s6_addr16[1] = 0;
			sin6 = &sa6;
		}
		sin6_print(ipaddr, sizeof(ipaddr), sin6);
		len = utf8ucs2str(ipaddr, sizeof(ipaddr), addr, addrlen);
		if (len < addrlen)
			addr[len] = '\0';

		sin6 = satosin6(ifa->ifa_netmask);
		sin6_print(ipaddr, sizeof(ipaddr), sin6);
		len = utf8ucs2str(ipaddr, sizeof(ipaddr), netmask, addrlen);
		if (len < addrlen)
			netmask[len] = '\0';

		*family = ADDR_FAMILY_IPV6;
		break;
#endif
	default:
		*family = ADDR_FAMILY_NONE;
		break;
	}

	pserialize_read_exit(s);

	return 0;
}

static void
hvkvp_process(struct hvkvp_softc *sc, struct vmbus_icmsg_kvp *msg)
{
	struct vmbusic_softc *vsc __unused /*XXX*/= &sc->sc_vmbusic;
	union vmbus_kvp_hdr *kvh = &msg->ic_kvh;
	union vmbus_kvp_msg *kvm __unused /*XXX*/ = &msg->ic_kvm;
	struct vmbus_icmsg_kvp_addr *amsg;
	struct vmbus_kvp_msg_addr *akvm;
	int error = 0;

	switch (kvh->kvh_op) {
	case HV_KVP_OP_GET:
		break;

	case HV_KVP_OP_SET:
		if (kvh->kvh_pool == HV_KVP_POOL_AUTO) {
			/* Auto Pool is not writeable from host side. */
			error = EINVAL;
		} else {
		}
		break;

	case HV_KVP_OP_DELETE:
		if (kvh->kvh_pool == HV_KVP_POOL_AUTO) {
			/* Auto Pool is not writeable from host side. */
			error = EINVAL;
		} else {
		}
		break;

	case HV_KVP_OP_ENUMERATE:
		break;

	case HV_KVP_OP_GET_IP_INFO:
		amsg = (struct vmbus_icmsg_kvp_addr *)msg;
		akvm = &amsg->ic_kvm;

		error = hvkvp_get_ip_info(sc, akvm->kvm_adapter_id,
		    &akvm->kvm_family, akvm->kvm_addr, akvm->kvm_netmask,
		    __arraycount(akvm->kvm_addr));
		break;

	case HV_KVP_OP_SET_IP_INFO:
		break;

	case HV_KVP_OP_COUNT:
	default:
		DPRINTF("%s: KVP message op %u pool %u\n",
		    device_xname(vsc->sc_dev), kvh->kvh_op, kvh->kvh_pool);
		error = EINVAL;
		break;
	}

	kvh->kvh_err = (error == 0) ? HV_S_OK : HV_S_CONT;
}

static void
hvkvp_channel_work(struct work *wk, void *arg)
{
	struct hvkvp_softc *sc = arg;
	struct vmbusic_softc *vsc = &sc->sc_vmbusic;
	struct vmbus_channel *ch = vsc->sc_chan;
	struct vmbus_icmsg_hdr *hdr;
	uint64_t rid;
	uint32_t rlen, fwver, msgver;
	int error;

	kmem_free(wk, sizeof(*wk));

	while (!sc->sc_dying) {
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
			if (rlen >= sizeof(struct vmbus_icmsg_kvp))
				hvkvp_process(sc, (struct vmbus_icmsg_kvp *)hdr);
			else
				device_printf(vsc->sc_dev,
				    "message too short: %u\n", hdr->ic_dsize);
			break;

		default:
			device_printf(vsc->sc_dev,
			    "unhandled KVP message type %u\n", hdr->ic_type);
			continue;
		}

		(void) vmbusic_sendresp(vsc, ch, vsc->sc_buf, rlen, rid);
	}
}

static void
hvkvp_channel_cb(void *arg)
{
	struct hvkvp_softc *sc = arg;
	struct work *wk;

	if (sc->sc_dying)
		return;

	wk = kmem_intr_alloc(sizeof(*wk), KM_NOSLEEP);
	workqueue_enqueue(sc->sc_channel_wq, wk, NULL);
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
static size_t
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
