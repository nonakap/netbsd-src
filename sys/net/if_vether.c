/*	$NetBSD: if_vether.c,v 1.4 2024/09/26 09:59:55 roy Exp $	*/
/* $OpenBSD: if_vether.c,v 1.27 2016/04/13 11:41:15 mpi Exp $ */

/*
 * Copyright (c) 2009 Theo de Raadt
 * Copyright (c) 2020 Roy Marples
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: if_vether.c,v 1.4 2024/09/26 09:59:55 roy Exp $");

#include <sys/cprng.h>
#include <sys/kmem.h>
#include <sys/mbuf.h>

#include <net/if.h>
#include <net/if_ether.h>
#include <net/if_media.h>
#include <net/bpf.h>

void		vetherattach(int);
static int	vether_ioctl(struct ifnet *, u_long, void *);
static int	vether_mediachange(struct ifnet *);
static void	vether_mediastatus(struct ifnet *, struct ifmediareq *);
static void	vether_start(struct ifnet *);
static int	vether_clone_create(struct if_clone *, int);
static int	vether_clone_destroy(struct ifnet *);

static void	vether_stop(struct ifnet *, int);
static int	vether_init(struct ifnet *);

struct vether_softc {
	struct ethercom		sc_ec;
	struct ifmedia		sc_im;
};

struct if_clone	vether_cloner =
    IF_CLONE_INITIALIZER("vether", vether_clone_create, vether_clone_destroy);

void
vetherattach(int nvether)
{

	if_clone_attach(&vether_cloner);
}

static int
vether_clone_create(struct if_clone *ifc, int unit)
{
	struct ifnet *ifp;
	struct vether_softc *sc;
	uint8_t enaddr[ETHER_ADDR_LEN] =
	    { 0xf2, 0x0b, 0xa4, 0xff, 0xff, 0xff };

	sc = kmem_zalloc(sizeof(*sc), KM_SLEEP);

	sc->sc_ec.ec_ifmedia = &sc->sc_im;
	ifmedia_init(&sc->sc_im, 0, vether_mediachange, vether_mediastatus);
	ifmedia_add(&sc->sc_im, IFM_ETHER|IFM_AUTO, 0, NULL);
	ifmedia_add(&sc->sc_im, IFM_ETHER|IFM_NONE, 0, NULL);
	ifmedia_set(&sc->sc_im, IFM_ETHER|IFM_AUTO);

	ifp = &sc->sc_ec.ec_if;
	if_initname(ifp, ifc->ifc_name, unit);
	ifp->if_softc = sc;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
#ifdef NET_MPSAFE
	ifp->if_extflags = IFEF_MPSAFE;
#endif
	ifp->if_ioctl = vether_ioctl;
	ifp->if_start = vether_start;
	ifp->if_stop  = vether_stop;
	ifp->if_init  = vether_init;
	IFQ_SET_MAXLEN(&ifp->if_snd, IFQ_MAXLEN);
	IFQ_SET_READY(&ifp->if_snd);

	sc->sc_ec.ec_capabilities = ETHERCAP_VLAN_MTU | ETHERCAP_JUMBO_MTU;

	/*
	 * In order to obtain unique initial Ethernet address on a host,
	 * do some randomisation.  It's not meant for anything but avoiding
	 * hard-coding an address.
	 */
	cprng_fast(&enaddr[3], 3);

	/* Those steps are mandatory for an Ethernet driver. */
	if_initialize(ifp);
	ether_ifattach(ifp, enaddr);
	if_register(ifp);

	/* Notify our link state */
	vether_mediachange(ifp);

	return 0;
}

static int
vether_clone_destroy(struct ifnet *ifp)
{
	struct vether_softc *sc = ifp->if_softc;

	ether_ifdetach(ifp);
	if_detach(ifp);
	kmem_free(sc, sizeof(*sc));
	return 0;
}

static int
vether_init(struct ifnet *ifp)
{

	ifp->if_flags |= IFF_RUNNING;
	vether_start(ifp);
	return 0;
}

static int
vether_mediachange(struct ifnet *ifp)
{
	struct vether_softc *sc = ifp->if_softc;
	int link_state;

	if (IFM_SUBTYPE(sc->sc_im.ifm_cur->ifm_media) == IFM_NONE)
		link_state = LINK_STATE_DOWN;
	else
		link_state = LINK_STATE_UP;

	if_link_state_change(ifp, link_state);
	return 0;
}

static void
vether_mediastatus(struct ifnet *ifp, struct ifmediareq *imr)
{
	struct vether_softc *sc = ifp->if_softc;

	imr->ifm_active = sc->sc_im.ifm_cur->ifm_media;

	imr->ifm_status = IFM_AVALID;
	if (IFM_SUBTYPE(imr->ifm_active) != IFM_NONE)
		imr->ifm_status |= IFM_ACTIVE;
}

/*
 * The bridge has magically already done all the work for us,
 * and we only need to discard the packets.
 */
static void
vether_start(struct ifnet *ifp)
{
	struct mbuf *m;

	for (;;) {
		IFQ_DEQUEUE(&ifp->if_snd, m);
		if (m == NULL)
			break;
		bpf_mtap(ifp, m, BPF_D_OUT);
		m_freem(m);
		if_statinc(ifp, if_opackets);
	}
}

static void
vether_stop(struct ifnet *ifp, __unused int disable)
{

	ifp->if_flags &= ~IFF_RUNNING;
}

static int
vether_ioctl(struct ifnet *ifp, unsigned long cmd, void *data)
{
	int error = 0;

	switch (cmd) {
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		break;

	default:
		error = ether_ioctl(ifp, cmd, data);
	}
	return error;
}
