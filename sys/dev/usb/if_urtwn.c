/*	$NetBSD: if_urtwn.c,v 1.112 2025/07/29 18:58:40 hgutch Exp $	*/
/*	$OpenBSD: if_urtwn.c,v 1.42 2015/02/10 23:25:46 mpi Exp $	*/

/*-
 * Copyright (c) 2010 Damien Bergamini <damien.bergamini@free.fr>
 * Copyright (c) 2014 Kevin Lo <kevlo@FreeBSD.org>
 * Copyright (c) 2016 Nathanial Sloss <nathanialsloss@yahoo.com.au>
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

/*-
 * Driver for Realtek RTL8188CE-VAU/RTL8188CUS/RTL8188EU/RTL8188RU/RTL8192CU
 * RTL8192EU.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: if_urtwn.c,v 1.112 2025/07/29 18:58:40 hgutch Exp $");

#ifdef _KERNEL_OPT
#include "opt_inet.h"
#include "opt_usb.h"
#endif

#include <sys/param.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/conf.h>
#include <sys/device.h>
#include <sys/rndsource.h>

#include <sys/bus.h>
#include <machine/endian.h>
#include <sys/intr.h>

#include <net/bpf.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_ether.h>
#include <net/if_media.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/if_inarp.h>

#include <net80211/ieee80211_netbsd.h>
#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_radiotap.h>

#include <dev/firmload.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdivar.h>
#include <dev/usb/usbdi_util.h>
#include <dev/usb/usbdevs.h>
#include <dev/usb/usbhist.h>

#include <dev/ic/rtwnreg.h>
#include <dev/ic/rtwn_data.h>
#include <dev/usb/if_urtwnreg.h>
#include <dev/usb/if_urtwnvar.h>

/*
 * The sc_write_mtx locking is to prevent sequences of writes from
 * being intermingled with each other.  I don't know if this is really
 * needed.  I have added it just to be on the safe side.
 */

#ifdef URTWN_DEBUG
#define	DBG_INIT	__BIT(0)
#define	DBG_FN		__BIT(1)
#define	DBG_TX		__BIT(2)
#define	DBG_RX		__BIT(3)
#define	DBG_STM		__BIT(4)
#define	DBG_RF		__BIT(5)
#define	DBG_REG		__BIT(6)
#define	DBG_ALL		0xffffffffU

#ifndef URTWN_DEBUG_DEFAULT
#define URTWN_DEBUG_DEFAULT 0
#endif

u_int urtwn_debug = URTWN_DEBUG_DEFAULT;

#define DPRINTFN(n, fmt, a, b, c, d) do {			\
	if (urtwn_debug & (n)) {				\
		KERNHIST_LOG(usbhist, fmt, a, b, c, d);		\
	}							\
} while (/*CONSTCOND*/0)
#define URTWNHIST_FUNC() USBHIST_FUNC()
#define URTWNHIST_CALLED() do {					\
	if (urtwn_debug & DBG_FN) {				\
		KERNHIST_CALLED(usbhist);			\
	}							\
} while(/*CONSTCOND*/0)
#define URTWNHIST_CALLARGS(fmt, a, b, c, d) do {		\
	if (urtwn_debug & DBG_FN) {				\
		KERNHIST_CALLARGS(usbhist, fmt, a, b, c, d);	\
	}							\
} while(/*CONSTCOND*/0)
#else
#define DPRINTFN(n, fmt, a, b, c, d)
#define URTWNHIST_FUNC()
#define URTWNHIST_CALLED()
#define URTWNHIST_CALLARGS(fmt, a, b, c, d)
#endif

#define URTWN_DEV(v,p)	{ { USB_VENDOR_##v, USB_PRODUCT_##v##_##p }, 0 }
#define URTWN_RTL8188E_DEV(v,p) \
	{ { USB_VENDOR_##v, USB_PRODUCT_##v##_##p }, FLAG_RTL8188E }
#define URTWN_RTL8192EU_DEV(v,p) \
	{ { USB_VENDOR_##v, USB_PRODUCT_##v##_##p }, FLAG_RTL8192E }
static const struct urtwn_dev {
	struct usb_devno	dev;
	uint32_t		flags;
#define	FLAG_RTL8188E	__BIT(0)
#define	FLAG_RTL8192E	__BIT(1)
} urtwn_devs[] = {
	URTWN_DEV(ABOCOM,	RTL8188CU_1),
	URTWN_DEV(ABOCOM,	RTL8188CU_2),
	URTWN_DEV(ABOCOM,	RTL8192CU),
	URTWN_DEV(ASUSTEK,	RTL8192CU),
	URTWN_DEV(ASUSTEK,	RTL8192CU_3),
	URTWN_DEV(ASUSTEK,	USBN10NANO),
	URTWN_DEV(AZUREWAVE,	RTL8188CE_1),
	URTWN_DEV(AZUREWAVE,	RTL8188CE_2),
	URTWN_DEV(AZUREWAVE,	RTL8188CU),
	URTWN_DEV(BELKIN,	F7D2102),
	URTWN_DEV(BELKIN,	RTL8188CU),
	URTWN_DEV(BELKIN,	RTL8188CUS),
	URTWN_DEV(BELKIN,	RTL8192CU),
	URTWN_DEV(BELKIN,	RTL8192CU_1),
	URTWN_DEV(BELKIN,	RTL8192CU_2),
	URTWN_DEV(CHICONY,	RTL8188CUS_1),
	URTWN_DEV(CHICONY,	RTL8188CUS_2),
	URTWN_DEV(CHICONY,	RTL8188CUS_3),
	URTWN_DEV(CHICONY,	RTL8188CUS_4),
	URTWN_DEV(CHICONY,	RTL8188CUS_5),
	URTWN_DEV(CHICONY,	RTL8188CUS_6),
	URTWN_DEV(COMPARE,	RTL8192CU),
	URTWN_DEV(COREGA,	RTL8192CU),
	URTWN_DEV(DLINK,	DWA131B),
	URTWN_DEV(DLINK,	RTL8188CU),
	URTWN_DEV(DLINK,	RTL8192CU_1),
	URTWN_DEV(DLINK,	RTL8192CU_2),
	URTWN_DEV(DLINK,	RTL8192CU_3),
	URTWN_DEV(DLINK,	RTL8192CU_4),
	URTWN_DEV(EDIMAX,	RTL8188CU),
	URTWN_DEV(EDIMAX,	RTL8192CU),
	URTWN_DEV(FEIXUN,	RTL8188CU),
	URTWN_DEV(FEIXUN,	RTL8192CU),
	URTWN_DEV(GUILLEMOT,	HWNUP150),
	URTWN_DEV(GUILLEMOT,	RTL8192CU),
	URTWN_DEV(HAWKING,	RTL8192CU),
	URTWN_DEV(HAWKING,	RTL8192CU_2),
	URTWN_DEV(HP3,		RTL8188CU),
	URTWN_DEV(IODATA,	WNG150UM),
	URTWN_DEV(IODATA,	RTL8192CU),
	URTWN_DEV(NETGEAR,	WNA1000M),
	URTWN_DEV(NETGEAR,	RTL8192CU),
	URTWN_DEV(NETGEAR4,	RTL8188CU),
	URTWN_DEV(NOVATECH,	RTL8188CU),
	URTWN_DEV(PLANEX2,	RTL8188CU_1),
	URTWN_DEV(PLANEX2,	RTL8188CU_2),
	URTWN_DEV(PLANEX2,	RTL8192CU),
	URTWN_DEV(PLANEX2,	RTL8188CU_3),
	URTWN_DEV(PLANEX2,	RTL8188CU_4),
	URTWN_DEV(PLANEX2,	RTL8188CUS),
	URTWN_DEV(REALTEK,	RTL8188CE_0),
	URTWN_DEV(REALTEK,	RTL8188CE_1),
	URTWN_DEV(REALTEK,	RTL8188CTV),
	URTWN_DEV(REALTEK,	RTL8188CU_0),
	URTWN_DEV(REALTEK,	RTL8188CU_1),
	URTWN_DEV(REALTEK,	RTL8188CU_2),
	URTWN_DEV(REALTEK,	RTL8188CU_3),
	URTWN_DEV(REALTEK,	RTL8188CU_COMBO),
	URTWN_DEV(REALTEK,	RTL8188CUS),
	URTWN_DEV(REALTEK,	RTL8188RU),
	URTWN_DEV(REALTEK,	RTL8188RU_2),
	URTWN_DEV(REALTEK,	RTL8188RU_3),
	URTWN_DEV(REALTEK,	RTL8191CU),
	URTWN_DEV(REALTEK,	RTL8192CE),
	URTWN_DEV(REALTEK,	RTL8192CU),
	URTWN_DEV(SITECOMEU,	RTL8188CU),
	URTWN_DEV(SITECOMEU,	RTL8188CU_2),
	URTWN_DEV(SITECOMEU,	RTL8192CU),
	URTWN_DEV(SITECOMEU,	RTL8192CUR2),
	URTWN_DEV(TPLINK,	RTL8192CU),
	URTWN_DEV(TRENDNET,	RTL8188CU),
	URTWN_DEV(TRENDNET,	RTL8192CU),
	URTWN_DEV(TRENDNET,	TEW648UBM),
	URTWN_DEV(ZYXEL,	RTL8192CU),

	/* URTWN_RTL8188E */
	URTWN_RTL8188E_DEV(ASUSTEK, USBN10NANO_B1),
	URTWN_RTL8188E_DEV(DLINK, DWA125D1),
	URTWN_RTL8188E_DEV(ELECOM, WDC150SU2M),
	URTWN_RTL8188E_DEV(MERCUSYS, MW150USV2),
	URTWN_RTL8188E_DEV(REALTEK, RTL8188ETV),
	URTWN_RTL8188E_DEV(REALTEK, RTL8188EU),
	URTWN_RTL8188E_DEV(ABOCOM, RTL8188EU),
	URTWN_RTL8188E_DEV(TPLINK, RTL8188EU),
	URTWN_RTL8188E_DEV(DLINK, DWA121B1),
	URTWN_RTL8188E_DEV(EDIMAX, EW7811UNV2),

	/* URTWN_RTL8192EU */
	URTWN_RTL8192EU_DEV(DLINK,	DWA131E),
	URTWN_RTL8192EU_DEV(REALTEK,	RTL8192EU),
	URTWN_RTL8192EU_DEV(TPLINK,	WN821NV5),
	URTWN_RTL8192EU_DEV(TPLINK,	WN822NV4),
	URTWN_RTL8192EU_DEV(TPLINK,	WN823NV2),
};
#undef URTWN_DEV
#undef URTWN_RTL8188E_DEV
#undef URTWN_RTL8192EU_DEV

static int	urtwn_match(device_t, cfdata_t, void *);
static void	urtwn_attach(device_t, device_t, void *);
static int	urtwn_detach(device_t, int);
static int	urtwn_activate(device_t, enum devact);

CFATTACH_DECL_NEW(urtwn, sizeof(struct urtwn_softc), urtwn_match,
    urtwn_attach, urtwn_detach, urtwn_activate);

static int	urtwn_open_pipes(struct urtwn_softc *);
static void	urtwn_close_pipes(struct urtwn_softc *);
static int	urtwn_alloc_rx_list(struct urtwn_softc *);
static void	urtwn_free_rx_list(struct urtwn_softc *);
static int	urtwn_alloc_tx_list(struct urtwn_softc *);
static void	urtwn_free_tx_list(struct urtwn_softc *);
static void	urtwn_task(void *);
static void	urtwn_do_async(struct urtwn_softc *,
		    void (*)(struct urtwn_softc *, void *), void *, int);
static void	urtwn_wait_async(struct urtwn_softc *);
static int	urtwn_write_region_1(struct urtwn_softc *, uint16_t, uint8_t *,
		    int);
static void	urtwn_write_1(struct urtwn_softc *, uint16_t, uint8_t);
static void	urtwn_write_2(struct urtwn_softc *, uint16_t, uint16_t);
static void	urtwn_write_4(struct urtwn_softc *, uint16_t, uint32_t);
static int	urtwn_write_region(struct urtwn_softc *, uint16_t, uint8_t *,
		    int);
static int	urtwn_read_region_1(struct urtwn_softc *, uint16_t, uint8_t *,
		    int);
static uint8_t	urtwn_read_1(struct urtwn_softc *, uint16_t);
static uint16_t	urtwn_read_2(struct urtwn_softc *, uint16_t);
static uint32_t	urtwn_read_4(struct urtwn_softc *, uint16_t);
static int	urtwn_fw_cmd(struct urtwn_softc *, uint8_t, const void *, int);
static void	urtwn_r92c_rf_write(struct urtwn_softc *, int, uint8_t,
		    uint32_t);
static void	urtwn_r88e_rf_write(struct urtwn_softc *, int, uint8_t,
		    uint32_t);
static void	urtwn_r92e_rf_write(struct urtwn_softc *, int, uint8_t,
		    uint32_t);
static uint32_t	urtwn_rf_read(struct urtwn_softc *, int, uint8_t);
static int	urtwn_llt_write(struct urtwn_softc *, uint32_t, uint32_t);
static uint8_t	urtwn_efuse_read_1(struct urtwn_softc *, uint16_t);
static void	urtwn_efuse_read(struct urtwn_softc *);
static void	urtwn_efuse_switch_power(struct urtwn_softc *);
static int	urtwn_read_chipid(struct urtwn_softc *);
#ifdef URTWN_DEBUG
static void	urtwn_dump_rom(struct urtwn_softc *, struct r92c_rom *);
#endif
static void	urtwn_read_rom(struct urtwn_softc *);
static void	urtwn_r88e_read_rom(struct urtwn_softc *);
static int	urtwn_media_change(struct ifnet *);
static int	urtwn_ra_init(struct urtwn_softc *);
static int	urtwn_get_nettype(struct urtwn_softc *);
static void	urtwn_set_nettype0_msr(struct urtwn_softc *, uint8_t);
static void	urtwn_tsf_sync_enable(struct urtwn_softc *);
static void	urtwn_set_led(struct urtwn_softc *, int, int);
static void	urtwn_calib_to(void *);
static void	urtwn_calib_to_cb(struct urtwn_softc *, void *);
static void	urtwn_next_scan(void *);
static int	urtwn_newstate(struct ieee80211com *, enum ieee80211_state,
		    int);
static void	urtwn_newstate_cb(struct urtwn_softc *, void *);
static int	urtwn_wme_update(struct ieee80211com *);
static void	urtwn_wme_update_cb(struct urtwn_softc *, void *);
static void	urtwn_update_avgrssi(struct urtwn_softc *, int, int8_t);
static int8_t	urtwn_get_rssi(struct urtwn_softc *, int, void *);
static int8_t	urtwn_r88e_get_rssi(struct urtwn_softc *, int, void *);
static void	urtwn_rx_frame(struct urtwn_softc *, uint8_t *, int);
static void	urtwn_rxeof(struct usbd_xfer *, void *, usbd_status);
static void	urtwn_txeof(struct usbd_xfer *, void *, usbd_status);
static int	urtwn_tx(struct urtwn_softc *, struct mbuf *,
		    struct ieee80211_node *, struct urtwn_tx_data *);
static struct urtwn_tx_data *
		urtwn_get_tx_data(struct urtwn_softc *, size_t);
static void	urtwn_start(struct ifnet *);
static void	urtwn_watchdog(struct ifnet *);
static int	urtwn_ioctl(struct ifnet *, u_long, void *);
static int	urtwn_r92c_power_on(struct urtwn_softc *);
static int	urtwn_r92e_power_on(struct urtwn_softc *);
static int	urtwn_r88e_power_on(struct urtwn_softc *);
static int	urtwn_llt_init(struct urtwn_softc *);
static void	urtwn_fw_reset(struct urtwn_softc *);
static void	urtwn_r88e_fw_reset(struct urtwn_softc *);
static int	urtwn_fw_loadpage(struct urtwn_softc *, int, uint8_t *, int);
static int	urtwn_load_firmware(struct urtwn_softc *);
static int	urtwn_r92c_dma_init(struct urtwn_softc *);
static int	urtwn_r88e_dma_init(struct urtwn_softc *);
static void	urtwn_mac_init(struct urtwn_softc *);
static void	urtwn_bb_init(struct urtwn_softc *);
static void	urtwn_rf_init(struct urtwn_softc *);
static void	urtwn_cam_init(struct urtwn_softc *);
static void	urtwn_pa_bias_init(struct urtwn_softc *);
static void	urtwn_rxfilter_init(struct urtwn_softc *);
static void	urtwn_edca_init(struct urtwn_softc *);
static void	urtwn_write_txpower(struct urtwn_softc *, int,
		    uint16_t[URTWN_RIDX_COUNT]);
static void	urtwn_get_txpower(struct urtwn_softc *, size_t, u_int, u_int,
		    uint16_t[URTWN_RIDX_COUNT]);
static void	urtwn_r88e_get_txpower(struct urtwn_softc *, size_t, u_int,
		    u_int, uint16_t[URTWN_RIDX_COUNT]);
static void	urtwn_set_txpower(struct urtwn_softc *, u_int, u_int);
static void	urtwn_set_chan(struct urtwn_softc *, struct ieee80211_channel *,
		    u_int);
static void	urtwn_iq_calib(struct urtwn_softc *, bool);
static void	urtwn_lc_calib(struct urtwn_softc *);
static void	urtwn_temp_calib(struct urtwn_softc *);
static int	urtwn_init(struct ifnet *);
static void	urtwn_stop(struct ifnet *, int);
static int	urtwn_reset(struct ifnet *);
static void	urtwn_chip_stop(struct urtwn_softc *);
static void	urtwn_newassoc(struct ieee80211_node *, int);
static void	urtwn_delay_ms(struct urtwn_softc *, int ms);

/* Aliases. */
#define	urtwn_bb_write	urtwn_write_4
#define	urtwn_bb_read	urtwn_read_4

#define	urtwn_lookup(d,v,p)	((const struct urtwn_dev *)usb_lookup(d,v,p))

static const uint16_t addaReg[] = {
	R92C_FPGA0_XCD_SWITCHCTL, R92C_BLUETOOTH, R92C_RX_WAIT_CCA,
	R92C_TX_CCK_RFON, R92C_TX_CCK_BBON, R92C_TX_OFDM_RFON,
	R92C_TX_OFDM_BBON, R92C_TX_TO_RX, R92C_TX_TO_TX, R92C_RX_CCK,
	R92C_RX_OFDM, R92C_RX_WAIT_RIFS, R92C_RX_TO_RX,
	R92C_STANDBY, R92C_SLEEP, R92C_PMPD_ANAEN
};

static int
urtwn_match(device_t parent, cfdata_t match, void *aux)
{
	struct usb_attach_arg *uaa = aux;

	return urtwn_lookup(urtwn_devs, uaa->uaa_vendor, uaa->uaa_product) !=
	    NULL ?  UMATCH_VENDOR_PRODUCT : UMATCH_NONE;
}

static void
urtwn_attach(device_t parent, device_t self, void *aux)
{
	struct urtwn_softc *sc = device_private(self);
	struct ieee80211com *ic = &sc->sc_ic;
	struct ifnet *ifp = &sc->sc_if;
	struct usb_attach_arg *uaa = aux;
	char *devinfop;
	const struct urtwn_dev *dev;
	usb_device_request_t req;
	size_t i;
	int error;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	sc->sc_dev = self;
	sc->sc_udev = uaa->uaa_device;

	sc->chip = 0;
	dev = urtwn_lookup(urtwn_devs, uaa->uaa_vendor, uaa->uaa_product);
	if (dev != NULL && ISSET(dev->flags, FLAG_RTL8188E))
		SET(sc->chip, URTWN_CHIP_88E);
	if (dev != NULL && ISSET(dev->flags, FLAG_RTL8192E))
		SET(sc->chip, URTWN_CHIP_92EU);

	aprint_naive("\n");
	aprint_normal("\n");

	devinfop = usbd_devinfo_alloc(sc->sc_udev, 0);
	aprint_normal_dev(self, "%s\n", devinfop);
	usbd_devinfo_free(devinfop);

	req.bmRequestType = UT_WRITE_DEVICE;
	req.bRequest = UR_SET_FEATURE;
	USETW(req.wValue, UF_DEVICE_REMOTE_WAKEUP);
	USETW(req.wIndex, UHF_PORT_SUSPEND);
	USETW(req.wLength, 0);

	(void) usbd_do_request(sc->sc_udev, &req, 0);

	cv_init(&sc->sc_task_cv, "urtwntsk");
	mutex_init(&sc->sc_task_mtx, MUTEX_DEFAULT, IPL_NET);
	mutex_init(&sc->sc_tx_mtx, MUTEX_DEFAULT, IPL_NONE);
	mutex_init(&sc->sc_rx_mtx, MUTEX_DEFAULT, IPL_NONE);
	mutex_init(&sc->sc_fwcmd_mtx, MUTEX_DEFAULT, IPL_NONE);
	mutex_init(&sc->sc_write_mtx, MUTEX_DEFAULT, IPL_NONE);

	usb_init_task(&sc->sc_task, urtwn_task, sc, 0);

	callout_init(&sc->sc_scan_to, 0);
	callout_setfunc(&sc->sc_scan_to, urtwn_next_scan, sc);
	callout_init(&sc->sc_calib_to, 0);
	callout_setfunc(&sc->sc_calib_to, urtwn_calib_to, sc);

	rnd_attach_source(&sc->rnd_source, device_xname(sc->sc_dev),
	    RND_TYPE_NET, RND_FLAG_DEFAULT);

	error = usbd_set_config_no(sc->sc_udev, 1, 0);
	if (error != 0) {
		aprint_error_dev(self, "failed to set configuration"
		    ", err=%s\n", usbd_errstr(error));
		goto fail;
	}

	/* Get the first interface handle. */
	error = usbd_device2interface_handle(sc->sc_udev, 0, &sc->sc_iface);
	if (error != 0) {
		aprint_error_dev(self, "could not get interface handle\n");
		goto fail;
	}

	error = urtwn_read_chipid(sc);
	if (error != 0) {
		aprint_error_dev(self, "unsupported test chip\n");
		goto fail;
	}

	/* Determine number of Tx/Rx chains. */
	if (sc->chip & URTWN_CHIP_92C) {
		sc->ntxchains = (sc->chip & URTWN_CHIP_92C_1T2R) ? 1 : 2;
		sc->nrxchains = 2;
	} else if (sc->chip & URTWN_CHIP_92EU) {
		sc->ntxchains = 2;
		sc->nrxchains = 2;
	} else {
		sc->ntxchains = 1;
		sc->nrxchains = 1;
	}

	if (ISSET(sc->chip, URTWN_CHIP_88E) ||
	    ISSET(sc->chip, URTWN_CHIP_92EU))
		urtwn_r88e_read_rom(sc);
	else
		urtwn_read_rom(sc);

	aprint_normal_dev(self, "MAC/BB RTL%s, RF 6052 %zdT%zdR, address %s\n",
	    (sc->chip & URTWN_CHIP_92EU) ? "8192EU" :
	    (sc->chip & URTWN_CHIP_92C) ? "8192CU" :
	    (sc->chip & URTWN_CHIP_88E) ? "8188EU" :
	    (sc->board_type == R92C_BOARD_TYPE_HIGHPA) ? "8188RU" :
	    (sc->board_type == R92C_BOARD_TYPE_MINICARD) ? "8188CE-VAU" :
	    "8188CUS", sc->ntxchains, sc->nrxchains,
	    ether_sprintf(ic->ic_myaddr));

	error = urtwn_open_pipes(sc);
	if (error != 0) {
		aprint_error_dev(sc->sc_dev, "could not open pipes\n");
		goto fail;
	}
	aprint_normal_dev(self, "%d rx pipe%s, %d tx pipe%s\n",
	    sc->rx_npipe, sc->rx_npipe > 1 ? "s" : "",
	    sc->tx_npipe, sc->tx_npipe > 1 ? "s" : "");

	/*
	 * Setup the 802.11 device.
	 */
	ic->ic_ifp = ifp;
	ic->ic_phytype = IEEE80211_T_OFDM;	/* Not only, but not used. */
	ic->ic_opmode = IEEE80211_M_STA;	/* Default to BSS mode. */
	ic->ic_state = IEEE80211_S_INIT;

	/* Set device capabilities. */
	ic->ic_caps =
	    IEEE80211_C_MONITOR |	/* Monitor mode supported. */
	    IEEE80211_C_IBSS |		/* IBSS mode supported */
	    IEEE80211_C_HOSTAP |	/* HostAp mode supported */
	    IEEE80211_C_SHPREAMBLE |	/* Short preamble supported. */
	    IEEE80211_C_SHSLOT |	/* Short slot time supported. */
	    IEEE80211_C_WME |		/* 802.11e */
	    IEEE80211_C_WPA;		/* 802.11i */

	/* Set supported .11b and .11g rates. */
	ic->ic_sup_rates[IEEE80211_MODE_11B] = ieee80211_std_rateset_11b;
	ic->ic_sup_rates[IEEE80211_MODE_11G] = ieee80211_std_rateset_11g;

	/* Set supported .11b and .11g channels (1 through 14). */
	for (i = 1; i <= 14; i++) {
		ic->ic_channels[i].ic_freq =
		    ieee80211_ieee2mhz(i, IEEE80211_CHAN_2GHZ);
		ic->ic_channels[i].ic_flags =
		    IEEE80211_CHAN_CCK | IEEE80211_CHAN_OFDM |
		    IEEE80211_CHAN_DYN | IEEE80211_CHAN_2GHZ;
	}

	ifp->if_softc = sc;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_init = urtwn_init;
	ifp->if_ioctl = urtwn_ioctl;
	ifp->if_start = urtwn_start;
	ifp->if_watchdog = urtwn_watchdog;
	IFQ_SET_READY(&ifp->if_snd);
	memcpy(ifp->if_xname, device_xname(sc->sc_dev), IFNAMSIZ);

	if_initialize(ifp);
	ieee80211_ifattach(ic);

	/* override default methods */
	ic->ic_newassoc = urtwn_newassoc;
	ic->ic_reset = urtwn_reset;
	ic->ic_wme.wme_update = urtwn_wme_update;

	/* Override state transition machine. */
	sc->sc_newstate = ic->ic_newstate;
	ic->ic_newstate = urtwn_newstate;

	/* XXX media locking needs revisiting */
	mutex_init(&sc->sc_media_mtx, MUTEX_DEFAULT, IPL_SOFTUSB);
	ieee80211_media_init_with_lock(ic,
	    urtwn_media_change, ieee80211_media_status, &sc->sc_media_mtx);

	bpf_attach2(ifp, DLT_IEEE802_11_RADIO,
	    sizeof(struct ieee80211_frame) + IEEE80211_RADIOTAP_HDRLEN,
	    &sc->sc_drvbpf);

	sc->sc_rxtap_len = sizeof(sc->sc_rxtapu);
	sc->sc_rxtap.wr_ihdr.it_len = htole16(sc->sc_rxtap_len);
	sc->sc_rxtap.wr_ihdr.it_present = htole32(URTWN_RX_RADIOTAP_PRESENT);

	sc->sc_txtap_len = sizeof(sc->sc_txtapu);
	sc->sc_txtap.wt_ihdr.it_len = htole16(sc->sc_txtap_len);
	sc->sc_txtap.wt_ihdr.it_present = htole32(URTWN_TX_RADIOTAP_PRESENT);

	ifp->if_percpuq = if_percpuq_create(ifp);
	if_register(ifp);

	ieee80211_announce(ic);

	usbd_add_drv_event(USB_EVENT_DRIVER_ATTACH, sc->sc_udev, sc->sc_dev);

	if (!pmf_device_register(self, NULL, NULL))
		aprint_error_dev(self, "couldn't establish power handler\n");

	SET(sc->sc_flags, URTWN_FLAG_ATTACHED);
	return;

 fail:
	sc->sc_dying = 1;
	aprint_error_dev(self, "attach failed\n");
}

static int
urtwn_detach(device_t self, int flags)
{
	struct urtwn_softc *sc = device_private(self);
	struct ifnet *ifp = &sc->sc_if;
	int s;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	pmf_device_deregister(self);

	s = splusb();

	sc->sc_dying = 1;

	callout_halt(&sc->sc_scan_to, NULL);
	callout_halt(&sc->sc_calib_to, NULL);

	if (ISSET(sc->sc_flags, URTWN_FLAG_ATTACHED)) {
		urtwn_stop(ifp, 0);
		usb_rem_task_wait(sc->sc_udev, &sc->sc_task, USB_TASKQ_DRIVER,
		    NULL);

		ifp->if_flags &= ~(IFF_RUNNING | IFF_OACTIVE);
		bpf_detach(ifp);
		ieee80211_ifdetach(&sc->sc_ic);
		if_detach(ifp);

		mutex_destroy(&sc->sc_media_mtx);

		/* Close Tx/Rx pipes.  Abort done by urtwn_stop. */
		urtwn_close_pipes(sc);
	}

	splx(s);

	usbd_add_drv_event(USB_EVENT_DRIVER_DETACH, sc->sc_udev, sc->sc_dev);

	rnd_detach_source(&sc->rnd_source);

	callout_destroy(&sc->sc_scan_to);
	callout_destroy(&sc->sc_calib_to);

	cv_destroy(&sc->sc_task_cv);
	mutex_destroy(&sc->sc_write_mtx);
	mutex_destroy(&sc->sc_fwcmd_mtx);
	mutex_destroy(&sc->sc_tx_mtx);
	mutex_destroy(&sc->sc_rx_mtx);
	mutex_destroy(&sc->sc_task_mtx);

	return 0;
}

static int
urtwn_activate(device_t self, enum devact act)
{
	struct urtwn_softc *sc = device_private(self);

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	switch (act) {
	case DVACT_DEACTIVATE:
		if_deactivate(sc->sc_ic.ic_ifp);
		return 0;
	default:
		return EOPNOTSUPP;
	}
}

static int
urtwn_open_pipes(struct urtwn_softc *sc)
{
	/* Bulk-out endpoints addresses (from highest to lowest prio). */
	static uint8_t epaddr[R92C_MAX_EPOUT];
	static uint8_t rxepaddr[R92C_MAX_EPIN];
	usb_interface_descriptor_t *id;
	usb_endpoint_descriptor_t *ed;
	size_t i, ntx = 0, nrx = 0;
	int error;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	/* Determine the number of bulk-out pipes. */
	id = usbd_get_interface_descriptor(sc->sc_iface);
	for (i = 0; i < id->bNumEndpoints; i++) {
		ed = usbd_interface2endpoint_descriptor(sc->sc_iface, i);
		if (ed == NULL || UE_GET_XFERTYPE(ed->bmAttributes) != UE_BULK) {
			continue;
		}
		if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_OUT) {
			if (ntx < sizeof(epaddr))
				epaddr[ntx] = ed->bEndpointAddress;
			ntx++;
		}
		if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_IN) {
			if (nrx < sizeof(rxepaddr))
				rxepaddr[nrx] = ed->bEndpointAddress;
			nrx++;
		}
	}
	if (nrx == 0 || nrx > R92C_MAX_EPIN) {
		aprint_error_dev(sc->sc_dev,
		    "%zd: invalid number of Rx bulk pipes\n", nrx);
		return EIO;
	}
	if (ntx == 0 || ntx > R92C_MAX_EPOUT) {
		aprint_error_dev(sc->sc_dev,
		    "%zd: invalid number of Tx bulk pipes\n", ntx);
		return EIO;
	}
	DPRINTFN(DBG_INIT, "found %jd/%jd bulk-in/out pipes",
	    nrx, ntx, 0, 0);
	sc->rx_npipe = nrx;
	sc->tx_npipe = ntx;

	/* Open bulk-in pipe at address 0x81. */
	for (i = 0; i < nrx; i++) {
		error = usbd_open_pipe(sc->sc_iface, rxepaddr[i],
		    USBD_EXCLUSIVE_USE, &sc->rx_pipe[i]);
		if (error != 0) {
			aprint_error_dev(sc->sc_dev,
			    "could not open Rx bulk pipe 0x%02x: %d\n",
			    rxepaddr[i], error);
			goto fail;
		}
	}

	/* Open bulk-out pipes (up to 3). */
	for (i = 0; i < ntx; i++) {
		error = usbd_open_pipe(sc->sc_iface, epaddr[i],
		    USBD_EXCLUSIVE_USE, &sc->tx_pipe[i]);
		if (error != 0) {
			aprint_error_dev(sc->sc_dev,
			    "could not open Tx bulk pipe 0x%02x: %d\n",
			    epaddr[i], error);
			goto fail;
		}
	}

	/* Map 802.11 access categories to USB pipes. */
	sc->ac2idx[WME_AC_BK] =
	sc->ac2idx[WME_AC_BE] = (ntx == 3) ? 2 : ((ntx == 2) ? 1 : 0);
	sc->ac2idx[WME_AC_VI] = (ntx == 3) ? 1 : 0;
	sc->ac2idx[WME_AC_VO] = 0;	/* Always use highest prio. */

 fail:
	if (error != 0)
		urtwn_close_pipes(sc);
	return error;
}

static void
urtwn_close_pipes(struct urtwn_softc *sc)
{
	struct usbd_pipe *pipe;
	size_t i;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	/* Close Rx pipes. */
	CTASSERT(sizeof(pipe) == sizeof(void *));
	for (i = 0; i < sc->rx_npipe; i++) {
		pipe = atomic_swap_ptr(&sc->rx_pipe[i], NULL);
		if (pipe != NULL) {
			usbd_close_pipe(pipe);
		}
	}

	/* Close Tx pipes. */
	for (i = 0; i < sc->tx_npipe; i++) {
		pipe = atomic_swap_ptr(&sc->tx_pipe[i], NULL);
		if (pipe != NULL) {
			usbd_close_pipe(pipe);
		}
	}
}

static int __noinline
urtwn_alloc_rx_list(struct urtwn_softc *sc)
{
	struct urtwn_rx_data *data;
	size_t i;
	int error = 0;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	for (size_t j = 0; j < sc->rx_npipe; j++) {
		TAILQ_INIT(&sc->rx_free_list[j]);
		for (i = 0; i < URTWN_RX_LIST_COUNT; i++) {
			data = &sc->rx_data[j][i];

			data->sc = sc;	/* Backpointer for callbacks. */

			error = usbd_create_xfer(sc->rx_pipe[j], URTWN_RXBUFSZ,
			    0, 0, &data->xfer);
			if (error) {
				aprint_error_dev(sc->sc_dev,
				    "could not allocate xfer\n");
				break;
			}

			data->buf = usbd_get_buffer(data->xfer);
			TAILQ_INSERT_TAIL(&sc->rx_free_list[j], data, next);
		}
	}
	if (error != 0)
		urtwn_free_rx_list(sc);
	return error;
}

static void
urtwn_free_rx_list(struct urtwn_softc *sc)
{
	struct usbd_xfer *xfer;
	size_t i;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	/* NB: Caller must abort pipe first. */
	for (size_t j = 0; j < sc->rx_npipe; j++) {
		for (i = 0; i < URTWN_RX_LIST_COUNT; i++) {
			CTASSERT(sizeof(xfer) == sizeof(void *));
			xfer = atomic_swap_ptr(&sc->rx_data[j][i].xfer, NULL);
			if (xfer != NULL)
				usbd_destroy_xfer(xfer);
		}
	}
}

static int __noinline
urtwn_alloc_tx_list(struct urtwn_softc *sc)
{
	struct urtwn_tx_data *data;
	size_t i;
	int error = 0;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	mutex_enter(&sc->sc_tx_mtx);
	for (size_t j = 0; j < sc->tx_npipe; j++) {
		TAILQ_INIT(&sc->tx_free_list[j]);
		for (i = 0; i < URTWN_TX_LIST_COUNT; i++) {
			data = &sc->tx_data[j][i];

			data->sc = sc;	/* Backpointer for callbacks. */
			data->pidx = j;

			error = usbd_create_xfer(sc->tx_pipe[j],
			    URTWN_TXBUFSZ, USBD_FORCE_SHORT_XFER, 0,
			    &data->xfer);
			if (error) {
				aprint_error_dev(sc->sc_dev,
				    "could not allocate xfer\n");
				goto fail;
			}

			data->buf = usbd_get_buffer(data->xfer);

			/* Append this Tx buffer to our free list. */
			TAILQ_INSERT_TAIL(&sc->tx_free_list[j], data, next);
		}
	}
	mutex_exit(&sc->sc_tx_mtx);
	return 0;

 fail:
	urtwn_free_tx_list(sc);
	mutex_exit(&sc->sc_tx_mtx);
	return error;
}

static void
urtwn_free_tx_list(struct urtwn_softc *sc)
{
	struct usbd_xfer *xfer;
	size_t i;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	/* NB: Caller must abort pipe first. */
	for (size_t j = 0; j < sc->tx_npipe; j++) {
		for (i = 0; i < URTWN_TX_LIST_COUNT; i++) {
			CTASSERT(sizeof(xfer) == sizeof(void *));
			xfer = atomic_swap_ptr(&sc->tx_data[j][i].xfer, NULL);
			if (xfer != NULL)
				usbd_destroy_xfer(xfer);
		}
	}
}

static int
urtwn_tx_beacon(struct urtwn_softc *sc, struct mbuf *m,
    struct ieee80211_node *ni)
{
	struct urtwn_tx_data *data =
	    urtwn_get_tx_data(sc, sc->ac2idx[WME_AC_VO]);

	if (data == NULL)
		return ENOBUFS;

	return urtwn_tx(sc, m, ni, data);
}

static void
urtwn_cmdq_invariants(struct urtwn_softc *sc)
{
	struct urtwn_host_cmd_ring *const ring = &sc->cmdq;

	KASSERT(mutex_owned(&sc->sc_task_mtx));
	KASSERTMSG((ring->cur >= 0 && ring->cur < URTWN_HOST_CMD_RING_COUNT),
	    "%s: cur=%d next=%d queued=%d",
	    device_xname(sc->sc_dev), ring->cur, ring->next, ring->queued);
	KASSERTMSG((ring->next >= 0 && ring->next < URTWN_HOST_CMD_RING_COUNT),
	    "%s: cur=%d next=%d queued=%d",
	    device_xname(sc->sc_dev), ring->cur, ring->next, ring->queued);
	KASSERTMSG((ring->queued >= 0 &&
		ring->queued <= URTWN_HOST_CMD_RING_COUNT),
	    "%s: %d commands queued",
	    device_xname(sc->sc_dev), ring->queued);
}

static void
urtwn_task(void *arg)
{
	struct urtwn_softc *sc = arg;
	struct ieee80211com *ic = &sc->sc_ic;
	struct urtwn_host_cmd_ring *ring = &sc->cmdq;
	struct urtwn_host_cmd *cmd;
	int s;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();
	if (ic->ic_state == IEEE80211_S_RUN &&
	    (ic->ic_opmode == IEEE80211_M_HOSTAP ||
	    ic->ic_opmode == IEEE80211_M_IBSS)) {

		struct mbuf *m = ieee80211_beacon_alloc(ic, ic->ic_bss,
		    &sc->sc_bo);
		if (m == NULL) {
			aprint_error_dev(sc->sc_dev,
			    "could not allocate beacon");
		}

		if (urtwn_tx_beacon(sc, m, ic->ic_bss) != 0) {
			aprint_error_dev(sc->sc_dev, "could not send beacon\n");
		}

		/* beacon is no longer needed */
		m_freem(m);
	}

	/* Process host commands. */
	s = splusb();
	mutex_spin_enter(&sc->sc_task_mtx);
	urtwn_cmdq_invariants(sc);
	while (ring->next != ring->cur) {
		KASSERTMSG(ring->queued > 0, "%s: cur=%d next=%d queued=%d",
		    device_xname(sc->sc_dev),
		    ring->cur, ring->next, ring->queued);
		cmd = &ring->cmd[ring->next];
		mutex_spin_exit(&sc->sc_task_mtx);
		splx(s);
		/* Invoke callback with kernel lock held. */
		cmd->cb(sc, cmd->data);
		s = splusb();
		mutex_spin_enter(&sc->sc_task_mtx);
		urtwn_cmdq_invariants(sc);
		KASSERTMSG(ring->queued > 0, "%s: cur=%d next=%d queued=%d",
		    device_xname(sc->sc_dev),
		    ring->cur, ring->next, ring->queued);
		ring->queued--;
		ring->next = (ring->next + 1) % URTWN_HOST_CMD_RING_COUNT;
	}
	cv_broadcast(&sc->sc_task_cv);
	mutex_spin_exit(&sc->sc_task_mtx);
	splx(s);
}

static void
urtwn_do_async(struct urtwn_softc *sc, void (*cb)(struct urtwn_softc *, void *),
    void *arg, int len)
{
	struct urtwn_host_cmd_ring *ring = &sc->cmdq;
	struct urtwn_host_cmd *cmd;
	bool schedtask = false;
	int s;

	URTWNHIST_FUNC();
	URTWNHIST_CALLARGS("cb=%#jx, arg=%#jx, len=%jd",
	    (uintptr_t)cb, (uintptr_t)arg, len, 0);

	s = splusb();
	mutex_spin_enter(&sc->sc_task_mtx);
	urtwn_cmdq_invariants(sc);
	cmd = &ring->cmd[ring->cur];
	cmd->cb = cb;
	KASSERT(len <= sizeof(cmd->data));
	memcpy(cmd->data, arg, len);
	ring->cur = (ring->cur + 1) % URTWN_HOST_CMD_RING_COUNT;

	/*
	 * Schedule a task to process the command if need be.
	 */
	if (!sc->sc_dying) {
		if (ring->queued == URTWN_HOST_CMD_RING_COUNT)
			device_printf(sc->sc_dev, "command queue overflow\n");
		else if (ring->queued++ == 0)
			schedtask = true;
	}
	mutex_spin_exit(&sc->sc_task_mtx);
	splx(s);

	if (schedtask)
		usb_add_task(sc->sc_udev, &sc->sc_task, USB_TASKQ_DRIVER);
}

static void
urtwn_wait_async(struct urtwn_softc *sc)
{

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	/* Wait for all queued asynchronous commands to complete. */
	mutex_spin_enter(&sc->sc_task_mtx);
	while (sc->cmdq.queued > 0)
		cv_wait(&sc->sc_task_cv, &sc->sc_task_mtx);
	mutex_spin_exit(&sc->sc_task_mtx);
}

static int
urtwn_write_region_1(struct urtwn_softc *sc, uint16_t addr, uint8_t *buf,
    int len)
{
	usb_device_request_t req;
	usbd_status error;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();
	KASSERT(mutex_owned(&sc->sc_write_mtx));

	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = R92C_REQ_REGS;
	USETW(req.wValue, addr);
	USETW(req.wIndex, 0);
	USETW(req.wLength, len);
	error = usbd_do_request(sc->sc_udev, &req, buf);
	if (error != USBD_NORMAL_COMPLETION) {
		DPRINTFN(DBG_REG, "error=%jd: addr=%#jx, len=%jd",
		    error, addr, len, 0);
	}
	return error;
}

static void
urtwn_write_1(struct urtwn_softc *sc, uint16_t addr, uint8_t val)
{

	URTWNHIST_FUNC(); URTWNHIST_CALLED();
	DPRINTFN(DBG_REG, "addr=%#jx, val=%#jx", addr, val, 0, 0);

	urtwn_write_region_1(sc, addr, &val, 1);
}

static void
urtwn_write_2(struct urtwn_softc *sc, uint16_t addr, uint16_t val)
{
	uint8_t buf[2];

	URTWNHIST_FUNC(); URTWNHIST_CALLED();
	DPRINTFN(DBG_REG, "addr=%#jx, val=%#jx", addr, val, 0, 0);

	buf[0] = (uint8_t)val;
	buf[1] = (uint8_t)(val >> 8);
	urtwn_write_region_1(sc, addr, buf, 2);
}

static void
urtwn_write_4(struct urtwn_softc *sc, uint16_t addr, uint32_t val)
{
	uint8_t buf[4];

	URTWNHIST_FUNC(); URTWNHIST_CALLED();
	DPRINTFN(DBG_REG, "addr=%#jx, val=%#jx", addr, val, 0, 0);

	buf[0] = (uint8_t)val;
	buf[1] = (uint8_t)(val >> 8);
	buf[2] = (uint8_t)(val >> 16);
	buf[3] = (uint8_t)(val >> 24);
	urtwn_write_region_1(sc, addr, buf, 4);
}

static int
urtwn_write_region(struct urtwn_softc *sc, uint16_t addr, uint8_t *buf, int len)
{

	URTWNHIST_FUNC();
	URTWNHIST_CALLARGS("addr=%#jx, len=%#jx", addr, len, 0, 0);

	return urtwn_write_region_1(sc, addr, buf, len);
}

static int
urtwn_read_region_1(struct urtwn_softc *sc, uint16_t addr, uint8_t *buf,
    int len)
{
	usb_device_request_t req;
	usbd_status error;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	req.bmRequestType = UT_READ_VENDOR_DEVICE;
	req.bRequest = R92C_REQ_REGS;
	USETW(req.wValue, addr);
	USETW(req.wIndex, 0);
	USETW(req.wLength, len);
	error = usbd_do_request(sc->sc_udev, &req, buf);
	if (error != USBD_NORMAL_COMPLETION) {
		DPRINTFN(DBG_REG, "error=%jd: addr=%#jx, len=%jd",
		    error, addr, len, 0);
	}
	return error;
}

static uint8_t
urtwn_read_1(struct urtwn_softc *sc, uint16_t addr)
{
	uint8_t val;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	if (urtwn_read_region_1(sc, addr, &val, 1) != USBD_NORMAL_COMPLETION)
		return 0xff;

	DPRINTFN(DBG_REG, "addr=%#jx, val=%#jx", addr, val, 0, 0);
	return val;
}

static uint16_t
urtwn_read_2(struct urtwn_softc *sc, uint16_t addr)
{
	uint8_t buf[2];
	uint16_t val;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	if (urtwn_read_region_1(sc, addr, buf, 2) != USBD_NORMAL_COMPLETION)
		return 0xffff;

	val = LE_READ_2(&buf[0]);
	DPRINTFN(DBG_REG, "addr=%#jx, val=%#jx", addr, val, 0, 0);
	return val;
}

static uint32_t
urtwn_read_4(struct urtwn_softc *sc, uint16_t addr)
{
	uint8_t buf[4];
	uint32_t val;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	if (urtwn_read_region_1(sc, addr, buf, 4) != USBD_NORMAL_COMPLETION)
		return 0xffffffff;

	val = LE_READ_4(&buf[0]);
	DPRINTFN(DBG_REG, "addr=%#jx, val=%#jx", addr, val, 0, 0);
	return val;
}

static int
urtwn_fw_cmd(struct urtwn_softc *sc, uint8_t id, const void *buf, int len)
{
	struct r92c_fw_cmd cmd;
	uint8_t *cp;
	int fwcur;
	int ntries;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();
	DPRINTFN(DBG_REG, "id=%jd, buf=%#jx, len=%jd", id, (uintptr_t)buf, len, 0);

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	mutex_enter(&sc->sc_fwcmd_mtx);
	fwcur = sc->fwcur;
	sc->fwcur = (sc->fwcur + 1) % R92C_H2C_NBOX;

	/* Wait for current FW box to be empty. */
	for (ntries = 0; ntries < 100; ntries++) {
		if (!(urtwn_read_1(sc, R92C_HMETFR) & (1 << fwcur)))
			break;
		urtwn_delay_ms(sc, 2);
	}
	if (ntries == 100) {
		aprint_error_dev(sc->sc_dev,
		    "could not send firmware command %d\n", id);
		mutex_exit(&sc->sc_fwcmd_mtx);
		return ETIMEDOUT;
	}

	memset(&cmd, 0, sizeof(cmd));
	KASSERT(len <= sizeof(cmd.msg));
	memcpy(cmd.msg, buf, len);

	/* Write the first word last since that will trigger the FW. */
	cp = (uint8_t *)&cmd;
	cmd.id = id;
	if (len >= 4) {
		if (!ISSET(sc->chip, URTWN_CHIP_92EU)) {
			cmd.id |= R92C_CMD_FLAG_EXT;
			urtwn_write_region(sc, R92C_HMEBOX_EXT(fwcur),
			    &cp[1], 2);
			urtwn_write_4(sc, R92C_HMEBOX(fwcur),
			    cp[0] + (cp[3] << 8) + (cp[4] << 16) +
			    ((uint32_t)cp[5] << 24));
		} else {
			urtwn_write_region(sc, R92E_HMEBOX_EXT(fwcur),
			    &cp[4], 2);
			urtwn_write_4(sc, R92C_HMEBOX(fwcur),
			    cp[0] + (cp[1] << 8) + (cp[2] << 16) +
			    ((uint32_t)cp[3] << 24));
		}
	} else {
		urtwn_write_region(sc, R92C_HMEBOX(fwcur), cp, len);
	}
	mutex_exit(&sc->sc_fwcmd_mtx);

	return 0;
}

static __inline void
urtwn_rf_write(struct urtwn_softc *sc, int chain, uint8_t addr, uint32_t val)
{

	sc->sc_rf_write(sc, chain, addr, val);
}

static void
urtwn_r92c_rf_write(struct urtwn_softc *sc, int chain, uint8_t addr,
    uint32_t val)
{

	urtwn_bb_write(sc, R92C_LSSI_PARAM(chain),
	    SM(R92C_LSSI_PARAM_ADDR, addr) | SM(R92C_LSSI_PARAM_DATA, val));
}

static void
urtwn_r88e_rf_write(struct urtwn_softc *sc, int chain, uint8_t addr,
    uint32_t val)
{

	urtwn_bb_write(sc, R92C_LSSI_PARAM(chain),
	    SM(R88E_LSSI_PARAM_ADDR, addr) | SM(R92C_LSSI_PARAM_DATA, val));
}

static void
urtwn_r92e_rf_write(struct urtwn_softc *sc, int chain, uint8_t addr,
    uint32_t val)
{

	urtwn_bb_write(sc, R92C_LSSI_PARAM(chain),
	    SM(R88E_LSSI_PARAM_ADDR, addr) | SM(R92C_LSSI_PARAM_DATA, val));
}

static uint32_t
urtwn_rf_read(struct urtwn_softc *sc, int chain, uint8_t addr)
{
	uint32_t reg[R92C_MAX_CHAINS], val;

	reg[0] = urtwn_bb_read(sc, R92C_HSSI_PARAM2(0));
	if (chain != 0) {
		reg[chain] = urtwn_bb_read(sc, R92C_HSSI_PARAM2(chain));
	}

	urtwn_bb_write(sc, R92C_HSSI_PARAM2(0),
	    reg[0] & ~R92C_HSSI_PARAM2_READ_EDGE);
	urtwn_delay_ms(sc, 1);

	urtwn_bb_write(sc, R92C_HSSI_PARAM2(chain),
	    RW(reg[chain], R92C_HSSI_PARAM2_READ_ADDR, addr) |
	    R92C_HSSI_PARAM2_READ_EDGE);
	urtwn_delay_ms(sc, 1);

	urtwn_bb_write(sc, R92C_HSSI_PARAM2(0),
	    reg[0] | R92C_HSSI_PARAM2_READ_EDGE);
	urtwn_delay_ms(sc, 1);

	if (urtwn_bb_read(sc, R92C_HSSI_PARAM1(chain)) & R92C_HSSI_PARAM1_PI) {
		val = urtwn_bb_read(sc, R92C_HSPI_READBACK(chain));
	} else {
		val = urtwn_bb_read(sc, R92C_LSSI_READBACK(chain));
	}
	return MS(val, R92C_LSSI_READBACK_DATA);
}

static int
urtwn_llt_write(struct urtwn_softc *sc, uint32_t addr, uint32_t data)
{
	int ntries;

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	urtwn_write_4(sc, R92C_LLT_INIT,
	    SM(R92C_LLT_INIT_OP, R92C_LLT_INIT_OP_WRITE) |
	    SM(R92C_LLT_INIT_ADDR, addr) |
	    SM(R92C_LLT_INIT_DATA, data));
	/* Wait for write operation to complete. */
	for (ntries = 0; ntries < 20; ntries++) {
		if (MS(urtwn_read_4(sc, R92C_LLT_INIT), R92C_LLT_INIT_OP) ==
		    R92C_LLT_INIT_OP_NO_ACTIVE) {
			/* Done */
			return 0;
		}
		DELAY(5);
	}
	return ETIMEDOUT;
}

static uint8_t
urtwn_efuse_read_1(struct urtwn_softc *sc, uint16_t addr)
{
	uint32_t reg;
	int ntries;

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	reg = urtwn_read_4(sc, R92C_EFUSE_CTRL);
	reg = RW(reg, R92C_EFUSE_CTRL_ADDR, addr);
	reg &= ~R92C_EFUSE_CTRL_VALID;
	urtwn_write_4(sc, R92C_EFUSE_CTRL, reg);

	/* Wait for read operation to complete. */
	for (ntries = 0; ntries < 100; ntries++) {
		reg = urtwn_read_4(sc, R92C_EFUSE_CTRL);
		if (reg & R92C_EFUSE_CTRL_VALID) {
			/* Done */
			return MS(reg, R92C_EFUSE_CTRL_DATA);
		}
		DELAY(5);
	}
	aprint_error_dev(sc->sc_dev,
	    "could not read efuse byte at address 0x%04x\n", addr);
	return 0xff;
}

static void
urtwn_efuse_read(struct urtwn_softc *sc)
{
	uint8_t *rom = (uint8_t *)&sc->rom;
	uint32_t reg;
	uint16_t addr = 0;
	uint8_t off, msk;
	size_t i;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	urtwn_efuse_switch_power(sc);

	memset(&sc->rom, 0xff, sizeof(sc->rom));
	while (addr < 512) {
		reg = urtwn_efuse_read_1(sc, addr);
		if (reg == 0xff)
			break;
		addr++;
		off = reg >> 4;
		msk = reg & 0xf;
		for (i = 0; i < 4; i++) {
			if (msk & (1U << i))
				continue;

			rom[off * 8 + i * 2 + 0] = urtwn_efuse_read_1(sc, addr);
			addr++;
			rom[off * 8 + i * 2 + 1] = urtwn_efuse_read_1(sc, addr);
			addr++;
		}
	}
#ifdef URTWN_DEBUG
	/* Dump ROM content. */
	for (i = 0; i < (int)sizeof(sc->rom); i++)
		DPRINTFN(DBG_INIT, "%04jx: %02jx", i, rom[i], 0, 0);
#endif
}

static void
urtwn_efuse_switch_power(struct urtwn_softc *sc)
{
	uint32_t reg;

	reg = urtwn_read_2(sc, R92C_SYS_ISO_CTRL);
	if (!(reg & R92C_SYS_ISO_CTRL_PWC_EV12V)) {
		urtwn_write_2(sc, R92C_SYS_ISO_CTRL,
		    reg | R92C_SYS_ISO_CTRL_PWC_EV12V);
	}
	reg = urtwn_read_2(sc, R92C_SYS_FUNC_EN);
	if (!(reg & R92C_SYS_FUNC_EN_ELDR)) {
		urtwn_write_2(sc, R92C_SYS_FUNC_EN,
		    reg | R92C_SYS_FUNC_EN_ELDR);
	}
	reg = urtwn_read_2(sc, R92C_SYS_CLKR);
	if ((reg & (R92C_SYS_CLKR_LOADER_EN | R92C_SYS_CLKR_ANA8M)) !=
	    (R92C_SYS_CLKR_LOADER_EN | R92C_SYS_CLKR_ANA8M)) {
		urtwn_write_2(sc, R92C_SYS_CLKR,
		    reg | R92C_SYS_CLKR_LOADER_EN | R92C_SYS_CLKR_ANA8M);
	}
}

static int
urtwn_read_chipid(struct urtwn_softc *sc)
{
	uint32_t reg;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	if (ISSET(sc->chip, URTWN_CHIP_88E) ||
	    ISSET(sc->chip, URTWN_CHIP_92EU))
		return 0;

	reg = urtwn_read_4(sc, R92C_SYS_CFG);
	if (reg & R92C_SYS_CFG_TRP_VAUX_EN) {
		/* test chip, not supported */
		return EIO;
	}
	if (reg & R92C_SYS_CFG_TYPE_92C) {
		sc->chip |= URTWN_CHIP_92C;
		/* Check if it is a castrated 8192C. */
		if (MS(urtwn_read_4(sc, R92C_HPON_FSM),
		    R92C_HPON_FSM_CHIP_BONDING_ID) ==
		    R92C_HPON_FSM_CHIP_BONDING_ID_92C_1T2R) {
			sc->chip |= URTWN_CHIP_92C_1T2R;
		}
	}
	if (reg & R92C_SYS_CFG_VENDOR_UMC) {
		sc->chip |= URTWN_CHIP_UMC;
		if (MS(reg, R92C_SYS_CFG_CHIP_VER_RTL) == 0) {
			sc->chip |= URTWN_CHIP_UMC_A_CUT;
		}
	}
	return 0;
}

#ifdef URTWN_DEBUG
static void
urtwn_dump_rom(struct urtwn_softc *sc, struct r92c_rom *rp)
{

	aprint_normal_dev(sc->sc_dev,
	    "id 0x%04x, dbg_sel %#x, vid %#x, pid %#x\n",
	    rp->id, rp->dbg_sel, rp->vid, rp->pid);

	aprint_normal_dev(sc->sc_dev,
	    "usb_opt %#x, ep_setting %#x, usb_phy %#x\n",
	    rp->usb_opt, rp->ep_setting, rp->usb_phy);

	aprint_normal_dev(sc->sc_dev,
	    "macaddr %s\n",
	    ether_sprintf(rp->macaddr));

	aprint_normal_dev(sc->sc_dev,
	    "string %s, subcustomer_id %#x\n",
	    rp->string, rp->subcustomer_id);

	aprint_normal_dev(sc->sc_dev,
	    "cck_tx_pwr c0: %d %d %d, c1: %d %d %d\n",
	    rp->cck_tx_pwr[0][0], rp->cck_tx_pwr[0][1], rp->cck_tx_pwr[0][2],
	    rp->cck_tx_pwr[1][0], rp->cck_tx_pwr[1][1], rp->cck_tx_pwr[1][2]);

	aprint_normal_dev(sc->sc_dev,
	    "ht40_1s_tx_pwr c0 %d %d %d, c1 %d %d %d\n",
	    rp->ht40_1s_tx_pwr[0][0], rp->ht40_1s_tx_pwr[0][1],
	    rp->ht40_1s_tx_pwr[0][2],
	    rp->ht40_1s_tx_pwr[1][0], rp->ht40_1s_tx_pwr[1][1],
	    rp->ht40_1s_tx_pwr[1][2]);

	aprint_normal_dev(sc->sc_dev,
	    "ht40_2s_tx_pwr_diff c0: %d %d %d, c1: %d %d %d\n",
	    rp->ht40_2s_tx_pwr_diff[0] & 0xf, rp->ht40_2s_tx_pwr_diff[1] & 0xf,
	    rp->ht40_2s_tx_pwr_diff[2] & 0xf,
	    rp->ht40_2s_tx_pwr_diff[0] >> 4, rp->ht40_2s_tx_pwr_diff[1] & 0xf,
	    rp->ht40_2s_tx_pwr_diff[2] >> 4);

	aprint_normal_dev(sc->sc_dev,
	    "ht20_tx_pwr_diff c0: %d %d %d, c1: %d %d %d\n",
	    rp->ht20_tx_pwr_diff[0] & 0xf, rp->ht20_tx_pwr_diff[1] & 0xf,
	    rp->ht20_tx_pwr_diff[2] & 0xf,
	    rp->ht20_tx_pwr_diff[0] >> 4, rp->ht20_tx_pwr_diff[1] >> 4,
	    rp->ht20_tx_pwr_diff[2] >> 4);

	aprint_normal_dev(sc->sc_dev,
	    "ofdm_tx_pwr_diff c0: %d %d %d, c1: %d %d %d\n",
	    rp->ofdm_tx_pwr_diff[0] & 0xf, rp->ofdm_tx_pwr_diff[1] & 0xf,
	    rp->ofdm_tx_pwr_diff[2] & 0xf,
	    rp->ofdm_tx_pwr_diff[0] >> 4, rp->ofdm_tx_pwr_diff[1] >> 4,
	    rp->ofdm_tx_pwr_diff[2] >> 4);

	aprint_normal_dev(sc->sc_dev,
	    "ht40_max_pwr_offset c0: %d %d %d, c1: %d %d %d\n",
	    rp->ht40_max_pwr[0] & 0xf, rp->ht40_max_pwr[1] & 0xf,
	    rp->ht40_max_pwr[2] & 0xf,
	    rp->ht40_max_pwr[0] >> 4, rp->ht40_max_pwr[1] >> 4,
	    rp->ht40_max_pwr[2] >> 4);

	aprint_normal_dev(sc->sc_dev,
	    "ht20_max_pwr_offset c0: %d %d %d, c1: %d %d %d\n",
	    rp->ht20_max_pwr[0] & 0xf, rp->ht20_max_pwr[1] & 0xf,
	    rp->ht20_max_pwr[2] & 0xf,
	    rp->ht20_max_pwr[0] >> 4, rp->ht20_max_pwr[1] >> 4,
	    rp->ht20_max_pwr[2] >> 4);

	aprint_normal_dev(sc->sc_dev,
	    "xtal_calib %d, tssi %d %d, thermal %d\n",
	    rp->xtal_calib, rp->tssi[0], rp->tssi[1], rp->thermal_meter);

	aprint_normal_dev(sc->sc_dev,
	    "rf_opt1 %#x, rf_opt2 %#x, rf_opt3 %#x, rf_opt4 %#x\n",
	    rp->rf_opt1, rp->rf_opt2, rp->rf_opt3, rp->rf_opt4);

	aprint_normal_dev(sc->sc_dev,
	    "channnel_plan %d, version %d customer_id %#x\n",
	    rp->channel_plan, rp->version, rp->curstomer_id);
}
#endif

static void
urtwn_read_rom(struct urtwn_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct r92c_rom *rom = &sc->rom;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	mutex_enter(&sc->sc_write_mtx);

	/* Read full ROM image. */
	urtwn_efuse_read(sc);
#ifdef URTWN_DEBUG
	if (urtwn_debug & DBG_REG)
		urtwn_dump_rom(sc, rom);
#endif

	/* XXX Weird but this is what the vendor driver does. */
	sc->pa_setting = urtwn_efuse_read_1(sc, 0x1fa);
	sc->board_type = MS(rom->rf_opt1, R92C_ROM_RF1_BOARD_TYPE);
	sc->regulatory = MS(rom->rf_opt1, R92C_ROM_RF1_REGULATORY);

	DPRINTFN(DBG_INIT,
	    "PA setting=%#jx, board=%#jx, regulatory=%jd",
	    sc->pa_setting, sc->board_type, sc->regulatory, 0);

	IEEE80211_ADDR_COPY(ic->ic_myaddr, rom->macaddr);

	sc->sc_rf_write = urtwn_r92c_rf_write;
	sc->sc_power_on = urtwn_r92c_power_on;
	sc->sc_dma_init = urtwn_r92c_dma_init;

	mutex_exit(&sc->sc_write_mtx);
}

static void
urtwn_r88e_read_rom(struct urtwn_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint8_t *rom = sc->r88e_rom;
	uint32_t reg;
	uint16_t addr = 0;
	uint8_t off, msk, tmp;
	int i;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	mutex_enter(&sc->sc_write_mtx);

	off = 0;
	urtwn_efuse_switch_power(sc);

	/* Read full ROM image. */
	memset(&sc->r88e_rom, 0xff, sizeof(sc->r88e_rom));
	while (addr < 4096) {
		reg = urtwn_efuse_read_1(sc, addr);
		if (reg == 0xff)
			break;
		addr++;
		if ((reg & 0x1f) == 0x0f) {
			tmp = (reg & 0xe0) >> 5;
			reg = urtwn_efuse_read_1(sc, addr);
			if ((reg & 0x0f) != 0x0f)
				off = ((reg & 0xf0) >> 1) | tmp;
			addr++;
		} else
			off = reg >> 4;
		msk = reg & 0xf;
		for (i = 0; i < 4; i++) {
			if (msk & (1 << i))
				continue;
			rom[off * 8 + i * 2 + 0] = urtwn_efuse_read_1(sc, addr);
			addr++;
			rom[off * 8 + i * 2 + 1] = urtwn_efuse_read_1(sc, addr);
			addr++;
		}
	}
#ifdef URTWN_DEBUG
	if (urtwn_debug & DBG_REG) {
	}
#endif

	addr = 0x10;
	for (i = 0; i < 6; i++)
		sc->cck_tx_pwr[i] = sc->r88e_rom[addr++];
	for (i = 0; i < 5; i++)
		sc->ht40_tx_pwr[i] = sc->r88e_rom[addr++];
	sc->bw20_tx_pwr_diff = (sc->r88e_rom[addr] & 0xf0) >> 4;
	if (sc->bw20_tx_pwr_diff & 0x08)
		sc->bw20_tx_pwr_diff |= 0xf0;
	sc->ofdm_tx_pwr_diff = (sc->r88e_rom[addr] & 0xf);
	if (sc->ofdm_tx_pwr_diff & 0x08)
		sc->ofdm_tx_pwr_diff |= 0xf0;
	sc->regulatory = MS(sc->r88e_rom[0xc1], R92C_ROM_RF1_REGULATORY);

	IEEE80211_ADDR_COPY(ic->ic_myaddr, &sc->r88e_rom[0xd7]);

	if (ISSET(sc->chip, URTWN_CHIP_92EU)) {
		sc->sc_power_on = urtwn_r92e_power_on;
		sc->sc_rf_write = urtwn_r92e_rf_write;
	} else {
		sc->sc_power_on = urtwn_r88e_power_on;
		sc->sc_rf_write = urtwn_r88e_rf_write;
	}
	sc->sc_dma_init = urtwn_r88e_dma_init;

	mutex_exit(&sc->sc_write_mtx);
}

static int
urtwn_media_change(struct ifnet *ifp)
{
	int error;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	if ((error = ieee80211_media_change(ifp)) != ENETRESET)
		return error;

	if ((ifp->if_flags & (IFF_UP | IFF_RUNNING)) ==
	    (IFF_UP | IFF_RUNNING)) {
		urtwn_init(ifp);
	}
	return 0;
}

/*
 * Initialize rate adaptation in firmware.
 */
static int __noinline
urtwn_ra_init(struct urtwn_softc *sc)
{
	static const uint8_t map[] = {
		2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108
	};
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni = ic->ic_bss;
	struct ieee80211_rateset *rs = &ni->ni_rates;
	struct r92c_fw_cmd_macid_cfg cmd;
	uint32_t rates, basicrates;
	uint32_t rrsr_mask, rrsr_rate;
	uint8_t mode;
	size_t maxrate, maxbasicrate, i, j;
	int error;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	/* Get normal and basic rates mask. */
	rates = basicrates = 1;
	maxrate = maxbasicrate = 0;
	for (i = 0; i < rs->rs_nrates; i++) {
		/* Convert 802.11 rate to HW rate index. */
		for (j = 0; j < __arraycount(map); j++) {
			if ((rs->rs_rates[i] & IEEE80211_RATE_VAL) == map[j]) {
				break;
			}
		}
		if (j == __arraycount(map)) {
			/* Unknown rate, skip. */
			continue;
		}

		rates |= 1U << j;
		if (j > maxrate) {
			maxrate = j;
		}

		if (rs->rs_rates[i] & IEEE80211_RATE_BASIC) {
			basicrates |= 1U << j;
			if (j > maxbasicrate) {
				maxbasicrate = j;
			}
		}
	}
	if (ic->ic_curmode == IEEE80211_MODE_11B) {
		mode = R92C_RAID_11B;
	} else {
		mode = R92C_RAID_11BG;
	}
	DPRINTFN(DBG_INIT, "mode=%#jx", mode, 0, 0, 0);
	DPRINTFN(DBG_INIT, "rates=%#jx, basicrates=%#jx, "
	    "maxrate=%jx, maxbasicrate=%jx",
	    rates, basicrates, maxrate, maxbasicrate);

	if (ni->ni_capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE) {
		maxbasicrate |= R92C_RATE_SHORTGI;
		maxrate |= R92C_RATE_SHORTGI;
	}

	/* Set rates mask for group addressed frames. */
	cmd.macid = RTWN_MACID_BC | RTWN_MACID_VALID;
	if (ni->ni_capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE)
		cmd.macid |= RTWN_MACID_SHORTGI;
	cmd.mask = htole32((mode << 28) | basicrates);
	error = urtwn_fw_cmd(sc, R92C_CMD_MACID_CONFIG, &cmd, sizeof(cmd));
	if (error != 0) {
		aprint_error_dev(sc->sc_dev,
		    "could not add broadcast station\n");
		return error;
	}
	/* Set initial MRR rate. */
	DPRINTFN(DBG_INIT, "maxbasicrate=%jd", maxbasicrate, 0, 0, 0);
	urtwn_write_1(sc, R92C_INIDATA_RATE_SEL(RTWN_MACID_BC), maxbasicrate);

	/* Set rates mask for unicast frames. */
	cmd.macid = RTWN_MACID_BSS | RTWN_MACID_VALID;
	if (ni->ni_capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE)
		cmd.macid |= RTWN_MACID_SHORTGI;
	cmd.mask = htole32((mode << 28) | rates);
	error = urtwn_fw_cmd(sc, R92C_CMD_MACID_CONFIG, &cmd, sizeof(cmd));
	if (error != 0) {
		aprint_error_dev(sc->sc_dev, "could not add BSS station\n");
		return error;
	}
	/* Set initial MRR rate. */
	DPRINTFN(DBG_INIT, "maxrate=%jd", maxrate, 0, 0, 0);
	urtwn_write_1(sc, R92C_INIDATA_RATE_SEL(RTWN_MACID_BSS), maxrate);

	rrsr_rate = ic->ic_fixed_rate;
	if (rrsr_rate == -1)
		rrsr_rate = 11;

	rrsr_mask = 0xffff >> (15 - rrsr_rate);
	urtwn_write_2(sc, R92C_RRSR, rrsr_mask);

	/* Indicate highest supported rate. */
	ni->ni_txrate = rs->rs_nrates - 1;

	return 0;
}

static int
urtwn_get_nettype(struct urtwn_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	int type;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	switch (ic->ic_opmode) {
	case IEEE80211_M_STA:
		type = R92C_CR_NETTYPE_INFRA;
		break;

	case IEEE80211_M_IBSS:
		type = R92C_CR_NETTYPE_ADHOC;
		break;

	default:
		type = R92C_CR_NETTYPE_NOLINK;
		break;
	}

	return type;
}

static void
urtwn_set_nettype0_msr(struct urtwn_softc *sc, uint8_t type)
{
	uint8_t	reg;

	URTWNHIST_FUNC();
	URTWNHIST_CALLARGS("type=%jd", type, 0, 0, 0);

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	reg = urtwn_read_1(sc, R92C_CR + 2) & 0x0c;
	urtwn_write_1(sc, R92C_CR + 2, reg | type);
}

static void
urtwn_tsf_sync_enable(struct urtwn_softc *sc)
{
	struct ieee80211_node *ni = sc->sc_ic.ic_bss;
	uint64_t tsf;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	/* Enable TSF synchronization. */
	urtwn_write_1(sc, R92C_BCN_CTRL,
	    urtwn_read_1(sc, R92C_BCN_CTRL) & ~R92C_BCN_CTRL_DIS_TSF_UDT0);

	/* Correct TSF */
	urtwn_write_1(sc, R92C_BCN_CTRL,
	    urtwn_read_1(sc, R92C_BCN_CTRL) & ~R92C_BCN_CTRL_EN_BCN);

	/* Set initial TSF. */
	tsf = ni->ni_tstamp.tsf;
	tsf = le64toh(tsf);
	tsf = tsf - (tsf % (ni->ni_intval * IEEE80211_DUR_TU));
	tsf -= IEEE80211_DUR_TU;
	urtwn_write_4(sc, R92C_TSFTR + 0, (uint32_t)tsf);
	urtwn_write_4(sc, R92C_TSFTR + 4, (uint32_t)(tsf >> 32));

	urtwn_write_1(sc, R92C_BCN_CTRL,
	    urtwn_read_1(sc, R92C_BCN_CTRL) | R92C_BCN_CTRL_EN_BCN);
}

static void
urtwn_set_led(struct urtwn_softc *sc, int led, int on)
{
	uint8_t reg;

	URTWNHIST_FUNC();
	URTWNHIST_CALLARGS("led=%jd, on=%jd", led, on, 0, 0);

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	if (led == URTWN_LED_LINK) {
		if (ISSET(sc->chip, URTWN_CHIP_92EU)) {
			urtwn_write_1(sc, 0x64, urtwn_read_1(sc, 0x64) & 0xfe);
			reg = urtwn_read_1(sc, R92C_LEDCFG1) & R92E_LEDSON;
			urtwn_write_1(sc, R92C_LEDCFG1, reg |
			    (R92C_LEDCFG0_DIS << 1));
			if (on) {
				reg = urtwn_read_1(sc, R92C_LEDCFG1) &
				    R92E_LEDSON;
				urtwn_write_1(sc, R92C_LEDCFG1, reg);
			}
		} else if (ISSET(sc->chip, URTWN_CHIP_88E)) {
			reg = urtwn_read_1(sc, R92C_LEDCFG2) & 0xf0;
			urtwn_write_1(sc, R92C_LEDCFG2, reg | 0x60);
			if (!on) {
				reg = urtwn_read_1(sc, R92C_LEDCFG2) & 0x90;
				urtwn_write_1(sc, R92C_LEDCFG2,
				    reg | R92C_LEDCFG0_DIS);
				reg = urtwn_read_1(sc, R92C_MAC_PINMUX_CFG);
				urtwn_write_1(sc, R92C_MAC_PINMUX_CFG,
				    reg & 0xfe);
			}
		} else {
			reg = urtwn_read_1(sc, R92C_LEDCFG0) & 0x70;
			if (!on) {
				reg |= R92C_LEDCFG0_DIS;
			}
			urtwn_write_1(sc, R92C_LEDCFG0, reg);
		}
		sc->ledlink = on;	/* Save LED state. */
	}
}

static void
urtwn_calib_to(void *arg)
{
	struct urtwn_softc *sc = arg;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	if (sc->sc_dying)
		return;

	/* Do it in a process context. */
	urtwn_do_async(sc, urtwn_calib_to_cb, NULL, 0);
}

/* ARGSUSED */
static void
urtwn_calib_to_cb(struct urtwn_softc *sc, void *arg)
{
	struct r92c_fw_cmd_rssi cmd;
	struct r92e_fw_cmd_rssi cmde;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	if (sc->sc_ic.ic_state != IEEE80211_S_RUN)
		goto restart_timer;

	mutex_enter(&sc->sc_write_mtx);
	if (sc->avg_pwdb != -1) {
		/* Indicate Rx signal strength to FW for rate adaptation. */
		memset(&cmd, 0, sizeof(cmd));
		memset(&cmde, 0, sizeof(cmde));
		cmd.macid = 0;	/* BSS. */
		cmde.macid = 0;	/* BSS. */
		cmd.pwdb = sc->avg_pwdb;
		cmde.pwdb = sc->avg_pwdb;
		DPRINTFN(DBG_RF, "sending RSSI command avg=%jd",
		    sc->avg_pwdb, 0, 0, 0);
		if (!ISSET(sc->chip, URTWN_CHIP_92EU)) {
			urtwn_fw_cmd(sc, R92C_CMD_RSSI_SETTING, &cmd,
			    sizeof(cmd));
		} else {
			urtwn_fw_cmd(sc, R92E_CMD_RSSI_REPORT, &cmde,
			    sizeof(cmde));
		}
	}

	/* Do temperature compensation. */
	urtwn_temp_calib(sc);
	mutex_exit(&sc->sc_write_mtx);

 restart_timer:
	if (!sc->sc_dying) {
		/* Restart calibration timer. */
		callout_schedule(&sc->sc_calib_to, hz);
	}
}

static void
urtwn_next_scan(void *arg)
{
	struct urtwn_softc *sc = arg;
	int s;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	if (sc->sc_dying)
		return;

	s = splnet();
	if (sc->sc_ic.ic_state == IEEE80211_S_SCAN)
		ieee80211_next_scan(&sc->sc_ic);
	splx(s);
}

static void
urtwn_newassoc(struct ieee80211_node *ni, int isnew)
{
	URTWNHIST_FUNC();
	URTWNHIST_CALLARGS("new node %06jx%06jx",
	    ni->ni_macaddr[0] << 2 |
	    ni->ni_macaddr[1] << 1 |
	    ni->ni_macaddr[2],
	    ni->ni_macaddr[3] << 2 |
	    ni->ni_macaddr[4] << 1 |
	    ni->ni_macaddr[5],
	    0, 0);
	/* start with lowest Tx rate */
	ni->ni_txrate = 0;
}

static int
urtwn_newstate(struct ieee80211com *ic, enum ieee80211_state nstate, int arg)
{
	struct urtwn_softc *sc = ic->ic_ifp->if_softc;
	struct urtwn_cmd_newstate cmd;

	URTWNHIST_FUNC();
	URTWNHIST_CALLARGS("nstate=%jd, arg=%jd", nstate, arg, 0, 0);

	callout_stop(&sc->sc_scan_to);
	callout_stop(&sc->sc_calib_to);

	/* Do it in a process context. */
	cmd.state = nstate;
	cmd.arg = arg;
	urtwn_do_async(sc, urtwn_newstate_cb, &cmd, sizeof(cmd));
	return 0;
}

static void
urtwn_newstate_cb(struct urtwn_softc *sc, void *arg)
{
	struct urtwn_cmd_newstate *cmd = arg;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni;
	enum ieee80211_state ostate = ic->ic_state;
	enum ieee80211_state nstate = cmd->state;
	uint32_t reg;
	uint8_t sifs_time, msr;
	int s;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();
	DPRINTFN(DBG_STM, "%jd->%jd", ostate, nstate, 0, 0);

	s = splnet();
	mutex_enter(&sc->sc_write_mtx);

	callout_stop(&sc->sc_scan_to);
	callout_stop(&sc->sc_calib_to);

	switch (ostate) {
	case IEEE80211_S_INIT:
		break;

	case IEEE80211_S_SCAN:
		if (nstate != IEEE80211_S_SCAN) {
			/*
			 * End of scanning
			 */
			/* flush 4-AC Queue after site_survey */
			urtwn_write_1(sc, R92C_TXPAUSE, 0x0);

			/* Allow Rx from our BSSID only. */
			urtwn_write_4(sc, R92C_RCR,
			    urtwn_read_4(sc, R92C_RCR) |
			      R92C_RCR_CBSSID_DATA | R92C_RCR_CBSSID_BCN);
		}
		break;

	case IEEE80211_S_AUTH:
	case IEEE80211_S_ASSOC:
		break;

	case IEEE80211_S_RUN:
		/* Turn link LED off. */
		urtwn_set_led(sc, URTWN_LED_LINK, 0);

		/* Set media status to 'No Link'. */
		urtwn_set_nettype0_msr(sc, R92C_CR_NETTYPE_NOLINK);

		/* Stop Rx of data frames. */
		urtwn_write_2(sc, R92C_RXFLTMAP2, 0);

		/* Reset TSF. */
		urtwn_write_1(sc, R92C_DUAL_TSF_RST, 0x03);

		/* Disable TSF synchronization. */
		urtwn_write_1(sc, R92C_BCN_CTRL,
		    urtwn_read_1(sc, R92C_BCN_CTRL) |
		      R92C_BCN_CTRL_DIS_TSF_UDT0);

		/* Back to 20MHz mode */
		urtwn_set_chan(sc, ic->ic_curchan,
		    IEEE80211_HTINFO_2NDCHAN_NONE);

		if (ic->ic_opmode == IEEE80211_M_IBSS ||
		    ic->ic_opmode == IEEE80211_M_HOSTAP) {
			/* Stop BCN */
			urtwn_write_1(sc, R92C_BCN_CTRL,
			    urtwn_read_1(sc, R92C_BCN_CTRL) &
			    ~(R92C_BCN_CTRL_EN_BCN | R92C_BCN_CTRL_TXBCN_RPT));
		}

		/* Reset EDCA parameters. */
		urtwn_write_4(sc, R92C_EDCA_VO_PARAM, 0x002f3217);
		urtwn_write_4(sc, R92C_EDCA_VI_PARAM, 0x005e4317);
		urtwn_write_4(sc, R92C_EDCA_BE_PARAM, 0x00105320);
		urtwn_write_4(sc, R92C_EDCA_BK_PARAM, 0x0000a444);

		/* flush all cam entries */
		urtwn_cam_init(sc);
		break;
	}

	switch (nstate) {
	case IEEE80211_S_INIT:
		/* Turn link LED off. */
		urtwn_set_led(sc, URTWN_LED_LINK, 0);
		break;

	case IEEE80211_S_SCAN:
		if (ostate != IEEE80211_S_SCAN) {
			/*
			 * Begin of scanning
			 */

			/* Set gain for scanning. */
			reg = urtwn_bb_read(sc, R92C_OFDM0_AGCCORE1(0));
			reg = RW(reg, R92C_OFDM0_AGCCORE1_GAIN, 0x20);
			urtwn_bb_write(sc, R92C_OFDM0_AGCCORE1(0), reg);

			if (!ISSET(sc->chip, URTWN_CHIP_88E)) {
				reg = urtwn_bb_read(sc, R92C_OFDM0_AGCCORE1(1));
				reg = RW(reg, R92C_OFDM0_AGCCORE1_GAIN, 0x20);
				urtwn_bb_write(sc, R92C_OFDM0_AGCCORE1(1), reg);
			}

			/* Set media status to 'No Link'. */
			urtwn_set_nettype0_msr(sc, R92C_CR_NETTYPE_NOLINK);

			/* Allow Rx from any BSSID. */
			urtwn_write_4(sc, R92C_RCR,
			    urtwn_read_4(sc, R92C_RCR) &
			    ~(R92C_RCR_CBSSID_DATA | R92C_RCR_CBSSID_BCN));

			/* Stop Rx of data frames. */
			urtwn_write_2(sc, R92C_RXFLTMAP2, 0);

			/* Disable update TSF */
			urtwn_write_1(sc, R92C_BCN_CTRL,
			    urtwn_read_1(sc, R92C_BCN_CTRL) |
			      R92C_BCN_CTRL_DIS_TSF_UDT0);
		}

		/* Make link LED blink during scan. */
		urtwn_set_led(sc, URTWN_LED_LINK, !sc->ledlink);

		/* Pause AC Tx queues. */
		urtwn_write_1(sc, R92C_TXPAUSE,
		    urtwn_read_1(sc, R92C_TXPAUSE) | 0x0f);

		urtwn_set_chan(sc, ic->ic_curchan,
		    IEEE80211_HTINFO_2NDCHAN_NONE);

		/* Start periodic scan. */
		if (!sc->sc_dying)
			callout_schedule(&sc->sc_scan_to, hz / 5);
		break;

	case IEEE80211_S_AUTH:
		/* Set initial gain under link. */
		reg = urtwn_bb_read(sc, R92C_OFDM0_AGCCORE1(0));
		reg = RW(reg, R92C_OFDM0_AGCCORE1_GAIN, 0x32);
		urtwn_bb_write(sc, R92C_OFDM0_AGCCORE1(0), reg);

		if (!ISSET(sc->chip, URTWN_CHIP_88E)) {
			reg = urtwn_bb_read(sc, R92C_OFDM0_AGCCORE1(1));
			reg = RW(reg, R92C_OFDM0_AGCCORE1_GAIN, 0x32);
			urtwn_bb_write(sc, R92C_OFDM0_AGCCORE1(1), reg);
		}

		/* Set media status to 'No Link'. */
		urtwn_set_nettype0_msr(sc, R92C_CR_NETTYPE_NOLINK);

		/* Allow Rx from any BSSID. */
		urtwn_write_4(sc, R92C_RCR,
		    urtwn_read_4(sc, R92C_RCR) &
		      ~(R92C_RCR_CBSSID_DATA | R92C_RCR_CBSSID_BCN));

		urtwn_set_chan(sc, ic->ic_curchan,
		    IEEE80211_HTINFO_2NDCHAN_NONE);
		break;

	case IEEE80211_S_ASSOC:
		break;

	case IEEE80211_S_RUN:
		ni = ic->ic_bss;

		/* XXX: Set 20MHz mode */
		urtwn_set_chan(sc, ic->ic_curchan,
		    IEEE80211_HTINFO_2NDCHAN_NONE);

		if (ic->ic_opmode == IEEE80211_M_MONITOR) {
			/* Back to 20MHz mode */
			urtwn_set_chan(sc, ic->ic_curchan,
			    IEEE80211_HTINFO_2NDCHAN_NONE);

			/* Set media status to 'No Link'. */
			urtwn_set_nettype0_msr(sc, R92C_CR_NETTYPE_NOLINK);

			/* Enable Rx of data frames. */
			urtwn_write_2(sc, R92C_RXFLTMAP2, 0xffff);

			/* Allow Rx from any BSSID. */
			urtwn_write_4(sc, R92C_RCR,
			    urtwn_read_4(sc, R92C_RCR) &
			    ~(R92C_RCR_CBSSID_DATA | R92C_RCR_CBSSID_BCN));

			/* Accept Rx data/control/management frames */
			urtwn_write_4(sc, R92C_RCR,
			    urtwn_read_4(sc, R92C_RCR) |
			    R92C_RCR_ADF | R92C_RCR_ACF | R92C_RCR_AMF);

			/* Turn link LED on. */
			urtwn_set_led(sc, URTWN_LED_LINK, 1);
			break;
		}

		/* Set media status to 'Associated'. */
		urtwn_set_nettype0_msr(sc, urtwn_get_nettype(sc));

		/* Set BSSID. */
		urtwn_write_4(sc, R92C_BSSID + 0, LE_READ_4(&ni->ni_bssid[0]));
		urtwn_write_4(sc, R92C_BSSID + 4, LE_READ_2(&ni->ni_bssid[4]));

		if (ic->ic_curmode == IEEE80211_MODE_11B) {
			urtwn_write_1(sc, R92C_INIRTS_RATE_SEL, 0);
		} else {
			/* 802.11b/g */
			urtwn_write_1(sc, R92C_INIRTS_RATE_SEL, 3);
		}

		/* Enable Rx of data frames. */
		urtwn_write_2(sc, R92C_RXFLTMAP2, 0xffff);

		/* Set beacon interval. */
		urtwn_write_2(sc, R92C_BCN_INTERVAL, ni->ni_intval);

		msr = urtwn_read_1(sc, R92C_MSR);
		msr &= R92C_MSR_MASK;
		switch (ic->ic_opmode) {
		case IEEE80211_M_STA:
			/* Allow Rx from our BSSID only. */
			urtwn_write_4(sc, R92C_RCR,
			    urtwn_read_4(sc, R92C_RCR) |
			      R92C_RCR_CBSSID_DATA | R92C_RCR_CBSSID_BCN);

			/* Enable TSF synchronization. */
			urtwn_tsf_sync_enable(sc);

			msr |= R92C_MSR_INFRA;
			break;
		case IEEE80211_M_HOSTAP:
			urtwn_write_2(sc, R92C_BCNTCFG, 0x000f);

			/* Allow Rx from any BSSID. */
			urtwn_write_4(sc, R92C_RCR,
			    urtwn_read_4(sc, R92C_RCR) &
			    ~(R92C_RCR_CBSSID_DATA | R92C_RCR_CBSSID_BCN));

			/* Reset TSF timer to zero. */
			reg = urtwn_read_4(sc, R92C_TCR);
			reg &= ~0x01;
			urtwn_write_4(sc, R92C_TCR, reg);
			reg |= 0x01;
			urtwn_write_4(sc, R92C_TCR, reg);

			msr |= R92C_MSR_AP;
			break;
		default:
			msr |= R92C_MSR_ADHOC;
			break;
		}
		urtwn_write_1(sc, R92C_MSR, msr);

		sifs_time = 10;
		urtwn_write_1(sc, R92C_SIFS_CCK + 1, sifs_time);
		urtwn_write_1(sc, R92C_SIFS_OFDM + 1, sifs_time);
		urtwn_write_1(sc, R92C_SPEC_SIFS + 1, sifs_time);
		urtwn_write_1(sc, R92C_MAC_SPEC_SIFS + 1, sifs_time);
		urtwn_write_1(sc, R92C_R2T_SIFS + 1, sifs_time);
		urtwn_write_1(sc, R92C_T2T_SIFS + 1, sifs_time);

		/* Initialize rate adaptation. */
		if (ISSET(sc->chip, URTWN_CHIP_88E) ||
		    ISSET(sc->chip, URTWN_CHIP_92EU))
			ni->ni_txrate = ni->ni_rates.rs_nrates - 1;
		else
			urtwn_ra_init(sc);

		/* Turn link LED on. */
		urtwn_set_led(sc, URTWN_LED_LINK, 1);

		/* Reset average RSSI. */
		sc->avg_pwdb = -1;

		/* Reset temperature calibration state machine. */
		sc->thcal_state = 0;
		sc->thcal_lctemp = 0;

		/* Start periodic calibration. */
		if (!sc->sc_dying)
			callout_schedule(&sc->sc_calib_to, hz);
		break;
	}

	(*sc->sc_newstate)(ic, nstate, cmd->arg);

	mutex_exit(&sc->sc_write_mtx);
	splx(s);
}

static int
urtwn_wme_update(struct ieee80211com *ic)
{
	struct urtwn_softc *sc = ic->ic_ifp->if_softc;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	/* don't override default WME values if WME is not actually enabled */
	if (!(ic->ic_flags & IEEE80211_F_WME))
		return 0;

	/* Do it in a process context. */
	urtwn_do_async(sc, urtwn_wme_update_cb, NULL, 0);
	return 0;
}

static void
urtwn_wme_update_cb(struct urtwn_softc *sc, void *arg)
{
	static const uint16_t ac2reg[WME_NUM_AC] = {
		R92C_EDCA_BE_PARAM,
		R92C_EDCA_BK_PARAM,
		R92C_EDCA_VI_PARAM,
		R92C_EDCA_VO_PARAM
	};
	struct ieee80211com *ic = &sc->sc_ic;
	const struct wmeParams *wmep;
	int ac, aifs, slottime;
	int s;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();
	DPRINTFN(DBG_STM, "called", 0, 0, 0, 0);

	s = splnet();
	mutex_enter(&sc->sc_write_mtx);
	slottime = (ic->ic_flags & IEEE80211_F_SHSLOT) ? 9 : 20;
	for (ac = 0; ac < WME_NUM_AC; ac++) {
		wmep = &ic->ic_wme.wme_chanParams.cap_wmeParams[ac];
		/* AIFS[AC] = AIFSN[AC] * aSlotTime + aSIFSTime. */
		aifs = wmep->wmep_aifsn * slottime + 10;
		urtwn_write_4(sc, ac2reg[ac],
		    SM(R92C_EDCA_PARAM_TXOP, wmep->wmep_txopLimit) |
		    SM(R92C_EDCA_PARAM_ECWMIN, wmep->wmep_logcwmin) |
		    SM(R92C_EDCA_PARAM_ECWMAX, wmep->wmep_logcwmax) |
		    SM(R92C_EDCA_PARAM_AIFS, aifs));
	}
	mutex_exit(&sc->sc_write_mtx);
	splx(s);
}

static void
urtwn_update_avgrssi(struct urtwn_softc *sc, int rate, int8_t rssi)
{
	int pwdb;

	URTWNHIST_FUNC();
	URTWNHIST_CALLARGS("rate=%jd, rsst=%jd", rate, rssi, 0, 0);

	/* Convert antenna signal to percentage. */
	if (rssi <= -100 || rssi >= 20)
		pwdb = 0;
	else if (rssi >= 0)
		pwdb = 100;
	else
		pwdb = 100 + rssi;
	if (!ISSET(sc->chip, URTWN_CHIP_88E)) {
		if (rate <= 3) {
			/* CCK gain is smaller than OFDM/MCS gain. */
			pwdb += 6;
			if (pwdb > 100)
				pwdb = 100;
			if (pwdb <= 14)
				pwdb -= 4;
			else if (pwdb <= 26)
				pwdb -= 8;
			else if (pwdb <= 34)
				pwdb -= 6;
			else if (pwdb <= 42)
				pwdb -= 2;
		}
	}
	if (sc->avg_pwdb == -1)	/* Init. */
		sc->avg_pwdb = pwdb;
	else if (sc->avg_pwdb < pwdb)
		sc->avg_pwdb = ((sc->avg_pwdb * 19 + pwdb) / 20) + 1;
	else
		sc->avg_pwdb = ((sc->avg_pwdb * 19 + pwdb) / 20);

	DPRINTFN(DBG_RF, "rate=%jd rssi=%jd PWDB=%jd EMA=%jd",
	    rate, rssi, pwdb, sc->avg_pwdb);
}

static int8_t
urtwn_get_rssi(struct urtwn_softc *sc, int rate, void *physt)
{
	static const int8_t cckoff[] = { 16, -12, -26, -46 };
	struct r92c_rx_phystat *phy;
	struct r92c_rx_cck *cck;
	uint8_t rpt;
	int8_t rssi;

	URTWNHIST_FUNC();
	URTWNHIST_CALLARGS("rate=%jd", rate, 0, 0, 0);

	if (rate <= 3) {
		cck = (struct r92c_rx_cck *)physt;
		if (ISSET(sc->sc_flags, URTWN_FLAG_CCK_HIPWR)) {
			rpt = (cck->agc_rpt >> 5) & 0x3;
			rssi = (cck->agc_rpt & 0x1f) << 1;
		} else {
			rpt = (cck->agc_rpt >> 6) & 0x3;
			rssi = cck->agc_rpt & 0x3e;
		}
		rssi = cckoff[rpt] - rssi;
	} else {	/* OFDM/HT. */
		phy = (struct r92c_rx_phystat *)physt;
		rssi = ((le32toh(phy->phydw1) >> 1) & 0x7f) - 110;
	}
	return rssi;
}

static int8_t
urtwn_r88e_get_rssi(struct urtwn_softc *sc, int rate, void *physt)
{
	struct r92c_rx_phystat *phy;
	struct r88e_rx_cck *cck;
	uint8_t cck_agc_rpt, lna_idx, vga_idx;
	int8_t rssi;

	URTWNHIST_FUNC();
	URTWNHIST_CALLARGS("rate=%jd", rate, 0, 0, 0);

	rssi = 0;
	if (rate <= 3) {
		cck = (struct r88e_rx_cck *)physt;
		cck_agc_rpt = cck->agc_rpt;
		lna_idx = (cck_agc_rpt & 0xe0) >> 5;
		vga_idx = cck_agc_rpt & 0x1f;
		switch (lna_idx) {
		case 7:
			if (vga_idx <= 27)
				rssi = -100 + 2* (27 - vga_idx);
			else
				rssi = -100;
			break;
		case 6:
			rssi = -48 + 2 * (2 - vga_idx);
			break;
		case 5:
			rssi = -42 + 2 * (7 - vga_idx);
			break;
		case 4:
			rssi = -36 + 2 * (7 - vga_idx);
			break;
		case 3:
			rssi = -24 + 2 * (7 - vga_idx);
			break;
		case 2:
			rssi = -12 + 2 * (5 - vga_idx);
			break;
		case 1:
			rssi = 8 - (2 * vga_idx);
			break;
		case 0:
			rssi = 14 - (2 * vga_idx);
			break;
		}
		rssi += 6;
	} else {	/* OFDM/HT. */
		phy = (struct r92c_rx_phystat *)physt;
		rssi = ((le32toh(phy->phydw1) >> 1) & 0x7f) - 110;
	}
	return rssi;
}

static void
urtwn_rx_frame(struct urtwn_softc *sc, uint8_t *buf, int pktlen)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ifnet *ifp = ic->ic_ifp;
	struct ieee80211_frame *wh;
	struct ieee80211_node *ni;
	struct r92c_rx_desc_usb *stat;
	uint32_t rxdw0, rxdw3;
	struct mbuf *m;
	uint8_t rate;
	int8_t rssi = 0;
	int s, infosz;

	URTWNHIST_FUNC();
	URTWNHIST_CALLARGS("buf=%jp, pktlen=%#jd", (uintptr_t)buf, pktlen, 0, 0);

	stat = (struct r92c_rx_desc_usb *)buf;
	rxdw0 = le32toh(stat->rxdw0);
	rxdw3 = le32toh(stat->rxdw3);

	if (__predict_false(rxdw0 & (R92C_RXDW0_CRCERR | R92C_RXDW0_ICVERR))) {
		/*
		 * This should not happen since we setup our Rx filter
		 * to not receive these frames.
		 */
		DPRINTFN(DBG_RX, "CRC error", 0, 0, 0, 0);
		if_statinc(ifp, if_ierrors);
		return;
	}
	/*
	 * XXX: This will drop most control packets.  Do we really
	 * want this in IEEE80211_M_MONITOR mode?
	 */
//	if (__predict_false(pktlen < (int)sizeof(*wh))) {
	if (__predict_false(pktlen < (int)sizeof(struct ieee80211_frame_ack))) {
		DPRINTFN(DBG_RX, "packet too short %jd", pktlen, 0, 0, 0);
		ic->ic_stats.is_rx_tooshort++;
		if_statinc(ifp, if_ierrors);
		return;
	}
	if (__predict_false(pktlen > MCLBYTES)) {
		DPRINTFN(DBG_RX, "packet too big %jd", pktlen, 0, 0, 0);
		if_statinc(ifp, if_ierrors);
		return;
	}

	rate = MS(rxdw3, R92C_RXDW3_RATE);
	infosz = MS(rxdw0, R92C_RXDW0_INFOSZ) * 8;

	/* Get RSSI from PHY status descriptor if present. */
	if (infosz != 0 && (rxdw0 & R92C_RXDW0_PHYST)) {
		if (!ISSET(sc->chip, URTWN_CHIP_92C))
			rssi = urtwn_r88e_get_rssi(sc, rate, &stat[1]);
		else
			rssi = urtwn_get_rssi(sc, rate, &stat[1]);
		/* Update our average RSSI. */
		urtwn_update_avgrssi(sc, rate, rssi);
	}

	DPRINTFN(DBG_RX, "Rx frame len=%jd rate=%jd infosz=%jd rssi=%jd",
	    pktlen, rate, infosz, rssi);

	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (__predict_false(m == NULL)) {
		aprint_error_dev(sc->sc_dev, "couldn't allocate rx mbuf\n");
		ic->ic_stats.is_rx_nobuf++;
		if_statinc(ifp, if_ierrors);
		return;
	}
	MCLAIM(m, &sc->sc_ec.ec_rx_mowner);
	if (pktlen > (int)MHLEN) {
		MCLGET(m, M_DONTWAIT);
		if (__predict_false(!(m->m_flags & M_EXT))) {
			aprint_error_dev(sc->sc_dev,
			    "couldn't allocate rx mbuf cluster\n");
			m_freem(m);
			ic->ic_stats.is_rx_nobuf++;
			if_statinc(ifp, if_ierrors);
			return;
		}
	}

	/* Finalize mbuf. */
	m_set_rcvif(m, ifp);
	wh = (struct ieee80211_frame *)((uint8_t *)&stat[1] + infosz);
	memcpy(mtod(m, uint8_t *), wh, pktlen);
	m->m_pkthdr.len = m->m_len = pktlen;

	s = splnet();
	if (__predict_false(sc->sc_drvbpf != NULL)) {
		struct urtwn_rx_radiotap_header *tap = &sc->sc_rxtap;

		tap->wr_flags = 0;
		if (!(rxdw3 & R92C_RXDW3_HT)) {
			switch (rate) {
			/* CCK. */
			case  0: tap->wr_rate =   2; break;
			case  1: tap->wr_rate =   4; break;
			case  2: tap->wr_rate =  11; break;
			case  3: tap->wr_rate =  22; break;
			/* OFDM. */
			case  4: tap->wr_rate =  12; break;
			case  5: tap->wr_rate =  18; break;
			case  6: tap->wr_rate =  24; break;
			case  7: tap->wr_rate =  36; break;
			case  8: tap->wr_rate =  48; break;
			case  9: tap->wr_rate =  72; break;
			case 10: tap->wr_rate =  96; break;
			case 11: tap->wr_rate = 108; break;
			}
		} else if (rate >= 12) {	/* MCS0~15. */
			/* Bit 7 set means HT MCS instead of rate. */
			tap->wr_rate = 0x80 | (rate - 12);
		}
		tap->wr_dbm_antsignal = rssi;
		tap->wr_chan_freq = htole16(ic->ic_curchan->ic_freq);
		tap->wr_chan_flags = htole16(ic->ic_curchan->ic_flags);

		bpf_mtap2(sc->sc_drvbpf, tap, sc->sc_rxtap_len, m, BPF_D_IN);
	}

	ni = ieee80211_find_rxnode(ic, (struct ieee80211_frame_min *)wh);

	/* push the frame up to the 802.11 stack */
	ieee80211_input(ic, m, ni, rssi, 0);

	/* Node is no longer needed. */
	ieee80211_free_node(ni);

	splx(s);
}

static void
urtwn_rxeof(struct usbd_xfer *xfer, void *priv, usbd_status status)
{
	struct urtwn_rx_data *data = priv;
	struct urtwn_softc *sc = data->sc;
	struct r92c_rx_desc_usb *stat;
	size_t pidx = data->pidx;
	uint32_t rxdw0;
	uint8_t *buf;
	int len, totlen, pktlen, infosz, npkts;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();
	DPRINTFN(DBG_RX, "status=%jd", status, 0, 0, 0);

	mutex_enter(&sc->sc_rx_mtx);
	TAILQ_REMOVE(&sc->rx_free_list[pidx], data, next);
	TAILQ_INSERT_TAIL(&sc->rx_free_list[pidx], data, next);
	/* Put this Rx buffer back to our free list. */
	mutex_exit(&sc->sc_rx_mtx);

	if (__predict_false(status != USBD_NORMAL_COMPLETION)) {
		if (status == USBD_STALLED)
			usbd_clear_endpoint_stall_async(sc->rx_pipe[pidx]);
		else if (status != USBD_CANCELLED)
			goto resubmit;
		return;
	}
	usbd_get_xfer_status(xfer, NULL, NULL, &len, NULL);

	if (__predict_false(len < (int)sizeof(*stat))) {
		DPRINTFN(DBG_RX, "xfer too short %jd", len, 0, 0, 0);
		goto resubmit;
	}
	buf = data->buf;

	/* Get the number of encapsulated frames. */
	stat = (struct r92c_rx_desc_usb *)buf;
	if (ISSET(sc->chip, URTWN_CHIP_92EU))
		npkts = MS(le32toh(stat->rxdw2), R92E_RXDW2_PKTCNT);
	else
		npkts = MS(le32toh(stat->rxdw2), R92C_RXDW2_PKTCNT);
	DPRINTFN(DBG_RX, "Rx %jd frames in one chunk", npkts, 0, 0, 0);

	if (npkts != 0)
		rnd_add_uint32(&sc->rnd_source, npkts);

	/* Process all of them. */
	while (npkts-- > 0) {
		if (__predict_false(len < (int)sizeof(*stat))) {
			DPRINTFN(DBG_RX, "len(%jd) is short than header",
			    len, 0, 0, 0);
			break;
		}
		stat = (struct r92c_rx_desc_usb *)buf;
		rxdw0 = le32toh(stat->rxdw0);

		pktlen = MS(rxdw0, R92C_RXDW0_PKTLEN);
		if (__predict_false(pktlen == 0)) {
			DPRINTFN(DBG_RX, "pktlen is 0 byte", 0, 0, 0, 0);
			break;
		}

		infosz = MS(rxdw0, R92C_RXDW0_INFOSZ) * 8;

		/* Make sure everything fits in xfer. */
		totlen = sizeof(*stat) + infosz + pktlen;
		if (__predict_false(totlen > len)) {
			DPRINTFN(DBG_RX, "pktlen (%jd+%jd+%jd) > %jd",
			    (int)sizeof(*stat), infosz, pktlen, len);
			break;
		}

		/* Process 802.11 frame. */
		urtwn_rx_frame(sc, buf, pktlen);

		/* Next chunk is 128-byte aligned. */
		totlen = roundup2(totlen, 128);
		buf += totlen;
		len -= totlen;
	}

 resubmit:
	/* Setup a new transfer. */
	usbd_setup_xfer(xfer, data, data->buf, URTWN_RXBUFSZ,
	    USBD_SHORT_XFER_OK, USBD_NO_TIMEOUT, urtwn_rxeof);
	(void)usbd_transfer(xfer);
}

static void
urtwn_put_tx_data(struct urtwn_softc *sc, struct urtwn_tx_data *data)
{
	size_t pidx = data->pidx;

	mutex_enter(&sc->sc_tx_mtx);
	/* Put this Tx buffer back to our free list. */
	TAILQ_INSERT_TAIL(&sc->tx_free_list[pidx], data, next);
	mutex_exit(&sc->sc_tx_mtx);
}

static void
urtwn_txeof(struct usbd_xfer *xfer, void *priv, usbd_status status)
{
	struct urtwn_tx_data *data = priv;
	struct urtwn_softc *sc = data->sc;
	struct ifnet *ifp = &sc->sc_if;
	size_t pidx = data->pidx;
	int s;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();
	DPRINTFN(DBG_TX, "status=%jd", status, 0, 0, 0);

	urtwn_put_tx_data(sc, data);

	s = splnet();
	sc->tx_timer = 0;
	ifp->if_flags &= ~IFF_OACTIVE;

	if (__predict_false(status != USBD_NORMAL_COMPLETION)) {
		if (status != USBD_NOT_STARTED && status != USBD_CANCELLED) {
			if (status == USBD_STALLED) {
				struct usbd_pipe *pipe = sc->tx_pipe[pidx];
				usbd_clear_endpoint_stall_async(pipe);
			}
			device_printf(sc->sc_dev, "transmit failed, %s\n",
			    usbd_errstr(status));
			if_statinc(ifp, if_oerrors);
		}
		splx(s);
		return;
	}

	if_statinc(ifp, if_opackets);
	urtwn_start(ifp);
	splx(s);

}

static int
urtwn_tx(struct urtwn_softc *sc, struct mbuf *m, struct ieee80211_node *ni,
    struct urtwn_tx_data *data)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_frame *wh;
	struct ieee80211_key *k = NULL;
	struct r92c_tx_desc_usb *txd;
	size_t i, padsize, xferlen, txd_len;
	uint16_t seq, sum;
	uint8_t raid, type, tid;
	int s, hasqos, error;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	wh = mtod(m, struct ieee80211_frame *);
	type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
	txd_len = sizeof(*txd);

	if (!ISSET(sc->chip, URTWN_CHIP_92EU))
		txd_len = 32;

	if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
		k = ieee80211_crypto_encap(ic, ni, m);
		if (k == NULL) {
			urtwn_put_tx_data(sc, data);
			m_free(m);
			return ENOBUFS;
		}

		/* packet header may have moved, reset our local pointer */
		wh = mtod(m, struct ieee80211_frame *);
	}

	if (__predict_false(sc->sc_drvbpf != NULL)) {
		struct urtwn_tx_radiotap_header *tap = &sc->sc_txtap;

		tap->wt_flags = 0;
		tap->wt_chan_freq = htole16(ic->ic_curchan->ic_freq);
		tap->wt_chan_flags = htole16(ic->ic_curchan->ic_flags);
		if (wh->i_fc[1] & IEEE80211_FC1_WEP)
			tap->wt_flags |= IEEE80211_RADIOTAP_F_WEP;

		/* XXX: set tap->wt_rate? */

		bpf_mtap2(sc->sc_drvbpf, tap, sc->sc_txtap_len, m, BPF_D_OUT);
	}

	/* non-qos data frames */
	tid = R92C_TXDW1_QSEL_BE;
	if ((hasqos = ieee80211_has_qos(wh))) {
		/* data frames in 11n mode */
		struct ieee80211_qosframe *qwh = (void *)wh;
		tid = qwh->i_qos[0] & IEEE80211_QOS_TID;
	} else if (type != IEEE80211_FC0_TYPE_DATA) {
		tid = R92C_TXDW1_QSEL_MGNT;
	}

	if (((txd_len + m->m_pkthdr.len) % 64) == 0) /* XXX: 64 */
		padsize = 8;
	else
		padsize = 0;

	if (ISSET(sc->chip, URTWN_CHIP_92EU))
		padsize = 0;

	/* Fill Tx descriptor. */
	txd = (struct r92c_tx_desc_usb *)data->buf;
	memset(txd, 0, txd_len + padsize);

	txd->txdw0 |= htole32(
	    SM(R92C_TXDW0_PKTLEN, m->m_pkthdr.len) |
	    SM(R92C_TXDW0_OFFSET, txd_len));
	if (!ISSET(sc->chip, URTWN_CHIP_92EU)) {
		txd->txdw0 |= htole32(
		    R92C_TXDW0_OWN | R92C_TXDW0_FSG | R92C_TXDW0_LSG);
	}

	if (IEEE80211_IS_MULTICAST(wh->i_addr1))
		txd->txdw0 |= htole32(R92C_TXDW0_BMCAST);

	/* fix pad field */
	if (padsize > 0) {
		DPRINTFN(DBG_TX, "padding: size=%jd", padsize, 0, 0, 0);
		txd->txdw1 |= htole32(SM(R92C_TXDW1_PKTOFF, (padsize / 8)));
	}

	if (!IEEE80211_IS_MULTICAST(wh->i_addr1) &&
	    type == IEEE80211_FC0_TYPE_DATA) {
		if (ic->ic_curmode == IEEE80211_MODE_11B)
			raid = R92C_RAID_11B;
		else
			raid = R92C_RAID_11BG;
		DPRINTFN(DBG_TX, "data packet: tid=%jd, raid=%jd",
		    tid, raid, 0, 0);

		if (!ISSET(sc->chip, URTWN_CHIP_92C)) {
			txd->txdw1 |= htole32(
			    SM(R88E_TXDW1_MACID, RTWN_MACID_BSS) |
			    SM(R92C_TXDW1_QSEL, tid) |
			    SM(R92C_TXDW1_RAID, raid) |
			    R92C_TXDW1_AGGBK);
		} else
			txd->txdw1 |= htole32(
			    SM(R92C_TXDW1_MACID, RTWN_MACID_BSS) |
			    SM(R92C_TXDW1_QSEL, tid) |
			    SM(R92C_TXDW1_RAID, raid) |
			    R92C_TXDW1_AGGBK);

		if (ISSET(sc->chip, URTWN_CHIP_88E))
			txd->txdw2 |= htole32(R88E_TXDW2_AGGBK);
		if (ISSET(sc->chip, URTWN_CHIP_92EU))
			txd->txdw3 |= htole32(R92E_TXDW3_AGGBK);

		if (hasqos) {
			txd->txdw4 |= htole32(R92C_TXDW4_QOS);
		}

		if (ic->ic_flags & IEEE80211_F_USEPROT) {
			/* for 11g */
			if (ic->ic_protmode == IEEE80211_PROT_CTSONLY) {
				txd->txdw4 |= htole32(R92C_TXDW4_CTS2SELF |
				    R92C_TXDW4_HWRTSEN);
			} else if (ic->ic_protmode == IEEE80211_PROT_RTSCTS) {
				txd->txdw4 |= htole32(R92C_TXDW4_RTSEN |
				    R92C_TXDW4_HWRTSEN);
			}
		}
		/* Send RTS at OFDM24. */
		txd->txdw4 |= htole32(SM(R92C_TXDW4_RTSRATE, 8));
		txd->txdw5 |= htole32(0x0001ff00);
		/* Send data at OFDM54. */
		if (ISSET(sc->chip, URTWN_CHIP_88E))
			txd->txdw5 |= htole32(0x13 & 0x3f);
		else
			txd->txdw5 |= htole32(SM(R92C_TXDW5_DATARATE, 11));
	} else if (type == IEEE80211_FC0_TYPE_MGT) {
		DPRINTFN(DBG_TX, "mgmt packet", 0, 0, 0, 0);
		txd->txdw1 |= htole32(
		    SM(R92C_TXDW1_MACID, RTWN_MACID_BSS) |
		    SM(R92C_TXDW1_QSEL, R92C_TXDW1_QSEL_MGNT) |
		    SM(R92C_TXDW1_RAID, R92C_RAID_11B));

		/* Force CCK1. */
		txd->txdw4 |= htole32(R92C_TXDW4_DRVRATE);
		/* Use 1Mbps */
		txd->txdw5 |= htole32(SM(R92C_TXDW5_DATARATE, 0));
	} else {
		/* broadcast or multicast packets */
		DPRINTFN(DBG_TX, "bc or mc packet", 0, 0, 0, 0);
		txd->txdw1 |= htole32(
		    SM(R92C_TXDW1_MACID, RTWN_MACID_BC) |
		    SM(R92C_TXDW1_RAID, R92C_RAID_11B));

		/* Force CCK1. */
		txd->txdw4 |= htole32(R92C_TXDW4_DRVRATE);
		/* Use 1Mbps */
		txd->txdw5 |= htole32(SM(R92C_TXDW5_DATARATE, 0));
	}
	/* Set sequence number */
	seq = LE_READ_2(&wh->i_seq[0]) >> IEEE80211_SEQ_SEQ_SHIFT;
	if (!ISSET(sc->chip, URTWN_CHIP_92EU)) {
		txd->txdseq |= htole16(seq);

		if (!hasqos) {
			/* Use HW sequence numbering for non-QoS frames. */
			txd->txdw4  |= htole32(R92C_TXDW4_HWSEQ);
			txd->txdseq |= htole16(R92C_HWSEQ_EN);
		}
	} else {
		txd->txdseq2 |= htole16((seq & R92E_HWSEQ_MASK) <<
		    R92E_HWSEQ_SHIFT);
		if (!hasqos) {
			/* Use HW sequence numbering for non-QoS frames. */
			txd->txdw4  |= htole32(R92C_TXDW4_HWSEQ);
			txd->txdw7 |= htole16(R92C_HWSEQ_EN);
		}
	}

	/* Compute Tx descriptor checksum. */
	sum = 0;
	for (i = 0; i < R92C_TXDESC_SUMSIZE / 2; i++)
		sum ^= ((uint16_t *)txd)[i];
	txd->txdsum = sum;	/* NB: already little endian. */

	xferlen = txd_len + m->m_pkthdr.len + padsize;
	m_copydata(m, 0, m->m_pkthdr.len, (char *)&txd[0] + txd_len + padsize);

	s = splnet();
	usbd_setup_xfer(data->xfer, data, data->buf, xferlen,
	    USBD_FORCE_SHORT_XFER, URTWN_TX_TIMEOUT,
	    urtwn_txeof);
	error = usbd_transfer(data->xfer);
	if (__predict_false(error != USBD_NORMAL_COMPLETION &&
	    error != USBD_IN_PROGRESS)) {
		splx(s);
		DPRINTFN(DBG_TX, "transfer failed %jd", error, 0, 0, 0);
		return error;
	}
	splx(s);
	return 0;
}

struct urtwn_tx_data *
urtwn_get_tx_data(struct urtwn_softc *sc, size_t pidx)
{
	struct urtwn_tx_data *data = NULL;

	mutex_enter(&sc->sc_tx_mtx);
	if (!TAILQ_EMPTY(&sc->tx_free_list[pidx])) {
		data = TAILQ_FIRST(&sc->tx_free_list[pidx]);
		TAILQ_REMOVE(&sc->tx_free_list[pidx], data, next);
	}
	mutex_exit(&sc->sc_tx_mtx);

	return data;
}

static void
urtwn_start(struct ifnet *ifp)
{
	struct urtwn_softc *sc = ifp->if_softc;
	struct ieee80211com *ic = &sc->sc_ic;
	struct urtwn_tx_data *data;
	struct ether_header *eh;
	struct ieee80211_node *ni;
	struct mbuf *m;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	if ((ifp->if_flags & (IFF_RUNNING | IFF_OACTIVE)) != IFF_RUNNING)
		return;

	data = NULL;
	for (;;) {
		/* Send pending management frames first. */
		IF_POLL(&ic->ic_mgtq, m);
		if (m != NULL) {
			/* Use AC_VO for management frames. */

			data = urtwn_get_tx_data(sc, sc->ac2idx[WME_AC_VO]);

			if (data == NULL) {
				ifp->if_flags |= IFF_OACTIVE;
				DPRINTFN(DBG_TX, "empty tx_free_list",
				    0, 0, 0, 0);
				return;
			}
			IF_DEQUEUE(&ic->ic_mgtq, m);
			ni = M_GETCTX(m, struct ieee80211_node *);
			M_CLEARCTX(m);
			goto sendit;
		}
		if (ic->ic_state != IEEE80211_S_RUN)
			break;

		/* Encapsulate and send data frames. */
		IFQ_POLL(&ifp->if_snd, m);
		if (m == NULL)
			break;

		struct ieee80211_frame *wh = mtod(m, struct ieee80211_frame *);
		uint8_t type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
		uint8_t qid = WME_AC_BE;
		if (ieee80211_has_qos(wh)) {
			/* data frames in 11n mode */
			struct ieee80211_qosframe *qwh = (void *)wh;
			uint8_t tid = qwh->i_qos[0] & IEEE80211_QOS_TID;
			qid = TID_TO_WME_AC(tid);
		} else if (type != IEEE80211_FC0_TYPE_DATA) {
			qid = WME_AC_VO;
		}
		data = urtwn_get_tx_data(sc, sc->ac2idx[qid]);

		if (data == NULL) {
			ifp->if_flags |= IFF_OACTIVE;
			DPRINTFN(DBG_TX, "empty tx_free_list", 0, 0, 0, 0);
			return;
		}
		IFQ_DEQUEUE(&ifp->if_snd, m);

		if (m->m_len < (int)sizeof(*eh) &&
		    (m = m_pullup(m, sizeof(*eh))) == NULL) {
			device_printf(sc->sc_dev, "m_pullup failed\n");
			if_statinc(ifp, if_oerrors);
			urtwn_put_tx_data(sc, data);
			m_freem(m);
			continue;
		}
		eh = mtod(m, struct ether_header *);
		ni = ieee80211_find_txnode(ic, eh->ether_dhost);
		if (ni == NULL) {
			device_printf(sc->sc_dev,
			    "unable to find transmit node\n");
			if_statinc(ifp, if_oerrors);
			urtwn_put_tx_data(sc, data);
			m_freem(m);
			continue;
		}

		bpf_mtap(ifp, m, BPF_D_OUT);

		if ((m = ieee80211_encap(ic, m, ni)) == NULL) {
			ieee80211_free_node(ni);
			device_printf(sc->sc_dev,
			    "unable to encapsulate packet\n");
			if_statinc(ifp, if_oerrors);
			urtwn_put_tx_data(sc, data);
			m_freem(m);
			continue;
		}
 sendit:
		bpf_mtap3(ic->ic_rawbpf, m, BPF_D_OUT);

		if (urtwn_tx(sc, m, ni, data) != 0) {
			m_freem(m);
			ieee80211_free_node(ni);
			device_printf(sc->sc_dev,
			    "unable to transmit packet\n");
			if_statinc(ifp, if_oerrors);
			continue;
		}
		m_freem(m);
		ieee80211_free_node(ni);
		sc->tx_timer = 5;
		ifp->if_timer = 1;
	}
}

static void
urtwn_watchdog(struct ifnet *ifp)
{
	struct urtwn_softc *sc = ifp->if_softc;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	ifp->if_timer = 0;

	if (sc->tx_timer > 0) {
		if (--sc->tx_timer == 0) {
			device_printf(sc->sc_dev, "device timeout\n");
			/* urtwn_init(ifp); XXX needs a process context! */
			if_statinc(ifp, if_oerrors);
			return;
		}
		ifp->if_timer = 1;
	}
	ieee80211_watchdog(&sc->sc_ic);
}

static int
urtwn_ioctl(struct ifnet *ifp, u_long cmd, void *data)
{
	struct urtwn_softc *sc = ifp->if_softc;
	struct ieee80211com *ic = &sc->sc_ic;
	int s, error = 0;

	URTWNHIST_FUNC();
	URTWNHIST_CALLARGS("cmd=0x%08jx, data=%#jx", cmd, (uintptr_t)data,
	    0, 0);

	s = splnet();

	switch (cmd) {
	case SIOCSIFFLAGS:
		if ((error = ifioctl_common(ifp, cmd, data)) != 0)
			break;
		switch (ifp->if_flags & (IFF_UP | IFF_RUNNING)) {
		case IFF_UP | IFF_RUNNING:
			break;
		case IFF_UP:
			urtwn_init(ifp);
			break;
		case IFF_RUNNING:
			urtwn_stop(ifp, 1);
			break;
		case 0:
			break;
		}
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		if ((error = ether_ioctl(ifp, cmd, data)) == ENETRESET) {
			/* setup multicast filter, etc */
			error = 0;
		}
		break;

	case SIOCS80211CHANNEL:
		/*
		 * This allows for fast channel switching in monitor mode
		 * (used by kismet). In IBSS mode, we must explicitly reset
		 * the interface to generate a new beacon frame.
		 */
		error = ieee80211_ioctl(ic, cmd, data);
		if (error == ENETRESET &&
		    ic->ic_opmode == IEEE80211_M_MONITOR) {
			urtwn_set_chan(sc, ic->ic_curchan,
			    IEEE80211_HTINFO_2NDCHAN_NONE);
			error = 0;
		}
		break;

	default:
		error = ieee80211_ioctl(ic, cmd, data);
		break;
	}
	if (error == ENETRESET) {
		if ((ifp->if_flags & (IFF_UP | IFF_RUNNING)) ==
		    (IFF_UP | IFF_RUNNING) &&
		    ic->ic_roaming != IEEE80211_ROAMING_MANUAL) {
			urtwn_init(ifp);
		}
		error = 0;
	}

	splx(s);

	return error;
}

static __inline int
urtwn_power_on(struct urtwn_softc *sc)
{

	return sc->sc_power_on(sc);
}

static int
urtwn_r92c_power_on(struct urtwn_softc *sc)
{
	uint32_t reg;
	int ntries;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	/* Wait for autoload done bit. */
	for (ntries = 0; ntries < 1000; ntries++) {
		if (urtwn_read_1(sc, R92C_APS_FSMCO) & R92C_APS_FSMCO_PFM_ALDN)
			break;
		DELAY(5);
	}
	if (ntries == 1000) {
		aprint_error_dev(sc->sc_dev,
		    "timeout waiting for chip autoload\n");
		return ETIMEDOUT;
	}

	/* Unlock ISO/CLK/Power control register. */
	urtwn_write_1(sc, R92C_RSV_CTRL, 0);
	DELAY(5);
	/* Move SPS into PWM mode. */
	urtwn_write_1(sc, R92C_SPS0_CTRL, 0x2b);
	DELAY(5);

	reg = urtwn_read_1(sc, R92C_LDOV12D_CTRL);
	if (!(reg & R92C_LDOV12D_CTRL_LDV12_EN)) {
		urtwn_write_1(sc, R92C_LDOV12D_CTRL,
		    reg | R92C_LDOV12D_CTRL_LDV12_EN);
		DELAY(100);
		urtwn_write_1(sc, R92C_SYS_ISO_CTRL,
		    urtwn_read_1(sc, R92C_SYS_ISO_CTRL) &
		    ~R92C_SYS_ISO_CTRL_MD2PP);
	}

	/* Auto enable WLAN. */
	urtwn_write_2(sc, R92C_APS_FSMCO,
	    urtwn_read_2(sc, R92C_APS_FSMCO) | R92C_APS_FSMCO_APFM_ONMAC);
	for (ntries = 0; ntries < 1000; ntries++) {
		if (!(urtwn_read_2(sc, R92C_APS_FSMCO) &
		    R92C_APS_FSMCO_APFM_ONMAC))
			break;
		DELAY(100);
	}
	if (ntries == 1000) {
		aprint_error_dev(sc->sc_dev,
		    "timeout waiting for MAC auto ON\n");
		return ETIMEDOUT;
	}

	/* Enable radio, GPIO and LED functions. */
	KASSERT((R92C_APS_FSMCO_AFSM_HSUS | R92C_APS_FSMCO_PDN_EN |
	    R92C_APS_FSMCO_PFM_ALDN) == 0x0812);
	urtwn_write_2(sc, R92C_APS_FSMCO,
	    R92C_APS_FSMCO_AFSM_HSUS |
	    R92C_APS_FSMCO_PDN_EN |
	    R92C_APS_FSMCO_PFM_ALDN);

	/* Release RF digital isolation. */
	urtwn_write_2(sc, R92C_SYS_ISO_CTRL,
	    urtwn_read_2(sc, R92C_SYS_ISO_CTRL) & ~R92C_SYS_ISO_CTRL_DIOR);

	/* Initialize MAC. */
	urtwn_write_1(sc, R92C_APSD_CTRL,
	    urtwn_read_1(sc, R92C_APSD_CTRL) & ~R92C_APSD_CTRL_OFF);
	for (ntries = 0; ntries < 200; ntries++) {
		if (!(urtwn_read_1(sc, R92C_APSD_CTRL) &
		    R92C_APSD_CTRL_OFF_STATUS))
			break;
		DELAY(5);
	}
	if (ntries == 200) {
		aprint_error_dev(sc->sc_dev,
		    "timeout waiting for MAC initialization\n");
		return ETIMEDOUT;
	}

	/* Enable MAC DMA/WMAC/SCHEDULE/SEC blocks. */
	reg = urtwn_read_2(sc, R92C_CR);
	reg |= R92C_CR_HCI_TXDMA_EN | R92C_CR_HCI_RXDMA_EN |
	    R92C_CR_TXDMA_EN | R92C_CR_RXDMA_EN | R92C_CR_PROTOCOL_EN |
	    R92C_CR_SCHEDULE_EN | R92C_CR_MACTXEN | R92C_CR_MACRXEN |
	    R92C_CR_ENSEC;
	urtwn_write_2(sc, R92C_CR, reg);

	urtwn_write_1(sc, 0xfe10, 0x19);

	urtwn_delay_ms(sc, 1);

	return 0;
}

static int
urtwn_r92e_power_on(struct urtwn_softc *sc)
{
	uint32_t reg;
	uint32_t val;
	int ntries;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	/* Enable radio, GPIO and LED functions. */
	KASSERT((R92C_APS_FSMCO_AFSM_HSUS | R92C_APS_FSMCO_PDN_EN |
	    R92C_APS_FSMCO_PFM_ALDN) == 0x0812);
	urtwn_write_2(sc, R92C_APS_FSMCO,
	    R92C_APS_FSMCO_AFSM_HSUS |
	    R92C_APS_FSMCO_PDN_EN |
	    R92C_APS_FSMCO_PFM_ALDN);

	if (urtwn_read_4(sc, R92E_SYS_CFG1_8192E) & R92E_SPSLDO_SEL){
		/* LDO. */
		urtwn_write_1(sc, R92E_LDO_SWR_CTRL, 0xc3);
	}
	else	{
		urtwn_write_2(sc, R92C_SYS_SWR_CTRL2, urtwn_read_2(sc,
		    R92C_SYS_SWR_CTRL2) & 0xffff);
		urtwn_write_1(sc, R92E_LDO_SWR_CTRL, 0x83);
	}

	for (ntries = 0; ntries < 2; ntries++) {
		urtwn_write_1(sc, R92C_AFE_PLL_CTRL,
		    urtwn_read_1(sc, R92C_AFE_PLL_CTRL));
		urtwn_write_2(sc, R92C_AFE_CTRL4, urtwn_read_2(sc,
		    R92C_AFE_CTRL4));
	}

	/* Reset BB. */
	urtwn_write_1(sc, R92C_SYS_FUNC_EN,
	urtwn_read_1(sc, R92C_SYS_FUNC_EN) & ~(R92C_SYS_FUNC_EN_BBRSTB |
	    R92C_SYS_FUNC_EN_BB_GLB_RST));

	urtwn_write_1(sc, R92C_AFE_XTAL_CTRL + 2, urtwn_read_1(sc,
	    R92C_AFE_XTAL_CTRL + 2) | 0x80);

	/* Disable HWPDN. */
	urtwn_write_2(sc, R92C_APS_FSMCO, urtwn_read_2(sc,
	    R92C_APS_FSMCO) & ~R92C_APS_FSMCO_APDM_HPDN);

	/* Disable WL suspend. */
	urtwn_write_2(sc, R92C_APS_FSMCO, urtwn_read_2(sc,
	    R92C_APS_FSMCO) & ~(R92C_APS_FSMCO_AFSM_PCIE |
	    R92C_APS_FSMCO_AFSM_HSUS));

	urtwn_write_4(sc, R92C_APS_FSMCO, urtwn_read_4(sc,
	    R92C_APS_FSMCO) | R92C_APS_FSMCO_RDY_MACON);
	urtwn_write_2(sc, R92C_APS_FSMCO, urtwn_read_2(sc,
	    R92C_APS_FSMCO) | R92C_APS_FSMCO_APFM_ONMAC);
	for (ntries = 0; ntries < 10000; ntries++) {
		val = urtwn_read_2(sc, R92C_APS_FSMCO) &
		 R92C_APS_FSMCO_APFM_ONMAC;
		if (val == 0x0)
			break;
		DELAY(10);
	}
	if (ntries == 10000) {
		aprint_error_dev(sc->sc_dev,
		    "timeout waiting for chip power up\n");
		return ETIMEDOUT;
	}

	urtwn_write_2(sc, R92C_CR, 0x00);
	reg = urtwn_read_2(sc, R92C_CR);
	reg |= R92C_CR_HCI_TXDMA_EN | R92C_CR_HCI_RXDMA_EN |
	    R92C_CR_TXDMA_EN | R92C_CR_RXDMA_EN | R92C_CR_PROTOCOL_EN |
	    R92C_CR_SCHEDULE_EN | R92C_CR_ENSEC;
	urtwn_write_2(sc, R92C_CR, reg);

	return 0;
}

static int
urtwn_r88e_power_on(struct urtwn_softc *sc)
{
	uint32_t reg;
	uint8_t val;
	int ntries;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	/* Wait for power ready bit. */
	for (ntries = 0; ntries < 5000; ntries++) {
		val = urtwn_read_1(sc, 0x6) & 0x2;
		if (val == 0x2)
			break;
		DELAY(10);
	}
	if (ntries == 5000) {
		aprint_error_dev(sc->sc_dev,
		    "timeout waiting for chip power up\n");
		return ETIMEDOUT;
	}

	/* Reset BB. */
	urtwn_write_1(sc, R92C_SYS_FUNC_EN,
	urtwn_read_1(sc, R92C_SYS_FUNC_EN) & ~(R92C_SYS_FUNC_EN_BBRSTB |
	    R92C_SYS_FUNC_EN_BB_GLB_RST));

	urtwn_write_1(sc, 0x26, urtwn_read_1(sc, 0x26) | 0x80);

	/* Disable HWPDN. */
	urtwn_write_1(sc, 0x5, urtwn_read_1(sc, 0x5) & ~0x80);

	/* Disable WL suspend. */
	urtwn_write_1(sc, 0x5, urtwn_read_1(sc, 0x5) & ~0x18);

	urtwn_write_1(sc, 0x5, urtwn_read_1(sc, 0x5) | 0x1);
	for (ntries = 0; ntries < 5000; ntries++) {
		if (!(urtwn_read_1(sc, 0x5) & 0x1))
			break;
		DELAY(10);
	}
	if (ntries == 5000)
		return ETIMEDOUT;

	/* Enable LDO normal mode. */
	urtwn_write_1(sc, 0x23, urtwn_read_1(sc, 0x23) & ~0x10);

	/* Enable MAC DMA/WMAC/SCHEDULE/SEC blocks. */
	urtwn_write_2(sc, R92C_CR, 0);
	reg = urtwn_read_2(sc, R92C_CR);
	reg |= R92C_CR_HCI_TXDMA_EN | R92C_CR_HCI_RXDMA_EN |
	    R92C_CR_TXDMA_EN | R92C_CR_RXDMA_EN | R92C_CR_PROTOCOL_EN |
	    R92C_CR_SCHEDULE_EN | R92C_CR_ENSEC | R92C_CR_CALTMR_EN;
	urtwn_write_2(sc, R92C_CR, reg);

	return 0;
}

static int __noinline
urtwn_llt_init(struct urtwn_softc *sc)
{
	size_t i, page_count, pktbuf_count;
	uint32_t val;
	int error;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	if (sc->chip & URTWN_CHIP_88E)
		page_count = R88E_TX_PAGE_COUNT;
	else if (sc->chip & URTWN_CHIP_92EU)
		page_count = R92E_TX_PAGE_COUNT;
	else
		page_count = R92C_TX_PAGE_COUNT;
	if (sc->chip & URTWN_CHIP_88E)
		pktbuf_count = R88E_TXPKTBUF_COUNT;
	else if (sc->chip & URTWN_CHIP_92EU)
		pktbuf_count = R88E_TXPKTBUF_COUNT;
	else
		pktbuf_count = R92C_TXPKTBUF_COUNT;

	if (sc->chip & URTWN_CHIP_92EU) {
		val = urtwn_read_4(sc, R92E_AUTO_LLT) | R92E_AUTO_LLT_EN;
		urtwn_write_4(sc, R92E_AUTO_LLT, val);
		DELAY(100);
		val = urtwn_read_4(sc, R92E_AUTO_LLT);
		if (val & R92E_AUTO_LLT_EN)
			return EIO;
		return 0;
	}

	/* Reserve pages [0; page_count]. */
	for (i = 0; i < page_count; i++) {
		if ((error = urtwn_llt_write(sc, i, i + 1)) != 0)
			return error;
	}
	/* NB: 0xff indicates end-of-list. */
	if ((error = urtwn_llt_write(sc, i, 0xff)) != 0)
		return error;
	/*
	 * Use pages [page_count + 1; pktbuf_count - 1]
	 * as ring buffer.
	 */
	for (++i; i < pktbuf_count - 1; i++) {
		if ((error = urtwn_llt_write(sc, i, i + 1)) != 0)
			return error;
	}
	/* Make the last page point to the beginning of the ring buffer. */
	error = urtwn_llt_write(sc, i, pktbuf_count + 1);
	return error;
}

static void
urtwn_fw_reset(struct urtwn_softc *sc)
{
	uint16_t reg;
	int ntries;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	/* Tell 8051 to reset itself. */
	mutex_enter(&sc->sc_fwcmd_mtx);
	urtwn_write_1(sc, R92C_HMETFR + 3, 0x20);
	sc->fwcur = 0;
	mutex_exit(&sc->sc_fwcmd_mtx);

	/* Wait until 8051 resets by itself. */
	for (ntries = 0; ntries < 100; ntries++) {
		reg = urtwn_read_2(sc, R92C_SYS_FUNC_EN);
		if (!(reg & R92C_SYS_FUNC_EN_CPUEN))
			return;
		DELAY(50);
	}
	/* Force 8051 reset. */
	urtwn_write_2(sc, R92C_SYS_FUNC_EN,
	    urtwn_read_2(sc, R92C_SYS_FUNC_EN) & ~R92C_SYS_FUNC_EN_CPUEN);
}

static void
urtwn_r88e_fw_reset(struct urtwn_softc *sc)
{
	uint16_t reg;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	if (ISSET(sc->chip, URTWN_CHIP_92EU)) {
		reg = urtwn_read_2(sc, R92C_RSV_CTRL) & ~R92E_RSV_MIO_EN;
		urtwn_write_2(sc,R92C_RSV_CTRL, reg);
	}
	DELAY(50);

	reg = urtwn_read_2(sc, R92C_SYS_FUNC_EN);
	urtwn_write_2(sc, R92C_SYS_FUNC_EN, reg & ~R92C_SYS_FUNC_EN_CPUEN);
	DELAY(50);

	urtwn_write_2(sc, R92C_SYS_FUNC_EN, reg | R92C_SYS_FUNC_EN_CPUEN);
	DELAY(50);

	if (ISSET(sc->chip, URTWN_CHIP_92EU)) {
		reg = urtwn_read_2(sc, R92C_RSV_CTRL) | R92E_RSV_MIO_EN;
		urtwn_write_2(sc,R92C_RSV_CTRL, reg);
	}
	DELAY(50);

	mutex_enter(&sc->sc_fwcmd_mtx);
	/* Init firmware commands ring. */
	sc->fwcur = 0;
	mutex_exit(&sc->sc_fwcmd_mtx);

}

static int
urtwn_fw_loadpage(struct urtwn_softc *sc, int page, uint8_t *buf, int len)
{
	uint32_t reg;
	int off, mlen, error = 0;

	URTWNHIST_FUNC();
	URTWNHIST_CALLARGS("page=%jd, buf=%#jx, len=%jd",
	    page, (uintptr_t)buf, len, 0);

	reg = urtwn_read_4(sc, R92C_MCUFWDL);
	reg = RW(reg, R92C_MCUFWDL_PAGE, page);
	urtwn_write_4(sc, R92C_MCUFWDL, reg);

	off = R92C_FW_START_ADDR;
	while (len > 0) {
		if (len > 196)
			mlen = 196;
		else if (len > 4)
			mlen = 4;
		else
			mlen = 1;
		error = urtwn_write_region(sc, off, buf, mlen);
		if (error != 0)
			break;
		off += mlen;
		buf += mlen;
		len -= mlen;
	}
	return error;
}

static int __noinline
urtwn_load_firmware(struct urtwn_softc *sc)
{
	firmware_handle_t fwh;
	const struct r92c_fw_hdr *hdr;
	const char *name;
	u_char *fw, *ptr;
	size_t len;
	uint32_t reg;
	int mlen, ntries, page, error;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	/* Read firmware image from the filesystem. */
	if (ISSET(sc->chip, URTWN_CHIP_88E))
		name = "rtl8188eufw.bin";
	else if (ISSET(sc->chip, URTWN_CHIP_92EU))
		name = "rtl8192eefw.bin";
	else if ((sc->chip & (URTWN_CHIP_UMC_A_CUT | URTWN_CHIP_92C)) ==
	    URTWN_CHIP_UMC_A_CUT)
		name = "rtl8192cfwU.bin";
	else
		name = "rtl8192cfw.bin";
	if ((error = firmware_open("if_urtwn", name, &fwh)) != 0) {
		aprint_error_dev(sc->sc_dev,
		    "failed load firmware of file %s (error %d)\n", name,
		    error);
		return error;
	}
	const size_t fwlen = len = firmware_get_size(fwh);
	fw = firmware_malloc(len);
	if (fw == NULL) {
		aprint_error_dev(sc->sc_dev,
		    "failed to allocate firmware memory\n");
		firmware_close(fwh);
		return ENOMEM;
	}
	error = firmware_read(fwh, 0, fw, len);
	firmware_close(fwh);
	if (error != 0) {
		aprint_error_dev(sc->sc_dev,
		    "failed to read firmware (error %d)\n", error);
		firmware_free(fw, fwlen);
		return error;
	}

	len = fwlen;
	ptr = fw;
	hdr = (const struct r92c_fw_hdr *)ptr;
	/* Check if there is a valid FW header and skip it. */
	if ((le16toh(hdr->signature) >> 4) == 0x88c ||
	    (le16toh(hdr->signature) >> 4) == 0x88e ||
	    (le16toh(hdr->signature) >> 4) == 0x92e ||
	    (le16toh(hdr->signature) >> 4) == 0x92c) {
		DPRINTFN(DBG_INIT, "FW V%jd.%jd",
		    le16toh(hdr->version), le16toh(hdr->subversion), 0, 0);
		DPRINTFN(DBG_INIT, "%02jd-%02jd %02jd:%02jd",
		    hdr->month, hdr->date, hdr->hour, hdr->minute);
		ptr += sizeof(*hdr);
		len -= sizeof(*hdr);
	}

	if (urtwn_read_1(sc, R92C_MCUFWDL) & R92C_MCUFWDL_RAM_DL_SEL) {
		/* Reset MCU ready status */
		urtwn_write_1(sc, R92C_MCUFWDL, 0);
		if (ISSET(sc->chip, URTWN_CHIP_88E) ||
		    ISSET(sc->chip, URTWN_CHIP_92EU))
			urtwn_r88e_fw_reset(sc);
		else
			urtwn_fw_reset(sc);
	}
	if (!ISSET(sc->chip, URTWN_CHIP_88E) &&
	    !ISSET(sc->chip, URTWN_CHIP_92EU)) {
		urtwn_write_2(sc, R92C_SYS_FUNC_EN,
		    urtwn_read_2(sc, R92C_SYS_FUNC_EN) |
		    R92C_SYS_FUNC_EN_CPUEN);
	}

	/* download enabled */
	urtwn_write_1(sc, R92C_MCUFWDL,
	    urtwn_read_1(sc, R92C_MCUFWDL) | R92C_MCUFWDL_EN);
	urtwn_write_1(sc, R92C_MCUFWDL + 2,
	    urtwn_read_1(sc, R92C_MCUFWDL + 2) & ~0x08);

	/* Reset the FWDL checksum. */
	urtwn_write_1(sc, R92C_MCUFWDL,
	urtwn_read_1(sc, R92C_MCUFWDL) | R92C_MCUFWDL_CHKSUM_RPT);

	DELAY(50);
	/* download firmware */
	for (page = 0; len > 0; page++) {
		mlen = MIN(len, R92C_FW_PAGE_SIZE);
		error = urtwn_fw_loadpage(sc, page, ptr, mlen);
		if (error != 0) {
			aprint_error_dev(sc->sc_dev,
			    "could not load firmware page %d\n", page);
			goto fail;
		}
		ptr += mlen;
		len -= mlen;
	}

	/* download disable */
	urtwn_write_1(sc, R92C_MCUFWDL,
	    urtwn_read_1(sc, R92C_MCUFWDL) & ~R92C_MCUFWDL_EN);
	urtwn_write_1(sc, R92C_MCUFWDL + 1, 0);

	/* Wait for checksum report. */
	for (ntries = 0; ntries < 1000; ntries++) {
		if (urtwn_read_4(sc, R92C_MCUFWDL) & R92C_MCUFWDL_CHKSUM_RPT)
			break;
		DELAY(5);
	}
	if (ntries == 1000) {
		aprint_error_dev(sc->sc_dev,
		    "timeout waiting for checksum report\n");
		error = ETIMEDOUT;
		goto fail;
	}

	/* Wait for firmware readiness. */
	reg = urtwn_read_4(sc, R92C_MCUFWDL);
	reg = (reg & ~R92C_MCUFWDL_WINTINI_RDY) | R92C_MCUFWDL_RDY;
	urtwn_write_4(sc, R92C_MCUFWDL, reg);
	if (ISSET(sc->chip, URTWN_CHIP_88E) ||
	    ISSET(sc->chip, URTWN_CHIP_92EU))
		urtwn_r88e_fw_reset(sc);
	for (ntries = 0; ntries < 6000; ntries++) {
		if (urtwn_read_4(sc, R92C_MCUFWDL) & R92C_MCUFWDL_WINTINI_RDY)
			break;
		DELAY(5);
	}
	if (ntries == 6000) {
		aprint_error_dev(sc->sc_dev,
		    "timeout waiting for firmware readiness\n");
		error = ETIMEDOUT;
		goto fail;
	}
 fail:
	firmware_free(fw, fwlen);
	return error;
}

static __inline int
urtwn_dma_init(struct urtwn_softc *sc)
{

	return sc->sc_dma_init(sc);
}

static int
urtwn_r92c_dma_init(struct urtwn_softc *sc)
{
	int hashq, hasnq, haslq, nqueues, nqpages, nrempages;
	uint32_t reg;
	int error;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	/* Initialize LLT table. */
	error = urtwn_llt_init(sc);
	if (error != 0)
		return error;

	/* Get Tx queues to USB endpoints mapping. */
	hashq = hasnq = haslq = 0;
	reg = urtwn_read_2(sc, R92C_USB_EP + 1);
	DPRINTFN(DBG_INIT, "USB endpoints mapping %#jx", reg, 0, 0, 0);
	if (MS(reg, R92C_USB_EP_HQ) != 0)
		hashq = 1;
	if (MS(reg, R92C_USB_EP_NQ) != 0)
		hasnq = 1;
	if (MS(reg, R92C_USB_EP_LQ) != 0)
		haslq = 1;
	nqueues = hashq + hasnq + haslq;
	if (nqueues == 0)
		return EIO;
	/* Get the number of pages for each queue. */
	nqpages = (R92C_TX_PAGE_COUNT - R92C_PUBQ_NPAGES) / nqueues;
	/* The remaining pages are assigned to the high priority queue. */
	nrempages = (R92C_TX_PAGE_COUNT - R92C_PUBQ_NPAGES) % nqueues;

	/* Set number of pages for normal priority queue. */
	urtwn_write_1(sc, R92C_RQPN_NPQ, hasnq ? nqpages : 0);
	urtwn_write_4(sc, R92C_RQPN,
	    /* Set number of pages for public queue. */
	    SM(R92C_RQPN_PUBQ, R92C_PUBQ_NPAGES) |
	    /* Set number of pages for high priority queue. */
	    SM(R92C_RQPN_HPQ, hashq ? nqpages + nrempages : 0) |
	    /* Set number of pages for low priority queue. */
	    SM(R92C_RQPN_LPQ, haslq ? nqpages : 0) |
	    /* Load values. */
	    R92C_RQPN_LD);

	urtwn_write_1(sc, R92C_TXPKTBUF_BCNQ_BDNY, R92C_TX_PAGE_BOUNDARY);
	urtwn_write_1(sc, R92C_TXPKTBUF_MGQ_BDNY, R92C_TX_PAGE_BOUNDARY);
	urtwn_write_1(sc, R92C_TXPKTBUF_WMAC_LBK_BF_HD, R92C_TX_PAGE_BOUNDARY);
	urtwn_write_1(sc, R92C_TRXFF_BNDY, R92C_TX_PAGE_BOUNDARY);
	urtwn_write_1(sc, R92C_TDECTRL + 1, R92C_TX_PAGE_BOUNDARY);

	/* Set queue to USB pipe mapping. */
	reg = urtwn_read_2(sc, R92C_TRXDMA_CTRL);
	reg &= ~R92C_TRXDMA_CTRL_QMAP_M;
	if (nqueues == 1) {
		if (hashq) {
			reg |= R92C_TRXDMA_CTRL_QMAP_HQ;
		} else if (hasnq) {
			reg |= R92C_TRXDMA_CTRL_QMAP_NQ;
		} else {
			reg |= R92C_TRXDMA_CTRL_QMAP_LQ;
		}
	} else if (nqueues == 2) {
		/* All 2-endpoints configs have a high priority queue. */
		if (!hashq) {
			return EIO;
		}
		if (hasnq) {
			reg |= R92C_TRXDMA_CTRL_QMAP_HQ_NQ;
		} else {
			reg |= R92C_TRXDMA_CTRL_QMAP_HQ_LQ;
		}
	} else {
		reg |= R92C_TRXDMA_CTRL_QMAP_3EP;
	}
	urtwn_write_2(sc, R92C_TRXDMA_CTRL, reg);

	/* Set Tx/Rx transfer page boundary. */
	urtwn_write_2(sc, R92C_TRXFF_BNDY + 2, 0x27ff);

	/* Set Tx/Rx transfer page size. */
	urtwn_write_1(sc, R92C_PBP,
	    SM(R92C_PBP_PSRX, R92C_PBP_128) | SM(R92C_PBP_PSTX, R92C_PBP_128));
	return 0;
}

static int
urtwn_r88e_dma_init(struct urtwn_softc *sc)
{
	usb_interface_descriptor_t *id;
	uint32_t reg;
	int nqueues;
	int error;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	/* Initialize LLT table. */
	error = urtwn_llt_init(sc);
	if (error != 0)
		return error;

	/* Get Tx queues to USB endpoints mapping. */
	id = usbd_get_interface_descriptor(sc->sc_iface);
	nqueues = id->bNumEndpoints - 1;
	if (nqueues == 0)
		return EIO;

	/* Set number of pages for normal priority queue. */
	urtwn_write_2(sc, R92C_RQPN_NPQ, 0);
	urtwn_write_2(sc, R92C_RQPN_NPQ, 0x000d);
	urtwn_write_4(sc, R92C_RQPN, 0x808e000d);

	urtwn_write_1(sc, R92C_TXPKTBUF_BCNQ_BDNY, R88E_TX_PAGE_BOUNDARY);
	urtwn_write_1(sc, R92C_TXPKTBUF_MGQ_BDNY, R88E_TX_PAGE_BOUNDARY);
	urtwn_write_1(sc, R92C_TXPKTBUF_WMAC_LBK_BF_HD, R88E_TX_PAGE_BOUNDARY);
	urtwn_write_1(sc, R92C_TRXFF_BNDY, R88E_TX_PAGE_BOUNDARY);
	urtwn_write_1(sc, R92C_TDECTRL + 1, R88E_TX_PAGE_BOUNDARY);

	/* Set queue to USB pipe mapping. */
	reg = urtwn_read_2(sc, R92C_TRXDMA_CTRL);
	reg &= ~R92C_TRXDMA_CTRL_QMAP_M;
	if (nqueues == 1)
		reg |= R92C_TRXDMA_CTRL_QMAP_LQ;
	else if (nqueues == 2)
		reg |= R92C_TRXDMA_CTRL_QMAP_HQ_NQ;
	else
		reg |= R92C_TRXDMA_CTRL_QMAP_3EP;
	urtwn_write_2(sc, R92C_TRXDMA_CTRL, reg);

	/* Set Tx/Rx transfer page boundary. */
	urtwn_write_2(sc, R92C_TRXFF_BNDY + 2, 0x23ff);

	/* Set Tx/Rx transfer page size. */
	urtwn_write_1(sc, R92C_PBP,
	    SM(R92C_PBP_PSRX, R92C_PBP_128) | SM(R92C_PBP_PSTX, R92C_PBP_128));

	return 0;
}

static void __noinline
urtwn_mac_init(struct urtwn_softc *sc)
{
	size_t i;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	/* Write MAC initialization values. */
	if (ISSET(sc->chip, URTWN_CHIP_88E)) {
		for (i = 0; i < __arraycount(rtl8188eu_mac); i++)
			urtwn_write_1(sc, rtl8188eu_mac[i].reg,
			    rtl8188eu_mac[i].val);
	} else if (ISSET(sc->chip, URTWN_CHIP_92EU)) {
		for (i = 0; i < __arraycount(rtl8192eu_mac); i++)
			urtwn_write_1(sc, rtl8192eu_mac[i].reg,
			    rtl8192eu_mac[i].val);
	} else {
		for (i = 0; i < __arraycount(rtl8192cu_mac); i++)
			urtwn_write_1(sc, rtl8192cu_mac[i].reg,
			    rtl8192cu_mac[i].val);
	}
}

static void __noinline
urtwn_bb_init(struct urtwn_softc *sc)
{
	const struct rtwn_bb_prog *prog;
	uint32_t reg;
	uint8_t crystalcap;
	size_t i;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	/* Enable BB and RF. */
	urtwn_write_2(sc, R92C_SYS_FUNC_EN,
	    urtwn_read_2(sc, R92C_SYS_FUNC_EN) |
	    R92C_SYS_FUNC_EN_BBRSTB | R92C_SYS_FUNC_EN_BB_GLB_RST |
	    R92C_SYS_FUNC_EN_DIO_RF);

	if (!ISSET(sc->chip, URTWN_CHIP_88E) &&
	    !ISSET(sc->chip, URTWN_CHIP_92EU)) {
		urtwn_write_1(sc, R92C_AFE_PLL_CTRL, 0x83);
		urtwn_write_1(sc, R92C_AFE_PLL_CTRL + 1, 0xdb);
	}

	urtwn_write_1(sc, R92C_RF_CTRL,
	    R92C_RF_CTRL_EN | R92C_RF_CTRL_RSTB | R92C_RF_CTRL_SDMRSTB);
	urtwn_write_1(sc, R92C_SYS_FUNC_EN,
	    R92C_SYS_FUNC_EN_USBA | R92C_SYS_FUNC_EN_USBD |
	    R92C_SYS_FUNC_EN_BB_GLB_RST | R92C_SYS_FUNC_EN_BBRSTB);

	if (!ISSET(sc->chip, URTWN_CHIP_88E) &&
	    !ISSET(sc->chip, URTWN_CHIP_92EU)) {
		urtwn_write_1(sc, R92C_LDOHCI12_CTRL, 0x0f);
		urtwn_write_1(sc, 0x15, 0xe9);
		urtwn_write_1(sc, R92C_AFE_XTAL_CTRL + 1, 0x80);
	}

	/* Select BB programming based on board type. */
	if (ISSET(sc->chip, URTWN_CHIP_88E))
		prog = &rtl8188eu_bb_prog;
	else if (ISSET(sc->chip, URTWN_CHIP_92EU))
		prog = &rtl8192eu_bb_prog;
	else if (!(sc->chip & URTWN_CHIP_92C)) {
		if (sc->board_type == R92C_BOARD_TYPE_MINICARD) {
			prog = &rtl8188ce_bb_prog;
		} else if (sc->board_type == R92C_BOARD_TYPE_HIGHPA) {
			prog = &rtl8188ru_bb_prog;
		} else {
			prog = &rtl8188cu_bb_prog;
		}
	} else {
		if (sc->board_type == R92C_BOARD_TYPE_MINICARD) {
			prog = &rtl8192ce_bb_prog;
		} else {
			prog = &rtl8192cu_bb_prog;
		}
	}
	/* Write BB initialization values. */
	for (i = 0; i < prog->count; i++) {
		/* additional delay depend on registers */
		switch (prog->regs[i]) {
		case 0xfe:
			urtwn_delay_ms(sc, 50);
			break;
		case 0xfd:
			urtwn_delay_ms(sc, 5);
			break;
		case 0xfc:
			urtwn_delay_ms(sc, 1);
			break;
		case 0xfb:
			DELAY(50);
			break;
		case 0xfa:
			DELAY(5);
			break;
		case 0xf9:
			DELAY(1);
			break;
		}
		urtwn_bb_write(sc, prog->regs[i], prog->vals[i]);
		DELAY(1);
	}

	if (sc->chip & URTWN_CHIP_92C_1T2R) {
		/* 8192C 1T only configuration. */
		reg = urtwn_bb_read(sc, R92C_FPGA0_TXINFO);
		reg = (reg & ~0x00000003) | 0x2;
		urtwn_bb_write(sc, R92C_FPGA0_TXINFO, reg);

		reg = urtwn_bb_read(sc, R92C_FPGA1_TXINFO);
		reg = (reg & ~0x00300033) | 0x00200022;
		urtwn_bb_write(sc, R92C_FPGA1_TXINFO, reg);

		reg = urtwn_bb_read(sc, R92C_CCK0_AFESETTING);
		reg = (reg & ~0xff000000) | (0x45 << 24);
		urtwn_bb_write(sc, R92C_CCK0_AFESETTING, reg);

		reg = urtwn_bb_read(sc, R92C_OFDM0_TRXPATHENA);
		reg = (reg & ~0x000000ff) | 0x23;
		urtwn_bb_write(sc, R92C_OFDM0_TRXPATHENA, reg);

		reg = urtwn_bb_read(sc, R92C_OFDM0_AGCPARAM1);
		reg = (reg & ~0x00000030) | (1 << 4);
		urtwn_bb_write(sc, R92C_OFDM0_AGCPARAM1, reg);

		reg = urtwn_bb_read(sc, 0xe74);
		reg = (reg & ~0x0c000000) | (2 << 26);
		urtwn_bb_write(sc, 0xe74, reg);
		reg = urtwn_bb_read(sc, 0xe78);
		reg = (reg & ~0x0c000000) | (2 << 26);
		urtwn_bb_write(sc, 0xe78, reg);
		reg = urtwn_bb_read(sc, 0xe7c);
		reg = (reg & ~0x0c000000) | (2 << 26);
		urtwn_bb_write(sc, 0xe7c, reg);
		reg = urtwn_bb_read(sc, 0xe80);
		reg = (reg & ~0x0c000000) | (2 << 26);
		urtwn_bb_write(sc, 0xe80, reg);
		reg = urtwn_bb_read(sc, 0xe88);
		reg = (reg & ~0x0c000000) | (2 << 26);
		urtwn_bb_write(sc, 0xe88, reg);
	}

	/* Write AGC values. */
	for (i = 0; i < prog->agccount; i++) {
		urtwn_bb_write(sc, R92C_OFDM0_AGCRSSITABLE, prog->agcvals[i]);
		DELAY(1);
	}

	if (ISSET(sc->chip, URTWN_CHIP_88E) ||
	    ISSET(sc->chip, URTWN_CHIP_92EU)) {
		urtwn_bb_write(sc, R92C_OFDM0_AGCCORE1(0), 0x69553422);
		DELAY(1);
		urtwn_bb_write(sc, R92C_OFDM0_AGCCORE1(0), 0x69553420);
		DELAY(1);
	}

	if (ISSET(sc->chip, URTWN_CHIP_92EU)) {
		crystalcap = sc->r88e_rom[0xb9];
		if (crystalcap == 0x00)
			crystalcap = 0x20;
		crystalcap &= 0x3f;
		reg = urtwn_bb_read(sc, R92C_AFE_CTRL3);
		urtwn_bb_write(sc, R92C_AFE_CTRL3,
		    RW(reg, R92C_AFE_XTAL_CTRL_ADDR,
		    crystalcap | crystalcap << 6));
		urtwn_write_4(sc, R92C_AFE_XTAL_CTRL, 0xf81fb);
	} else if (ISSET(sc->chip, URTWN_CHIP_88E)) {
		crystalcap = sc->r88e_rom[0xb9];
		if (crystalcap == 0xff)
			crystalcap = 0x20;
		crystalcap &= 0x3f;
		reg = urtwn_bb_read(sc, R92C_AFE_XTAL_CTRL);
		urtwn_bb_write(sc, R92C_AFE_XTAL_CTRL,
		    RW(reg, R92C_AFE_XTAL_CTRL_ADDR,
		    crystalcap | crystalcap << 6));
	} else {
		if (urtwn_bb_read(sc, R92C_HSSI_PARAM2(0)) &
		    R92C_HSSI_PARAM2_CCK_HIPWR) {
			SET(sc->sc_flags, URTWN_FLAG_CCK_HIPWR);
		}
	}
}

static void __noinline
urtwn_rf_init(struct urtwn_softc *sc)
{
	const struct rtwn_rf_prog *prog;
	uint32_t reg, mask, saved;
	size_t i, j, idx;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	/* Select RF programming based on board type. */
	if (ISSET(sc->chip, URTWN_CHIP_88E))
		prog = rtl8188eu_rf_prog;
	else if (ISSET(sc->chip, URTWN_CHIP_92EU))
		prog = rtl8192eu_rf_prog;
	else if (!(sc->chip & URTWN_CHIP_92C)) {
		if (sc->board_type == R92C_BOARD_TYPE_MINICARD) {
			prog = rtl8188ce_rf_prog;
		} else if (sc->board_type == R92C_BOARD_TYPE_HIGHPA) {
			prog = rtl8188ru_rf_prog;
		} else {
			prog = rtl8188cu_rf_prog;
		}
	} else {
		prog = rtl8192ce_rf_prog;
	}

	for (i = 0; i < sc->nrxchains; i++) {
		/* Save RF_ENV control type. */
		idx = i / 2;
		mask = 0xffffU << ((i % 2) * 16);
		saved = urtwn_bb_read(sc, R92C_FPGA0_RFIFACESW(idx)) & mask;

		/* Set RF_ENV enable. */
		reg = urtwn_bb_read(sc, R92C_FPGA0_RFIFACEOE(i));
		reg |= 0x100000;
		urtwn_bb_write(sc, R92C_FPGA0_RFIFACEOE(i), reg);
		DELAY(50);

		/* Set RF_ENV output high. */
		reg = urtwn_bb_read(sc, R92C_FPGA0_RFIFACEOE(i));
		reg |= 0x10;
		urtwn_bb_write(sc, R92C_FPGA0_RFIFACEOE(i), reg);
		DELAY(50);

		/* Set address and data lengths of RF registers. */
		reg = urtwn_bb_read(sc, R92C_HSSI_PARAM2(i));
		reg &= ~R92C_HSSI_PARAM2_ADDR_LENGTH;
		urtwn_bb_write(sc, R92C_HSSI_PARAM2(i), reg);
		DELAY(50);
		reg = urtwn_bb_read(sc, R92C_HSSI_PARAM2(i));
		reg &= ~R92C_HSSI_PARAM2_DATA_LENGTH;
		urtwn_bb_write(sc, R92C_HSSI_PARAM2(i), reg);
		DELAY(50);

		/* Write RF initialization values for this chain. */
		for (j = 0; j < prog[i].count; j++) {
			if (prog[i].regs[j] >= 0xf9 &&
			    prog[i].regs[j] <= 0xfe) {
				/*
				 * These are fake RF registers offsets that
				 * indicate a delay is required.
				 */
				urtwn_delay_ms(sc, 50);
				continue;
			}
			urtwn_rf_write(sc, i, prog[i].regs[j], prog[i].vals[j]);
			DELAY(5);
		}

		/* Restore RF_ENV control type. */
		reg = urtwn_bb_read(sc, R92C_FPGA0_RFIFACESW(idx)) & ~mask;
		urtwn_bb_write(sc, R92C_FPGA0_RFIFACESW(idx), reg | saved);
	}

	if ((sc->chip & (URTWN_CHIP_UMC_A_CUT | URTWN_CHIP_92C)) ==
	    URTWN_CHIP_UMC_A_CUT) {
		urtwn_rf_write(sc, 0, R92C_RF_RX_G1, 0x30255);
		urtwn_rf_write(sc, 0, R92C_RF_RX_G2, 0x50a00);
	}

	/* Cache RF register CHNLBW. */
	for (i = 0; i < 2; i++) {
		sc->rf_chnlbw[i] = urtwn_rf_read(sc, i, R92C_RF_CHNLBW);
	}
}

static void __noinline
urtwn_cam_init(struct urtwn_softc *sc)
{
	uint32_t content, command;
	uint8_t idx;
	size_t i;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	KASSERT(mutex_owned(&sc->sc_write_mtx));
	if (ISSET(sc->chip, URTWN_CHIP_92EU))
		return;

	for (idx = 0; idx < R92C_CAM_ENTRY_COUNT; idx++) {
		content = (idx & 3)
		    | (R92C_CAM_ALGO_AES << R92C_CAM_ALGO_S)
		    | R92C_CAM_VALID;

		command = R92C_CAMCMD_POLLING
		    | R92C_CAMCMD_WRITE
		    | R92C_CAM_CTL0(idx);

		urtwn_write_4(sc, R92C_CAMWRITE, content);
		urtwn_write_4(sc, R92C_CAMCMD, command);
	}

	for (idx = 0; idx < R92C_CAM_ENTRY_COUNT; idx++) {
		for (i = 0; i < /* CAM_CONTENT_COUNT */ 8; i++) {
			if (i == 0) {
				content = (idx & 3)
				    | (R92C_CAM_ALGO_AES << R92C_CAM_ALGO_S)
				    | R92C_CAM_VALID;
			} else {
				content = 0;
			}

			command = R92C_CAMCMD_POLLING
			    | R92C_CAMCMD_WRITE
			    | R92C_CAM_CTL0(idx)
			    | i;

			urtwn_write_4(sc, R92C_CAMWRITE, content);
			urtwn_write_4(sc, R92C_CAMCMD, command);
		}
	}

	/* Invalidate all CAM entries. */
	urtwn_write_4(sc, R92C_CAMCMD, R92C_CAMCMD_POLLING | R92C_CAMCMD_CLR);
}

static void __noinline
urtwn_pa_bias_init(struct urtwn_softc *sc)
{
	uint8_t reg;
	size_t i;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	for (i = 0; i < sc->nrxchains; i++) {
		if (sc->pa_setting & (1U << i))
			continue;

		urtwn_rf_write(sc, i, R92C_RF_IPA, 0x0f406);
		urtwn_rf_write(sc, i, R92C_RF_IPA, 0x4f406);
		urtwn_rf_write(sc, i, R92C_RF_IPA, 0x8f406);
		urtwn_rf_write(sc, i, R92C_RF_IPA, 0xcf406);
	}
	if (!(sc->pa_setting & 0x10)) {
		reg = urtwn_read_1(sc, 0x16);
		reg = (reg & ~0xf0) | 0x90;
		urtwn_write_1(sc, 0x16, reg);
	}
}

static void __noinline
urtwn_rxfilter_init(struct urtwn_softc *sc)
{

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	/* Initialize Rx filter. */
	/* TODO: use better filter for monitor mode. */
	urtwn_write_4(sc, R92C_RCR,
	    R92C_RCR_AAP | R92C_RCR_APM | R92C_RCR_AM | R92C_RCR_AB |
	    R92C_RCR_APP_ICV | R92C_RCR_AMF | R92C_RCR_HTC_LOC_CTRL |
	    R92C_RCR_APP_MIC | R92C_RCR_APP_PHYSTS);
	/* Accept all multicast frames. */
	urtwn_write_4(sc, R92C_MAR + 0, 0xffffffff);
	urtwn_write_4(sc, R92C_MAR + 4, 0xffffffff);
	/* Accept all management frames. */
	urtwn_write_2(sc, R92C_RXFLTMAP0, 0xffff);
	/* Reject all control frames. */
	urtwn_write_2(sc, R92C_RXFLTMAP1, 0x0000);
	/* Accept all data frames. */
	urtwn_write_2(sc, R92C_RXFLTMAP2, 0xffff);
}

static void __noinline
urtwn_edca_init(struct urtwn_softc *sc)
{

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	/* set spec SIFS (used in NAV) */
	urtwn_write_2(sc, R92C_SPEC_SIFS, 0x100a);
	urtwn_write_2(sc, R92C_MAC_SPEC_SIFS, 0x100a);

	/* set SIFS CCK/OFDM */
	urtwn_write_2(sc, R92C_SIFS_CCK, 0x100a);
	urtwn_write_2(sc, R92C_SIFS_OFDM, 0x100a);

	/* TXOP */
	urtwn_write_4(sc, R92C_EDCA_BE_PARAM, 0x005ea42b);
	urtwn_write_4(sc, R92C_EDCA_BK_PARAM, 0x0000a44f);
	urtwn_write_4(sc, R92C_EDCA_VI_PARAM, 0x005ea324);
	urtwn_write_4(sc, R92C_EDCA_VO_PARAM, 0x002fa226);
}

static void
urtwn_write_txpower(struct urtwn_softc *sc, int chain,
    uint16_t power[URTWN_RIDX_COUNT])
{
	uint32_t reg;

	URTWNHIST_FUNC();
	URTWNHIST_CALLARGS("chain=%jd", chain, 0, 0, 0);

	/* Write per-CCK rate Tx power. */
	if (chain == 0) {
		reg = urtwn_bb_read(sc, R92C_TXAGC_A_CCK1_MCS32);
		reg = RW(reg, R92C_TXAGC_A_CCK1,  power[0]);
		urtwn_bb_write(sc, R92C_TXAGC_A_CCK1_MCS32, reg);

		reg = urtwn_bb_read(sc, R92C_TXAGC_B_CCK11_A_CCK2_11);
		reg = RW(reg, R92C_TXAGC_A_CCK2,  power[1]);
		reg = RW(reg, R92C_TXAGC_A_CCK55, power[2]);
		reg = RW(reg, R92C_TXAGC_A_CCK11, power[3]);
		urtwn_bb_write(sc, R92C_TXAGC_B_CCK11_A_CCK2_11, reg);
	} else {
		reg = urtwn_bb_read(sc, R92C_TXAGC_B_CCK1_55_MCS32);
		reg = RW(reg, R92C_TXAGC_B_CCK1,  power[0]);
		reg = RW(reg, R92C_TXAGC_B_CCK2,  power[1]);
		reg = RW(reg, R92C_TXAGC_B_CCK55, power[2]);
		urtwn_bb_write(sc, R92C_TXAGC_B_CCK1_55_MCS32, reg);

		reg = urtwn_bb_read(sc, R92C_TXAGC_B_CCK11_A_CCK2_11);
		reg = RW(reg, R92C_TXAGC_B_CCK11, power[3]);
		urtwn_bb_write(sc, R92C_TXAGC_B_CCK11_A_CCK2_11, reg);
	}
	/* Write per-OFDM rate Tx power. */
	urtwn_bb_write(sc, R92C_TXAGC_RATE18_06(chain),
	    SM(R92C_TXAGC_RATE06, power[ 4]) |
	    SM(R92C_TXAGC_RATE09, power[ 5]) |
	    SM(R92C_TXAGC_RATE12, power[ 6]) |
	    SM(R92C_TXAGC_RATE18, power[ 7]));
	urtwn_bb_write(sc, R92C_TXAGC_RATE54_24(chain),
	    SM(R92C_TXAGC_RATE24, power[ 8]) |
	    SM(R92C_TXAGC_RATE36, power[ 9]) |
	    SM(R92C_TXAGC_RATE48, power[10]) |
	    SM(R92C_TXAGC_RATE54, power[11]));
	/* Write per-MCS Tx power. */
	urtwn_bb_write(sc, R92C_TXAGC_MCS03_MCS00(chain),
	    SM(R92C_TXAGC_MCS00,  power[12]) |
	    SM(R92C_TXAGC_MCS01,  power[13]) |
	    SM(R92C_TXAGC_MCS02,  power[14]) |
	    SM(R92C_TXAGC_MCS03,  power[15]));
	urtwn_bb_write(sc, R92C_TXAGC_MCS07_MCS04(chain),
	    SM(R92C_TXAGC_MCS04,  power[16]) |
	    SM(R92C_TXAGC_MCS05,  power[17]) |
	    SM(R92C_TXAGC_MCS06,  power[18]) |
	    SM(R92C_TXAGC_MCS07,  power[19]));
	urtwn_bb_write(sc, R92C_TXAGC_MCS11_MCS08(chain),
	    SM(R92C_TXAGC_MCS08,  power[20]) |
	    SM(R92C_TXAGC_MCS09,  power[21]) |
	    SM(R92C_TXAGC_MCS10,  power[22]) |
	    SM(R92C_TXAGC_MCS11,  power[23]));
	urtwn_bb_write(sc, R92C_TXAGC_MCS15_MCS12(chain),
	    SM(R92C_TXAGC_MCS12,  power[24]) |
	    SM(R92C_TXAGC_MCS13,  power[25]) |
	    SM(R92C_TXAGC_MCS14,  power[26]) |
	    SM(R92C_TXAGC_MCS15,  power[27]));
}

static void
urtwn_get_txpower(struct urtwn_softc *sc, size_t chain, u_int chan, u_int ht40m,
    uint16_t power[URTWN_RIDX_COUNT])
{
	struct r92c_rom *rom = &sc->rom;
	uint16_t cckpow, ofdmpow, htpow, diff, maxpow;
	const struct rtwn_txpwr *base;
	int ridx, group;

	URTWNHIST_FUNC();
	URTWNHIST_CALLARGS("chain=%jd, chan=%jd", chain, chan, 0, 0);

	/* Determine channel group. */
	if (chan <= 3) {
		group = 0;
	} else if (chan <= 9) {
		group = 1;
	} else {
		group = 2;
	}

	/* Get original Tx power based on board type and RF chain. */
	if (!(sc->chip & URTWN_CHIP_92C)) {
		if (sc->board_type == R92C_BOARD_TYPE_HIGHPA) {
			base = &rtl8188ru_txagc[chain];
		} else {
			base = &rtl8192cu_txagc[chain];
		}
	} else {
		base = &rtl8192cu_txagc[chain];
	}

	memset(power, 0, URTWN_RIDX_COUNT * sizeof(power[0]));
	if (sc->regulatory == 0) {
		for (ridx = 0; ridx <= 3; ridx++) {
			power[ridx] = base->pwr[0][ridx];
		}
	}
	for (ridx = 4; ridx < URTWN_RIDX_COUNT; ridx++) {
		if (sc->regulatory == 3) {
			power[ridx] = base->pwr[0][ridx];
			/* Apply vendor limits. */
			if (ht40m != IEEE80211_HTINFO_2NDCHAN_NONE) {
				maxpow = rom->ht40_max_pwr[group];
			} else {
				maxpow = rom->ht20_max_pwr[group];
			}
			maxpow = (maxpow >> (chain * 4)) & 0xf;
			if (power[ridx] > maxpow) {
				power[ridx] = maxpow;
			}
		} else if (sc->regulatory == 1) {
			if (ht40m == IEEE80211_HTINFO_2NDCHAN_NONE) {
				power[ridx] = base->pwr[group][ridx];
			}
		} else if (sc->regulatory != 2) {
			power[ridx] = base->pwr[0][ridx];
		}
	}

	/* Compute per-CCK rate Tx power. */
	cckpow = rom->cck_tx_pwr[chain][group];
	for (ridx = 0; ridx <= 3; ridx++) {
		power[ridx] += cckpow;
		if (power[ridx] > R92C_MAX_TX_PWR) {
			power[ridx] = R92C_MAX_TX_PWR;
		}
	}

	htpow = rom->ht40_1s_tx_pwr[chain][group];
	if (sc->ntxchains > 1) {
		/* Apply reduction for 2 spatial streams. */
		diff = rom->ht40_2s_tx_pwr_diff[group];
		diff = (diff >> (chain * 4)) & 0xf;
		htpow = (htpow > diff) ? htpow - diff : 0;
	}

	/* Compute per-OFDM rate Tx power. */
	diff = rom->ofdm_tx_pwr_diff[group];
	diff = (diff >> (chain * 4)) & 0xf;
	ofdmpow = htpow + diff;	/* HT->OFDM correction. */
	for (ridx = 4; ridx <= 11; ridx++) {
		power[ridx] += ofdmpow;
		if (power[ridx] > R92C_MAX_TX_PWR) {
			power[ridx] = R92C_MAX_TX_PWR;
		}
	}

	/* Compute per-MCS Tx power. */
	if (ht40m == IEEE80211_HTINFO_2NDCHAN_NONE) {
		diff = rom->ht20_tx_pwr_diff[group];
		diff = (diff >> (chain * 4)) & 0xf;
		htpow += diff;	/* HT40->HT20 correction. */
	}
	for (ridx = 12; ridx < URTWN_RIDX_COUNT; ridx++) {
		power[ridx] += htpow;
		if (power[ridx] > R92C_MAX_TX_PWR) {
			power[ridx] = R92C_MAX_TX_PWR;
		}
	}
#ifdef URTWN_DEBUG
	if (urtwn_debug & DBG_RF) {
		/* Dump per-rate Tx power values. */
		DPRINTFN(DBG_RF, "Tx power for chain %jd:", chain, 0, 0, 0);
		for (ridx = 0; ridx < URTWN_RIDX_COUNT; ridx++)
			DPRINTFN(DBG_RF, "Rate %jd = %ju", ridx, power[ridx], 0, 0);
	}
#endif
}

void
urtwn_r88e_get_txpower(struct urtwn_softc *sc, size_t chain, u_int chan,
    u_int ht40m, uint16_t power[URTWN_RIDX_COUNT])
{
	uint16_t cckpow, ofdmpow, bw20pow, htpow;
	const struct rtwn_r88e_txpwr *base;
	int ridx, group;

	URTWNHIST_FUNC();
	URTWNHIST_CALLARGS("chain=%jd, chan=%jd", chain, chan, 0, 0);

	/* Determine channel group. */
	if (chan <= 2)
		group = 0;
	else if (chan <= 5)
		group = 1;
	else if (chan <= 8)
		group = 2;
	else if (chan <= 11)
		group = 3;
	else if (chan <= 13)
		group = 4;
	else
		group = 5;

	/* Get original Tx power based on board type and RF chain. */
	base = &rtl8188eu_txagc[chain];

	memset(power, 0, URTWN_RIDX_COUNT * sizeof(power[0]));
	if (sc->regulatory == 0) {
		for (ridx = 0; ridx <= 3; ridx++)
			power[ridx] = base->pwr[0][ridx];
	}
	for (ridx = 4; ridx < URTWN_RIDX_COUNT; ridx++) {
		if (sc->regulatory == 3)
			power[ridx] = base->pwr[0][ridx];
		else if (sc->regulatory == 1) {
			if (ht40m == IEEE80211_HTINFO_2NDCHAN_NONE)
				power[ridx] = base->pwr[group][ridx];
		} else if (sc->regulatory != 2)
			power[ridx] = base->pwr[0][ridx];
	}

	/* Compute per-CCK rate Tx power. */
	cckpow = sc->cck_tx_pwr[group];
	for (ridx = 0; ridx <= 3; ridx++) {
		power[ridx] += cckpow;
		if (power[ridx] > R92C_MAX_TX_PWR)
			power[ridx] = R92C_MAX_TX_PWR;
	}

	htpow = sc->ht40_tx_pwr[group];

	/* Compute per-OFDM rate Tx power. */
	ofdmpow = htpow + sc->ofdm_tx_pwr_diff;
	for (ridx = 4; ridx <= 11; ridx++) {
		power[ridx] += ofdmpow;
		if (power[ridx] > R92C_MAX_TX_PWR)
			power[ridx] = R92C_MAX_TX_PWR;
	}

	bw20pow = htpow + sc->bw20_tx_pwr_diff;
	for (ridx = 12; ridx <= 27; ridx++) {
		power[ridx] += bw20pow;
		if (power[ridx] > R92C_MAX_TX_PWR)
			power[ridx] = R92C_MAX_TX_PWR;
	}
}

static void
urtwn_set_txpower(struct urtwn_softc *sc, u_int chan, u_int ht40m)
{
	uint16_t power[URTWN_RIDX_COUNT];
	size_t i;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	for (i = 0; i < sc->ntxchains; i++) {
		/* Compute per-rate Tx power values. */
		if (ISSET(sc->chip, URTWN_CHIP_88E) ||
		    ISSET(sc->chip, URTWN_CHIP_92EU))
			urtwn_r88e_get_txpower(sc, i, chan, ht40m, power);
		else
			urtwn_get_txpower(sc, i, chan, ht40m, power);
		/* Write per-rate Tx power values to hardware. */
		urtwn_write_txpower(sc, i, power);
	}
}

static void __noinline
urtwn_set_chan(struct urtwn_softc *sc, struct ieee80211_channel *c, u_int ht40m)
{
	struct ieee80211com *ic = &sc->sc_ic;
	u_int chan;
	size_t i;

	chan = ieee80211_chan2ieee(ic, c);	/* XXX center freq! */

	URTWNHIST_FUNC();
	URTWNHIST_CALLARGS("chan=%jd", chan, 0, 0, 0);

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	if (ht40m == IEEE80211_HTINFO_2NDCHAN_ABOVE) {
		chan += 2;
	} else if (ht40m == IEEE80211_HTINFO_2NDCHAN_BELOW){
		chan -= 2;
	}

	/* Set Tx power for this new channel. */
	urtwn_set_txpower(sc, chan, ht40m);

	for (i = 0; i < sc->nrxchains; i++) {
		urtwn_rf_write(sc, i, R92C_RF_CHNLBW,
		    RW(sc->rf_chnlbw[i], R92C_RF_CHNLBW_CHNL, chan));
	}

	if (ht40m) {
		/* Is secondary channel below or above primary? */
		int prichlo = (ht40m == IEEE80211_HTINFO_2NDCHAN_ABOVE);
		uint32_t reg;

		urtwn_write_1(sc, R92C_BWOPMODE,
		    urtwn_read_1(sc, R92C_BWOPMODE) & ~R92C_BWOPMODE_20MHZ);

		reg = urtwn_read_1(sc, R92C_RRSR + 2);
		reg = (reg & ~0x6f) | (prichlo ? 1 : 2) << 5;
		urtwn_write_1(sc, R92C_RRSR + 2, (uint8_t)reg);

		urtwn_bb_write(sc, R92C_FPGA0_RFMOD,
		    urtwn_bb_read(sc, R92C_FPGA0_RFMOD) | R92C_RFMOD_40MHZ);
		urtwn_bb_write(sc, R92C_FPGA1_RFMOD,
		    urtwn_bb_read(sc, R92C_FPGA1_RFMOD) | R92C_RFMOD_40MHZ);

		/* Set CCK side band. */
		reg = urtwn_bb_read(sc, R92C_CCK0_SYSTEM);
		reg = (reg & ~0x00000010) | (prichlo ? 0 : 1) << 4;
		urtwn_bb_write(sc, R92C_CCK0_SYSTEM, reg);

		reg = urtwn_bb_read(sc, R92C_OFDM1_LSTF);
		reg = (reg & ~0x00000c00) | (prichlo ? 1 : 2) << 10;
		urtwn_bb_write(sc, R92C_OFDM1_LSTF, reg);

		urtwn_bb_write(sc, R92C_FPGA0_ANAPARAM2,
		    urtwn_bb_read(sc, R92C_FPGA0_ANAPARAM2) &
		    ~R92C_FPGA0_ANAPARAM2_CBW20);

		reg = urtwn_bb_read(sc, 0x818);
		reg = (reg & ~0x0c000000) | (prichlo ? 2 : 1) << 26;
		urtwn_bb_write(sc, 0x818, reg);

		/* Select 40MHz bandwidth. */
		urtwn_rf_write(sc, 0, R92C_RF_CHNLBW,
		    (sc->rf_chnlbw[0] & ~0xfff) | chan);
	} else {
		urtwn_write_1(sc, R92C_BWOPMODE,
		    urtwn_read_1(sc, R92C_BWOPMODE) | R92C_BWOPMODE_20MHZ);

		urtwn_bb_write(sc, R92C_FPGA0_RFMOD,
		    urtwn_bb_read(sc, R92C_FPGA0_RFMOD) & ~R92C_RFMOD_40MHZ);
		urtwn_bb_write(sc, R92C_FPGA1_RFMOD,
		    urtwn_bb_read(sc, R92C_FPGA1_RFMOD) & ~R92C_RFMOD_40MHZ);

		if (!ISSET(sc->chip, URTWN_CHIP_88E) &&
		    !ISSET(sc->chip, URTWN_CHIP_92EU)) {
			urtwn_bb_write(sc, R92C_FPGA0_ANAPARAM2,
			    urtwn_bb_read(sc, R92C_FPGA0_ANAPARAM2) |
			    R92C_FPGA0_ANAPARAM2_CBW20);
		}

		/* Select 20MHz bandwidth. */
		urtwn_rf_write(sc, 0, R92C_RF_CHNLBW,
		    (sc->rf_chnlbw[0] & ~0xfff) | chan |
		    (ISSET(sc->chip, URTWN_CHIP_88E) ||
		     ISSET(sc->chip, URTWN_CHIP_92EU) ?
		      R88E_RF_CHNLBW_BW20 : R92C_RF_CHNLBW_BW20));
	}
}

static void __noinline
urtwn_iq_calib(struct urtwn_softc *sc, bool inited)
{

	URTWNHIST_FUNC();
	URTWNHIST_CALLARGS("inited=%jd", inited, 0, 0, 0);

	uint32_t addaBackup[16], iqkBackup[4], piMode;

#ifdef notyet
	uint32_t odfm0_agccore_regs[3];
	uint32_t ant_regs[3];
	uint32_t rf_regs[8];
#endif
	uint32_t reg0, reg1, reg2;
	int i, attempt;

#ifdef notyet
	urtwn_write_1(sc, R92E_STBC_SETTING + 2, urtwn_read_1(sc,
	    R92E_STBC_SETTING + 2));
	urtwn_write_1(sc, R92C_ACLK_MON, 0);
	/* Save AGCCORE regs. */
	for (i = 0; i < sc->nrxchains; i++) {
		odfm0_agccore_regs[i] = urtwn_read_4(sc,
		    R92C_OFDM0_AGCCORE1(i));
	}
#endif
	/* Save BB regs. */
	reg0 = urtwn_bb_read(sc, R92C_OFDM0_TRXPATHENA);
	reg1 = urtwn_bb_read(sc, R92C_OFDM0_TRMUXPAR);
	reg2 = urtwn_bb_read(sc, R92C_FPGA0_RFIFACESW(1));

	/* Save adda regs to be restored when finished. */
	for (i = 0; i < __arraycount(addaReg); i++)
		addaBackup[i] = urtwn_bb_read(sc, addaReg[i]);
	/* Save mac regs. */
	iqkBackup[0] = urtwn_read_1(sc, R92C_TXPAUSE);
	iqkBackup[1] = urtwn_read_1(sc, R92C_BCN_CTRL);
	iqkBackup[2] = urtwn_read_1(sc, R92C_BCN_CTRL1);
	iqkBackup[3] = urtwn_read_4(sc, R92C_GPIO_MUXCFG);

#ifdef notyet
	ant_regs[0] = urtwn_read_4(sc, R92C_CONFIG_ANT_A);
	ant_regs[1] = urtwn_read_4(sc, R92C_CONFIG_ANT_B);

	rf_regs[0] = urtwn_read_4(sc, R92C_FPGA0_RFIFACESW(0));
	for (i = 0; i < sc->nrxchains; i++)
		rf_regs[i+1] = urtwn_read_4(sc, R92C_FPGA0_RFIFACEOE(i));
	reg4 = urtwn_read_4(sc, R92C_CCK0_AFESETTING);
#endif

	piMode = (urtwn_bb_read(sc, R92C_HSSI_PARAM1(0)) &
	    R92C_HSSI_PARAM1_PI);
	if (piMode == 0) {
		urtwn_bb_write(sc, R92C_HSSI_PARAM1(0),
		    urtwn_bb_read(sc, R92C_HSSI_PARAM1(0))|
		    R92C_HSSI_PARAM1_PI);
		urtwn_bb_write(sc, R92C_HSSI_PARAM1(1),
		    urtwn_bb_read(sc, R92C_HSSI_PARAM1(1))|
		    R92C_HSSI_PARAM1_PI);
	}

	attempt = 1;

next_attempt:

	/* Set mac regs for calibration. */
	for (i = 0; i < __arraycount(addaReg); i++) {
		urtwn_bb_write(sc, addaReg[i],
		    addaReg[__arraycount(addaReg) - 1]);
	}
	urtwn_write_2(sc, R92C_CCK0_AFESETTING, urtwn_read_2(sc,
	    R92C_CCK0_AFESETTING));
	urtwn_write_2(sc, R92C_OFDM0_TRXPATHENA, R92C_IQK_TRXPATHENA);
	urtwn_write_2(sc, R92C_OFDM0_TRMUXPAR, R92C_IQK_TRMUXPAR);
	urtwn_write_2(sc, R92C_FPGA0_RFIFACESW(1), R92C_IQK_RFIFACESW1);
	urtwn_write_4(sc, R92C_LSSI_PARAM(0), R92C_IQK_LSSI_PARAM);

	if (sc->ntxchains > 1)
		urtwn_bb_write(sc, R92C_LSSI_PARAM(1), R92C_IQK_LSSI_PARAM);

	urtwn_write_1(sc, R92C_TXPAUSE, (~R92C_TXPAUSE_BCN) & R92C_TXPAUSE_ALL);
	urtwn_write_1(sc, R92C_BCN_CTRL, (iqkBackup[1] &
	    ~R92C_BCN_CTRL_EN_BCN));
	urtwn_write_1(sc, R92C_BCN_CTRL1, (iqkBackup[2] &
	    ~R92C_BCN_CTRL_EN_BCN));

	urtwn_write_1(sc, R92C_GPIO_MUXCFG, (iqkBackup[3] &
	    ~R92C_GPIO_MUXCFG_ENBT));

	urtwn_bb_write(sc, R92C_CONFIG_ANT_A, R92C_IQK_CONFIG_ANT);

	if (sc->ntxchains > 1)
		urtwn_bb_write(sc, R92C_CONFIG_ANT_B, R92C_IQK_CONFIG_ANT);
	urtwn_bb_write(sc, R92C_FPGA0_IQK, R92C_FPGA0_IQK_SETTING);
	urtwn_bb_write(sc, R92C_TX_IQK, R92C_TX_IQK_SETTING);
	urtwn_bb_write(sc, R92C_RX_IQK, R92C_RX_IQK_SETTING);

	/* Restore BB regs. */
	urtwn_bb_write(sc, R92C_OFDM0_TRXPATHENA, reg0);
	urtwn_bb_write(sc, R92C_FPGA0_RFIFACESW(1), reg2);
	urtwn_bb_write(sc, R92C_OFDM0_TRMUXPAR, reg1);

	urtwn_bb_write(sc, R92C_FPGA0_IQK, 0x0);
	urtwn_bb_write(sc, R92C_LSSI_PARAM(0), R92C_IQK_LSSI_RESTORE);
	if (sc->nrxchains > 1)
		urtwn_bb_write(sc, R92C_LSSI_PARAM(1), R92C_IQK_LSSI_RESTORE);

	if (attempt-- > 0)
		goto next_attempt;

	/* Restore mode. */
	if (piMode == 0) {
		urtwn_bb_write(sc, R92C_HSSI_PARAM1(0),
		    urtwn_bb_read(sc, R92C_HSSI_PARAM1(0)) &
		    ~R92C_HSSI_PARAM1_PI);
		urtwn_bb_write(sc, R92C_HSSI_PARAM1(1),
		    urtwn_bb_read(sc, R92C_HSSI_PARAM1(1)) &
		    ~R92C_HSSI_PARAM1_PI);
	}

#ifdef notyet
	for (i = 0; i < sc->nrxchains; i++) {
		urtwn_write_4(sc, R92C_OFDM0_AGCCORE1(i),
		    odfm0_agccore_regs[i]);
	}
#endif

	/* Restore adda regs. */
	for (i = 0; i < __arraycount(addaReg); i++)
		urtwn_bb_write(sc, addaReg[i], addaBackup[i]);
	/* Restore mac regs. */
	urtwn_write_1(sc, R92C_TXPAUSE, iqkBackup[0]);
	urtwn_write_1(sc, R92C_BCN_CTRL, iqkBackup[1]);
	urtwn_write_1(sc, R92C_USTIME_TSF, iqkBackup[2]);
	urtwn_write_4(sc, R92C_GPIO_MUXCFG, iqkBackup[3]);

#ifdef notyet
	urtwn_write_4(sc, R92C_CONFIG_ANT_A, ant_regs[0]);
	urtwn_write_4(sc, R92C_CONFIG_ANT_B, ant_regs[1]);

	urtwn_write_4(sc, R92C_FPGA0_RFIFACESW(0), rf_regs[0]);
	for (i = 0; i < sc->nrxchains; i++)
		urtwn_write_4(sc, R92C_FPGA0_RFIFACEOE(i), rf_regs[i+1]);
	urtwn_write_4(sc, R92C_CCK0_AFESETTING, reg4);
#endif
}

static void
urtwn_lc_calib(struct urtwn_softc *sc)
{
	uint32_t rf_ac[2];
	uint8_t txmode;
	size_t i;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	txmode = urtwn_read_1(sc, R92C_OFDM1_LSTF + 3);
	if ((txmode & 0x70) != 0) {
		/* Disable all continuous Tx. */
		urtwn_write_1(sc, R92C_OFDM1_LSTF + 3, txmode & ~0x70);

		/* Set RF mode to standby mode. */
		for (i = 0; i < sc->nrxchains; i++) {
			rf_ac[i] = urtwn_rf_read(sc, i, R92C_RF_AC);
			urtwn_rf_write(sc, i, R92C_RF_AC,
			    RW(rf_ac[i], R92C_RF_AC_MODE,
				R92C_RF_AC_MODE_STANDBY));
		}
	} else {
		/* Block all Tx queues. */
		urtwn_write_1(sc, R92C_TXPAUSE, 0xff);
	}
	/* Start calibration. */
	urtwn_rf_write(sc, 0, R92C_RF_CHNLBW,
	    urtwn_rf_read(sc, 0, R92C_RF_CHNLBW) | R92C_RF_CHNLBW_LCSTART);

	/* Give calibration the time to complete. */
	urtwn_delay_ms(sc, 100);

	/* Restore configuration. */
	if ((txmode & 0x70) != 0) {
		/* Restore Tx mode. */
		urtwn_write_1(sc, R92C_OFDM1_LSTF + 3, txmode);
		/* Restore RF mode. */
		for (i = 0; i < sc->nrxchains; i++) {
			urtwn_rf_write(sc, i, R92C_RF_AC, rf_ac[i]);
		}
	} else {
		/* Unblock all Tx queues. */
		urtwn_write_1(sc, R92C_TXPAUSE, 0x00);
	}
}

static void
urtwn_temp_calib(struct urtwn_softc *sc)
{
	int temp, t_meter_reg;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	KASSERT(mutex_owned(&sc->sc_write_mtx));

	if (!ISSET(sc->chip, URTWN_CHIP_92EU))
		t_meter_reg = R92C_RF_T_METER;
	else
		t_meter_reg = R92E_RF_T_METER;

	if (sc->thcal_state == 0) {
		/* Start measuring temperature. */
		DPRINTFN(DBG_RF, "start measuring temperature", 0, 0, 0, 0);
		urtwn_rf_write(sc, 0, t_meter_reg, 0x60);
		sc->thcal_state = 1;
		return;
	}
	sc->thcal_state = 0;

	/* Read measured temperature. */
	temp = urtwn_rf_read(sc, 0, R92C_RF_T_METER) & 0x1f;
	DPRINTFN(DBG_RF, "temperature=%jd", temp, 0, 0, 0);
	if (temp == 0)		/* Read failed, skip. */
		return;

	/*
	 * Redo LC calibration if temperature changed significantly since
	 * last calibration.
	 */
	if (sc->thcal_lctemp == 0) {
		/* First LC calibration is performed in urtwn_init(). */
		sc->thcal_lctemp = temp;
	} else if (abs(temp - sc->thcal_lctemp) > 1) {
		DPRINTFN(DBG_RF, "LC calib triggered by temp: %jd -> %jd",
		    sc->thcal_lctemp, temp, 0, 0);
		urtwn_lc_calib(sc);
		/* Record temperature of last LC calibration. */
		sc->thcal_lctemp = temp;
	}
}

static int
urtwn_init(struct ifnet *ifp)
{
	struct urtwn_softc *sc = ifp->if_softc;
	struct ieee80211com *ic = &sc->sc_ic;
	struct urtwn_rx_data *data;
	uint32_t reg;
	size_t i;
	int error;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	urtwn_stop(ifp, 0);

	mutex_enter(&sc->sc_write_mtx);

	mutex_enter(&sc->sc_task_mtx);
	/* Init host async commands ring. */
	sc->cmdq.cur = sc->cmdq.next = sc->cmdq.queued = 0;
	mutex_exit(&sc->sc_task_mtx);

	mutex_enter(&sc->sc_fwcmd_mtx);
	/* Init firmware commands ring. */
	sc->fwcur = 0;
	mutex_exit(&sc->sc_fwcmd_mtx);

	/* Allocate Tx/Rx buffers. */
	error = urtwn_alloc_rx_list(sc);
	if (error != 0) {
		aprint_error_dev(sc->sc_dev,
		    "could not allocate Rx buffers\n");
		goto fail;
	}
	error = urtwn_alloc_tx_list(sc);
	if (error != 0) {
		aprint_error_dev(sc->sc_dev,
		    "could not allocate Tx buffers\n");
		goto fail;
	}

	/* Power on adapter. */
	error = urtwn_power_on(sc);
	if (error != 0)
		goto fail;

	/* Initialize DMA. */
	error = urtwn_dma_init(sc);
	if (error != 0)
		goto fail;

	/* Set info size in Rx descriptors (in 64-bit words). */
	urtwn_write_1(sc, R92C_RX_DRVINFO_SZ, 4);

	/* Init interrupts. */
	if (ISSET(sc->chip, URTWN_CHIP_88E) ||
	    ISSET(sc->chip, URTWN_CHIP_92EU)) {
		urtwn_write_4(sc, R88E_HISR, 0xffffffff);
		urtwn_write_4(sc, R88E_HIMR, R88E_HIMR_CPWM | R88E_HIMR_CPWM2 |
		    R88E_HIMR_TBDER | R88E_HIMR_PSTIMEOUT);
		urtwn_write_4(sc, R88E_HIMRE, R88E_HIMRE_RXFOVW |
		    R88E_HIMRE_TXFOVW | R88E_HIMRE_RXERR | R88E_HIMRE_TXERR);
		if (ISSET(sc->chip, URTWN_CHIP_88E)) {
			urtwn_write_1(sc, R92C_USB_SPECIAL_OPTION,
			    urtwn_read_1(sc, R92C_USB_SPECIAL_OPTION) |
			      R92C_USB_SPECIAL_OPTION_INT_BULK_SEL);
		}
		if (ISSET(sc->chip, URTWN_CHIP_92EU))
			urtwn_write_1(sc, R92C_USB_HRPWM, 0);
	} else {
		urtwn_write_4(sc, R92C_HISR, 0xffffffff);
		urtwn_write_4(sc, R92C_HIMR, 0xffffffff);
	}

	/* Set MAC address. */
	IEEE80211_ADDR_COPY(ic->ic_myaddr, CLLADDR(ifp->if_sadl));
	urtwn_write_region(sc, R92C_MACID, ic->ic_myaddr, IEEE80211_ADDR_LEN);

	/* Set initial network type. */
	reg = urtwn_read_4(sc, R92C_CR);
	switch (ic->ic_opmode) {
	case IEEE80211_M_STA:
	default:
		reg = RW(reg, R92C_CR_NETTYPE, R92C_CR_NETTYPE_INFRA);
		break;

	case IEEE80211_M_IBSS:
		reg = RW(reg, R92C_CR_NETTYPE, R92C_CR_NETTYPE_ADHOC);
		break;
	}
	urtwn_write_4(sc, R92C_CR, reg);

	/* Set response rate */
	reg = urtwn_read_4(sc, R92C_RRSR);
	reg = RW(reg, R92C_RRSR_RATE_BITMAP, R92C_RRSR_RATE_CCK_ONLY_1M);
	urtwn_write_4(sc, R92C_RRSR, reg);

	/* SIFS (used in NAV) */
	urtwn_write_2(sc, R92C_SPEC_SIFS,
	    SM(R92C_SPEC_SIFS_CCK, 0x10) | SM(R92C_SPEC_SIFS_OFDM, 0x10));

	/* Set short/long retry limits. */
	urtwn_write_2(sc, R92C_RL,
	    SM(R92C_RL_SRL, 0x30) | SM(R92C_RL_LRL, 0x30));

	/* Initialize EDCA parameters. */
	urtwn_edca_init(sc);

	/* Setup rate fallback. */
	if (!ISSET(sc->chip, URTWN_CHIP_88E) &&
	    !ISSET(sc->chip, URTWN_CHIP_92EU)) {
		urtwn_write_4(sc, R92C_DARFRC + 0, 0x00000000);
		urtwn_write_4(sc, R92C_DARFRC + 4, 0x10080404);
		urtwn_write_4(sc, R92C_RARFRC + 0, 0x04030201);
		urtwn_write_4(sc, R92C_RARFRC + 4, 0x08070605);
	}

	urtwn_write_1(sc, R92C_FWHW_TXQ_CTRL,
	    urtwn_read_1(sc, R92C_FWHW_TXQ_CTRL) |
	    R92C_FWHW_TXQ_CTRL_AMPDU_RTY_NEW);
	/* Set ACK timeout. */
	urtwn_write_1(sc, R92C_ACKTO, 0x40);

	/* Setup USB aggregation. */
	/* Tx */
	reg = urtwn_read_4(sc, R92C_TDECTRL);
	reg = RW(reg, R92C_TDECTRL_BLK_DESC_NUM, 6);
	urtwn_write_4(sc, R92C_TDECTRL, reg);
	/* Rx */
	urtwn_write_1(sc, R92C_TRXDMA_CTRL,
	    urtwn_read_1(sc, R92C_TRXDMA_CTRL) |
	      R92C_TRXDMA_CTRL_RXDMA_AGG_EN);
	urtwn_write_1(sc, R92C_USB_SPECIAL_OPTION,
	    urtwn_read_1(sc, R92C_USB_SPECIAL_OPTION) &
	      ~R92C_USB_SPECIAL_OPTION_AGG_EN);
	urtwn_write_1(sc, R92C_RXDMA_AGG_PG_TH, 48);
	if (ISSET(sc->chip, URTWN_CHIP_88E) ||
	    ISSET(sc->chip, URTWN_CHIP_92EU))
		urtwn_write_1(sc, R92C_RXDMA_AGG_PG_TH + 1, 4);
	else
		urtwn_write_1(sc, R92C_USB_DMA_AGG_TO, 4);

	/* Initialize beacon parameters. */
	urtwn_write_2(sc, R92C_BCN_CTRL, 0x1010);
	urtwn_write_2(sc, R92C_TBTT_PROHIBIT, 0x6404);
	urtwn_write_1(sc, R92C_DRVERLYINT, R92C_DRVERLYINT_INIT_TIME);
	urtwn_write_1(sc, R92C_BCNDMATIM, R92C_BCNDMATIM_INIT_TIME);
	urtwn_write_2(sc, R92C_BCNTCFG, 0x660f);

	if (!ISSET(sc->chip, URTWN_CHIP_88E) &&
	    !ISSET(sc->chip, URTWN_CHIP_92EU)) {
		/* Setup AMPDU aggregation. */
		urtwn_write_4(sc, R92C_AGGLEN_LMT, 0x99997631);	/* MCS7~0 */
		urtwn_write_1(sc, R92C_AGGR_BREAK_TIME, 0x16);
		urtwn_write_2(sc, 0x4ca, 0x0708);

		urtwn_write_1(sc, R92C_BCN_MAX_ERR, 0xff);
		urtwn_write_1(sc, R92C_BCN_CTRL, R92C_BCN_CTRL_DIS_TSF_UDT0);
	}

	/* Load 8051 microcode. */
	error = urtwn_load_firmware(sc);
	if (error != 0)
		goto fail;
	SET(sc->sc_flags, URTWN_FLAG_FWREADY);

	/* Initialize MAC/BB/RF blocks. */
	/*
	 * XXX: urtwn_mac_init() sets R92C_RCR[0:15] = R92C_RCR_APM |
	 * R92C_RCR_AM | R92C_RCR_AB | R92C_RCR_AICV | R92C_RCR_AMF.
	 * XXX: This setting should be removed from rtl8192cu_mac[].
	 */
	urtwn_mac_init(sc);		// sets R92C_RCR[0:15]
	urtwn_rxfilter_init(sc);	// reset R92C_RCR
	urtwn_bb_init(sc);
	urtwn_rf_init(sc);

	if (ISSET(sc->chip, URTWN_CHIP_88E) ||
	    ISSET(sc->chip, URTWN_CHIP_92EU)) {
		urtwn_write_2(sc, R92C_CR,
		    urtwn_read_2(sc, R92C_CR) | R92C_CR_MACTXEN |
		      R92C_CR_MACRXEN);
	}

	/* Turn CCK and OFDM blocks on. */
	reg = urtwn_bb_read(sc, R92C_FPGA0_RFMOD);
	reg |= R92C_RFMOD_CCK_EN;
	urtwn_bb_write(sc, R92C_FPGA0_RFMOD, reg);
	reg = urtwn_bb_read(sc, R92C_FPGA0_RFMOD);
	reg |= R92C_RFMOD_OFDM_EN;
	urtwn_bb_write(sc, R92C_FPGA0_RFMOD, reg);

	/* Clear per-station keys table. */
	urtwn_cam_init(sc);

	/* Enable hardware sequence numbering. */
	urtwn_write_1(sc, R92C_HWSEQ_CTRL, 0xff);

	/* Perform LO and IQ calibrations. */
	urtwn_iq_calib(sc, sc->iqk_inited);
	sc->iqk_inited = true;

	/* Perform LC calibration. */
	urtwn_lc_calib(sc);

	if (!ISSET(sc->chip, URTWN_CHIP_88E) &&
	    !ISSET(sc->chip, URTWN_CHIP_92EU)) {
		/* Fix USB interference issue. */
		urtwn_write_1(sc, 0xfe40, 0xe0);
		urtwn_write_1(sc, 0xfe41, 0x8d);
		urtwn_write_1(sc, 0xfe42, 0x80);
		urtwn_write_4(sc, 0x20c, 0xfd0320);

		urtwn_pa_bias_init(sc);
	}

	if (!(sc->chip & (URTWN_CHIP_92C | URTWN_CHIP_92C_1T2R)) ||
	    !(sc->chip & URTWN_CHIP_92EU)) {
		/* 1T1R */
		urtwn_bb_write(sc, R92C_FPGA0_RFPARAM(0),
		    urtwn_bb_read(sc, R92C_FPGA0_RFPARAM(0)) | __BIT(13));
	}

	/* Initialize GPIO setting. */
	urtwn_write_1(sc, R92C_GPIO_MUXCFG,
	    urtwn_read_1(sc, R92C_GPIO_MUXCFG) & ~R92C_GPIO_MUXCFG_ENBT);

	/* Fix for lower temperature. */
	if (!ISSET(sc->chip, URTWN_CHIP_88E) &&
	    !ISSET(sc->chip, URTWN_CHIP_92EU))
		urtwn_write_1(sc, 0x15, 0xe9);

	/* Set default channel. */
	urtwn_set_chan(sc, ic->ic_curchan, IEEE80211_HTINFO_2NDCHAN_NONE);

	/* Queue Rx xfers. */
	for (size_t j = 0; j < sc->rx_npipe; j++) {
		for (i = 0; i < URTWN_RX_LIST_COUNT; i++) {
			data = &sc->rx_data[j][i];
			usbd_setup_xfer(data->xfer, data, data->buf,
			    URTWN_RXBUFSZ, USBD_SHORT_XFER_OK, USBD_NO_TIMEOUT,
			    urtwn_rxeof);
			error = usbd_transfer(data->xfer);
			if (__predict_false(error != USBD_NORMAL_COMPLETION &&
			    error != USBD_IN_PROGRESS))
				goto fail;
		}
	}

	/* We're ready to go. */
	ifp->if_flags &= ~IFF_OACTIVE;
	ifp->if_flags |= IFF_RUNNING;
	sc->sc_running = true;

	mutex_exit(&sc->sc_write_mtx);

	if (ic->ic_opmode == IEEE80211_M_MONITOR)
		ieee80211_new_state(ic, IEEE80211_S_RUN, -1);
	else if (ic->ic_roaming != IEEE80211_ROAMING_MANUAL)
		ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
	urtwn_wait_async(sc);

	return 0;

 fail:
	mutex_exit(&sc->sc_write_mtx);

	urtwn_stop(ifp, 1);
	return error;
}

static void __noinline
urtwn_stop(struct ifnet *ifp, int disable)
{
	struct urtwn_softc *sc = ifp->if_softc;
	struct ieee80211com *ic = &sc->sc_ic;
	size_t i;
	int s;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	s = splusb();
	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
	urtwn_wait_async(sc);
	splx(s);

	sc->tx_timer = 0;
	ifp->if_timer = 0;
	ifp->if_flags &= ~(IFF_RUNNING | IFF_OACTIVE);

	callout_stop(&sc->sc_scan_to);
	callout_stop(&sc->sc_calib_to);

	/* Abort Tx. */
	for (i = 0; i < sc->tx_npipe; i++) {
		if (sc->tx_pipe[i] != NULL)
			usbd_abort_pipe(sc->tx_pipe[i]);
	}

	/* Stop Rx pipe. */
	for (i = 0; i < sc->rx_npipe; i++) {
		if (sc->rx_pipe[i] != NULL)
			usbd_abort_pipe(sc->rx_pipe[i]);
	}

	/* Free Tx/Rx buffers. */
	urtwn_free_tx_list(sc);
	urtwn_free_rx_list(sc);

	sc->sc_running = false;
	if (disable)
		urtwn_chip_stop(sc);
}

static int
urtwn_reset(struct ifnet *ifp)
{
	struct urtwn_softc *sc = ifp->if_softc;
	struct ieee80211com *ic = &sc->sc_ic;

	if (ic->ic_opmode != IEEE80211_M_MONITOR)
		return ENETRESET;

	urtwn_set_chan(sc, ic->ic_curchan, IEEE80211_HTINFO_2NDCHAN_NONE);

	return 0;
}

static void
urtwn_chip_stop(struct urtwn_softc *sc)
{
	uint32_t reg;
	bool disabled = true;

	URTWNHIST_FUNC(); URTWNHIST_CALLED();

	if (ISSET(sc->chip, URTWN_CHIP_88E) ||
	    ISSET(sc->chip, URTWN_CHIP_92EU))
		return;

	mutex_enter(&sc->sc_write_mtx);

	/*
	 * RF Off Sequence
	 */
	/* Pause MAC TX queue */
	urtwn_write_1(sc, R92C_TXPAUSE, 0xFF);

	/* Disable RF */
	urtwn_rf_write(sc, 0, 0, 0);

	urtwn_write_1(sc, R92C_APSD_CTRL, R92C_APSD_CTRL_OFF);

	/* Reset BB state machine */
	urtwn_write_1(sc, R92C_SYS_FUNC_EN,
	    R92C_SYS_FUNC_EN_USBD |
	    R92C_SYS_FUNC_EN_USBA |
	    R92C_SYS_FUNC_EN_BB_GLB_RST);
	urtwn_write_1(sc, R92C_SYS_FUNC_EN,
	    R92C_SYS_FUNC_EN_USBD | R92C_SYS_FUNC_EN_USBA);

	/*
	 * Reset digital sequence
	 */
	if (urtwn_read_1(sc, R92C_MCUFWDL) & R92C_MCUFWDL_RDY) {
		/* Reset MCU ready status */
		urtwn_write_1(sc, R92C_MCUFWDL, 0);
		/* If firmware in ram code, do reset */
		if (ISSET(sc->sc_flags, URTWN_FLAG_FWREADY)) {
			if (ISSET(sc->chip, URTWN_CHIP_88E) ||
			    ISSET(sc->chip, URTWN_CHIP_92EU))
				urtwn_r88e_fw_reset(sc);
			else
				urtwn_fw_reset(sc);
			CLR(sc->sc_flags, URTWN_FLAG_FWREADY);
		}
	}

	/* Reset MAC and Enable 8051 */
	urtwn_write_1(sc, R92C_SYS_FUNC_EN + 1, 0x54);

	/* Reset MCU ready status */
	urtwn_write_1(sc, R92C_MCUFWDL, 0);

	if (disabled) {
		/* Disable MAC clock */
		urtwn_write_2(sc, R92C_SYS_CLKR, 0x70A3);
		/* Disable AFE PLL */
		urtwn_write_1(sc, R92C_AFE_PLL_CTRL, 0x80);
		/* Gated AFE DIG_CLOCK */
		urtwn_write_2(sc, R92C_AFE_XTAL_CTRL, 0x880F);
		/* Isolated digital to PON */
		urtwn_write_1(sc, R92C_SYS_ISO_CTRL, 0xF9);
	}

	/*
	 * Pull GPIO PIN to balance level and LED control
	 */
	/* 1. Disable GPIO[7:0] */
	urtwn_write_2(sc, R92C_GPIO_PIN_CTRL + 2, 0x0000);

	reg = urtwn_read_4(sc, R92C_GPIO_PIN_CTRL) & ~0x0000ff00;
	reg |= ((reg << 8) & 0x0000ff00) | 0x00ff0000;
	urtwn_write_4(sc, R92C_GPIO_PIN_CTRL, reg);

	/* Disable GPIO[10:8] */
	urtwn_write_1(sc, R92C_GPIO_MUXCFG + 3, 0x00);

	reg = urtwn_read_2(sc, R92C_GPIO_MUXCFG + 2) & ~0x00f0;
	reg |= (((reg & 0x000f) << 4) | 0x0780);
	urtwn_write_2(sc, R92C_GPIO_MUXCFG + 2, reg);

	/* Disable LED0 & 1 */
	urtwn_write_2(sc, R92C_LEDCFG0, 0x8080);

	/*
	 * Reset digital sequence
	 */
	if (disabled) {
		/* Disable ELDR clock */
		urtwn_write_2(sc, R92C_SYS_CLKR, 0x70A3);
		/* Isolated ELDR to PON */
		urtwn_write_1(sc, R92C_SYS_ISO_CTRL + 1, 0x82);
	}

	/*
	 * Disable analog sequence
	 */
	if (disabled) {
		/* Disable A15 power */
		urtwn_write_1(sc, R92C_LDOA15_CTRL, 0x04);
		/* Disable digital core power */
		urtwn_write_1(sc, R92C_LDOV12D_CTRL,
		    urtwn_read_1(sc, R92C_LDOV12D_CTRL) &
		      ~R92C_LDOV12D_CTRL_LDV12_EN);
	}

	/* Enter PFM mode */
	urtwn_write_1(sc, R92C_SPS0_CTRL, 0x23);

	/* Set USB suspend */
	urtwn_write_2(sc, R92C_APS_FSMCO,
	    R92C_APS_FSMCO_APDM_HOST |
	    R92C_APS_FSMCO_AFSM_HSUS |
	    R92C_APS_FSMCO_PFM_ALDN);

	urtwn_write_1(sc, R92C_RSV_CTRL, 0x0E);

	mutex_exit(&sc->sc_write_mtx);
}

static void
urtwn_delay_ms(struct urtwn_softc *sc, int ms)
{
	if (sc->sc_running == false)
		DELAY(ms * 1000);
	else
		usbd_delay_ms(sc->sc_udev, ms);
}

MODULE(MODULE_CLASS_DRIVER, if_urtwn, NULL);

#ifdef _MODULE
#include "ioconf.c"
#endif

static int
if_urtwn_modcmd(modcmd_t cmd, void *aux)
{
	int error = 0;

	switch (cmd) {
	case MODULE_CMD_INIT:
#ifdef _MODULE
		error = config_init_component(cfdriver_ioconf_urtwn,
		    cfattach_ioconf_urtwn, cfdata_ioconf_urtwn);
#endif
		return error;
	case MODULE_CMD_FINI:
#ifdef _MODULE
		error = config_fini_component(cfdriver_ioconf_urtwn,
		    cfattach_ioconf_urtwn, cfdata_ioconf_urtwn);
#endif
		return error;
	default:
		return ENOTTY;
	}
}
