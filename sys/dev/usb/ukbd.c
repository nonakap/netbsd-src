/*      $NetBSD: ukbd.c,v 1.165 2024/12/10 11:21:30 mlelstv Exp $        */

/*
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Lennart Augustsson (lennart@augustsson.net) at
 * Carlstedt Research & Technology.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * HID spec: http://www.usb.org/developers/devclass_docs/HID1_11.pdf
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: ukbd.c,v 1.165 2024/12/10 11:21:30 mlelstv Exp $");

#ifdef _KERNEL_OPT
#include "opt_ddb.h"
#include "opt_ukbd.h"
#include "opt_ukbd_layout.h"
#include "opt_usb.h"
#include "opt_usbverbose.h"
#include "opt_wsdisplay_compat.h"
#endif /* _KERNEL_OPT */

#include <sys/param.h>

#include <sys/callout.h>
#include <sys/device.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/kernel.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/select.h>
#include <sys/systm.h>
#include <sys/vnode.h>

#include <dev/hid/hid.h>

#include <dev/usb/uhidev.h>
#include <dev/usb/ukbdvar.h>
#include <dev/usb/usb.h>
#include <dev/usb/usb_quirks.h>
#include <dev/usb/usbdevs.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdi_util.h>
#include <dev/usb/usbdivar.h>
#include <dev/usb/usbhid.h>

#include <dev/wscons/wsconsio.h>
#include <dev/wscons/wskbdvar.h>
#include <dev/wscons/wsksymdef.h>
#include <dev/wscons/wsksymvar.h>

#ifdef UKBD_DEBUG
#define DPRINTF(x)	if (ukbddebug) printf x
#define DPRINTFN(n,x)	if (ukbddebug>(n)) printf x
int	ukbddebug = 0;
#else
#define DPRINTF(x)
#define DPRINTFN(n,x)
#endif

#define MAXKEYCODE 32
#define MAXKEYS 256

struct ukbd_data {
	uint8_t		keys[MAXKEYS/NBBY];
};

#define PRESS    0x000
#define RELEASE  0x100
#define CODEMASK 0x0ff

struct ukbd_keycodetrans {
	uint16_t	from;
	uint16_t	to;
};

#define IS_PMF	0x8000

Static const struct ukbd_keycodetrans trtab_apple_fn[] = {
	{ 0x0c, 0x5d },	/* i -> KP 5 */
	{ 0x0d, 0x59 },	/* j -> KP 1 */
	{ 0x0e, 0x5a },	/* k -> KP 2 */
	{ 0x0f, 0x5b },	/* l -> KP 3 */
	{ 0x10, 0x62 },	/* m -> KP 0 */
	{ 0x12, 0x5e },	/* o -> KP 6 */
	{ 0x13, 0x55 },	/* o -> KP * */
	{ 0x18, 0x5c },	/* u -> KP 4 */
	{ 0x0c, 0x5d },	/* i -> KP 5 */
	{ 0x2a, 0x4c },	/* Backspace -> Delete */
	{ 0x28, 0x49 },	/* Return -> Insert */
	{ 0x24, 0x5f }, /* 7 -> KP 7 */
	{ 0x25, 0x60 }, /* 8 -> KP 8 */
	{ 0x26, 0x61 }, /* 9 -> KP 9 */
	{ 0x27, 0x54 }, /* 0 -> KP / */
	{ 0x2d, 0x67 }, /* - -> KP = */
	{ 0x33, 0x56 },	/* ; -> KP - */
	{ 0x37, 0x63 },	/* . -> KP . */
	{ 0x38, 0x57 },	/* / -> KP + */
	{ 0x3a, IS_PMF | PMFE_DISPLAY_BRIGHTNESS_DOWN },
	{ 0x3b, IS_PMF | PMFE_DISPLAY_BRIGHTNESS_UP },
	{ 0x3c, IS_PMF | PMFE_AUDIO_VOLUME_TOGGLE },
	{ 0x3d, IS_PMF | PMFE_AUDIO_VOLUME_DOWN },
	{ 0x3e, IS_PMF | PMFE_AUDIO_VOLUME_UP },
	{ 0x3f, 0xd6 },	/* num lock */
	{ 0x40, 0xd7 },
	{ 0x41, IS_PMF | PMFE_KEYBOARD_BRIGHTNESS_TOGGLE },
	{ 0x42, IS_PMF | PMFE_KEYBOARD_BRIGHTNESS_DOWN },
	{ 0x43, IS_PMF | PMFE_KEYBOARD_BRIGHTNESS_UP },
	{ 0x44, 0xdb },
	{ 0x45, 0xdc },
	{ 0x4f, 0x4d },	/* Right -> End */
	{ 0x50, 0x4a },	/* Left -> Home */
	{ 0x51, 0x4e },	/* Down -> PageDown */
	{ 0x52, 0x4b },	/* Up -> PageUp */
	{ 0x00, 0x00 }
};

Static const struct ukbd_keycodetrans trtab_apple_iso[] = {
	{ 0x35, 0x64 },	/* swap the key above tab with key right of shift */
	{ 0x64, 0x35 },
	{ 0x31, 0x32 },	/* key left of return is Europe1, not "\|" */
	{ 0x00, 0x00 }
};

#ifdef GDIUM_KEYBOARD_HACK
Static const struct ukbd_keycodetrans trtab_gdium_fn[] = {
#ifdef notyet
	{ 58, 0 },	/* F1 -> toggle camera */
	{ 59, 0 },	/* F2 -> toggle wireless */
#endif
	{ 60, IS_PMF | PMFE_AUDIO_VOLUME_TOGGLE },
	{ 61, IS_PMF | PMFE_AUDIO_VOLUME_UP },
	{ 62, IS_PMF | PMFE_AUDIO_VOLUME_DOWN },
#ifdef notyet
	{ 63, 0 },	/* F6 -> toggle ext. video */
	{ 64, 0 },	/* F7 -> toggle mouse */
#endif
	{ 65, IS_PMF | PMFE_DISPLAY_BRIGHTNESS_UP },
	{ 66, IS_PMF | PMFE_DISPLAY_BRIGHTNESS_DOWN },
#ifdef notyet
	{ 67, 0 },	/* F10 -> suspend */
	{ 68, 0 },	/* F11 -> user1 */
	{ 69, 0 },	/* F12 -> user2 */
	{ 70, 0 },	/* print screen -> sysrq */
#endif
	{ 76, 71 },	/* delete -> scroll lock */
	{ 81, 78 },	/* down -> page down */
	{ 82, 75 },	/* up -> page up */
	{  0, 0 }
};
#endif

Static const struct ukbd_keycodetrans trtab_generic[] = {
	{ 0x7f, IS_PMF | PMFE_AUDIO_VOLUME_TOGGLE },
	{ 0x80, IS_PMF | PMFE_AUDIO_VOLUME_UP },
	{ 0x81, IS_PMF | PMFE_AUDIO_VOLUME_DOWN },
	{ 0x00, 0x00 }
};

#if defined(WSDISPLAY_COMPAT_RAWKBD)
#define NN 0			/* no translation */
/*
 * Translate USB keycodes to US keyboard XT scancodes.
 * Scancodes >= 0x80 represent EXTENDED keycodes.
 *
 * See http://www.microsoft.com/whdc/archive/scancode.mspx
 *
 * Note: a real pckbd(4) has more complexity in its
 * protocol for some keys than this translation implements.
 * For example, some keys generate Fake ShiftL events (e0 2a)
 * before the actual key sequence.
 */
Static const uint8_t ukbd_trtab[256] = {
      NN,   NN,   NN,   NN, 0x1e, 0x30, 0x2e, 0x20, /* 00 - 07 */
    0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, /* 08 - 0f */
    0x32, 0x31, 0x18, 0x19, 0x10, 0x13, 0x1f, 0x14, /* 10 - 17 */
    0x16, 0x2f, 0x11, 0x2d, 0x15, 0x2c, 0x02, 0x03, /* 18 - 1f */
    0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, /* 20 - 27 */
    0x1c, 0x01, 0x0e, 0x0f, 0x39, 0x0c, 0x0d, 0x1a, /* 28 - 2f */
    0x1b, 0x2b, 0x2b, 0x27, 0x28, 0x29, 0x33, 0x34, /* 30 - 37 */
    0x35, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, /* 38 - 3f */
    0x41, 0x42, 0x43, 0x44, 0x57, 0x58, 0xb7, 0x46, /* 40 - 47 */
    0x7f, 0xd2, 0xc7, 0xc9, 0xd3, 0xcf, 0xd1, 0xcd, /* 48 - 4f */
    0xcb, 0xd0, 0xc8, 0x45, 0xb5, 0x37, 0x4a, 0x4e, /* 50 - 57 */
    0x9c, 0x4f, 0x50, 0x51, 0x4b, 0x4c, 0x4d, 0x47, /* 58 - 5f */
    0x48, 0x49, 0x52, 0x53, 0x56, 0xdd, 0xdf, 0x59, /* 60 - 67 */
    0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,   NN, /* 68 - 6f */
      NN,   NN,   NN,   NN, 0x84, 0x85, 0x87, 0x88, /* 70 - 77 */
    0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,   NN, /* 78 - 7f */
      NN,   NN,   NN,   NN,   NN, 0x7e,   NN, 0x73, /* 80 - 87 */
    0x70, 0x7d, 0x79, 0x7b, 0x5c,   NN,   NN,   NN, /* 88 - 8f */
      NN,   NN, 0x78, 0x77, 0x76,   NN,   NN,   NN, /* 90 - 97 */
      NN,   NN,   NN,   NN,   NN,   NN,   NN,   NN, /* 98 - 9f */
      NN,   NN,   NN,   NN,   NN,   NN,   NN,   NN, /* a0 - a7 */
      NN,   NN,   NN,   NN,   NN,   NN,   NN,   NN, /* a8 - af */
      NN,   NN,   NN,   NN,   NN,   NN,   NN,   NN, /* b0 - b7 */
      NN,   NN,   NN,   NN,   NN,   NN,   NN,   NN, /* b8 - bf */
      NN,   NN,   NN,   NN,   NN,   NN,   NN,   NN, /* c0 - c7 */
      NN,   NN,   NN,   NN,   NN,   NN,   NN,   NN, /* c8 - cf */
      NN,   NN,   NN,   NN,   NN,   NN,   NN,   NN, /* d0 - d7 */
      NN,   NN,   NN,   NN,   NN,   NN,   NN,   NN, /* d8 - df */
    0x1d, 0x2a, 0x38, 0xdb, 0x9d, 0x36, 0xb8, 0xdc, /* e0 - e7 */
      NN,   NN,   NN,   NN,   NN,   NN,   NN,   NN, /* e8 - ef */
      NN,   NN,   NN,   NN,   NN,   NN,   NN,   NN, /* f0 - f7 */
      NN,   NN,   NN,   NN,   NN,   NN,   NN,   NN, /* f8 - ff */
};
#endif /* defined(WSDISPLAY_COMPAT_RAWKBD) */

#define KEY_ERROR 0x01

struct ukbd_softc {
	device_t sc_dev;
	struct uhidev *sc_hdev;
	struct usbd_device *sc_udev;
	struct usbd_interface *sc_iface;
	int sc_report_id;

	struct ukbd_data sc_ndata;
	struct ukbd_data sc_odata;
	struct hid_location sc_keyloc[MAXKEYS];
	uint8_t sc_keyuse[MAXKEYS];
	u_int sc_nkeyloc;

	struct hid_location sc_keycodeloc;
	u_int sc_nkeycode;

	u_int sc_flags;			/* flags */
#define FLAG_ENABLED		0x0001
#define FLAG_POLLING		0x0002
#define FLAG_DEBOUNCE		0x0004	/* for quirk handling */
#define FLAG_APPLE_FIX_ISO	0x0008
#define FLAG_APPLE_FN		0x0010
#define FLAG_GDIUM_FN		0x0020
#define FLAG_FN_PRESSED		0x0100	/* FN key is held down */
#define FLAG_FN_ALT		0x0200	/* Last Alt key was FN-Alt = AltGr */
#define FLAG_NO_CONSOLE		0x0400	/* Don't attach as console */

	int sc_console_keyboard;	/* we are the console keyboard */

	struct callout sc_delay;	/* for quirk handling */
#define MAXPENDING 32
	struct ukbd_data sc_data[MAXPENDING];
	size_t sc_data_w, sc_data_r;

	struct hid_location sc_apple_fn;
	struct hid_location sc_numloc;
	struct hid_location sc_capsloc;
	struct hid_location sc_scroloc;
	struct hid_location sc_compose;
	int sc_leds;
	struct usb_task sc_ledtask;
	struct callout sc_ledreset;
	int sc_leds_set;
	device_t sc_wskbddev;

#if defined(WSDISPLAY_COMPAT_RAWKBD)
	int sc_rawkbd;
#if defined(UKBD_REPEAT)
	struct callout sc_rawrepeat_ch;
#define REP_DELAY1 400
#define REP_DELAYN 100
	int sc_nrep;
	char sc_rep[MAXKEYS];
#endif /* defined(UKBD_REPEAT) */
#endif /* defined(WSDISPLAY_COMPAT_RAWKBD) */

	int sc_spl;
	int sc_npollchar;
	uint16_t sc_pollchars[MAXKEYS];

	bool sc_dying;
	bool sc_attached;
};

#ifdef UKBD_DEBUG
#define UKBDTRACESIZE 64
struct ukbdtraceinfo {
	int unit;
	struct timeval tv;
	struct ukbd_data ud;
};
struct ukbdtraceinfo ukbdtracedata[UKBDTRACESIZE];
int ukbdtraceindex = 0;
int ukbdtrace = 0;
void ukbdtracedump(void);
void
ukbdtracedump(void)
{
	size_t i, j;
	for (i = 0; i < UKBDTRACESIZE; i++) {
		struct ukbdtraceinfo *p =
		    &ukbdtracedata[(i+ukbdtraceindex)%UKBDTRACESIZE];
		printf("%"PRIu64".%06"PRIu64":", p->tv.tv_sec,
		    (uint64_t)p->tv.tv_usec);
		for (j = 0; j < MAXKEYS; j++) {
			if (isset(p->ud.keys, j))
				printf(" %zu", j);
		}
		printf(".\n");
	}
}
#endif

#define	UKBDUNIT(dev)	(minor(dev))
#define	UKBD_CHUNK	128	/* chunk size for read */
#define	UKBD_BSIZE	1020	/* buffer size */

Static int	ukbd_is_console;

Static void	ukbd_cngetc(void *, u_int *, int *);
Static void	ukbd_cnpollc(void *, int);

const struct wskbd_consops ukbd_consops = {
	.getc =  ukbd_cngetc,
	.pollc = ukbd_cnpollc,
	.bell =  NULL,
};

Static const char *ukbd_parse_desc(struct ukbd_softc *);

Static void	ukbd_intr(void *, void *, u_int);
Static void	ukbd_decode(struct ukbd_softc *, struct ukbd_data *);
Static void	ukbd_delayed_decode(void *);

Static int	ukbd_enable(void *, int);
Static void	ukbd_set_leds(void *, int);
Static void	ukbd_set_leds_task(void *);
Static void	ukbd_delayed_leds_off(void *);

Static int	ukbd_ioctl(void *, u_long, void *, int, struct lwp *);
#if  defined(WSDISPLAY_COMPAT_RAWKBD) && defined(UKBD_REPEAT)
Static void	ukbd_rawrepeat(void *v);
#endif

const struct wskbd_accessops ukbd_accessops = {
	ukbd_enable,
	ukbd_set_leds,
	ukbd_ioctl,
};

extern const struct wscons_keydesc hidkbd_keydesctab[];

const struct wskbd_mapdata ukbd_keymapdata = {
	hidkbd_keydesctab,
#if defined(UKBD_LAYOUT)
	UKBD_LAYOUT,
#elif defined(PCKBD_LAYOUT)
	PCKBD_LAYOUT,
#else
	KB_US,
#endif
};

static const struct ukbd_type {
	struct usb_devno	dev;
	int			flags;
} ukbd_devs[] = {
#define UKBD_DEV(v, p, f) \
	{ { USB_VENDOR_##v, USB_PRODUCT_##v##_##p }, (f) }
#ifdef GDIUM_KEYBOARD_HACK
	UKBD_DEV(CYPRESS, LPRDK, FLAG_GDIUM_FN),
#endif
	UKBD_DEV(YUBICO, YUBIKEY4MODE1, FLAG_NO_CONSOLE),
	UKBD_DEV(YUBICO, YUBIKEY4MODE2, FLAG_NO_CONSOLE),
	UKBD_DEV(YUBICO, YUBIKEY4MODE6, FLAG_NO_CONSOLE)
};
#define ukbd_lookup(v, p) \
	((const struct ukbd_type *)usb_lookup(ukbd_devs, v, p))

static int ukbd_match(device_t, cfdata_t, void *);
static void ukbd_attach(device_t, device_t, void *);
static int ukbd_detach(device_t, int);
static int ukbd_activate(device_t, enum devact);
static void ukbd_childdet(device_t, device_t);



CFATTACH_DECL2_NEW(ukbd, sizeof(struct ukbd_softc), ukbd_match, ukbd_attach,
    ukbd_detach, ukbd_activate, NULL, ukbd_childdet);

int
ukbd_match(device_t parent, cfdata_t match, void *aux)
{
	struct uhidev_attach_arg *uha = aux;
	int size;
	void *desc;

	uhidev_get_report_desc(uha->parent, &desc, &size);
	if (!hid_is_collection(desc, size, uha->reportid,
			       HID_USAGE2(HUP_GENERIC_DESKTOP, HUG_KEYBOARD)))
		return UMATCH_NONE;

	return UMATCH_IFACECLASS;
}

void
ukbd_attach(device_t parent, device_t self, void *aux)
{
	struct ukbd_softc *sc = device_private(self);
	struct uhidev_attach_arg *uha = aux;
	uint32_t qflags;
	const char *parseerr;
	struct wskbddev_attach_args a;
	const struct ukbd_type *ukt;

	sc->sc_dev = self;
	sc->sc_hdev = uha->parent;
	sc->sc_udev = uha->uiaa->uiaa_device;
	sc->sc_iface = uha->uiaa->uiaa_iface;
	sc->sc_report_id = uha->reportid;
	sc->sc_flags = 0;

	aprint_naive("\n");

	if (!pmf_device_register(self, NULL, NULL)) {
		aprint_normal("\n");
		aprint_error_dev(self, "couldn't establish power handler\n");
	}

	parseerr = ukbd_parse_desc(sc);
	if (parseerr != NULL) {
		aprint_normal("\n");
		aprint_error_dev(self, "attach failed, %s\n", parseerr);
		return;
	}

	/* Quirks */
	qflags = usbd_get_quirks(sc->sc_udev)->uq_flags;
	if (qflags & UQ_SPUR_BUT_UP)
		sc->sc_flags |= FLAG_DEBOUNCE;
	if (qflags & UQ_APPLE_ISO)
		sc->sc_flags |= FLAG_APPLE_FIX_ISO;

	/* Other Quirks */
	ukt = ukbd_lookup(uha->uiaa->uiaa_vendor, uha->uiaa->uiaa_product);
	if (ukt)
		sc->sc_flags |= ukt->flags;

#ifdef USBVERBOSE
	aprint_normal(": %d Variable keys, %d Array codes", sc->sc_nkeyloc,
	       sc->sc_nkeycode);
	if (sc->sc_flags & FLAG_APPLE_FN)
		aprint_normal(", apple fn key");
	if (sc->sc_flags & FLAG_APPLE_FIX_ISO)
		aprint_normal(", fix apple iso");
	if (sc->sc_flags & FLAG_GDIUM_FN)
		aprint_normal(", Gdium fn key");
#endif
	aprint_normal("\n");

	if ((sc->sc_flags & FLAG_NO_CONSOLE) == 0) {
		/*
		 * Remember if we're the console keyboard.
		 *
		 * XXX This always picks the first keyboard on the
		 * first USB bus, but what else can we really do?
		 */
		if ((sc->sc_console_keyboard = ukbd_is_console) != 0) {
			/* Don't let any other keyboard have it. */
			ukbd_is_console = 0;
		}
	}

	if (sc->sc_console_keyboard) {
		DPRINTF(("%s: console keyboard sc=%p\n", __func__, sc));
		wskbd_cnattach(&ukbd_consops, sc, &ukbd_keymapdata);
		ukbd_enable(sc, 1);
	}

	a.console = sc->sc_console_keyboard;

	a.keymap = &ukbd_keymapdata;

	a.accessops = &ukbd_accessops;
	a.accesscookie = sc;

#ifdef UKBD_REPEAT
	callout_init(&sc->sc_rawrepeat_ch, 0);
#endif

	callout_init(&sc->sc_delay, 0);

	sc->sc_data_w = 0;
	sc->sc_data_r = 0;

	usb_init_task(&sc->sc_ledtask, ukbd_set_leds_task, sc, 0);
	callout_init(&sc->sc_ledreset, 0);

	/* Flash the leds; no real purpose, just shows we're alive. */
	ukbd_set_leds(sc, WSKBD_LED_SCROLL | WSKBD_LED_NUM | WSKBD_LED_CAPS
			| WSKBD_LED_COMPOSE);
	sc->sc_leds_set = 0;	/* not explicitly set by wskbd yet */
	callout_reset(&sc->sc_ledreset, mstohz(400), ukbd_delayed_leds_off,
	    sc);

	sc->sc_wskbddev = config_found(self, &a, wskbddevprint, CFARGS_NONE);

	sc->sc_attached = true;

	return;
}

int
ukbd_enable(void *v, int on)
{
	struct ukbd_softc *sc = v;
	int error = 0;

	if (on && sc->sc_dying)
		return EIO;

	DPRINTF(("%s: sc=%p on=%d\n", __func__, sc, on));
	if (on) {
		if ((sc->sc_flags & FLAG_ENABLED) == 0) {
			error = uhidev_open(sc->sc_hdev, &ukbd_intr, sc);
			if (error == 0)
				sc->sc_flags |= FLAG_ENABLED;
		}
	} else {
		if ((sc->sc_flags & FLAG_ENABLED) != 0) {
			uhidev_close(sc->sc_hdev);
			sc->sc_flags &= ~FLAG_ENABLED;
		}
	}

	return error;
}


static void
ukbd_childdet(device_t self, device_t child)
{
	struct ukbd_softc *sc = device_private(self);

	KASSERT(sc->sc_wskbddev == child);
	sc->sc_wskbddev = NULL;
}

int
ukbd_activate(device_t self, enum devact act)
{
	struct ukbd_softc *sc = device_private(self);

	switch (act) {
	case DVACT_DEACTIVATE:
		sc->sc_dying = true;
		return 0;
	default:
		return EOPNOTSUPP;
	}
}

int
ukbd_detach(device_t self, int flags)
{
	struct ukbd_softc *sc = device_private(self);
	int rv = 0;

	DPRINTF(("%s: sc=%p flags=%d\n", __func__, sc, flags));

	pmf_device_deregister(self);

	if (!sc->sc_attached)
		return rv;

	if (sc->sc_console_keyboard) {
		/*
		 * Disconnect our consops and set ukbd_is_console
		 * back to 1 so that the next USB keyboard attached
		 * to the system will get it.
		 * XXX Should notify some other keyboard that it can be
		 * XXX console, if there are any other keyboards.
		 */
		printf("%s: was console keyboard\n",
		       device_xname(sc->sc_dev));
		wskbd_cndetach();
		ukbd_is_console = 1;
	}
	/* No need to do reference counting of ukbd, wskbd has all the goo. */
	if (sc->sc_wskbddev != NULL)
		rv = config_detach(sc->sc_wskbddev, flags);

	callout_halt(&sc->sc_delay, NULL);
	callout_halt(&sc->sc_ledreset, NULL);
	usb_rem_task_wait(sc->sc_udev, &sc->sc_ledtask,
	    USB_TASKQ_DRIVER, NULL);

	/* The console keyboard does not get a disable call, so check pipe. */
	if (sc->sc_flags & FLAG_ENABLED)
		uhidev_close(sc->sc_hdev);

	return rv;
}

static void
ukbd_translate_keycodes(struct ukbd_softc *sc, struct ukbd_data *ud,
    const struct ukbd_keycodetrans *tab)
{
	const struct ukbd_keycodetrans *tp;
	struct ukbd_data oud;
	int i;

	oud = *ud;

	for (i = 4; i < MAXKEYS; i++) {
		if (isset(oud.keys, i))
			for (tp = tab; tp->from; tp++)
				if (tp->from == i) {
					if (tp->to & IS_PMF) {
						pmf_event_inject(sc->sc_dev,
						    tp->to & 0xff);
					} else
						setbit(ud->keys, tp->to);
					clrbit(ud->keys, i);
					break;
				}
	}
}

static uint16_t
ukbd_translate_modifier(struct ukbd_softc *sc, uint16_t key)
{
	if ((sc->sc_flags & FLAG_APPLE_FN) && (key & CODEMASK) == 0x00e2) {
		if ((key & ~CODEMASK) == PRESS) {
			if (sc->sc_flags & FLAG_FN_PRESSED) {
				/* pressed FN-Alt, translate to AltGr */
				key = 0x00e6 | PRESS;
				sc->sc_flags |= FLAG_FN_ALT;
			}
		} else {
			if (sc->sc_flags & FLAG_FN_ALT) {
				/* released Alt, which was treated as FN-Alt */
				key = 0x00e6 | RELEASE;
				sc->sc_flags &= ~FLAG_FN_ALT;
			}
		}
	}
	return key;
}

void
ukbd_intr(void *cookie, void *ibuf, u_int len)
{
	struct ukbd_softc *sc = cookie;
	struct ukbd_data *ud = &sc->sc_ndata;
	int i;

#ifdef UKBD_DEBUG
	if (ukbddebug > 5) {
		printf("ukbd_intr: data");
		for (i = 0; i < len; i++)
			printf(" 0x%02x", ((u_char *)ibuf)[i]);
		printf("\n");
	}
#endif

	memset(ud->keys, 0, sizeof(ud->keys));

	for (i = 0; i < sc->sc_nkeyloc; i++)
		if (hid_get_data(ibuf, &sc->sc_keyloc[i]))
			setbit(ud->keys, sc->sc_keyuse[i]);

	const uint8_t * const scancode = (char *)ibuf + sc->sc_keycodeloc.pos / 8;
	const uint16_t Keyboard_NoEvent = 0x0000;
	for (i = 0; i < sc->sc_nkeycode; i++) {
		if (scancode[i] != Keyboard_NoEvent)
			setbit(ud->keys, scancode[i]);
	}

	if (sc->sc_flags & FLAG_APPLE_FN) {
		if (hid_get_data(ibuf, &sc->sc_apple_fn)) {
			sc->sc_flags |= FLAG_FN_PRESSED;
			ukbd_translate_keycodes(sc, ud, trtab_apple_fn);
		}
		else
			sc->sc_flags &= ~FLAG_FN_PRESSED;
	}

#ifdef GDIUM_KEYBOARD_HACK
	if (sc->sc_flags & FLAG_GDIUM_FN) {
		if (sc->sc_flags & FLAG_FN_PRESSED) {
			ukbd_translate_keycodes(sc, ud, trtab_gdium_fn);
		}
	}
#endif

	ukbd_translate_keycodes(sc, ud, trtab_generic);

	if ((sc->sc_flags & FLAG_DEBOUNCE) && !(sc->sc_flags & FLAG_POLLING)) {
		/*
		 * Some keyboards have a peculiar quirk.  They sometimes
		 * generate a key up followed by a key down for the same
		 * key after about 10 ms.
		 * We avoid this bug by holding off decoding for 20 ms.
		 * Note that this comes at a cost: we deliberately overwrite
		 * the data for any keyboard event that is followed by
		 * another one within this time window.
		 */
		if (sc->sc_data_w == sc->sc_data_r) {
			sc->sc_data_w = (sc->sc_data_w + 1) % MAXPENDING;
		}
		sc->sc_data[sc->sc_data_w] = *ud;
		callout_reset(&sc->sc_delay, hz / 50, ukbd_delayed_decode, sc);
#ifdef DDB
	} else if (sc->sc_console_keyboard && !(sc->sc_flags & FLAG_POLLING)) {
		/*
		 * For the console keyboard we can't deliver CTL-ALT-ESC
		 * from the interrupt routine.  Doing so would start
		 * polling from inside the interrupt routine and that
		 * loses bigtime.
		 */
		sc->sc_data_w = (sc->sc_data_w + 1) % MAXPENDING;
		sc->sc_data[sc->sc_data_w] = *ud;
		callout_reset(&sc->sc_delay, 0, ukbd_delayed_decode, sc);
#endif
	} else {
		ukbd_decode(sc, ud);
	}
}

Static void
ukbd_delayed_leds_off(void *addr)
{
	struct ukbd_softc *sc = addr;

	/*
	 * If the LEDs have already been set after attach, other than
	 * by our initial flashing of them, leave them be.
	 */
	if (sc->sc_leds_set)
		return;

	ukbd_set_leds(sc, 0);
}

void
ukbd_delayed_decode(void *addr)
{
	struct ukbd_softc *sc = addr;

	while (sc->sc_data_r != sc->sc_data_w) {
		sc->sc_data_r = (sc->sc_data_r + 1) % MAXPENDING;
		ukbd_decode(sc, &sc->sc_data[sc->sc_data_r]);
	}
}

void
ukbd_decode(struct ukbd_softc *sc, struct ukbd_data *ud)
{
	uint16_t ibuf[MAXKEYS];	/* chars events */
	int s;
	int nkeys, i;
#ifdef WSDISPLAY_COMPAT_RAWKBD
	int j;
#endif
	int key;
#define ADDKEY(c) do { \
    KASSERT(nkeys < MAXKEYS); \
    ibuf[nkeys++] = (c); \
} while (0)

#ifdef UKBD_DEBUG
	/*
	 * Keep a trace of the last events.  Using printf changes the
	 * timing, so this can be useful sometimes.
	 */
	if (ukbdtrace) {
		struct ukbdtraceinfo *p = &ukbdtracedata[ukbdtraceindex];
		p->unit = device_unit(sc->sc_dev);
		microtime(&p->tv);
		p->ud = *ud;
		if (++ukbdtraceindex >= UKBDTRACESIZE)
			ukbdtraceindex = 0;
	}
	if (ukbddebug > 5) {
		struct timeval tv;
		microtime(&tv);
		DPRINTF((" at %"PRIu64".%06"PRIu64":", tv.tv_sec,
		    (uint64_t)tv.tv_usec));
		for (size_t k = 0; k < MAXKEYS; k++) {
			if (isset(ud->keys, k))
				DPRINTF((" %zu", k));
		}
		DPRINTF((".\n"));
	}
#endif

	if (isset(ud->keys, KEY_ERROR)) {
		DPRINTF(("%s: KEY_ERROR\n", __func__));
		return;		/* ignore  */
	}

	if (sc->sc_flags & FLAG_APPLE_FIX_ISO)
		ukbd_translate_keycodes(sc, ud, trtab_apple_iso);

	nkeys = 0;
	for (i = 0; i < MAXKEYS; i++) {
#ifdef GDIUM_KEYBOARD_HACK
			if (sc->sc_flags & FLAG_GDIUM_FN && i == 0x82) {
				if (isset(ud->keys, i))
					sc->sc_flags |= FLAG_FN_PRESSED;
				else
					sc->sc_flags &= ~FLAG_FN_PRESSED;
			}
#endif
			if (isset(ud->keys, i) != isset(sc->sc_odata.keys, i)) {
				key = i | ((isset(ud->keys, i) ? PRESS : RELEASE));
				ADDKEY(ukbd_translate_modifier(sc, key));
			}
	}
	sc->sc_odata = *ud;

	if (nkeys == 0)
		return;

	if (sc->sc_flags & FLAG_POLLING) {
		DPRINTFN(1,("%s: pollchar = 0x%03x\n", __func__, ibuf[0]));
		memcpy(sc->sc_pollchars, ibuf, nkeys * sizeof(uint16_t));
		sc->sc_npollchar = nkeys;
		return;
	}
#ifdef WSDISPLAY_COMPAT_RAWKBD
	if (sc->sc_rawkbd) {
		u_char cbuf[MAXKEYS * 2];
		int c;
#if defined(UKBD_REPEAT)
		int npress = 0;
#endif

		for (i = j = 0; i < nkeys; i++) {
			key = ibuf[i];
			c = ukbd_trtab[key & CODEMASK];
			if (c == NN)
				continue;
			if (c == 0x7f) {
				/* pause key */
				cbuf[j++] = 0xe1;
				cbuf[j++] = 0x1d;
				cbuf[j-1] |= (key & RELEASE) ? 0x80 : 0;
				cbuf[j] = 0x45;
			} else {
				if (c & 0x80)
					cbuf[j++] = 0xe0;
				cbuf[j] = c & 0x7f;
			}
			if (key & RELEASE)
				cbuf[j] |= 0x80;
#if defined(UKBD_REPEAT)
			else {
				/* remember pressed keys for autorepeat */
				if (c & 0x80)
					sc->sc_rep[npress++] = 0xe0;
				sc->sc_rep[npress++] = c & 0x7f;
			}
#endif
			DPRINTFN(1,("%s: raw = %s0x%02x\n", __func__,
				    c & 0x80 ? "0xe0 " : "",
				    cbuf[j]));
			j++;
		}
		s = spltty();
		wskbd_rawinput(sc->sc_wskbddev, cbuf, j);
		splx(s);
#ifdef UKBD_REPEAT
		callout_stop(&sc->sc_rawrepeat_ch);
		if (npress != 0) {
			sc->sc_nrep = npress;
			callout_reset(&sc->sc_rawrepeat_ch,
			    hz * REP_DELAY1 / 1000, ukbd_rawrepeat, sc);
		}
#endif
		return;
	}
#endif

	s = spltty();
	for (i = 0; i < nkeys; i++) {
		key = ibuf[i];
		wskbd_input(sc->sc_wskbddev,
		    key&RELEASE ? WSCONS_EVENT_KEY_UP : WSCONS_EVENT_KEY_DOWN,
		    key&CODEMASK);
	}
	splx(s);
}

void
ukbd_set_leds(void *v, int leds)
{
	struct ukbd_softc *sc = v;
	struct usbd_device *udev = sc->sc_udev;

	DPRINTF(("%s: sc=%p leds=%d, sc_leds=%d\n", __func__,
		 sc, leds, sc->sc_leds));

	if (sc->sc_dying)
		return;

	sc->sc_leds_set = 1;

	if (sc->sc_leds == leds)
		return;

	sc->sc_leds = leds;
	usb_add_task(udev, &sc->sc_ledtask, USB_TASKQ_DRIVER);
}

void
ukbd_set_leds_task(void *v)
{
	struct ukbd_softc *sc = v;
	int leds = sc->sc_leds;
	uint8_t res = 0;

	/* XXX not really right */
	if ((leds & WSKBD_LED_COMPOSE) && sc->sc_compose.size == 1)
		res |= 1 << sc->sc_compose.pos;
	if ((leds & WSKBD_LED_SCROLL) && sc->sc_scroloc.size == 1)
		res |= 1 << sc->sc_scroloc.pos;
	if ((leds & WSKBD_LED_NUM) && sc->sc_numloc.size == 1)
		res |= 1 << sc->sc_numloc.pos;
	if ((leds & WSKBD_LED_CAPS) && sc->sc_capsloc.size == 1)
		res |= 1 << sc->sc_capsloc.pos;

	uhidev_set_report(sc->sc_hdev, UHID_OUTPUT_REPORT, &res, 1);
}

#if defined(WSDISPLAY_COMPAT_RAWKBD) && defined(UKBD_REPEAT)
void
ukbd_rawrepeat(void *v)
{
	struct ukbd_softc *sc = v;
	int s;

	s = spltty();
	wskbd_rawinput(sc->sc_wskbddev, sc->sc_rep, sc->sc_nrep);
	splx(s);
	callout_reset(&sc->sc_rawrepeat_ch, hz * REP_DELAYN / 1000,
	    ukbd_rawrepeat, sc);
}
#endif /* defined(WSDISPLAY_COMPAT_RAWKBD) && defined(UKBD_REPEAT) */

int
ukbd_ioctl(void *v, u_long cmd, void *data, int flag,
    struct lwp *l)
{
	struct ukbd_softc *sc = v;

	switch (cmd) {
	case WSKBDIO_GTYPE:
		*(int *)data = WSKBD_TYPE_USB;
		return 0;
	case WSKBDIO_SETLEDS:
		ukbd_set_leds(v, *(int *)data);
		return 0;
	case WSKBDIO_GETLEDS:
		*(int *)data = sc->sc_leds;
		return 0;
#if defined(WSDISPLAY_COMPAT_RAWKBD)
	case WSKBDIO_SETMODE:
		DPRINTF(("%s: set raw = %d\n", __func__, *(int *)data));
		sc->sc_rawkbd = *(int *)data == WSKBD_RAW;
#if defined(UKBD_REPEAT)
		callout_stop(&sc->sc_rawrepeat_ch);
#endif
		return 0;
#endif
	}
	return EPASSTHROUGH;
}

/*
 * This is a hack to work around some broken ports that don't call
 * cnpollc() before cngetc().
 */
static int pollenter, warned;

/* Console interface. */
void
ukbd_cngetc(void *v, u_int *type, int *data)
{
	struct ukbd_softc *sc = v;
	int c;
	int broken;

	if (pollenter == 0) {
		if (!warned) {
			printf("\n"
"This port is broken, it does not call cnpollc() before calling cngetc().\n"
"This should be fixed, but it will work anyway (for now).\n");
			warned = 1;
		}
		broken = 1;
		ukbd_cnpollc(v, 1);
	} else
		broken = 0;

	DPRINTFN(0,("%s: enter\n", __func__));
	sc->sc_flags |= FLAG_POLLING;
	if (sc->sc_npollchar <= 0)
		usbd_dopoll(sc->sc_iface);
	sc->sc_flags &= ~FLAG_POLLING;
	if (sc->sc_npollchar > 0) {
		c = sc->sc_pollchars[0];
		sc->sc_npollchar--;
		memmove(sc->sc_pollchars, sc->sc_pollchars+1,
		       sc->sc_npollchar * sizeof(uint16_t));
		*type = c & RELEASE ? WSCONS_EVENT_KEY_UP : WSCONS_EVENT_KEY_DOWN;
		*data = c & CODEMASK;
		DPRINTFN(0,("%s: return 0x%02x\n", __func__, c));
	} else {
		*type = 0;
		*data = 0;
	}
	if (broken)
		ukbd_cnpollc(v, 0);
}

void
ukbd_cnpollc(void *v, int on)
{
	struct ukbd_softc *sc = v;
	struct usbd_device *dev;

	DPRINTFN(2,("%s: sc=%p on=%d\n", __func__, v, on));

	/* XXX Can this just use sc->sc_udev, or am I mistaken?  */
	usbd_interface2device_handle(sc->sc_iface, &dev);
	if (on) {
		sc->sc_spl = splusb();
		pollenter++;
	}
	usbd_set_polling(dev, on);
	if (!on) {
		pollenter--;
		splx(sc->sc_spl);
	}
}

int
ukbd_cnattach(void)
{

	/*
	 * XXX USB requires too many parts of the kernel to be running
	 * XXX in order to work, so we can't do much for the console
	 * XXX keyboard until autoconfiguration has run its course.
	 */
	ukbd_is_console = 1;
	return 0;
}

const char *
ukbd_parse_desc(struct ukbd_softc *sc)
{
	struct hid_data *d;
	struct hid_item h;
	int size;
	void *desc;
	int ikey;

	uhidev_get_report_desc(sc->sc_hdev, &desc, &size);
	ikey = 0;
	sc->sc_nkeycode = 0;
	d = hid_start_parse(desc, size, hid_input);
	while (hid_get_item(d, &h)) {
		/* Check for special Apple notebook FN key */
		if (HID_GET_USAGE_PAGE(h.usage) == 0x00ff &&
		    HID_GET_USAGE(h.usage) == 0x0003 &&
		    h.kind == hid_input && (h.flags & HIO_VARIABLE)) {
			sc->sc_flags |= FLAG_APPLE_FN;
			sc->sc_apple_fn = h.loc;
		}

		if (h.kind != hid_input || (h.flags & HIO_CONST) ||
		    HID_GET_USAGE_PAGE(h.usage) != HUP_KEYBOARD ||
		    h.report_ID != sc->sc_report_id)
			continue;
		DPRINTF(("%s: ikey=%d usage=%#x flags=%#x pos=%d size=%d "
		    "cnt=%d\n", __func__, ikey, h.usage, h.flags, h.loc.pos,
		    h.loc.size, h.loc.count));
		if (h.flags & HIO_VARIABLE) {
			if (h.loc.size != 1) {
				hid_end_parse(d);
				return "bad modifier size";
			}
			/* Single item */
			if (ikey < MAXKEYS) {
				sc->sc_keyloc[ikey] = h.loc;
				sc->sc_keyuse[ikey] = HID_GET_USAGE(h.usage);
				ikey++;
			} else {
				hid_end_parse(d);
				return "too many Variable keys";
			}
		} else {
			/* Array */
			if (h.loc.size != 8) {
				hid_end_parse(d);
				return "key code size != 8";
			}
			if (h.loc.count > MAXKEYCODE)
				h.loc.count = MAXKEYCODE;
			if (h.loc.pos % 8 != 0) {
				hid_end_parse(d);
				return "key codes not on byte boundary";
			}
			if (sc->sc_nkeycode != 0) {
				hid_end_parse(d);
				return "multiple key code arrays";
			}
			sc->sc_keycodeloc = h.loc;
			sc->sc_nkeycode = h.loc.count;
		}
	}
	sc->sc_nkeyloc = ikey;
	hid_end_parse(d);

	hid_locate(desc, size, HID_USAGE2(HUP_LEDS, HUD_LED_NUM_LOCK),
	    sc->sc_report_id, hid_output, &sc->sc_numloc, NULL);
	hid_locate(desc, size, HID_USAGE2(HUP_LEDS, HUD_LED_CAPS_LOCK),
	    sc->sc_report_id, hid_output, &sc->sc_capsloc, NULL);
	hid_locate(desc, size, HID_USAGE2(HUP_LEDS, HUD_LED_SCROLL_LOCK),
	    sc->sc_report_id, hid_output, &sc->sc_scroloc, NULL);
	hid_locate(desc, size, HID_USAGE2(HUP_LEDS, HUD_LED_COMPOSE),
	    sc->sc_report_id, hid_output, &sc->sc_compose, NULL);

	return NULL;
}
