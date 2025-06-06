/*	$NetBSD: ulpt.c,v 1.108 2025/04/14 16:43:00 andvar Exp $	*/

/*
 * Copyright (c) 1998, 2003 The NetBSD Foundation, Inc.
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
 * Printer Class spec: https://www.usb.org/sites/default/files/usbprint11a021811.pdf
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: ulpt.c,v 1.108 2025/04/14 16:43:00 andvar Exp $");

#ifdef _KERNEL_OPT
#include "opt_usb.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/fcntl.h>
#include <sys/device.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/conf.h>
#include <sys/vnode.h>
#include <sys/syslog.h>

#include <machine/vmparam.h>	/* PAGE_SIZE */

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdi_util.h>
#include <dev/usb/usbdevs.h>
#include <dev/usb/usb_quirks.h>

#include "ioconf.h"

#define	TIMEOUT		hz*16	/* wait up to 16 seconds for a ready */
#define	STEP		hz/4

#define	LPTPRI		(PZERO+8)
#define	ULPT_BSIZE	PAGE_SIZE

#define ULPT_READS_PER_SEC 5
/* XXX Why is 10 us a reasonable value? */
#define ULPT_READ_TIMO 10

#ifdef ULPT_DEBUG
#define DPRINTFN(n,x)	if (ulptdebug>=(n)) printf x
int	ulptdebug = 0;
/*
 * The strategy for debug levels is:
 *   1: attach-time operations
 *   2: open/close/status/reset
 *   3: read/write basic
 *   4: read/write details
 *  10: left over from previous debug code
 */
#else
#define DPRINTFN(n,x)
#endif

#define UR_GET_DEVICE_ID 0
#define UR_GET_PORT_STATUS 1
#define UR_SOFT_RESET 2

#define	LPS_NERR		0x08	/* printer no error */
#define	LPS_SELECT		0x10	/* printer selected */
#define	LPS_NOPAPER		0x20	/* printer out of paper */
#define LPS_INVERT      (LPS_SELECT|LPS_NERR)
#define LPS_MASK        (LPS_SELECT|LPS_NERR|LPS_NOPAPER)

struct ulpt_softc {
	device_t sc_dev;
	struct usbd_device *sc_udev;	/* device */
	struct usbd_interface *sc_iface;	/* interface */
	int sc_ifaceno;

	int sc_out;
	struct usbd_pipe *sc_out_pipe;	/* bulk out pipe */
	struct usbd_xfer *sc_out_xfer;
	void *sc_out_buf;

	int sc_in;
	struct usbd_pipe *sc_in_pipe;	/* bulk in pipe */
	struct usbd_xfer *sc_in_xfer;
	void *sc_in_buf;

	struct callout sc_read_callout;	/* to drain input on write-only opens */
	int sc_has_callout;

	u_char sc_state;
#define	ULPT_OPEN	0x01	/* device is open */
#define	ULPT_OBUSY	0x02	/* printer is busy doing output */
#define	ULPT_INIT	0x04	/* waiting to initialize for open */
	u_char sc_flags;
#define	ULPT_NOPRIME	0x40	/* don't prime on open */
	u_char sc_laststatus;

	int sc_refcnt;
	u_char sc_dying;
};

static dev_type_open(ulptopen);
static dev_type_close(ulptclose);
static dev_type_write(ulptwrite);
static dev_type_read(ulptread);
static dev_type_ioctl(ulptioctl);

const struct cdevsw ulpt_cdevsw = {
	.d_open = ulptopen,
	.d_close = ulptclose,
	.d_read = ulptread,
	.d_write = ulptwrite,
	.d_ioctl = ulptioctl,
	.d_stop = nostop,
	.d_tty = notty,
	.d_poll = nopoll,
	.d_mmap = nommap,
	.d_kqfilter = nokqfilter,
	.d_discard = nodiscard,
	.d_flag = D_OTHER
};

static int ulpt_do_write(struct ulpt_softc *, struct uio *, int);
static int ulpt_do_read(struct ulpt_softc *, struct uio *, int);
static int ulpt_status(struct ulpt_softc *);
static void ulpt_reset(struct ulpt_softc *);
static int ulpt_statusmsg(u_char, struct ulpt_softc *);
static void ulpt_read_cb(struct usbd_xfer *, void *, usbd_status);
static void ulpt_tick(void *xsc);

#if 0
void ieee1284_print_id(char *);
#endif

#define	ULPTUNIT(s)	(minor(s) & 0x1f)
#define	ULPTFLAGS(s)	(minor(s) & 0xe0)


static int ulpt_match(device_t, cfdata_t, void *);
static void ulpt_attach(device_t, device_t, void *);
static int ulpt_detach(device_t, int);
static int ulpt_activate(device_t, enum devact);



CFATTACH_DECL_NEW(ulpt, sizeof(struct ulpt_softc), ulpt_match, ulpt_attach,
    ulpt_detach, ulpt_activate);

static int
ulpt_match(device_t parent, cfdata_t match, void *aux)
{
	struct usbif_attach_arg *uiaa = aux;
	/* XXX Print something useful, or don't. */
	DPRINTFN(10,("ulpt_match\n"));

	if (uiaa->uiaa_class == UICLASS_PRINTER &&
	    uiaa->uiaa_subclass == UISUBCLASS_PRINTER &&
	    (uiaa->uiaa_proto == UIPROTO_PRINTER_UNI ||
	     uiaa->uiaa_proto == UIPROTO_PRINTER_BI ||
	     uiaa->uiaa_proto == UIPROTO_PRINTER_1284))
		return UMATCH_IFACECLASS_IFACESUBCLASS_IFACEPROTO;
	return UMATCH_NONE;
}

static void
ulpt_attach(device_t parent, device_t self, void *aux)
{
	struct ulpt_softc *sc = device_private(self);
	struct usbif_attach_arg *uiaa = aux;
	struct usbd_device *dev = uiaa->uiaa_device;
	struct usbd_interface *iface = uiaa->uiaa_iface;
	usb_interface_descriptor_t *ifcd = usbd_get_interface_descriptor(iface);
	const usb_interface_descriptor_t *id;
	usbd_status err;
	char *devinfop;
	usb_endpoint_descriptor_t *ed;
	uint8_t epcount;
	int i, altno;
	usbd_desc_iter_t iter;

	sc->sc_dev = self;

	aprint_naive("\n");
	aprint_normal("\n");

	devinfop = usbd_devinfo_alloc(dev, 0);
	aprint_normal_dev(self, "%s, iclass %d/%d\n",
	       devinfop, ifcd->bInterfaceClass, ifcd->bInterfaceSubClass);
	usbd_devinfo_free(devinfop);

	/* Loop through descriptors looking for a bidir mode. */
	usb_desc_iter_init(dev, &iter);
	for (altno = 0;;) {
		id = (const usb_interface_descriptor_t *)usb_desc_iter_next(&iter);
		if (!id)
			break;
		if (id->bDescriptorType == UDESC_INTERFACE &&
		    id->bInterfaceNumber == ifcd->bInterfaceNumber) {
			if (id->bInterfaceClass == UICLASS_PRINTER &&
			    id->bInterfaceSubClass == UISUBCLASS_PRINTER &&
			    (id->bInterfaceProtocol == UIPROTO_PRINTER_BI /*||
			     id->bInterfaceProtocol == UIPROTO_PRINTER_1284*/))
				goto found;
			altno++;
		}
	}
	id = ifcd;		/* not found, use original */
 found:
	if (id != ifcd) {
		/* Found a new bidir setting */
		DPRINTFN(1, ("ulpt_attach: set altno = %d\n", altno));
		err = usbd_set_interface(iface, altno);
		if (err) {
			aprint_error_dev(self,
			    "setting alternate interface failed\n");
			sc->sc_dying = 1;
			return;
		}
	}

	epcount = 0;
	(void)usbd_endpoint_count(iface, &epcount);

	sc->sc_in = -1;
	sc->sc_out = -1;
	for (i = 0; i < epcount; i++) {
		ed = usbd_interface2endpoint_descriptor(iface, i);
		if (ed == NULL) {
			aprint_error_dev(self, "couldn't get ep %d\n", i);
			return;
		}
		if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_IN &&
		    UE_GET_XFERTYPE(ed->bmAttributes) == UE_BULK) {
			sc->sc_in = ed->bEndpointAddress;
		} else if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_OUT &&
			   UE_GET_XFERTYPE(ed->bmAttributes) == UE_BULK) {
			sc->sc_out = ed->bEndpointAddress;
		}
	}
	if (sc->sc_out == -1) {
		aprint_error_dev(self, "could not find bulk out endpoint\n");
		sc->sc_dying = 1;
		return;
	}

	if (usbd_get_quirks(dev)->uq_flags & UQ_BROKEN_BIDIR) {
		/* This device doesn't handle reading properly. */
		sc->sc_in = -1;
	}

	aprint_normal_dev(self, "using %s-directional mode\n",
	       sc->sc_in >= 0 ? "bi" : "uni");

	sc->sc_iface = iface;
	sc->sc_ifaceno = id->bInterfaceNumber;
	sc->sc_udev = dev;

#if 0
/*
 * This code is disabled because for some mysterious reason it causes
 * printing not to work.  But only sometimes, and mostly with
 * UHCI and less often with OHCI.  *sigh*
 */
	{
	usb_config_descriptor_t *cd = usbd_get_config_descriptor(dev);
	usb_device_request_t req;
	int len, alen;

	req.bmRequestType = UT_READ_CLASS_INTERFACE;
	req.bRequest = UR_GET_DEVICE_ID;
	USETW(req.wValue, cd->bConfigurationValue);
	USETW2(req.wIndex, id->bInterfaceNumber, id->bAlternateSetting);
	USETW(req.wLength, DEVINFOSIZE - 1);
	err = usbd_do_request_flags(dev, &req, devinfop, USBD_SHORT_XFER_OK,
		  &alen, USBD_DEFAULT_TIMEOUT);
	if (err) {
		printf("%s: cannot get device id\n", device_xname(sc->sc_dev));
	} else if (alen <= 2) {
		printf("%s: empty device id, no printer connected?\n",
		       device_xname(sc->sc_dev));
	} else {
		/* devinfop now contains an IEEE-1284 device ID */
		len = ((devinfop[0] & 0xff) << 8) | (devinfop[1] & 0xff);
		if (len > DEVINFOSIZE - 3)
			len = DEVINFOSIZE - 3;
		devinfop[len] = 0;
		printf("%s: device id <", device_xname(sc->sc_dev));
		ieee1284_print_id(devinfop+2);
		printf(">\n");
	}
	}
#endif

	usbd_add_drv_event(USB_EVENT_DRIVER_ATTACH, sc->sc_udev, sc->sc_dev);

	DPRINTFN(1, ("ulpt_attach: sc=%p in=%d out=%d\n",
		     sc, sc->sc_out, sc->sc_in));

	return;
}

static int
ulpt_activate(device_t self, enum devact act)
{
	struct ulpt_softc *sc = device_private(self);

	switch (act) {
	case DVACT_DEACTIVATE:
		sc->sc_dying = 1;
		return 0;
	default:
		return EOPNOTSUPP;
	}
}

static int
ulpt_detach(device_t self, int flags)
{
	struct ulpt_softc *sc = device_private(self);
	int s;
	int maj, mn;

	DPRINTFN(1, ("ulpt_detach: sc=%p\n", sc));

	sc->sc_dying = 1;
	if (sc->sc_out_pipe != NULL)
		usbd_abort_pipe(sc->sc_out_pipe);
	if (sc->sc_in_pipe != NULL)
		usbd_abort_pipe(sc->sc_in_pipe);

	s = splusb();
	if (--sc->sc_refcnt >= 0) {
		/* There is nothing to wake, aborting the pipe is enough */
		/* Wait for processes to go away. */
		usb_detach_waitold(sc->sc_dev);
	}
	splx(s);

	/* locate the major number */
	maj = cdevsw_lookup_major(&ulpt_cdevsw);

	/* Nuke the vnodes for any open instances (calls close). */
	mn = device_unit(self);
	vdevgone(maj, mn, mn, VCHR);
	vdevgone(maj, mn | ULPT_NOPRIME , mn | ULPT_NOPRIME, VCHR);

	if (sc->sc_udev != NULL)
		usbd_add_drv_event(USB_EVENT_DRIVER_DETACH, sc->sc_udev,
		    sc->sc_dev);

	return 0;
}

static int
ulpt_status(struct ulpt_softc *sc)
{
	usb_device_request_t req;
	usbd_status err;
	u_char status;

	req.bmRequestType = UT_READ_CLASS_INTERFACE;
	req.bRequest = UR_GET_PORT_STATUS;
	USETW(req.wValue, 0);
	USETW(req.wIndex, sc->sc_ifaceno);
	USETW(req.wLength, 1);
	err = usbd_do_request(sc->sc_udev, &req, &status);
	DPRINTFN(2, ("ulpt_status: status=0x%02x err=%d\n", status, err));
	if (!err)
		return status;
	else
		return 0;
}

static void
ulpt_reset(struct ulpt_softc *sc)
{
	usb_device_request_t req;

	DPRINTFN(2, ("ulpt_reset\n"));
	req.bRequest = UR_SOFT_RESET;
	USETW(req.wValue, 0);
	USETW(req.wIndex, sc->sc_ifaceno);
	USETW(req.wLength, 0);

	/*
	 * There was a mistake in the USB printer 1.0 spec that gave the
	 * request type as UT_WRITE_CLASS_OTHER; it should have been
	 * UT_WRITE_CLASS_INTERFACE.  Many printers use the old one,
	 * so we try both.
	 */
	req.bmRequestType = UT_WRITE_CLASS_OTHER;
	if (usbd_do_request(sc->sc_udev, &req, 0)) {	/* 1.0 */
		req.bmRequestType = UT_WRITE_CLASS_INTERFACE;
		(void)usbd_do_request(sc->sc_udev, &req, 0); /* 1.1 */
	}
}

int ulptusein = 1;

/*
 * Reset the printer, then wait until it's selected and not busy.
 */
static int
ulptopen(dev_t dev, int flag, int mode, struct lwp *l)
{
	u_char flags = ULPTFLAGS(dev);
	struct ulpt_softc *sc;
	usbd_status err;
	int spin, error;

	sc = device_lookup_private(&ulpt_cd, ULPTUNIT(dev));
	if (sc == NULL)
		return ENXIO;

	if (sc == NULL || sc->sc_iface == NULL || sc->sc_dying)
		return ENXIO;

	if (sc->sc_state)
		return EBUSY;

	sc->sc_state = ULPT_INIT;
	sc->sc_flags = flags;
	DPRINTFN(2, ("ulptopen: flags=%#x\n", (unsigned)flags));

	error = 0;
	sc->sc_refcnt++;

	if ((flags & ULPT_NOPRIME) == 0)
		ulpt_reset(sc);

	for (spin = 0; (ulpt_status(sc) & LPS_SELECT) == 0; spin += STEP) {
		DPRINTFN(2, ("ulpt_open: waiting a while\n"));
		if (spin >= TIMEOUT) {
			error = EBUSY;
			sc->sc_state = 0;
			goto done;
		}

		/* wait 1/4 second, give up if we get a signal */
		error = kpause("ulptop", true, STEP, NULL);
		if (error != EWOULDBLOCK) {
			sc->sc_state = 0;
			goto done;
		}

		if (sc->sc_dying) {
			error = ENXIO;
			sc->sc_state = 0;
			goto done;
		}
	}

	err = usbd_open_pipe(sc->sc_iface, sc->sc_out, 0, &sc->sc_out_pipe);
	if (err) {
		error = EIO;
		goto err0;
	}
	error = usbd_create_xfer(sc->sc_out_pipe, ULPT_BSIZE, 0, 0,
	    &sc->sc_out_xfer);
	if (error)
		goto err2;
	sc->sc_out_buf = usbd_get_buffer(sc->sc_out_xfer);

	if (ulptusein && sc->sc_in != -1) {
		DPRINTFN(2, ("ulpt_open: opening input pipe %d\n", sc->sc_in));
		err = usbd_open_pipe(sc->sc_iface, sc->sc_in,0,&sc->sc_in_pipe);
		if (err) {
			error = EIO;
			goto err2;
		}
		error = usbd_create_xfer(sc->sc_in_pipe, ULPT_BSIZE,
		    0, 0, &sc->sc_in_xfer);
		if (error)
			goto err3;
		sc->sc_in_buf = usbd_get_buffer(sc->sc_in_xfer);
		/* If it's not opened for read then set up a reader. */
		if (!(flag & FREAD)) {
			DPRINTFN(2, ("ulpt_open: start read callout\n"));
			callout_init(&sc->sc_read_callout, 0);
			callout_reset(&sc->sc_read_callout, hz/5, ulpt_tick, sc);
			sc->sc_has_callout = 1;
		}
	}

	sc->sc_state = ULPT_OPEN;
	goto done;

 err3:
	usbd_close_pipe(sc->sc_in_pipe);
	sc->sc_in_pipe = NULL;
 err2:
	usbd_destroy_xfer(sc->sc_out_xfer);
	sc->sc_out_xfer = NULL;

	usbd_close_pipe(sc->sc_out_pipe);
	sc->sc_out_pipe = NULL;
 err0:
	sc->sc_state = 0;

 done:
	if (--sc->sc_refcnt < 0)
		usb_detach_wakeupold(sc->sc_dev);

	DPRINTFN(2, ("ulptopen: done, error=%d\n", error));
	return error;
}

/*
 * XXX Document return value semantics.
 */
static int
ulpt_statusmsg(u_char status, struct ulpt_softc *sc)
{
	u_char new;

	status = (status ^ LPS_INVERT) & LPS_MASK;
	new = status & ~sc->sc_laststatus;
	sc->sc_laststatus = status;

	if (new & LPS_SELECT)
		log(LOG_NOTICE, "%s: offline\n", device_xname(sc->sc_dev));
	if (new & LPS_NOPAPER)
		log(LOG_NOTICE, "%s: out of paper\n", device_xname(sc->sc_dev));
	if (new & LPS_NERR)
		log(LOG_NOTICE, "%s: output error\n", device_xname(sc->sc_dev));

	return status;
}

static int
ulptclose(dev_t dev, int flag, int mode,
    struct lwp *l)
{
	struct ulpt_softc *sc;

	sc = device_lookup_private(&ulpt_cd, ULPTUNIT(dev));

	if (sc->sc_state != ULPT_OPEN)
		/* We are being forced to close before the open completed. */
		return 0;

	if (sc->sc_has_callout) {
		DPRINTFN(2, ("ulptclose: stopping read callout\n"));
		callout_halt(&sc->sc_read_callout, NULL);
		callout_destroy(&sc->sc_read_callout);
		sc->sc_has_callout = 0;
	}

	if (sc->sc_out_pipe != NULL) {
		usbd_abort_pipe(sc->sc_out_pipe);
	}
	if (sc->sc_out_xfer != NULL) {
		usbd_destroy_xfer(sc->sc_out_xfer);
		sc->sc_out_xfer = NULL;
	}
	if (sc->sc_out_pipe != NULL) {
		usbd_close_pipe(sc->sc_out_pipe);
		sc->sc_out_pipe = NULL;
	}
	if (sc->sc_in_pipe != NULL) {
		usbd_abort_pipe(sc->sc_in_pipe);
	}
	if (sc->sc_in_xfer != NULL) {
		usbd_destroy_xfer(sc->sc_in_xfer);
		sc->sc_in_xfer = NULL;
	}
	if (sc->sc_in_pipe != NULL) {
		usbd_close_pipe(sc->sc_in_pipe);
		sc->sc_in_pipe = NULL;
	}

	sc->sc_state = 0;

	DPRINTFN(2, ("ulptclose: closed\n"));
	return 0;
}

static int
ulpt_do_write(struct ulpt_softc *sc, struct uio *uio, int flags)
{
	uint32_t n;
	int error = 0;
	void *bufp;
	struct usbd_xfer *xfer;
	usbd_status err;

	DPRINTFN(3, ("ulptwrite\n"));
	xfer = sc->sc_out_xfer;
	bufp = sc->sc_out_buf;
	while ((n = uimin(ULPT_BSIZE, uio->uio_resid)) != 0) {
		ulpt_statusmsg(ulpt_status(sc), sc);
		error = uiomove(bufp, n, uio);
		if (error)
			break;
		DPRINTFN(4, ("ulptwrite: transfer %d bytes\n", n));
		err = usbd_bulk_transfer(xfer, sc->sc_out_pipe, 0,
		    USBD_NO_TIMEOUT, bufp, &n);
		if (err) {
			DPRINTFN(3, ("ulptwrite: error=%d\n", err));
			error = EIO;
			break;
		}
	}

	return error;
}

static int
ulptwrite(dev_t dev, struct uio *uio, int flags)
{
	struct ulpt_softc *sc;
	int error;

	sc = device_lookup_private(&ulpt_cd, ULPTUNIT(dev));

	if (sc->sc_dying)
		return EIO;

	sc->sc_refcnt++;
	error = ulpt_do_write(sc, uio, flags);
	if (--sc->sc_refcnt < 0)
		usb_detach_wakeupold(sc->sc_dev);
	return error;
}

/*
 * Perform a read operation according to the given uio.
 * This should respect nonblocking I/O status.
 *
 * XXX Doing a short read when more data is available seems to be
 * problematic.  See
 * http://www.freebsd.org/cgi/query-pr.cgi?pr=91538&cat= for a fix.
 * However, this will be unnecessary given a proper fix for the next
 * problem, and most actual callers read a lot.
 *
 * XXX This code should interact properly with select/poll, and that
 * requires the USB transactions to be queued and function before the
 * user does a read.  Read will then consume data from a buffer, and
 * not interact with the device. See ucom.c for an example of how to
 * do this.
 */
static int
ulpt_do_read(struct ulpt_softc *sc, struct uio *uio, int flags)
{
	uint32_t n, nread, nreq;
	int error = 0, nonblocking, timeout;
	void *bufp;
	struct usbd_xfer *xfer;
	usbd_status err = USBD_NORMAL_COMPLETION;

	/* XXX Resolve with background reader process.  KASSERT? */
	if (sc->sc_in_pipe == NULL)
		return EIO;

	if (flags & IO_NDELAY)
		nonblocking = 1;
	else
		nonblocking = 0;

	if (nonblocking)
		timeout = USBD_DEFAULT_TIMEOUT; /* 5 ms */
	else
		timeout = USBD_NO_TIMEOUT;

	DPRINTFN(3, ("ulptread nonblocking=%d uio_reside=%ld timeout=%d\n",
		     nonblocking, (u_long)uio->uio_resid, timeout));

	xfer = sc->sc_in_xfer;
	bufp = sc->sc_in_buf;
	nread = 0;
	while ((nreq = uimin(ULPT_BSIZE, uio->uio_resid)) != 0) {
		KASSERT(error == 0);
		if (error != 0) {
			printf("ulptread: pre-switch error %d != 0", error);
			goto done;
		}

		/*
		 * XXX Even with the short timeout, this will sleep,
		 * but it should be adequately prompt in practice.
		 */
		n = nreq;
		DPRINTFN(4, ("ulptread: transfer %d bytes, nonblocking=%d timeout=%d\n",
			     n, nonblocking, timeout));
		err = usbd_bulk_transfer(xfer, sc->sc_in_pipe,
		    USBD_SHORT_XFER_OK, timeout, bufp, &n);

		DPRINTFN(4, ("ulptread: transfer complete nreq %d n %d nread %d err %d\n",
			     nreq, n, nread, err));
		/*
		 * Process "err" return, jumping to done if we set "error".
		 */
		switch (err) {
		case USBD_NORMAL_COMPLETION:
			if (n == 0) {
				DPRINTFN(3, ("ulptread: NORMAL n==0\n"));
			}
			break;

		case USBD_SHORT_XFER:
			/* We said SHORT_XFER_OK, so shouldn't happen. */
			DPRINTFN(3, ("ulptread: SHORT n=%d\n", n));
			break;

		case USBD_TIMEOUT:
			if (nonblocking == 0) {
				/* XXX Cannot happen; perhaps KASSERT. */
				printf("ulptread: timeout in blocking mode\n");
				error = EIO;
				goto done;
			}

			DPRINTFN(3, ("ulptread: TIMEOUT n %d nread %d error %d\n",
				     n, nread, error));
			/*
			 * Don't set error until we understand why
			 * this happens.
			 */
			break;

		case USBD_INTERRUPTED:
			/*
			 * The sleep in usbd_bulk_transfer was
			 * interrupted.  Reflect it to the caller so
			 * that reading can be interrupted.
			 */
			error = EINTR;
			DPRINTFN(3, ("ulptread: EINTR error %d\n", error));
			goto done;
			break;

		default:
			/* Assume all other return codes are really errors. */
			error = EIO;
			DPRINTFN(3, ("ulptread: n %d err %d error %d\n",
				     n, err, error));
			goto done;
			break;
		}
		/* XXX KASSERT */
		if (error != 0) {
			printf("ulptread: post-switch error %d != 0", error);
			goto done;
		}

		if (n > 0) {
			/*
			 * Record progress to enable later choosing
			 * between short reads and EWOULDBLOCK.
			 */
			nread += n;

			/* Copy to userspace, giving up on any error. */
			error = uiomove(bufp, n, uio);
			if (error != 0)
				break;
		} else {
			/*
			 * We read 0 bytes, and therefore are done,
			 * even if we aren't in nonblocking mode.
			 */
			if (error == 0 && nread == 0)
				error = EWOULDBLOCK;
			DPRINTFN(3, ("ulptread: read 0=>done error %d\n",
				     error));
			goto done;
		}

		/*
		 * A short transfer indicates no more data will be
		 * forthcoming.  Terminate this read regardless of
		 * whether we are in nonblocking mode.  XXX Reconsider
		 * for blocking mode; maybe we should continue to
		 * block, but maybe it just doesn't make sense to do
		 * blocking reads from devices like this.
		 */
		if (err == USBD_SHORT_XFER) {
			DPRINTFN(3, ("ulptread: SHORT=>done n %d nread %d err %d error %d\n",
				     n, nread, err, error));
			break;
		}
	}

done:
	DPRINTFN(3, ("ulptread: finished n %d nread %d err %d error %d\n",
			     n, nread, err, error));
	return error;
}

static int
ulptread(dev_t dev, struct uio *uio, int flags)
{
	struct ulpt_softc *sc;
	int error;

	sc = device_lookup_private(&ulpt_cd, ULPTUNIT(dev));

	if (sc->sc_dying)
		return EIO;

	sc->sc_refcnt++;
	error = ulpt_do_read(sc, uio, flags);
	if (--sc->sc_refcnt < 0)
		usb_detach_wakeupold(sc->sc_dev);
	return error;
}

static void
ulpt_read_cb(struct usbd_xfer *xfer, void *priv,
	     usbd_status status)
{
	usbd_status err;
	uint32_t n;
	void *xsc;
	struct ulpt_softc *sc;

	usbd_get_xfer_status(xfer, &xsc, NULL, &n, &err);
	sc = xsc;

	DPRINTFN(4, ("ulpt_read_cb: start sc=%p, err=%d n=%d\n", sc, err, n));

#ifdef ULPT_DEBUG
	if (!err && n > 0)
		DPRINTFN(3, ("ulpt_tick: discarding %d bytes\n", n));
#endif
	if (!err || err == USBD_TIMEOUT)
		callout_reset(&sc->sc_read_callout, hz / ULPT_READS_PER_SEC,
			    ulpt_tick, sc);
}

/*
 * For devices which are not opened for reading, this function is
 * called continuously to start read bulk transfers to avoid the
 * printer overflowing its output buffer.
 *
 * XXX This should be adapted for continuous reads to allow select to
 * work; see do_ulpt_read().
 */
static void
ulpt_tick(void *xsc)
{
	struct ulpt_softc *sc = xsc;
	usbd_status err __unused;

	if (sc == NULL || sc->sc_dying)
		return;

	usbd_setup_xfer(sc->sc_in_xfer, sc, sc->sc_in_buf, ULPT_BSIZE,
	    USBD_SHORT_XFER_OK, ULPT_READ_TIMO, ulpt_read_cb);
	err = usbd_transfer(sc->sc_in_xfer);
	DPRINTFN(3, ("ulpt_tick: sc=%p err=%d\n", sc, err));
}

static int
ulptioctl(dev_t dev, u_long cmd, void *data,
    int flag, struct lwp *l)
{
#if 0
	struct ulpt_softc *sc;

	sc = device_lookup_private(&ulpt_cd, ULPTUNIT(dev));
#endif

	switch (cmd) {
	case FIONBIO:
		return 0;
	}

	return ENODEV;
}

#if 0
/* XXX This does not belong here. */
/*
 * Print select parts of a IEEE 1284 device ID.
 */
void
ieee1284_print_id(char *str)
{
	char *p, *q;

	for (p = str-1; p; p = strchr(p, ';')) {
		p++;		/* skip ';' */
		if (strncmp(p, "MFG:", 4) == 0 ||
		    strncmp(p, "MANUFACTURER:", 14) == 0 ||
		    strncmp(p, "MDL:", 4) == 0 ||
		    strncmp(p, "MODEL:", 6) == 0) {
			q = strchr(p, ';');
			if (q)
				printf("%.*s", (int)(q - p + 1), p);
		}
	}
}
#endif
