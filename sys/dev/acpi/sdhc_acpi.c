/*	$NetBSD: sdhc_acpi.c,v 1.8 2019/10/15 00:13:52 chs Exp $	*/

/*
 * Copyright (c) 2016 Kimihiro Nonaka <nonaka@NetBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: sdhc_acpi.c,v 1.8 2019/10/15 00:13:52 chs Exp $");

#include <sys/param.h>
#include <sys/device.h>
#include <sys/systm.h>
#include <sys/kmem.h>

#include <dev/acpi/acpireg.h>
#include <dev/acpi/acpivar.h>
#include <dev/acpi/acpi_intr.h>

#include <dev/sdmmc/sdhcreg.h>
#include <dev/sdmmc/sdhcvar.h>
#include <dev/sdmmc/sdmmcvar.h>

#define _COMPONENT	ACPI_RESOURCE_COMPONENT
ACPI_MODULE_NAME	("sdhc_acpi")

static const struct sdhc_acpi_device {
	const char	*hid;
	const char	*uid;
	const char	*desc;
	u_int		quirks;
} sdhc_acpi_devices[] = {
	{ "80860F14",	"1",
	    "Intel Bay Trail/Braswell eMMC 4.5/4.5.1 Controller",
	    SDHC_FLAG_USE_DMA |
	    SDHC_FLAG_POWERUP_RESET |
	    SDHC_FLAG_MMC_WAIT_WHILE_BUSY },
	{ "80860F14",	"3",
	    "Intel Bay Trail/Braswell SDXC Controller",
	    SDHC_FLAG_USE_DMA |
	    SDHC_FLAG_MMC_WAIT_WHILE_BUSY },
	{ "80860F16",	NULL,
	    "Intel Bay Trail/Braswell SDXC Controller",
	    SDHC_FLAG_USE_DMA |
	    SDHC_FLAG_MMC_WAIT_WHILE_BUSY },
	{ "80865ACA",	NULL,
	    "Intel Apollo Lake SDXC Controller",
	    // SDHC_FLAG_USE_DMA |	/* APL18 erratum */
	    SDHC_FLAG_MMC_WAIT_WHILE_BUSY },
	{ "80865ACC",	NULL,
	    "Intel Apollo Lake eMMC 5.0 Controller",
	    // SDHC_FLAG_USE_DMA |	/* APL18 erratum */
	    SDHC_FLAG_POWERUP_RESET |
	    SDHC_FLAG_MMC_WAIT_WHILE_BUSY |
	    SDHC_FLAG_MMC_DDR52 },
	{ "AMDI0040",	NULL,
	    "AMD eMMC 5.0 Controller",
	    SDHC_FLAG_USE_DMA },
};

static int	sdhc_acpi_match(device_t, cfdata_t, void *);
static void	sdhc_acpi_attach(device_t, device_t, void *);
static int	sdhc_acpi_detach(device_t, int);
static bool	sdhc_acpi_resume(device_t, const pmf_qual_t *);

struct sdhc_acpi_softc {
	struct sdhc_softc sc;
	bus_space_tag_t sc_memt;
	bus_space_handle_t sc_memh;
	bus_size_t sc_memsize;
	void *sc_ih;
	const struct sdhc_acpi_device *sc_sadev;

	ACPI_HANDLE sc_crs, sc_srs;
	ACPI_BUFFER sc_crs_buffer;
};

CFATTACH_DECL_NEW(sdhc_acpi, sizeof(struct sdhc_acpi_softc),
    sdhc_acpi_match, sdhc_acpi_attach, sdhc_acpi_detach, NULL);

#define HREAD4(sc, reg)	\
	(bus_space_read_4((sc)->sc_memt, (sc)->sc_memh, (reg)))

static const struct sdhc_acpi_device *
sdhc_acpi_find_device(ACPI_DEVICE_INFO *ad)
{
	const struct sdhc_acpi_device *dev;
	const char *hid, *uid;
	size_t i;

	hid = ad->HardwareId.String;
	uid = ad->UniqueId.String;

	if (!(ad->Valid & ACPI_VALID_HID) || hid == NULL)
		return NULL;

	if (!(ad->Valid & ACPI_VALID_UID))
		uid = NULL;

	for (i = 0; i < __arraycount(sdhc_acpi_devices); i++) {
		dev = &sdhc_acpi_devices[i];
		if (strcmp(hid, dev->hid))
			continue;

		if (dev->uid == NULL ||
		    (uid != NULL && strcmp(uid, dev->uid) == 0))
			return dev;
	}
	return NULL;
}

static int
sdhc_acpi_match(device_t parent, cfdata_t match, void *opaque)
{
	struct acpi_attach_args *aa = opaque;

	if (aa->aa_node->ad_type != ACPI_TYPE_DEVICE)
		return 0;

	return sdhc_acpi_find_device(aa->aa_node->ad_devinfo) != NULL;
}

static void
sdhc_acpi_attach(device_t parent, device_t self, void *opaque)
{
	struct sdhc_acpi_softc *sc = device_private(self);
	struct acpi_attach_args *aa = opaque;
	struct acpi_resources res;
	struct acpi_mem *mem;
	struct acpi_irq *irq;
	ACPI_STATUS rv;

	sc->sc.sc_dev = self;
	sc->sc.sc_dmat = aa->aa_dmat;
	sc->sc.sc_host = NULL;
	sc->sc_memt = aa->aa_memt;

	sc->sc_sadev = sdhc_acpi_find_device(aa->aa_node->ad_devinfo);
	sc->sc.sc_flags = sc->sc_sadev->quirks;

	rv = acpi_resource_parse(self, aa->aa_node->ad_handle, "_CRS",
	    &res, &acpi_resource_parse_ops_default);
	if (ACPI_FAILURE(rv))
		return;

	AcpiGetHandle(aa->aa_node->ad_handle, "_CRS", &sc->sc_crs);
	AcpiGetHandle(aa->aa_node->ad_handle, "_SRS", &sc->sc_srs);
	if (sc->sc_crs && sc->sc_srs) {
		/* XXX Why need this? */
		sc->sc_crs_buffer.Pointer = NULL;
		sc->sc_crs_buffer.Length = ACPI_ALLOCATE_LOCAL_BUFFER;
		rv = AcpiGetCurrentResources(sc->sc_crs, &sc->sc_crs_buffer);
		if (ACPI_FAILURE(rv))
			sc->sc_crs = sc->sc_srs = NULL;
	}

	mem = acpi_res_mem(&res, 0);
	irq = acpi_res_irq(&res, 0);
	if (mem == NULL || irq == NULL) {
		aprint_error_dev(self, "incomplete resources\n");
		goto cleanup;
	}
	if (mem->ar_length == 0) {
		aprint_error_dev(self, "zero length memory resource\n");
		goto cleanup;
	}
	sc->sc_memsize = mem->ar_length;

	if (bus_space_map(sc->sc_memt, mem->ar_base, sc->sc_memsize, 0,
	    &sc->sc_memh)) {
		aprint_error_dev(self, "couldn't map registers\n");
		goto cleanup;
	}

	sc->sc_ih = acpi_intr_establish(self,
	    (uint64_t)(uintptr_t)aa->aa_node->ad_handle,
	    IPL_BIO, false, sdhc_intr, &sc->sc, device_xname(self));
	if (sc->sc_ih == NULL) {
		aprint_error_dev(self,
		    "couldn't establish interrupt handler\n");
		goto unmap;
	}

	/*
	 * Intel Bay Trail and Braswell eMMC controllers share the same IDs,
	 * but while with these former DDR52 is affected by the VLI54 erratum,
	 * these latter require the timeout clock to be hardcoded to 1 MHz.
	 */
	if (strcmp(sc->sc_sadev->hid, "80860F14") == 0 &&
	    strcmp(sc->sc_sadev->uid, "1") == 0 &&
	    HREAD4(sc, SDHC_CAPABILITIES) == 0x446cc8b2 &&
	    HREAD4(sc, SDHC_CAPABILITIES2) == 0x00000807) {
		sc->sc.sc_flags |= SDHC_FLAG_MMC_DDR52;
#if 0	/* XXX timeout */
		sc->sc.sc_flags |= SDHC_FLAG_DATA_TIMEOUT_1MHZ;
#endif
	}

	if (ISSET(sc->sc.sc_flags, SDHC_FLAG_USE_DMA))
		SET(sc->sc.sc_flags, SDHC_FLAG_USE_ADMA2);

	sc->sc.sc_host = kmem_zalloc(sizeof(struct sdhc_host *), KM_SLEEP);
	if (sdhc_host_found(&sc->sc, sc->sc_memt, sc->sc_memh,
	    sc->sc_memsize) != 0) {
		aprint_error_dev(self, "couldn't initialize host\n");
		goto fail;
	}

	if (!pmf_device_register1(self, sdhc_suspend, sdhc_acpi_resume,
	    sdhc_shutdown)) {
		aprint_error_dev(self, "couldn't establish powerhook\n");
	}

	acpi_resource_cleanup(&res);
	return;

fail:
	if (sc->sc.sc_host != NULL)
		kmem_free(sc->sc.sc_host, sizeof(struct sdhc_host *));
	sc->sc.sc_host = NULL;
	if (sc->sc_ih != NULL)
		acpi_intr_disestablish(sc->sc_ih);
	sc->sc_ih = NULL;
unmap:
	bus_space_unmap(sc->sc_memt, sc->sc_memh, sc->sc_memsize);
	sc->sc_memsize = 0;
cleanup:
	if (sc->sc_crs_buffer.Pointer)
		ACPI_FREE(sc->sc_crs_buffer.Pointer);
	sc->sc_crs_buffer.Pointer = NULL;
	acpi_resource_cleanup(&res);
}

static int
sdhc_acpi_detach(device_t self, int flags)
{
	struct sdhc_acpi_softc *sc = device_private(self);
	int rv;

	pmf_device_deregister(self);

	rv = sdhc_detach(&sc->sc, flags);
	if (rv)
		return rv;

	if (sc->sc_ih != NULL)
		acpi_intr_disestablish(sc->sc_ih);

	if (sc->sc.sc_host != NULL)
		kmem_free(sc->sc.sc_host, sizeof(struct sdhc_host *));

	if (sc->sc_memsize > 0)
		bus_space_unmap(sc->sc_memt, sc->sc_memh, sc->sc_memsize);

	if (sc->sc_crs_buffer.Pointer)
		ACPI_FREE(sc->sc_crs_buffer.Pointer);

	return 0;
}

static bool
sdhc_acpi_resume(device_t self, const pmf_qual_t *qual)
{
	struct sdhc_acpi_softc *sc = device_private(self);
	ACPI_STATUS rv;

	if (sc->sc_crs && sc->sc_srs) {
		rv = AcpiSetCurrentResources(sc->sc_srs, &sc->sc_crs_buffer);
		if (ACPI_FAILURE(rv))
			printf("%s: _SRS failed: %s\n",
			    device_xname(self), AcpiFormatException(rv));
	}

	return sdhc_resume(self, qual);
}
