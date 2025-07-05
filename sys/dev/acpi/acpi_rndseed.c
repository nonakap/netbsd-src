/*	$NetBSD$	*/

/*-
 * Copyright (c) 2025 The NetBSD Foundation, Inc.
 * All rights reserved.
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
 * ACPI-OEM0
 *
 * The ACPI-OEM0 is an ACPI table with the name OEM0. The Hyper-V hypervisor
 * will create this table with 64 bytes of random data. The random data is
 * derived from the host RNG infrastructure, and a fresh value is passed
 * every time a guest is powered up. OEMs could provide this table on
 * physical machines too, but we are not aware of any OEM doing that.
 *
 * References:
 *
 *	`The Windows 10 random number generation infrastructure',
 *	Niels Ferguson, October 2019.
 *	https://aka.ms/win10rng
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD");

#include <sys/device.h>
#include <sys/rndsource.h>

#include <dev/acpi/acpireg.h>
#include <dev/acpi/acpivar.h>

struct acpirndseed_softc {
	device_t		sc_dev;
	struct krndsource	sc_rndsource;
};

static int	acpirndseed_match(device_t, cfdata_t, void *);
static void	acpirndseed_attach(device_t, device_t, void *);

CFATTACH_DECL_NEW(acpirndseed, sizeof(struct acpirndseed_softc),
    acpirndseed_match, acpirndseed_attach, NULL, NULL);

#define	RNDSEED_LENGTH	64

static int
acpirndseed_match(device_t parent, cfdata_t cf, void *aux)
{
	const ACPI_TABLE_HEADER *hdrp = aux;

	if (memcmp(hdrp->Signature, "OEM0", ACPI_NAMESEG_SIZE))
		return 0;

	if (hdrp->Length != sizeof(*hdrp) + RNDSEED_LENGTH)
		return 0;

	return 1;
}

static void
acpirndseed_attach(device_t parent, device_t self, void *aux)
{
	struct acpirndseed_softc * const sc = device_private(self);
	ACPI_TABLE_HEADER *hdrp = aux;
	char *data = (char *)(hdrp + 1);
	uint32_t len = hdrp->Length - sizeof(*hdrp);

	sc->sc_dev = self;

	aprint_naive("\n");
	aprint_normal(": %u random bytes\n", len);

	rnd_attach_source(&sc->sc_rndsource, device_xname(self),
	    RND_TYPE_UNKNOWN, RND_FLAG_COLLECT_VALUE);

	/* Enter it into the pool and promptly zero it. */
	rnd_add_data(&sc->sc_rndsource, data, len, len * NBBY);
	explicit_memset(data, 0, len);
}
