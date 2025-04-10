/* $NetBSD: acpi_event.h,v 1.3 2024/12/17 21:55:50 riastradh Exp $ */

/*-
 * Copyright (c) 2018 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jared McNeill <jmcneill@invisible.ca>.
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

#ifndef _DEV_ACPI_ACPI_EVENT_H
#define _DEV_ACPI_ACPI_EVENT_H

#include <sys/device_if.h>

#include <dev/acpi/acpica.h>

struct acpi_event;
struct acpi_irq;

ACPI_STATUS	acpi_event_create_gpio(device_t, ACPI_HANDLE,
		    void (*)(void *, struct acpi_event *,
			ACPI_RESOURCE_GPIO *),
		    void *);
ACPI_STATUS	acpi_event_create_int(device_t, ACPI_HANDLE,
		    void (*)(void *, struct acpi_event *, struct acpi_irq *),
		    void *);
ACPI_STATUS	acpi_event_notify(struct acpi_event *);
void		acpi_event_set_intrcookie(struct acpi_event *, void *);

#endif /* !_DEV_ACPI_ACPI_EVENT_H */
