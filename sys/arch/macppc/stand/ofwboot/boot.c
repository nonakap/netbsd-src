/*	$NetBSD: boot.c,v 1.32 2025/01/13 17:33:10 tsutsui Exp $	*/

/*-
 * Copyright (c) 1997 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe.
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
 * Copyright (C) 1995, 1996 Wolfgang Solfrank.
 * Copyright (C) 1995, 1996 TooLs GmbH.
 * All rights reserved.
 *
 * ELF support derived from NetBSD/alpha's boot loader, written
 * by Christopher G. Demetriou.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by TooLs GmbH.
 * 4. The name of TooLs GmbH may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY TOOLS GMBH ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL TOOLS GMBH BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * First try for the boot code
 *
 * Input syntax is:
 *	[promdev[{:|,}partition]]/[filename] [flags]
 */

#include "boot.h"

#include <sys/param.h>
#include <sys/boot_flag.h>
#include <sys/disklabel.h>

#include <lib/libsa/stand.h>
#include <lib/libsa/loadfile.h>
#include <lib/libkern/libkern.h>

#include "ofdev.h"
#include "openfirm.h"

extern void __syncicache(void *, size_t); /* in libkern */


#ifdef DEBUG
# define DPRINTF printf
#else
# define DPRINTF while (0) printf
#endif

char bootdev[MAXBOOTPATHLEN];
extern char bootfile[MAXBOOTPATHLEN];
int boothowto;
bool floppyboot;
int ofw_version = 0;

static const char *kernels[] = { "/netbsd", "/netbsd.gz", "/netbsd.macppc", NULL };

static void
prom2boot(char *dev)
{
	char *cp;

	DPRINTF("%s: bootpath from OF: \"%s\"\n", __func__, dev);
	cp = dev + strlen(dev) - 1;
	for (; *cp; cp--) {
		if (*cp == ':') {
			if (ofw_version < 3) {
				/* sd@0:0 -> sd@0 */
				*cp = 0;
				break;
			} else {
				/*
				 * OpenBIOS v1.1 on qemu-system-ppc emulates
				 * Open Firmware 3.x but it also recognizes
				 * pmBootEntry info in the Apple Partition Map
				 * like old Open Firmware 1.x/2.x machines.
				 * In such case, the OpenBIOS passes
				 * "/[boot device]/disk@0:,%BOOT"
				 * for bootpath strings, but it looks
				 * the OpenBIOS doesn't recognize
				 * partition info in "disk@0:0" format.
				 * So just remove file arg strings without
				 * adding partition info in such case.
				 */
				if (cp[1] == ',') {
					/* just drop extra ",[bootfile]" */
					cp[1] = '\0';
				} else {
					/* disk@0:5,boot -> disk@0:0 */
					strcpy(cp, ":0");
				}
				break;
			}
		}
	}
	DPRINTF("%s: bootpath patched: \"%s\"\n", __func__, dev);
}

static void
parseargs(char *str, int *howtop)
{
	char *cp;

	/* Allow user to drop back to the PROM. */
	if (strcmp(str, "exit") == 0)
		OF_exit();

	*howtop = 0;

	cp = str;
	if (*cp == '-')
		goto found;
	for (cp = str; *cp; cp++)
		if (*cp == ' ')
			goto found;
	return;

found:
	*cp++ = 0;
	while (*cp)
		BOOT_FLAG(*cp++, *howtop);
}

static bool
is_floppyboot(const char *path, const char *defaultdev)
{
	char dev[MAXBOOTPATHLEN];
	char nam[16];
	int handle, rv;

	if (parsefilepath(path, dev, NULL, NULL)) {
		if (dev[0] == '\0' && defaultdev != NULL)
			strlcpy(dev, defaultdev, sizeof(dev));

		/* check properties */
		handle = OF_finddevice(dev);
		if (handle != -1) {
			rv = OF_getprop(handle, "name", nam, sizeof(nam));
			if (rv >= 0 &&
			    (strcmp(nam, "swim3") == 0 ||
			     strcmp(nam, "floppy") == 0))
				return true;
		}

		/* also check devalias */
		if (strcmp(dev, "fd") == 0)
			return true;
	}

	return false;
}

static void
chain(boot_entry_t entry, char *args, void *ssym, void *esym)
{
	extern char end[];
	int l;

#if !defined(HEAP_VARIABLE)
	freeall();
#endif

	/*
	 * Stash pointer to end of symbol table after the argument
	 * strings.
	 */
	l = strlen(args) + 1;
	memcpy(args + l, &ssym, sizeof(ssym));
	l += sizeof(ssym);
	memcpy(args + l, &esym, sizeof(esym));
	l += sizeof(esym);
	l += sizeof(int);	/* XXX */

	OF_chain((void *) RELOC, end - (char *) RELOC, entry, args, l);
	panic("chain");
}

__dead void
_rtt(void)
{

	OF_exit();
}

void
main(void)
{
	extern char bootprog_name[], bootprog_rev[];
	char bootline[512];		/* Should check size? */
	char prop[32];
	char *cp;
	u_long marks[MARK_MAX];
	u_int32_t entry;
	void *ssym, *esym;

	printf("\n");
	printf(">> %s, Revision %s\n", bootprog_name, bootprog_rev);

	/*
	 * Figure out what version of Open Firmware...
	 */
	if (ofw_openprom != -1) {
		memset(prop, 0, sizeof prop);
		OF_getprop(ofw_openprom, "model", prop, sizeof prop);
		for (cp = prop; *cp; cp++)
			if (*cp >= '0' && *cp <= '9') {
				ofw_version = *cp - '0';
				break;
			}
		printf(">> Open Firmware version %d.x\n", ofw_version);
	}
	printf(">> Open Firmware running in %s-mode.\n",
	    ofw_real_mode ? "real" : "virtual");

	/*
	 * Get the boot arguments from Openfirmware
	 */
	if (OF_getprop(ofw_chosen, "bootpath", bootdev, sizeof bootdev) < 0 ||
	    OF_getprop(ofw_chosen, "bootargs", bootline, sizeof bootline) < 0) {
		printf("Invalid Openfirmware environment\n");
		OF_exit();
	}

	/*
	 * Some versions of Openfirmware sets bootpath to "".
	 * We use boot-device instead if it occurs.
	 */
	if (bootdev[0] == 0) {
		printf("Cannot use bootpath\n");
		if (ofw_options == -1 ||
		    OF_getprop(ofw_options, "boot-device", bootdev,
			       sizeof bootdev) < 0) {
			printf("Invalid Openfirmware environment\n");
			OF_exit();
		}
		printf("Using boot-device instead\n");
	}

	prom2boot(bootdev);
	parseargs(bootline, &boothowto);
	DPRINTF("bootline=%s\n", bootline);

	for (;;) {
		int i, loadflag;

		if (boothowto & RB_ASKNAME) {
			printf("Boot: ");
			kgets(bootline, sizeof(bootline));
			parseargs(bootline, &boothowto);
		}

		if (bootline[0]) {
			kernels[0] = bootline;
			kernels[1] = NULL;
		}

		for (i = 0; kernels[i]; i++) {
			floppyboot = is_floppyboot(kernels[i], bootdev);

			DPRINTF("Trying %s%s\n", kernels[i],
			    floppyboot ? " (floppyboot)" : "");

			loadflag = LOAD_KERNEL;
			if (floppyboot)
				loadflag &= ~LOAD_BACKWARDS;

			marks[MARK_START] = 0;
			if (loadfile(kernels[i], marks, loadflag) >= 0)
				goto loaded;
		}
		boothowto |= RB_ASKNAME;
	}
loaded:

#ifdef	__notyet__
	OF_setprop(ofw_chosen, "bootpath", opened_name,
		   strlen(opened_name) + 1);
	cp = bootline;
#else
	strcpy(bootline, opened_name);
	cp = bootline + strlen(bootline);
	*cp++ = ' ';
#endif
	*cp = '-';
	if (boothowto & RB_ASKNAME)
		*++cp = 'a';
	if (boothowto & RB_USERCONF)
		*++cp = 'c';
	if (boothowto & RB_SINGLE)
		*++cp = 's';
	if (boothowto & RB_KDB)
		*++cp = 'd';
	if (*cp == '-')
#ifdef	__notyet__
		*cp = 0;
#else
		*--cp = 0;
#endif
	else
		*++cp = 0;
#ifdef	__notyet__
	OF_setprop(ofw_chosen, "bootargs", bootline, strlen(bootline) + 1);
#endif

	entry = marks[MARK_ENTRY];
	ssym = (void *)marks[MARK_SYM];
	esym = (void *)marks[MARK_END];

	printf(" start=0x%x\n", entry);
	__syncicache((void *)(uintptr_t)entry, (size_t)ssym - entry);
	chain((boot_entry_t)(uintptr_t)entry, bootline, ssym, esym);

	OF_exit();
}

#ifdef HAVE_CHANGEDISK_HOOK
void
changedisk_hook(struct open_file *of)
{
	struct of_dev *op = of->f_devdata;
	int c;

	OF_call_method("eject", op->handle, 0, 0, NULL);

	c = getchar();
	if (c == 'q') {
		printf("quit\n");
		OF_exit();
	}

	OF_call_method("close", op->handle, 0, 0, NULL);
	OF_call_method("open", op->handle, 0, 0, NULL);
}
#endif
