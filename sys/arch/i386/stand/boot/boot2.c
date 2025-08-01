/*	$NetBSD: boot2.c,v 1.90 2025/07/31 02:59:13 pgoyette Exp $	*/

/*-
 * Copyright (c) 2008, 2009 The NetBSD Foundation, Inc.
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
 * Copyright (c) 2003
 *	David Laight.  All rights reserved
 * Copyright (c) 1996, 1997, 1999
 * 	Matthias Drochner.  All rights reserved.
 * Copyright (c) 1996, 1997
 * 	Perry E. Metzger.  All rights reserved.
 * Copyright (c) 1997
 *	Jason R. Thorpe.  All rights reserved
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
 *    must display the following acknowledgements:
 *	This product includes software developed for the NetBSD Project
 *	by Matthias Drochner.
 *	This product includes software developed for the NetBSD Project
 *	by Perry E. Metzger.
 * 4. The names of the authors may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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

/* Based on stand/biosboot/main.c */

#include <sys/types.h>
#include <sys/reboot.h>
#include <sys/bootblock.h>

#include <lib/libsa/stand.h>
#include <lib/libsa/bootcfg.h>
#include <lib/libsa/ufs.h>
#include <lib/libkern/libkern.h>

#include <libi386.h>
#include <bootmod.h>
#include <bootmenu.h>
#include <biosdisk.h>
#include <vbe.h>
#include "devopen.h"

#ifdef _STANDALONE
#include <bootinfo.h>
#endif
#ifdef SUPPORT_PS2
#include <biosmca.h>
#endif

extern struct x86_boot_params boot_params;

extern	const char bootprog_name[], bootprog_rev[], bootprog_kernrev[];

int errno;

int boot_biosdev;
daddr_t boot_biossector;

static const char * const names[][2] = {
	{ "netbsd", "netbsd.gz" },
	{ "onetbsd", "onetbsd.gz" },
	{ "netbsd.old", "netbsd.old.gz" },
	{ "netbsd/kernel", "netbsd/kernel.gz" },
	{ "onetbsd/kernel", "onetbsd/kernel.gz" },
	{ "netbsd.old/kernel", "netbsd.old/kernel.gz" },
};

#define NUMNAMES (sizeof(names)/sizeof(names[0]))
#define DEFFILENAME names[0][0]

#ifndef NO_GPT
#define MAXDEVNAME 39 /* "NAME=" + 34 char part_name */
#else
#define MAXDEVNAME 16
#endif

static char *default_devname;
static int default_unit, default_partition;
static const char *default_filename;
static const char *default_part_name;

char *sprint_bootsel(const char *);
static void bootit(const char *, int);
static void bootit2(char *, size_t, int);
void boot2(int, uint64_t);

void	command_help(char *);
#if LIBSA_ENABLE_LS_OP
void	command_ls(char *);
#endif
void	command_quit(char *);
void	command_boot(char *);
void	command_pkboot(char *);
void	command_consdev(char *);
void	command_root(char *);
#ifndef SMALL
void	command_menu(char *);
#endif
void	command_modules(char *);
void	command_multiboot(char *);

const struct bootblk_command commands[] = {
	{ "help",	command_help },
	{ "?",		command_help },
#if LIBSA_ENABLE_LS_OP
	{ "ls",		command_ls },
#endif
	{ "quit",	command_quit },
	{ "boot",	command_boot },
	{ "pkboot",	command_pkboot },
	{ "dev",	command_dev },
	{ "consdev",	command_consdev },
	{ "root",	command_root },
#ifndef SMALL
	{ "menu",	command_menu },
#endif
	{ "modules",	command_modules },
	{ "load",	module_add },
	{ "multiboot",	command_multiboot },
	{ "vesa",	command_vesa },
	{ "splash",	splash_add },
	{ "rndseed",	rnd_add },
	{ "fs",		fs_add },
	{ "userconf",	userconf_add },
	{ NULL,		NULL },
};

int
parsebootfile(const char *fname, char **fsname, char **devname,
	      int *unit, int *partition, const char **file)
{
	const char *col;
	static char savedevname[MAXDEVNAME+1];

	*fsname = "ufs";
	if (default_part_name == NULL) {
		*devname = default_devname;
	} else {
		snprintf(savedevname, sizeof(savedevname),
		    "NAME=%s", default_part_name);
		*devname = savedevname;
	}
	*unit = default_unit;
	*partition = default_partition;
	*file = default_filename;

	if (fname == NULL)
		return 0;

	if ((col = strchr(fname, ':')) != NULL) {	/* device given */
		int devlen;
		int u = 0, p = 0;
		int i = 0;

		devlen = col - fname;
		if (devlen > MAXDEVNAME)
			return EINVAL;

#ifndef NO_GPT
		if (strstr(fname, "NAME=") == fname) {
			strlcpy(savedevname, fname, devlen + 1);
			*devname = savedevname;
			*unit = -1;
			*partition = -1;
			fname = col + 1;
			goto out;
		}
#endif

#define isvalidname(c) ((c) >= 'a' && (c) <= 'z')
		if (!isvalidname(fname[i]))
			return EINVAL;
		do {
			savedevname[i] = fname[i];
			i++;
		} while (isvalidname(fname[i]));
		savedevname[i] = '\0';

#define isnum(c) ((c) >= '0' && (c) <= '9')
		if (i < devlen) {
			if (!isnum(fname[i]))
				return EUNIT;
			do {
				u *= 10;
				u += fname[i++] - '0';
			} while (isnum(fname[i]));
		}

#define isvalidpart(c) ((c) >= 'a' && (c) <= 'z')
		if (i < devlen) {
			if (!isvalidpart(fname[i]))
				return EPART;
			p = fname[i++] - 'a';
		}

		if (i != devlen)
			return ENXIO;

		*devname = savedevname;
		*unit = u;
		*partition = p;
		fname = col + 1;
	}

out:
	if (*fname)
		*file = fname;

	return 0;
}

char *
sprint_bootsel(const char *filename)
{
	char *fsname, *devname;
	int unit, partition;
	const char *file;
	static char buf[80];

	if (parsebootfile(filename, &fsname, &devname, &unit,
			  &partition, &file) == 0) {
		if (strstr(devname, "NAME=") == devname)
			snprintf(buf, sizeof(buf), "%s:%s", devname, file);
		else
			snprintf(buf, sizeof(buf), "%s%d%c:%s", devname, unit,
			    'a' + partition, file);
		return buf;
	}
	return "(invalid)";
}

static void
clearit(void)
{

	if (bootcfg_info.clear)
		clear_pc_screen();
}

static void
bootit(const char *filename, int howto)
{
	if (howto & AB_VERBOSE)
		printf("booting %s (howto 0x%x)\n", sprint_bootsel(filename),
		    howto);

	if (exec_netbsd(filename, 0, howto, boot_biosdev < 0x80, clearit) < 0)
		printf("boot: %s: %s\n", sprint_bootsel(filename),
		       strerror(errno));
	else
		printf("boot returned\n");
}

/*
 * Called from the initial entry point boot_start in biosboot.S
 *
 * biosdev: BIOS drive number the system booted from
 * biossector: Sector number of the NetBSD partition
 */
void
boot2(int biosdev, uint64_t biossector)
{
	extern char twiddle_toggle;
	int currname;
	char c;

	twiddle_toggle = 1;	/* no twiddling until we're ready */

	initio(boot_params.bp_consdev);

#ifdef SUPPORT_PS2
	biosmca();
#endif
	gateA20();

	boot_modules_enabled = !(boot_params.bp_flags
				 & X86_BP_FLAGS_NOMODULES);
	if (boot_params.bp_flags & X86_BP_FLAGS_RESET_VIDEO)
		biosvideomode();

	vbe_init();

	/* need to remember these */
	boot_biosdev = biosdev;
	boot_biossector = biossector;

	/* try to set default device to what BIOS tells us */
	bios2dev(biosdev, biossector, &default_devname, &default_unit,
		 &default_partition, &default_part_name);

	/* if the user types "boot" without filename */
	default_filename = DEFFILENAME;

#ifndef SMALL
	if (!(boot_params.bp_flags & X86_BP_FLAGS_NOBOOTCONF)) {
		parsebootconf(BOOTCFG_FILENAME);
	} else {
		bootcfg_info.timeout = boot_params.bp_timeout;
	}
	

	/*
	 * If console set in boot.cfg, switch to it.
	 * This will print the banner, so we don't need to explicitly do it
	 */
	if (bootcfg_info.consdev) {
		command_consdev(bootcfg_info.consdev);
	} else {
		clearit();
		print_bootcfg_banner(bootprog_name, bootprog_rev);
	}

	/* Display the menu, if applicable */
	twiddle_toggle = 0;
	if (bootcfg_info.nummenu > 0) {
		/* Does not return */
		doboottypemenu();
	}

#else
	twiddle_toggle = 0;
	clearit();
	print_bootcfg_banner(bootprog_name, bootprog_rev);
#endif

	printf("Press return to boot now, any other key for boot menu\n");
	for (currname = 0; currname < NUMNAMES; currname++) {
		printf("booting %s - starting in ",
		       sprint_bootsel(names[currname][0]));

#ifdef SMALL
		c = awaitkey(boot_params.bp_timeout, 1);
#else
		c = awaitkey((bootcfg_info.timeout < 0) ? 0
		    : bootcfg_info.timeout, 1);
#endif
		if ((c != '\r') && (c != '\n') && (c != '\0')) {
		    if ((boot_params.bp_flags & X86_BP_FLAGS_PASSWORD) == 0) {
			/* do NOT ask for password */
			bootmenu(); /* does not return */
		    } else {
			/* DO ask for password */
			if (check_password((char *)boot_params.bp_password)) {
			    /* password ok */
			    printf("type \"?\" or \"help\" for help.\n");
			    bootmenu(); /* does not return */
			} else {
			    /* bad password */
			    printf("Wrong password.\n");
			    currname = 0;
			    continue;
			}
		    }
		}

		/*
		 * try pairs of names[] entries, foo and foo.gz
		 */
		/* don't print "booting..." again */
		bootit(names[currname][0], 0);
		/* since it failed, try compressed bootfile. */
		bootit(names[currname][1], AB_VERBOSE);
	}

	bootmenu();	/* does not return */
}

/* ARGSUSED */
void
command_help(char *arg)
{

	printf("commands are:\n"
	       "boot [dev:][filename] [-12acdqsvxz]\n"
#ifndef NO_RAIDFRAME
	       "     dev syntax is (hd|fd|cd|raid)[N[x]]\n"
#else
	       "     dev syntax is (hd|fd|cd)[N[x]]n"
#endif
#ifndef NO_GPT
	       "                or NAME=gpt_label\n"
#endif
	       "     (ex. \"hd0a:netbsd.old -s\")\n"
	       "pkboot [dev:][filename] [-12acdqsvxz]\n"
#if LIBSA_ENABLE_LS_OP
	       "ls [dev:][path]\n"
#endif
	       "dev [dev:]\n"
	       "consdev {pc|{com[0123]|com[0123]kbd|auto}[,{speed}]}\n"
	       "root    {spec}\n"
	       "     spec can be disk, e.g. wd0, sd0\n"
	       "     or string like wedge:name\n"
	       "vesa {modenum|on|off|enabled|disabled|list}\n"
#ifndef SMALL
	       "menu (reenters boot menu, if defined in boot.cfg)\n"
#endif
	       "modules {on|off|enabled|disabled}\n"
	       "load {path_to_module}\n"
	       "multiboot [dev:][filename] [<args>]\n"
	       "splash {path_to_image_file}\n"
	       "userconf {command}\n"
	       "rndseed {path_to_rndseed_file}\n"
	       "help|?\n"
	       "quit\n");
}

#if LIBSA_ENABLE_LS_OP
void
command_ls(char *arg)
{
	const char *save = default_filename;

	default_filename = "/";
	ls(arg);
	default_filename = save;
}
#endif

/* ARGSUSED */
void
command_quit(char *arg)
{

	printf("Exiting...\n");
	delay(1000000);
	reboot();
	/* Note: we shouldn't get to this point! */
	panic("Could not reboot!");
}

static void
bootit2(char *path, size_t plen, int howto)
{
	bootit(path, howto);
	snprintf(path, plen, "%s.gz", path);
	bootit(path, howto | AB_VERBOSE);
}

void
command_boot(char *arg)
{
	char *filename;
	char path[512];
	int howto;

	if (!parseboot(arg, &filename, &howto))
		return;

	if (filename != NULL && filename[0] != '\0') {
		/* try old locations first to assist atf test beds */
		snprintf(path, sizeof(path) - 4, "%s", filename);
		bootit2(path, sizeof(path), howto);

		/*
		 * now treat given filename as a directory unless there
		 * is already an embedded path-name separator '/' present
		 */
		if (strchr(filename + 1, '/') == NULL) {
			snprintf(path, sizeof(path) - 4, "%s/kernel",
			    filename);
			bootit2(path, sizeof(path), howto);
		}
	} else {
		int i;

		for (i = 0; i < NUMNAMES; i++) {
			bootit(names[i][0], howto);
			bootit(names[i][1], howto);
		}
	}
}

void
command_pkboot(char *arg)
{
	extern int has_prekern;
	has_prekern = 1;
	command_boot(arg);
	has_prekern = 0;
}

void
command_dev(char *arg)
{
	static char savedevname[MAXDEVNAME + 1];
	char *fsname, *devname;
	const char *file; /* dummy */

	if (*arg == '\0') {
		biosdisk_probe();

#ifndef NO_GPT
		if (default_part_name)
			printf("default NAME=%s on %s%d\n", default_part_name,
			       default_devname, default_unit);
		else
#endif
			printf("default %s%d%c\n",
			       default_devname, default_unit,
			       'a' + default_partition);
		return;
	}

	if (strchr(arg, ':') == NULL ||
	    parsebootfile(arg, &fsname, &devname, &default_unit,
			  &default_partition, &file)) {
		command_help(NULL);
		return;
	}

	/* put to own static storage */
	strncpy(savedevname, devname, MAXDEVNAME + 1);
	default_devname = savedevname;

	/* +5 to skip leading NAME= */
	if (strstr(devname, "NAME=") == devname)
		default_part_name = default_devname + 5;
}

static const struct cons_devs {
	const char	*name;
	u_int		tag;
} cons_devs[] = {
	{ "pc",		CONSDEV_PC },
	{ "com0",	CONSDEV_COM0 },
	{ "com1",	CONSDEV_COM1 },
	{ "com2",	CONSDEV_COM2 },
	{ "com3",	CONSDEV_COM3 },
	{ "com0kbd",	CONSDEV_COM0KBD },
	{ "com1kbd",	CONSDEV_COM1KBD },
	{ "com2kbd",	CONSDEV_COM2KBD },
	{ "com3kbd",	CONSDEV_COM3KBD },
	{ "auto",	CONSDEV_AUTO },
	{ NULL,		0 }
};

void
command_consdev(char *arg)
{
	const struct cons_devs *cdp;
	char *sep;
	int speed;

	sep = strchr(arg, ',');
	if (sep != NULL)
		*sep++ = '\0';

	for (cdp = cons_devs; cdp->name; cdp++) {
		if (strcmp(arg, cdp->name) != 0)
			continue;

		if (sep != NULL) {
			if (cdp->tag == CONSDEV_PC)
				goto error;

			speed = atoi(sep);
			if (speed < 0)
				goto error;
			boot_params.bp_conspeed = speed;
		}

		initio(cdp->tag);
		clearit();
		print_bootcfg_banner(bootprog_name, bootprog_rev);
		return;
	}
error:
	printf("invalid console device.\n");
}

void
command_root(char *arg)
{
	struct btinfo_rootdevice *biv = &bi_root;

	strncpy(biv->devname, arg, sizeof(biv->devname));
	if (biv->devname[sizeof(biv->devname)-1] != '\0') {
		biv->devname[sizeof(biv->devname)-1] = '\0';
		printf("truncated to %s\n",biv->devname);
	}
}

#ifndef SMALL
/* ARGSUSED */
void
command_menu(char *arg)
{

	if (bootcfg_info.nummenu > 0) {
		/* Does not return */
		doboottypemenu();
	} else {
		printf("No menu defined in boot.cfg\n");
	}
}
#endif /* !SMALL */

void
command_modules(char *arg)
{

	if (strcmp(arg, "enabled") == 0 ||
	    strcmp(arg, "on") == 0)
		boot_modules_enabled = true;
	else if (strcmp(arg, "disabled") == 0 ||
	    strcmp(arg, "off") == 0)
		boot_modules_enabled = false;
	else
		printf("invalid flag, must be 'enabled' or 'disabled'.\n");
}

void
command_multiboot(char *arg)
{
	char *filename;

	filename = arg;
	if (exec_multiboot(filename, gettrailer(arg)) < 0)
		printf("multiboot: %s: %s\n", sprint_bootsel(filename),
		       strerror(errno));
	else
		printf("boot returned\n");
}

