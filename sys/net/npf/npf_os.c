/*-
 * Copyright (c) 2009-2016 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This material is based upon work partially supported by The
 * NetBSD Foundation under a contract with Mindaugas Rasiukevicius.
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
 * NPF main: dynamic load/initialisation and unload routines.
 */

#ifdef _KERNEL
#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: npf_os.c,v 1.23 2025/07/01 18:42:37 joe Exp $");

#ifdef _KERNEL_OPT
#include "pf.h"
#if NPF > 0
#error "NPF and PF are mutually exclusive; please select one"
#endif
#endif

#include <sys/param.h>
#include <sys/types.h>

#include <sys/conf.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/lwp.h>
#include <sys/module.h>
#include <sys/pserialize.h>
#include <sys/socketvar.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <netinet6/in6_var.h>
#endif

#include "npf_impl.h"
#include "npfkern.h"

#ifdef _KERNEL
#ifndef _MODULE
#include "opt_modular.h"
#include "opt_net_mpsafe.h"
#endif
#include "ioconf.h"
#endif

/*
 * Module and device structures.
 */
#ifndef _MODULE
/*
 * Modular kernels load drivers too early, and we need percpu to be inited
 * So we make this misc; a better way would be to have early boot and late
 * boot drivers.
 */
MODULE(MODULE_CLASS_MISC, npf, "bpf");
#else
/* This module autoloads via /dev/npf so it needs to be a driver */
MODULE(MODULE_CLASS_DRIVER, npf, "bpf");
#endif

#define	NPF_IOCTL_DATA_LIMIT	(4 * 1024 * 1024)

static int	npf_pfil_register(bool);
static void	npf_pfil_unregister(bool);

static int	npf_dev_open(dev_t, int, int, lwp_t *);
static int	npf_dev_close(dev_t, int, int, lwp_t *);
static int	npf_dev_ioctl(dev_t, u_long, void *, int, lwp_t *);
static int	npf_dev_poll(dev_t, int, lwp_t *);
static int	npf_dev_read(dev_t, struct uio *, int);

const struct cdevsw npf_cdevsw = {
	.d_open = npf_dev_open,
	.d_close = npf_dev_close,
	.d_read = npf_dev_read,
	.d_write = nowrite,
	.d_ioctl = npf_dev_ioctl,
	.d_stop = nostop,
	.d_tty = notty,
	.d_poll = npf_dev_poll,
	.d_mmap = nommap,
	.d_kqfilter = nokqfilter,
	.d_discard = nodiscard,
	.d_flag = D_OTHER | D_MPSAFE
};

static const char *	npf_ifop_getname(npf_t *, ifnet_t *);
static ifnet_t *	npf_ifop_lookup(npf_t *, const char *);
static void		npf_ifop_flush(npf_t *, void *);
static void *		npf_ifop_getmeta(npf_t *, const ifnet_t *);
static void		npf_ifop_setmeta(npf_t *, ifnet_t *, void *);

static const unsigned	nworkers = 1;

static bool		pfil_registered = false;
static pfil_head_t *	npf_ph_if = NULL;
static pfil_head_t *	npf_ph_inet = NULL;
static pfil_head_t *	npf_ph_inet6 = NULL;
static pfil_head_t *	npf_ph_etherlist[NPF_MAX_IFMAP];

static const npf_ifops_t kern_ifops = {
	.getname	= npf_ifop_getname,
	.lookup		= npf_ifop_lookup,
	.flush		= npf_ifop_flush,
	.getmeta	= npf_ifop_getmeta,
	.setmeta	= npf_ifop_setmeta,
};

static int
npf_fini(void)
{
	npf_t *npf = npf_getkernctx();

	/* At first, detach device and remove pfil hooks. */
#ifdef _MODULE
	devsw_detach(NULL, &npf_cdevsw);
#endif
	npf_pfil_unregister(true);
	npfk_destroy(npf);
	npfk_sysfini();
	return 0;
}

static int
npf_init(void)
{
	npf_t *npf;
	int error = 0;

	error = npfk_sysinit(nworkers);
	if (error)
		return error;
	npf = npfk_create(0, NULL, &kern_ifops, NULL);
	npf_setkernctx(npf);
	npf_pfil_register(true);

#ifdef _MODULE
	devmajor_t bmajor = NODEVMAJOR, cmajor = NODEVMAJOR;

	/* Attach /dev/npf device. */
	error = devsw_attach("npf", NULL, &bmajor, &npf_cdevsw, &cmajor);
	if (error) {
		/* It will call devsw_detach(), which is safe. */
		(void)npf_fini();
	}
#endif
	return error;
}


/*
 * Module interface.
 */
static int
npf_modcmd(modcmd_t cmd, void *arg)
{
	switch (cmd) {
	case MODULE_CMD_INIT:
		return npf_init();
	case MODULE_CMD_FINI:
		return npf_fini();
	case MODULE_CMD_AUTOUNLOAD:
/*
 * XXX npf_autounload_p() is insufficient here.  At least one other
 * XXX path leads to unloading while something tries later on to
 * XXX continue (perhaps closing of an open fd).  For now, just
 * XXX disabble autounload.
 */
		return EBUSY;
	default:
		return ENOTTY;
	}
	return 0;
}

void
npfattach(int nunits)
{
	/* Nothing */
}

static int
npf_dev_open(dev_t dev, int flag, int mode, lwp_t *l)
{
	/* Available only for super-user. */
	if (kauth_authorize_network(l->l_cred, KAUTH_NETWORK_FIREWALL,
	    KAUTH_REQ_NETWORK_FIREWALL_FW, NULL, NULL, NULL)) {
		return EPERM;
	}
	return 0;
}

static int
npf_dev_close(dev_t dev, int flag, int mode, lwp_t *l)
{
	return 0;
}

static int
npf_stats_export(npf_t *npf, void *data)
{
	uint64_t *fullst, *uptr = *(uint64_t **)data;
	int error;

	fullst = kmem_alloc(NPF_STATS_SIZE, KM_SLEEP);
	npfk_stats(npf, fullst); /* will zero the buffer */
	error = copyout(fullst, uptr, NPF_STATS_SIZE);
	kmem_free(fullst, NPF_STATS_SIZE);
	return error;
}

/*
 * npfctl_switch: enable or disable packet inspection.
 */
static int
npfctl_switch(void *data)
{
	const bool onoff = *(int *)data ? true : false;
	int error;

	if (onoff) {
		/* Enable: add pfil hooks. */
		error = npf_pfil_register(false);
	} else {
		/* Disable: remove pfil hooks. */
		npf_pfil_unregister(false);
		error = 0;
	}
	return error;
}

static int
npf_dev_ioctl(dev_t dev, u_long cmd, void *data, int flag, lwp_t *l)
{
	npf_t *npf = npf_getkernctx();
	nvlist_t *req, *resp;
	int error;

	/* Available only for super-user. */
	if (kauth_authorize_network(l->l_cred, KAUTH_NETWORK_FIREWALL,
	    KAUTH_REQ_NETWORK_FIREWALL_FW, NULL, NULL, NULL)) {
		return EPERM;
	}

	switch (cmd) {
	case IOC_NPF_VERSION:
		*(int *)data = NPF_VERSION;
		return 0;
	case IOC_NPF_SWITCH:
		return npfctl_switch(data);
	case IOC_NPF_TABLE:
		return npfctl_table(npf, data);
	case IOC_NPF_STATS:
		return npf_stats_export(npf, data);
	case IOC_NPF_LOAD:
	case IOC_NPF_SAVE:
	case IOC_NPF_RULE:
	case IOC_NPF_CONN_LOOKUP:
	case IOC_NPF_TABLE_REPLACE:
		/* nvlist_ref_t argument, handled below */
		break;
	default:
		return EINVAL;
	}

	error = nvlist_copyin(data, &req, NPF_IOCTL_DATA_LIMIT);
	if (__predict_false(error)) {
#ifdef __NetBSD__
		/* Until the version bump. */
		if (cmd != IOC_NPF_SAVE) {
			return error;
		}
		req = nvlist_create(0);
#else
		return error;
#endif
	}
	resp = nvlist_create(0);

	if ((error = npfctl_run_op(npf, cmd, req, resp)) == 0) {
		error = nvlist_copyout(data, resp);
	}

	nvlist_destroy(resp);
	nvlist_destroy(req);

	return error;
}

static int
npf_dev_poll(dev_t dev, int events, lwp_t *l)
{
	return ENOTSUP;
}

static int
npf_dev_read(dev_t dev, struct uio *uio, int flag)
{
	return ENOTSUP;
}

bool
npf_autounload_p(void)
{
	if (npf_active_p())
		return false;

	npf_t *npf = npf_getkernctx();

	npf_config_enter(npf);
	bool pass = npf_default_pass(npf);
	npf_config_exit(npf);

	return pass;
}

/*
 * Interface operations.
 */

static const char *
npf_ifop_getname(npf_t *npf __unused, ifnet_t *ifp)
{
	return ifp->if_xname;
}

static ifnet_t *
npf_ifop_lookup(npf_t *npf __unused, const char *name)
{
	return ifunit(name);
}

static void
npf_ifop_flush(npf_t *npf __unused, void *arg)
{
	ifnet_t *ifp;

	KERNEL_LOCK(1, NULL);
	IFNET_GLOBAL_LOCK();
	IFNET_WRITER_FOREACH(ifp) {
		ifp->if_npf_private = arg;
	}
	IFNET_GLOBAL_UNLOCK();
	KERNEL_UNLOCK_ONE(NULL);
}

static void *
npf_ifop_getmeta(npf_t *npf __unused, const ifnet_t *ifp)
{
	return ifp->if_npf_private;
}

static void
npf_ifop_setmeta(npf_t *npf __unused, ifnet_t *ifp, void *arg)
{
	ifp->if_npf_private = arg;
}

#ifdef _KERNEL

/*
 * Wrapper of the main packet handler to pass the kernel NPF context.
 */
static int
npfos_packet_handler(void *arg, struct mbuf **mp, ifnet_t *ifp, int di)
{
	npf_t *npf = npf_getkernctx();
	return npfk_packet_handler(npf, mp, ifp, di);
}

static int
npfos_layer2_handler(void *arg, struct mbuf **mp, ifnet_t *ifp, int di)
{
	npf_t *npf = npf_getkernctx();
	return npfk_layer2_handler(npf, mp, ifp, di);
}

/*
 * npf_ifhook: hook handling interface changes.
 */
static void
npf_ifhook(void *arg, unsigned long cmd, void *arg2)
{
	npf_t *npf = npf_getkernctx();
	ifnet_t *ifp = arg2;

	switch (cmd) {
	case PFIL_IFNET_ATTACH:
		npfk_ifmap_attach(npf, ifp);
		npf_ifaddr_sync(npf, ifp);
		break;
	case PFIL_IFNET_DETACH:
		npfk_ifmap_detach(npf, ifp);
		npf_ifaddr_flush(npf, ifp);
		break;
	}
}

static void
npf_ifaddrhook(void *arg, u_long cmd, void *arg2)
{
	npf_t *npf = npf_getkernctx();
	struct ifaddr *ifa = arg2;

	switch (cmd) {
	case SIOCSIFADDR:
	case SIOCAIFADDR:
	case SIOCDIFADDR:
#ifdef INET6
	case SIOCSIFADDR_IN6:
	case SIOCAIFADDR_IN6:
	case SIOCDIFADDR_IN6:
#endif
		KASSERT(ifa != NULL);
		break;
	default:
		return;
	}
	npf_ifaddr_sync(npf, ifa->ifa_ifp);
}

static int
register_etherpfil_hook(npf_t *npf, ifnet_t *ifp, int i)
{
	int error = 0;
	static pfil_head_t *npf_ph_ether;
	/* Capture points of activity at link layer */
	if ((npf_ph_ether = pfil_head_get(PFIL_TYPE_IFNET, ifp)) == NULL) {
		error = ENOENT;
		return error;
	}

	if (npf_ph_ether) {
		error = pfil_add_hook(npfos_layer2_handler, npf,
		    PFIL_ALL, npf_ph_ether);
		KASSERT(error == 0);
	}
	npf_ph_etherlist[i] = npf_ph_ether;

	return error;
}

static int
get_etherpfil_head(npf_t *npf)
{
	int error = 0, i = 0;
	ifnet_t *ifp;

	KERNEL_LOCK(1, NULL);
	IFNET_GLOBAL_LOCK();
	IFNET_WRITER_FOREACH(ifp) {
		error = register_etherpfil_hook(npf, ifp, i);
		if (!error)
			break;
		i++;
	}
	IFNET_GLOBAL_UNLOCK();
	KERNEL_UNLOCK_ONE(NULL);
	return error;
}

static void
destroy_pfilether_hook(npf_t *npf)
{
	int i = 0;
	while (npf_ph_etherlist[i]) {
		pfil_head_t *npf_ph_ether = npf_ph_etherlist[i];

		if (npf_ph_ether) {
			(void)pfil_remove_hook(npfos_layer2_handler, npf,
				PFIL_ALL, npf_ph_ether);
		}
		i++;
	}
}

/*
 * npf_pfil_register: register pfil(9) hooks.
 */
static int
npf_pfil_register(bool init)
{
	npf_t *npf = npf_getkernctx();
	int error = 0;

	SOFTNET_KERNEL_LOCK_UNLESS_NET_MPSAFE();

	/* Init: interface re-config and attach/detach hook. */
	if (!npf_ph_if) {
		npf_ph_if = pfil_head_get(PFIL_TYPE_IFNET, 0);
		if (!npf_ph_if) {
			error = ENOENT;
			goto out;
		}

		error = pfil_add_ihook(npf_ifhook, NULL,
		    PFIL_IFNET, npf_ph_if);
		KASSERT(error == 0);

		error = pfil_add_ihook(npf_ifaddrhook, NULL,
		    PFIL_IFADDR, npf_ph_if);
		KASSERT(error == 0);
	}
	if (init) {
		goto out;
	}

	/* Check if pfil hooks are not already registered. */
	if (pfil_registered) {
		error = EEXIST;
		goto out;
	}

	/* Capture points of the activity in the IP layer. */
	npf_ph_inet = pfil_head_get(PFIL_TYPE_AF, (void *)AF_INET);
	npf_ph_inet6 = pfil_head_get(PFIL_TYPE_AF, (void *)AF_INET6);
	if (!npf_ph_inet && !npf_ph_inet6) {
		error = ENOENT;
		goto out;
	}

	/* Packet IN/OUT handlers for IP layer. */
	if (npf_ph_inet) {
		error = pfil_add_hook(npfos_packet_handler, npf,
		    PFIL_ALL, npf_ph_inet);
		KASSERT(error == 0);
	}
	if (npf_ph_inet6) {
		error = pfil_add_hook(npfos_packet_handler, npf,
		    PFIL_ALL, npf_ph_inet6);
		KASSERT(error == 0);
	}

	get_etherpfil_head(npf);

	/*
	 * It is necessary to re-sync all/any interface address tables,
	 * since we did not listen for any changes.
	 */
	npf_ifaddr_syncall(npf);
	pfil_registered = true;
out:
	SOFTNET_KERNEL_UNLOCK_UNLESS_NET_MPSAFE();

	return error;
}

/*
 * npf_pfil_unregister: unregister pfil(9) hooks.
 */
static void
npf_pfil_unregister(bool fini)
{
	npf_t *npf = npf_getkernctx();

	SOFTNET_KERNEL_LOCK_UNLESS_NET_MPSAFE();

	if (fini && npf_ph_if) {
		(void)pfil_remove_ihook(npf_ifhook, NULL,
		    PFIL_IFNET, npf_ph_if);
		(void)pfil_remove_ihook(npf_ifaddrhook, NULL,
		    PFIL_IFADDR, npf_ph_if);
	}
	if (npf_ph_inet) {
		(void)pfil_remove_hook(npfos_packet_handler, npf,
		    PFIL_ALL, npf_ph_inet);
	}
	if (npf_ph_inet6) {
		(void)pfil_remove_hook(npfos_packet_handler, npf,
		    PFIL_ALL, npf_ph_inet6);
	}
	destroy_pfilether_hook(npf);
	pfil_registered = false;

	SOFTNET_KERNEL_UNLOCK_UNLESS_NET_MPSAFE();
}

bool
npf_active_p(void)
{
	return pfil_registered;
}

#endif

#ifdef __NetBSD__

/*
 * Epoch-Based Reclamation (EBR) wrappers: in NetBSD, we rely on the
 * passive serialization mechanism (see pserialize(9) manual page),
 * which provides sufficient guarantees for NPF.
 */

ebr_t *
npf_ebr_create(void)
{
	return pserialize_create();
}

void
npf_ebr_destroy(ebr_t *ebr)
{
	pserialize_destroy(ebr);
}

void
npf_ebr_register(ebr_t *ebr)
{
	KASSERT(ebr != NULL); (void)ebr;
}

void
npf_ebr_unregister(ebr_t *ebr)
{
	KASSERT(ebr != NULL); (void)ebr;
}

int
npf_ebr_enter(ebr_t *ebr)
{
	KASSERT(ebr != NULL); (void)ebr;
	return pserialize_read_enter();
}

void
npf_ebr_exit(ebr_t *ebr, int s)
{
	KASSERT(ebr != NULL); (void)ebr;
	pserialize_read_exit(s);
}

void
npf_ebr_full_sync(ebr_t *ebr)
{
	pserialize_perform(ebr);
}

bool
npf_ebr_incrit_p(ebr_t *ebr)
{
	KASSERT(ebr != NULL); (void)ebr;
	return pserialize_in_read_section();
}

#endif
