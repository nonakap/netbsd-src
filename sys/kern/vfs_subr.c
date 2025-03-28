/*	$NetBSD: vfs_subr.c,v 1.502 2024/12/07 02:27:38 riastradh Exp $	*/

/*-
 * Copyright (c) 1997, 1998, 2004, 2005, 2007, 2008, 2019, 2020
 *     The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of the Numerical Aerospace Simulation Facility,
 * NASA Ames Research Center, by Charles M. Hannum, by Andrew Doran,
 * by Marshall Kirk McKusick and Greg Ganger at the University of Michigan.
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
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)vfs_subr.c	8.13 (Berkeley) 4/18/94
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: vfs_subr.c,v 1.502 2024/12/07 02:27:38 riastradh Exp $");

#ifdef _KERNEL_OPT
#include "opt_compat_43.h"
#include "opt_compat_netbsd.h"
#include "opt_ddb.h"
#endif

#include <sys/param.h>
#include <sys/types.h>

#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/dirent.h>
#include <sys/errno.h>
#include <sys/filedesc.h>
#include <sys/fstrans.h>
#include <sys/kauth.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/sdt.h>
#include <sys/stat.h>
#include <sys/syscallargs.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/vnode_impl.h>

#include <miscfs/deadfs/deadfs.h>
#include <miscfs/genfs/genfs.h>
#include <miscfs/specfs/specdev.h>

#include <uvm/uvm_ddb.h>

SDT_PROBE_DEFINE3(vfs, syncer, worklist, vnode__add,
    "struct vnode *"/*vp*/,
    "int"/*delayx*/,
    "int"/*slot*/);
SDT_PROBE_DEFINE4(vfs, syncer, worklist, vnode__update,
    "struct vnode *"/*vp*/,
    "int"/*delayx*/,
    "int"/*oslot*/,
    "int"/*nslot*/);
SDT_PROBE_DEFINE1(vfs, syncer, worklist, vnode__remove,
    "struct vnode *"/*vp*/);

SDT_PROBE_DEFINE3(vfs, syncer, worklist, mount__add,
    "struct mount *"/*mp*/,
    "int"/*vdelay*/,
    "int"/*slot*/);
SDT_PROBE_DEFINE4(vfs, syncer, worklist, mount__update,
    "struct mount *"/*vp*/,
    "int"/*vdelay*/,
    "int"/*oslot*/,
    "int"/*nslot*/);
SDT_PROBE_DEFINE1(vfs, syncer, worklist, mount__remove,
    "struct mount *"/*mp*/);

SDT_PROBE_DEFINE1(vfs, syncer, sync, start,
    "int"/*starttime*/);
SDT_PROBE_DEFINE1(vfs, syncer, sync, mount__start,
    "struct mount *"/*mp*/);
SDT_PROBE_DEFINE2(vfs, syncer, sync, mount__done,
    "struct mount *"/*mp*/,
    "int"/*error*/);
SDT_PROBE_DEFINE1(vfs, syncer, sync, mount__skip,
    "struct mount *"/*mp*/);
SDT_PROBE_DEFINE1(vfs, syncer, sync, vnode__start,
    "struct vnode *"/*vp*/);
SDT_PROBE_DEFINE2(vfs, syncer, sync, vnode__done,
    "struct vnode *"/*vp*/,
    "int"/*error*/);
SDT_PROBE_DEFINE2(vfs, syncer, sync, vnode__fail__lock,
    "struct vnode *"/*vp*/,
    "int"/*error*/);
SDT_PROBE_DEFINE2(vfs, syncer, sync, vnode__fail__vget,
    "struct vnode *"/*vp*/,
    "int"/*error*/);
SDT_PROBE_DEFINE2(vfs, syncer, sync, done,
    "int"/*starttime*/,
    "int"/*endtime*/);

const enum vtype iftovt_tab[16] = {
	VNON, VFIFO, VCHR, VNON, VDIR, VNON, VBLK, VNON,
	VREG, VNON, VLNK, VNON, VSOCK, VNON, VNON, VBAD,
};
const int	vttoif_tab[9] = {
	0, S_IFREG, S_IFDIR, S_IFBLK, S_IFCHR, S_IFLNK,
	S_IFSOCK, S_IFIFO, S_IFMT,
};

/*
 * Insq/Remq for the vnode usage lists.
 */
#define	bufinsvn(bp, dp)	LIST_INSERT_HEAD(dp, bp, b_vnbufs)
#define	bufremvn(bp) {							\
	LIST_REMOVE(bp, b_vnbufs);					\
	(bp)->b_vnbufs.le_next = NOLIST;				\
}

int doforce = 1;		/* 1 => permit forcible unmounting */

/*
 * Local declarations.
 */

static void vn_initialize_syncerd(void);

/*
 * Initialize the vnode management data structures.
 */
void
vntblinit(void)
{

	vn_initialize_syncerd();
	vfs_mount_sysinit();
	vfs_vnode_sysinit();
}

/*
 * Flush out and invalidate all buffers associated with a vnode.
 * Called with the underlying vnode locked, which should prevent new dirty
 * buffers from being queued.
 */
int
vinvalbuf(struct vnode *vp, int flags, kauth_cred_t cred, struct lwp *l,
    bool catch_p, int slptimeo)
{
	struct buf *bp, *nbp;
	int error;
	int flushflags = PGO_ALLPAGES | PGO_FREE | PGO_SYNCIO |
	    (flags & V_SAVE ? PGO_CLEANIT | PGO_RECLAIM : 0);

	/* XXXUBC this doesn't look at flags or slp* */
	rw_enter(vp->v_uobj.vmobjlock, RW_WRITER);
	error = VOP_PUTPAGES(vp, 0, 0, flushflags);
	if (error) {
		return error;
	}

	if (flags & V_SAVE) {
		error = VOP_FSYNC(vp, cred, FSYNC_WAIT|FSYNC_RECLAIM, 0, 0);
		if (error)
		        return error;
		KASSERT(LIST_EMPTY(&vp->v_dirtyblkhd));
	}

	mutex_enter(&bufcache_lock);
restart:
	for (bp = LIST_FIRST(&vp->v_dirtyblkhd); bp; bp = nbp) {
		KASSERT(bp->b_vp == vp);
		nbp = LIST_NEXT(bp, b_vnbufs);
		error = bbusy(bp, catch_p, slptimeo, NULL);
		if (error != 0) {
			if (error == EPASSTHROUGH)
				goto restart;
			mutex_exit(&bufcache_lock);
			return error;
		}
		brelsel(bp, BC_INVAL | BC_VFLUSH);
	}

	for (bp = LIST_FIRST(&vp->v_cleanblkhd); bp; bp = nbp) {
		KASSERT(bp->b_vp == vp);
		nbp = LIST_NEXT(bp, b_vnbufs);
		error = bbusy(bp, catch_p, slptimeo, NULL);
		if (error != 0) {
			if (error == EPASSTHROUGH)
				goto restart;
			mutex_exit(&bufcache_lock);
			return error;
		}
		/*
		 * XXX Since there are no node locks for NFS, I believe
		 * there is a slight chance that a delayed write will
		 * occur while sleeping just above, so check for it.
		 */
		if ((bp->b_oflags & BO_DELWRI) && (flags & V_SAVE)) {
#ifdef DEBUG
			printf("buffer still DELWRI\n");
#endif
			bp->b_cflags |= BC_BUSY | BC_VFLUSH;
			mutex_exit(&bufcache_lock);
			VOP_BWRITE(bp->b_vp, bp);
			mutex_enter(&bufcache_lock);
			goto restart;
		}
		brelsel(bp, BC_INVAL | BC_VFLUSH);
	}

#ifdef DIAGNOSTIC
	if (!LIST_EMPTY(&vp->v_cleanblkhd) || !LIST_EMPTY(&vp->v_dirtyblkhd))
		panic("vinvalbuf: flush failed, vp %p", vp);
#endif

	mutex_exit(&bufcache_lock);

	return 0;
}

/*
 * Destroy any in core blocks past the truncation length.
 * Called with the underlying vnode locked, which should prevent new dirty
 * buffers from being queued.
 */
int
vtruncbuf(struct vnode *vp, daddr_t lbn, bool catch_p, int slptimeo)
{
	struct buf *bp, *nbp;
	int error;
	voff_t off;

	off = round_page((voff_t)lbn << vp->v_mount->mnt_fs_bshift);
	rw_enter(vp->v_uobj.vmobjlock, RW_WRITER);
	error = VOP_PUTPAGES(vp, off, 0, PGO_FREE | PGO_SYNCIO);
	if (error) {
		return error;
	}

	mutex_enter(&bufcache_lock);
restart:
	for (bp = LIST_FIRST(&vp->v_dirtyblkhd); bp; bp = nbp) {
		KASSERT(bp->b_vp == vp);
		nbp = LIST_NEXT(bp, b_vnbufs);
		if (bp->b_lblkno < lbn)
			continue;
		error = bbusy(bp, catch_p, slptimeo, NULL);
		if (error != 0) {
			if (error == EPASSTHROUGH)
				goto restart;
			mutex_exit(&bufcache_lock);
			return error;
		}
		brelsel(bp, BC_INVAL | BC_VFLUSH);
	}

	for (bp = LIST_FIRST(&vp->v_cleanblkhd); bp; bp = nbp) {
		KASSERT(bp->b_vp == vp);
		nbp = LIST_NEXT(bp, b_vnbufs);
		if (bp->b_lblkno < lbn)
			continue;
		error = bbusy(bp, catch_p, slptimeo, NULL);
		if (error != 0) {
			if (error == EPASSTHROUGH)
				goto restart;
			mutex_exit(&bufcache_lock);
			return error;
		}
		brelsel(bp, BC_INVAL | BC_VFLUSH);
	}
	mutex_exit(&bufcache_lock);

	return 0;
}

/*
 * Flush all dirty buffers from a vnode.
 * Called with the underlying vnode locked, which should prevent new dirty
 * buffers from being queued.
 */
int
vflushbuf(struct vnode *vp, int flags)
{
	struct buf *bp, *nbp;
	int error, pflags;
	bool dirty, sync;

	sync = (flags & FSYNC_WAIT) != 0;
	pflags = PGO_CLEANIT | PGO_ALLPAGES |
	    (sync ? PGO_SYNCIO : 0) |
	    ((flags & FSYNC_LAZY) ? PGO_LAZY : 0);
	rw_enter(vp->v_uobj.vmobjlock, RW_WRITER);
	(void) VOP_PUTPAGES(vp, 0, 0, pflags);

loop:
	mutex_enter(&bufcache_lock);
	for (bp = LIST_FIRST(&vp->v_dirtyblkhd); bp; bp = nbp) {
		KASSERT(bp->b_vp == vp);
		nbp = LIST_NEXT(bp, b_vnbufs);
		if ((bp->b_cflags & BC_BUSY))
			continue;
		if ((bp->b_oflags & BO_DELWRI) == 0)
			panic("vflushbuf: not dirty, bp %p", bp);
		bp->b_cflags |= BC_BUSY | BC_VFLUSH;
		mutex_exit(&bufcache_lock);
		/*
		 * Wait for I/O associated with indirect blocks to complete,
		 * since there is no way to quickly wait for them below.
		 */
		if (bp->b_vp == vp || !sync)
			(void) bawrite(bp);
		else {
			error = bwrite(bp);
			if (error)
				return error;
		}
		goto loop;
	}
	mutex_exit(&bufcache_lock);

	if (!sync)
		return 0;

	mutex_enter(vp->v_interlock);
	while (vp->v_numoutput != 0)
		cv_wait(&vp->v_cv, vp->v_interlock);
	dirty = !LIST_EMPTY(&vp->v_dirtyblkhd);
	mutex_exit(vp->v_interlock);

	if (dirty) {
		vprint("vflushbuf: dirty", vp);
		goto loop;
	}

	return 0;
}

/*
 * Create a vnode for a block device.
 * Used for root filesystem and swap areas.
 * Also used for memory file system special devices.
 */
int
bdevvp(dev_t dev, vnode_t **vpp)
{
	struct vattr va;

	vattr_null(&va);
	va.va_type = VBLK;
	va.va_rdev = dev;

	return vcache_new(dead_rootmount, NULL, &va, NOCRED, NULL, vpp);
}

/*
 * Create a vnode for a character device.
 * Used for kernfs and some console handling.
 */
int
cdevvp(dev_t dev, vnode_t **vpp)
{
	struct vattr va;

	vattr_null(&va);
	va.va_type = VCHR;
	va.va_rdev = dev;

	return vcache_new(dead_rootmount, NULL, &va, NOCRED, NULL, vpp);
}

/*
 * Associate a buffer with a vnode.  There must already be a hold on
 * the vnode.
 */
void
bgetvp(struct vnode *vp, struct buf *bp)
{

	KASSERT(bp->b_vp == NULL);
	KASSERT(bp->b_objlock == &buffer_lock);
	KASSERT(mutex_owned(vp->v_interlock));
	KASSERT(mutex_owned(&bufcache_lock));
	KASSERT((bp->b_cflags & BC_BUSY) != 0);
	KASSERT(!cv_has_waiters(&bp->b_done));

	vholdl(vp);
	bp->b_vp = vp;
	if (vp->v_type == VBLK || vp->v_type == VCHR)
		bp->b_dev = vp->v_rdev;
	else
		bp->b_dev = NODEV;

	/*
	 * Insert onto list for new vnode.
	 */
	bufinsvn(bp, &vp->v_cleanblkhd);
	bp->b_objlock = vp->v_interlock;
}

/*
 * Disassociate a buffer from a vnode.
 */
void
brelvp(struct buf *bp)
{
	struct vnode *vp = bp->b_vp;

	KASSERT(vp != NULL);
	KASSERT(bp->b_objlock == vp->v_interlock);
	KASSERT(mutex_owned(vp->v_interlock));
	KASSERT(mutex_owned(&bufcache_lock));
	KASSERT((bp->b_cflags & BC_BUSY) != 0);
	KASSERT(!cv_has_waiters(&bp->b_done));

	/*
	 * Delete from old vnode list, if on one.
	 */
	if (LIST_NEXT(bp, b_vnbufs) != NOLIST)
		bufremvn(bp);

	if ((vp->v_iflag & (VI_ONWORKLST | VI_PAGES)) == VI_ONWORKLST &&
	    LIST_FIRST(&vp->v_dirtyblkhd) == NULL)
		vn_syncer_remove_from_worklist(vp);

	bp->b_objlock = &buffer_lock;
	bp->b_vp = NULL;
	holdrelel(vp);
}

/*
 * Reassign a buffer from one vnode list to another.
 * The list reassignment must be within the same vnode.
 * Used to assign file specific control information
 * (indirect blocks) to the list to which they belong.
 */
void
reassignbuf(struct buf *bp, struct vnode *vp)
{
	struct buflists *listheadp;
	int delayx;

	KASSERT(mutex_owned(&bufcache_lock));
	KASSERT(bp->b_objlock == vp->v_interlock);
	KASSERT(mutex_owned(vp->v_interlock));
	KASSERT((bp->b_cflags & BC_BUSY) != 0);

	/*
	 * Delete from old vnode list, if on one.
	 */
	if (LIST_NEXT(bp, b_vnbufs) != NOLIST)
		bufremvn(bp);

	/*
	 * If dirty, put on list of dirty buffers;
	 * otherwise insert onto list of clean buffers.
	 */
	if ((bp->b_oflags & BO_DELWRI) == 0) {
		listheadp = &vp->v_cleanblkhd;
		if ((vp->v_iflag & (VI_ONWORKLST | VI_PAGES)) ==
		    VI_ONWORKLST &&
		    LIST_FIRST(&vp->v_dirtyblkhd) == NULL)
			vn_syncer_remove_from_worklist(vp);
	} else {
		listheadp = &vp->v_dirtyblkhd;
		if ((vp->v_iflag & VI_ONWORKLST) == 0) {
			switch (vp->v_type) {
			case VDIR:
				delayx = dirdelay;
				break;
			case VBLK:
				if (spec_node_getmountedfs(vp) != NULL) {
					delayx = metadelay;
					break;
				}
				/* fall through */
			default:
				delayx = filedelay;
				break;
			}
			if (!vp->v_mount ||
			    (vp->v_mount->mnt_flag & MNT_ASYNC) == 0)
				vn_syncer_add_to_worklist(vp, delayx);
		}
	}
	bufinsvn(bp, listheadp);
}

/*
 * Lookup a vnode by device number and return it referenced.
 */
int
vfinddev(dev_t dev, enum vtype type, vnode_t **vpp)
{

	return (spec_node_lookup_by_dev(type, dev, VDEAD_NOWAIT, vpp) == 0);
}

/*
 * Revoke all the vnodes corresponding to the specified minor number
 * range (endpoints inclusive) of the specified major.
 */
void
vdevgone(int maj, int minl, int minh, enum vtype type)
{
	vnode_t *vp;
	dev_t dev;
	int mn;

	for (mn = minl; mn <= minh; mn++) {
		dev = makedev(maj, mn);
		/*
		 * Notify anyone trying to get at this device that it
		 * has been detached, and then revoke it.
		 */
		switch (type) {
		case VBLK:
			bdev_detached(dev);
			break;
		case VCHR:
			cdev_detached(dev);
			break;
		default:
			panic("invalid specnode type: %d", type);
		}
		/*
		 * Passing 0 as flags, instead of VDEAD_NOWAIT, means
		 * spec_node_lookup_by_dev will wait for vnodes it
		 * finds concurrently being revoked before returning.
		 */
		while (spec_node_lookup_by_dev(type, dev, 0, &vp) == 0) {
			VOP_REVOKE(vp, REVOKEALL);
			vrele(vp);
		}
	}
}

/*
 * The filesystem synchronizer mechanism - syncer.
 *
 * It is useful to delay writes of file data and filesystem metadata for
 * a certain amount of time so that quickly created and deleted files need
 * not waste disk bandwidth being created and removed.  To implement this,
 * vnodes are appended to a "workitem" queue.
 *
 * Most pending metadata should not wait for more than ten seconds.  Thus,
 * mounted on block devices are delayed only about a half the time that file
 * data is delayed.  Similarly, directory updates are more critical, so are
 * only delayed about a third the time that file data is delayed.
 *
 * There are SYNCER_MAXDELAY queues that are processed in a round-robin
 * manner at a rate of one each second (driven off the filesystem syner
 * thread). The syncer_delayno variable indicates the next queue that is
 * to be processed.  Items that need to be processed soon are placed in
 * this queue:
 *
 *	syncer_workitem_pending[syncer_delayno]
 *
 * A delay of e.g. fifteen seconds is done by placing the request fifteen
 * entries later in the queue:
 *
 *	syncer_workitem_pending[(syncer_delayno + 15) & syncer_mask]
 *
 * Flag VI_ONWORKLST indicates that vnode is added into the queue.
 */

#define SYNCER_MAXDELAY		32

typedef TAILQ_HEAD(synclist, vnode_impl) synclist_t;

static void	vn_syncer_add1(struct vnode *, int);
static void	sysctl_vfs_syncfs_setup(struct sysctllog **);

/*
 * Defines and variables for the syncer process.
 */
int syncer_maxdelay = SYNCER_MAXDELAY;	/* maximum delay time */
time_t syncdelay = 30;			/* max time to delay syncing data */
time_t filedelay = 30;			/* time to delay syncing files */
time_t dirdelay  = 15;			/* time to delay syncing directories */
time_t metadelay = 10;			/* time to delay syncing metadata */
time_t lockdelay = 1;			/* time to delay if locking fails */

static kmutex_t		syncer_data_lock; /* short term lock on data structs */

static int		syncer_delayno = 0;
static long		syncer_last;
static synclist_t *	syncer_workitem_pending;

static void
vn_initialize_syncerd(void)
{
	int i;

	syncer_last = SYNCER_MAXDELAY + 2;

	sysctl_vfs_syncfs_setup(NULL);

	syncer_workitem_pending =
	    kmem_alloc(syncer_last * sizeof (struct synclist), KM_SLEEP);

	for (i = 0; i < syncer_last; i++)
		TAILQ_INIT(&syncer_workitem_pending[i]);

	mutex_init(&syncer_data_lock, MUTEX_DEFAULT, IPL_NONE);
}

/*
 * Return delay factor appropriate for the given file system.   For
 * WAPBL we use the sync vnode to burst out metadata updates: sync
 * those file systems more frequently.
 */
static inline int
sync_delay(struct mount *mp)
{

	return mp->mnt_wapbl != NULL ? metadelay : syncdelay;
}

/*
 * Compute the next slot index from delay.
 */
static inline int
sync_delay_slot(int delayx)
{

	if (delayx > syncer_maxdelay - 2)
		delayx = syncer_maxdelay - 2;
	return (syncer_delayno + delayx) % syncer_last;
}

/*
 * Add an item to the syncer work queue.
 */
static void
vn_syncer_add1(struct vnode *vp, int delayx)
{
	synclist_t *slp;
	vnode_impl_t *vip = VNODE_TO_VIMPL(vp);

	KASSERT(mutex_owned(&syncer_data_lock));

	if (vp->v_iflag & VI_ONWORKLST) {
		/*
		 * Remove in order to adjust the position of the vnode.
		 * Note: called from sched_sync(), which will not hold
		 * interlock, therefore we cannot modify v_iflag here.
		 */
		slp = &syncer_workitem_pending[vip->vi_synclist_slot];
		TAILQ_REMOVE(slp, vip, vi_synclist);
	} else {
		KASSERT(mutex_owned(vp->v_interlock));
		vp->v_iflag |= VI_ONWORKLST;
	}

	vip->vi_synclist_slot = sync_delay_slot(delayx);

	slp = &syncer_workitem_pending[vip->vi_synclist_slot];
	TAILQ_INSERT_TAIL(slp, vip, vi_synclist);
}

void
vn_syncer_add_to_worklist(struct vnode *vp, int delayx)
{
	vnode_impl_t *vip = VNODE_TO_VIMPL(vp);

	KASSERT(mutex_owned(vp->v_interlock));

	mutex_enter(&syncer_data_lock);
	vn_syncer_add1(vp, delayx);
	SDT_PROBE3(vfs, syncer, worklist, vnode__add,
	    vp, delayx, vip->vi_synclist_slot);
	mutex_exit(&syncer_data_lock);
}

/*
 * Remove an item from the syncer work queue.
 */
void
vn_syncer_remove_from_worklist(struct vnode *vp)
{
	synclist_t *slp;
	vnode_impl_t *vip = VNODE_TO_VIMPL(vp);

	KASSERT(mutex_owned(vp->v_interlock));

	if (vp->v_iflag & VI_ONWORKLST) {
		mutex_enter(&syncer_data_lock);
		SDT_PROBE1(vfs, syncer, worklist, vnode__remove,  vp);
		vp->v_iflag &= ~VI_ONWORKLST;
		slp = &syncer_workitem_pending[vip->vi_synclist_slot];
		TAILQ_REMOVE(slp, vip, vi_synclist);
		mutex_exit(&syncer_data_lock);
	}
}

/*
 * Add this mount point to the syncer.
 */
void
vfs_syncer_add_to_worklist(struct mount *mp)
{
	static int start, incr, next;
	int vdelay;

	KASSERT(mutex_owned(mp->mnt_updating));
	KASSERT((mp->mnt_iflag & IMNT_ONWORKLIST) == 0);

	/*
	 * We attempt to scatter the mount points on the list
	 * so that they will go off at evenly distributed times
	 * even if all the filesystems are mounted at once.
	 */

	next += incr;
	if (next == 0 || next > syncer_maxdelay) {
		start /= 2;
		incr /= 2;
		if (start == 0) {
			start = syncer_maxdelay / 2;
			incr = syncer_maxdelay;
		}
		next = start;
	}
	mp->mnt_iflag |= IMNT_ONWORKLIST;
	vdelay = sync_delay(mp);
	mp->mnt_synclist_slot = vdelay > 0 ? next % vdelay : 0;
	SDT_PROBE3(vfs, syncer, worklist, mount__add,
	    mp, vdelay, mp->mnt_synclist_slot);
}

/*
 * Remove the mount point from the syncer.
 */
void
vfs_syncer_remove_from_worklist(struct mount *mp)
{

	KASSERT(mutex_owned(mp->mnt_updating));
	KASSERT((mp->mnt_iflag & IMNT_ONWORKLIST) != 0);

	SDT_PROBE1(vfs, syncer, worklist, mount__remove,  mp);
	mp->mnt_iflag &= ~IMNT_ONWORKLIST;
}

/*
 * Try lazy sync, return true on success.
 */
static bool
lazy_sync_vnode(struct vnode *vp)
{
	bool synced;
	int error;

	KASSERT(mutex_owned(&syncer_data_lock));

	synced = false;
	if ((error = vcache_tryvget(vp)) == 0) {
		mutex_exit(&syncer_data_lock);
		if ((error = vn_lock(vp, LK_EXCLUSIVE | LK_NOWAIT)) == 0) {
			synced = true;
			SDT_PROBE1(vfs, syncer, sync, vnode__start,  vp);
			error = VOP_FSYNC(vp, curlwp->l_cred,
			    FSYNC_LAZY, 0, 0);
			SDT_PROBE2(vfs, syncer, sync, vnode__done,  vp, error);
			vput(vp);
		} else {
			SDT_PROBE2(vfs, syncer, sync, vnode__fail__lock,
			    vp, error);
			vrele(vp);
		}
		mutex_enter(&syncer_data_lock);
	} else {
		SDT_PROBE2(vfs, syncer, sync, vnode__fail__vget,  vp, error);
	}
	return synced;
}

/*
 * System filesystem synchronizer daemon.
 */
void
sched_sync(void *arg)
{
	mount_iterator_t *iter;
	synclist_t *slp;
	struct vnode_impl *vi;
	struct vnode *vp;
	struct mount *mp;
	time_t starttime, endtime;
	int vdelay, oslot, nslot, delayx;
	bool synced;
	int error;

	for (;;) {
		starttime = time_second;
		SDT_PROBE1(vfs, syncer, sync, start,  starttime);

		/*
		 * Sync mounts whose dirty time has expired.
		 */
		mountlist_iterator_init(&iter);
		while ((mp = mountlist_iterator_trynext(iter)) != NULL) {
			if ((mp->mnt_iflag & IMNT_ONWORKLIST) == 0 ||
			    mp->mnt_synclist_slot != syncer_delayno) {
				SDT_PROBE1(vfs, syncer, sync, mount__skip,
				    mp);
				continue;
			}

			vdelay = sync_delay(mp);
			oslot = mp->mnt_synclist_slot;
			nslot = sync_delay_slot(vdelay);
			mp->mnt_synclist_slot = nslot;
			SDT_PROBE4(vfs, syncer, worklist, mount__update,
			    mp, vdelay, oslot, nslot);

			SDT_PROBE1(vfs, syncer, sync, mount__start,  mp);
			error = VFS_SYNC(mp, MNT_LAZY, curlwp->l_cred);
			SDT_PROBE2(vfs, syncer, sync, mount__done,
			    mp, error);
		}
		mountlist_iterator_destroy(iter);

		mutex_enter(&syncer_data_lock);

		/*
		 * Push files whose dirty time has expired.
		 */
		slp = &syncer_workitem_pending[syncer_delayno];
		syncer_delayno += 1;
		if (syncer_delayno >= syncer_last)
			syncer_delayno = 0;

		while ((vi = TAILQ_FIRST(slp)) != NULL) {
			vp = VIMPL_TO_VNODE(vi);
			synced = lazy_sync_vnode(vp);

			/*
			 * XXX The vnode may have been recycled, in which
			 * case it may have a new identity.
			 */
			vi = TAILQ_FIRST(slp);
			if (vi != NULL && VIMPL_TO_VNODE(vi) == vp) {
				/*
				 * Put us back on the worklist.  The worklist
				 * routine will remove us from our current
				 * position and then add us back in at a later
				 * position.
				 *
				 * Try again sooner rather than later if
				 * we were unable to lock the vnode.  Lock
				 * failure should not prevent us from doing
				 * the sync "soon".
				 *
				 * If we locked it yet arrive here, it's
				 * likely that lazy sync is in progress and
				 * so the vnode still has dirty metadata.
				 * syncdelay is mainly to get this vnode out
				 * of the way so we do not consider it again
				 * "soon" in this loop, so the delay time is
				 * not critical as long as it is not "soon".
				 * While write-back strategy is the file
				 * system's domain, we expect write-back to
				 * occur no later than syncdelay seconds
				 * into the future.
				 */
				delayx = synced ? syncdelay : lockdelay;
				oslot = vi->vi_synclist_slot;
				vn_syncer_add1(vp, delayx);
				nslot = vi->vi_synclist_slot;
				SDT_PROBE4(vfs, syncer, worklist,
				    vnode__update,
				    vp, delayx, oslot, nslot);
			}
		}

		endtime = time_second;

		SDT_PROBE2(vfs, syncer, sync, done,  starttime, endtime);

		/*
		 * If it has taken us less than a second to process the
		 * current work, then wait.  Otherwise start right over
		 * again.  We can still lose time if any single round
		 * takes more than two seconds, but it does not really
		 * matter as we are just trying to generally pace the
		 * filesystem activity.
		 */
		if (endtime == starttime) {
			kpause("syncer", false, hz, &syncer_data_lock);
		}
		mutex_exit(&syncer_data_lock);
	}
}

static void
sysctl_vfs_syncfs_setup(struct sysctllog **clog)
{
	const struct sysctlnode *rnode, *cnode;

	sysctl_createv(clog, 0, NULL, &rnode,
	    CTLFLAG_PERMANENT,
	    CTLTYPE_NODE, "sync",
	    SYSCTL_DESCR("syncer options"),
	    NULL, 0, NULL, 0,
	    CTL_VFS, CTL_CREATE, CTL_EOL);

	sysctl_createv(clog, 0, &rnode, &cnode,
	    CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
	    CTLTYPE_QUAD, "delay",
	    SYSCTL_DESCR("max time to delay syncing data"),
	    NULL, 0, &syncdelay, 0,
	    CTL_CREATE, CTL_EOL);

	sysctl_createv(clog, 0, &rnode, &cnode,
	    CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
	    CTLTYPE_QUAD, "filedelay",
	    SYSCTL_DESCR("time to delay syncing files"),
	    NULL, 0, &filedelay, 0,
	    CTL_CREATE, CTL_EOL);

	sysctl_createv(clog, 0, &rnode, &cnode,
	    CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
	    CTLTYPE_QUAD, "dirdelay",
	    SYSCTL_DESCR("time to delay syncing directories"),
	    NULL, 0, &dirdelay, 0,
	    CTL_CREATE, CTL_EOL);

	sysctl_createv(clog, 0, &rnode, &cnode,
	    CTLFLAG_PERMANENT|CTLFLAG_READWRITE,
	    CTLTYPE_QUAD, "metadelay",
	    SYSCTL_DESCR("time to delay syncing metadata"),
	    NULL, 0, &metadelay, 0,
	    CTL_CREATE, CTL_EOL);
}

/*
 * sysctl helper routine to return list of supported fstypes
 */
int
sysctl_vfs_generic_fstypes(SYSCTLFN_ARGS)
{
	char bf[sizeof(((struct statvfs *)NULL)->f_fstypename)];
	char *where = oldp;
	struct vfsops *v;
	size_t needed, left, slen;
	int error, first;

	if (newp != NULL)
		return SET_ERROR(EPERM);
	if (namelen != 0)
		return SET_ERROR(EINVAL);

	first = 1;
	error = 0;
	needed = 0;
	left = *oldlenp;

	sysctl_unlock();
	mutex_enter(&vfs_list_lock);
	LIST_FOREACH(v, &vfs_list, vfs_list) {
		if (where == NULL)
			needed += strlen(v->vfs_name) + 1;
		else {
			memset(bf, 0, sizeof(bf));
			if (first) {
				strncpy(bf, v->vfs_name, sizeof(bf));
				first = 0;
			} else {
				bf[0] = ' ';
				strncpy(bf + 1, v->vfs_name, sizeof(bf) - 1);
			}
			bf[sizeof(bf)-1] = '\0';
			slen = strlen(bf);
			if (left < slen + 1)
				break;
			v->vfs_refcount++;
			mutex_exit(&vfs_list_lock);
			/* +1 to copy out the trailing NUL byte */
			error = copyout(bf, where, slen + 1);
			mutex_enter(&vfs_list_lock);
			v->vfs_refcount--;
			if (error)
				break;
			where += slen;
			needed += slen;
			left -= slen;
		}
	}
	mutex_exit(&vfs_list_lock);
	sysctl_relock();
	*oldlenp = needed;
	return error;
}

int kinfo_vdebug = 1;
int kinfo_vgetfailed;

#define KINFO_VNODESLOP	10

/*
 * Dump vnode list (via sysctl).
 * Copyout address of vnode followed by vnode.
 */
int
sysctl_kern_vnode(SYSCTLFN_ARGS)
{
	char *where = oldp;
	size_t *sizep = oldlenp;
	struct mount *mp;
	vnode_t *vp, vbuf;
	mount_iterator_t *iter;
	struct vnode_iterator *marker;
	char *bp = where;
	char *ewhere;
	int error;

	if (namelen != 0)
		return SET_ERROR(EOPNOTSUPP);
	if (newp != NULL)
		return SET_ERROR(EPERM);

#define VPTRSZ	sizeof(vnode_t *)
#define VNODESZ	sizeof(vnode_t)
	if (where == NULL) {
		*sizep = (numvnodes + KINFO_VNODESLOP) * (VPTRSZ + VNODESZ);
		return 0;
	}
	ewhere = where + *sizep;

	sysctl_unlock();
	mountlist_iterator_init(&iter);
	while ((mp = mountlist_iterator_next(iter)) != NULL) {
		vfs_vnode_iterator_init(mp, &marker);
		while ((vp = vfs_vnode_iterator_next(marker, NULL, NULL))) {
			if (bp + VPTRSZ + VNODESZ > ewhere) {
				vrele(vp);
				vfs_vnode_iterator_destroy(marker);
				mountlist_iterator_destroy(iter);
				sysctl_relock();
				*sizep = bp - where;
				return SET_ERROR(ENOMEM);
			}
			memcpy(&vbuf, vp, VNODESZ);
			if ((error = copyout(&vp, bp, VPTRSZ)) ||
			    (error = copyout(&vbuf, bp + VPTRSZ, VNODESZ))) {
				vrele(vp);
				vfs_vnode_iterator_destroy(marker);
				mountlist_iterator_destroy(iter);
				sysctl_relock();
				return error;
			}
			vrele(vp);
			bp += VPTRSZ + VNODESZ;
		}
		vfs_vnode_iterator_destroy(marker);
	}
	mountlist_iterator_destroy(iter);
	sysctl_relock();

	*sizep = bp - where;
	return 0;
}

/*
 * Set vnode attributes to VNOVAL
 */
void
vattr_null(struct vattr *vap)
{

	memset(vap, 0, sizeof(*vap));

	vap->va_type = VNON;

	/*
	 * Assign individually so that it is safe even if size and
	 * sign of each member are varied.
	 */
	vap->va_mode = VNOVAL;
	vap->va_nlink = VNOVAL;
	vap->va_uid = VNOVAL;
	vap->va_gid = VNOVAL;
	vap->va_fsid = VNOVAL;
	vap->va_fileid = VNOVAL;
	vap->va_size = VNOVAL;
	vap->va_blocksize = VNOVAL;
	vap->va_atime.tv_sec =
	    vap->va_mtime.tv_sec =
	    vap->va_ctime.tv_sec =
	    vap->va_birthtime.tv_sec = VNOVAL;
	vap->va_atime.tv_nsec =
	    vap->va_mtime.tv_nsec =
	    vap->va_ctime.tv_nsec =
	    vap->va_birthtime.tv_nsec = VNOVAL;
	vap->va_gen = VNOVAL;
	vap->va_flags = VNOVAL;
	vap->va_rdev = VNOVAL;
	vap->va_bytes = VNOVAL;
}

/*
 * Vnode state to string.
 */
const char *
vstate_name(enum vnode_state state)
{

	switch (state) {
	case VS_ACTIVE:
		return "ACTIVE";
	case VS_MARKER:
		return "MARKER";
	case VS_LOADING:
		return "LOADING";
	case VS_LOADED:
		return "LOADED";
	case VS_BLOCKED:
		return "BLOCKED";
	case VS_RECLAIMING:
		return "RECLAIMING";
	case VS_RECLAIMED:
		return "RECLAIMED";
	default:
		return "ILLEGAL";
	}
}

/*
 * Print a description of a vnode (common part).
 */
static void
vprint_common(struct vnode *vp, const char *prefix,
    void (*pr)(const char *, ...) __printflike(1, 2))
{
	int n;
	char bf[96];
	const uint8_t *cp;
	vnode_impl_t *vip;
	const char * const vnode_tags[] = { VNODE_TAGS };
	const char * const vnode_types[] = { VNODE_TYPES };
	const char vnode_flagbits[] = VNODE_FLAGBITS;

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#define ARRAY_PRINT(idx, arr) \
    ((unsigned int)(idx) < ARRAY_SIZE(arr) ? (arr)[(idx)] : "UNKNOWN")

	vip = VNODE_TO_VIMPL(vp);

	snprintb(bf, sizeof(bf),
	    vnode_flagbits, vp->v_iflag | vp->v_vflag | vp->v_uflag);

	(*pr)("vnode %p flags %s\n", vp, bf);
	(*pr)("%stag %s(%d) type %s(%d) mount %p typedata %p\n", prefix,
	    ARRAY_PRINT(vp->v_tag, vnode_tags), vp->v_tag,
	    ARRAY_PRINT(vp->v_type, vnode_types), vp->v_type,
	    vp->v_mount, vp->v_mountedhere);
	(*pr)("%susecount %d writecount %d holdcount %d\n", prefix,
	    vrefcnt(vp), vp->v_writecount, vp->v_holdcnt);
	(*pr)("%ssize %" PRIx64 " writesize %" PRIx64 " numoutput %d\n",
	    prefix, vp->v_size, vp->v_writesize, vp->v_numoutput);
	(*pr)("%sdata %p lock %p\n", prefix, vp->v_data, &vip->vi_lock);

	(*pr)("%sstate %s key(%p %zd)", prefix, vstate_name(vip->vi_state),
	    vip->vi_key.vk_mount, vip->vi_key.vk_key_len);
	n = vip->vi_key.vk_key_len;
	cp = vip->vi_key.vk_key;
	while (n-- > 0)
		(*pr)(" %02x", *cp++);
	(*pr)("\n");
	(*pr)("%slrulisthd %p\n", prefix, vip->vi_lrulisthd);

#undef ARRAY_PRINT
#undef ARRAY_SIZE
}

/*
 * Print out a description of a vnode.
 */
void
vprint(const char *label, struct vnode *vp)
{

	if (label != NULL)
		printf("%s: ", label);
	vprint_common(vp, "\t", printf);
	if (vp->v_data != NULL) {
		printf("\t");
		VOP_PRINT(vp);
	}
}

/*
 * Given a file system name, look up the vfsops for that
 * file system, or return NULL if file system isn't present
 * in the kernel.
 */
struct vfsops *
vfs_getopsbyname(const char *name)
{
	struct vfsops *v;

	mutex_enter(&vfs_list_lock);
	LIST_FOREACH(v, &vfs_list, vfs_list) {
		if (strcmp(v->vfs_name, name) == 0)
			break;
	}
	if (v != NULL)
		v->vfs_refcount++;
	mutex_exit(&vfs_list_lock);

	return v;
}

void
copy_statvfs_info(struct statvfs *sbp, const struct mount *mp)
{
	const struct statvfs *mbp;

	if (sbp == (mbp = &mp->mnt_stat))
		return;

	(void)memcpy(&sbp->f_fsidx, &mbp->f_fsidx, sizeof(sbp->f_fsidx));
	sbp->f_fsid = mbp->f_fsid;
	sbp->f_owner = mbp->f_owner;
	sbp->f_flag = mbp->f_flag;
	sbp->f_syncwrites = mbp->f_syncwrites;
	sbp->f_asyncwrites = mbp->f_asyncwrites;
	sbp->f_syncreads = mbp->f_syncreads;
	sbp->f_asyncreads = mbp->f_asyncreads;
	(void)memcpy(sbp->f_spare, mbp->f_spare, sizeof(mbp->f_spare));
	(void)memcpy(sbp->f_fstypename, mbp->f_fstypename,
	    sizeof(sbp->f_fstypename));
	(void)memcpy(sbp->f_mntonname, mbp->f_mntonname,
	    sizeof(sbp->f_mntonname));
	(void)memcpy(sbp->f_mntfromname, mp->mnt_stat.f_mntfromname,
	    sizeof(sbp->f_mntfromname));
	(void)memcpy(sbp->f_mntfromlabel, mp->mnt_stat.f_mntfromlabel,
	    sizeof(sbp->f_mntfromlabel));
	sbp->f_namemax = mbp->f_namemax;
}

int
set_statvfs_info(const char *onp, int ukon, const char *fromp, int ukfrom,
    const char *vfsname, struct mount *mp, struct lwp *l)
{
	int error;
	size_t size;
	struct statvfs *sfs = &mp->mnt_stat;
	int (*fun)(const void *, void *, size_t, size_t *);

	(void)strlcpy(mp->mnt_stat.f_fstypename, vfsname,
	    sizeof(mp->mnt_stat.f_fstypename));

	if (onp) {
		struct cwdinfo *cwdi = l->l_proc->p_cwdi;
		fun = (ukon == UIO_SYSSPACE) ? copystr : copyinstr;
		if (cwdi->cwdi_rdir != NULL) {
			size_t len;
			char *bp;
			char *path = PNBUF_GET();

			bp = path + MAXPATHLEN;
			*--bp = '\0';
			rw_enter(&cwdi->cwdi_lock, RW_READER);
			error = getcwd_common(cwdi->cwdi_rdir, rootvnode, &bp,
			    path, MAXPATHLEN / 2, 0, l);
			rw_exit(&cwdi->cwdi_lock);
			if (error) {
				PNBUF_PUT(path);
				return error;
			}

			len = strlen(bp);
			if (len > sizeof(sfs->f_mntonname) - 1)
				len = sizeof(sfs->f_mntonname) - 1;
			(void)strncpy(sfs->f_mntonname, bp, len);
			PNBUF_PUT(path);

			if (len < sizeof(sfs->f_mntonname) - 1) {
				error = (*fun)(onp, &sfs->f_mntonname[len],
				    sizeof(sfs->f_mntonname) - len - 1, &size);
				if (error)
					return error;
				size += len;
			} else {
				size = len;
			}
		} else {
			error = (*fun)(onp, &sfs->f_mntonname,
			    sizeof(sfs->f_mntonname) - 1, &size);
			if (error)
				return error;
		}
		(void)memset(sfs->f_mntonname + size, 0,
		    sizeof(sfs->f_mntonname) - size);
	}

	if (fromp) {
		fun = (ukfrom == UIO_SYSSPACE) ? copystr : copyinstr;
		error = (*fun)(fromp, sfs->f_mntfromname,
		    sizeof(sfs->f_mntfromname) - 1, &size);
		if (error)
			return error;
		(void)memset(sfs->f_mntfromname + size, 0,
		    sizeof(sfs->f_mntfromname) - size);
	}
	return 0;
}

/*
 * Knob to control the precision of file timestamps:
 *
 *   0 = seconds only; nanoseconds zeroed.
 *   1 = seconds and nanoseconds, accurate within 1/HZ.
 *   2 = seconds and nanoseconds, truncated to microseconds.
 * >=3 = seconds and nanoseconds, maximum precision.
 */
enum { TSP_SEC, TSP_HZ, TSP_USEC, TSP_NSEC };

int vfs_timestamp_precision __read_mostly = TSP_NSEC;

void
vfs_timestamp(struct timespec *tsp)
{
	struct timeval tv;

	switch (vfs_timestamp_precision) {
	case TSP_SEC:
		tsp->tv_sec = time_second;
		tsp->tv_nsec = 0;
		break;
	case TSP_HZ:
		getnanotime(tsp);
		break;
	case TSP_USEC:
		microtime(&tv);
		TIMEVAL_TO_TIMESPEC(&tv, tsp);
		break;
	case TSP_NSEC:
	default:
		nanotime(tsp);
		break;
	}
}

/*
 * The purpose of this routine is to remove granularity from accmode_t,
 * reducing it into standard unix access bits - VEXEC, VREAD, VWRITE,
 * VADMIN and VAPPEND.
 *
 * If it returns 0, the caller is supposed to continue with the usual
 * access checks using 'accmode' as modified by this routine.  If it
 * returns nonzero value, the caller is supposed to return that value
 * as errno.
 *
 * Note that after this routine runs, accmode may be zero.
 */
int
vfs_unixify_accmode(accmode_t *accmode)
{

	/*
	 * There is no way to specify explicit "deny" rule using
	 * file mode or POSIX.1e ACLs.
	 */
	if (*accmode & VEXPLICIT_DENY) {
		*accmode = 0;
		return 0;
	}

	/*
	 * None of these can be translated into usual access bits.
	 * Also, the common case for NFSv4 ACLs is to not contain
	 * either of these bits. Caller should check for VWRITE
	 * on the containing directory instead.
	 */
	if (*accmode & (VDELETE_CHILD | VDELETE))
		return SET_ERROR(EPERM);

	if (*accmode & VADMIN_PERMS) {
		*accmode &= ~VADMIN_PERMS;
		*accmode |= VADMIN;
	}

	/*
	 * There is no way to deny VREAD_ATTRIBUTES, VREAD_ACL
	 * or VSYNCHRONIZE using file mode or POSIX.1e ACL.
	 */
	*accmode &= ~(VSTAT_PERMS | VSYNCHRONIZE);

	return 0;
}

time_t	rootfstime;			/* recorded root fs time, if known */
void
setrootfstime(time_t t)
{

	rootfstime = t;
}

static const uint8_t vttodt_tab[] = {
	[VNON]	=	DT_UNKNOWN,
	[VREG]	=	DT_REG,
	[VDIR]	=	DT_DIR,
	[VBLK]	=	DT_BLK,
	[VCHR]	=	DT_CHR,
	[VLNK]	=	DT_LNK,
	[VSOCK]	=	DT_SOCK,
	[VFIFO]	=	DT_FIFO,
	[VBAD]	=	DT_UNKNOWN
};

uint8_t
vtype2dt(enum vtype vt)
{

	CTASSERT(VBAD == __arraycount(vttodt_tab) - 1);
	return vttodt_tab[vt];
}

int
VFS_MOUNT(struct mount *mp, const char *a, void *b, size_t *c)
{
	int mpsafe = mp->mnt_iflag & IMNT_MPSAFE;
	int error;

	/*
	 * Note: The first time through, the vfs_mount function may set
	 * IMNT_MPSAFE, so we have to cache it on entry in order to
	 * avoid leaking a kernel lock.
	 *
	 * XXX Maybe the MPSAFE bit should be set in struct vfsops and
	 * not in struct mount.
	 */
	if (mpsafe) {
		KERNEL_LOCK(1, NULL);
	}
	error = (*(mp->mnt_op->vfs_mount))(mp, a, b, c);
	if (mpsafe) {
		KERNEL_UNLOCK_ONE(NULL);
	}

	return error;
}

int
VFS_START(struct mount *mp, int a)
{
	int error;

	if ((mp->mnt_iflag & IMNT_MPSAFE) == 0) {
		KERNEL_LOCK(1, NULL);
	}
	error = (*(mp->mnt_op->vfs_start))(mp, a);
	if ((mp->mnt_iflag & IMNT_MPSAFE) == 0) {
		KERNEL_UNLOCK_ONE(NULL);
	}

	return error;
}

int
VFS_UNMOUNT(struct mount *mp, int a)
{
	int error;

	if ((mp->mnt_iflag & IMNT_MPSAFE) == 0) {
		KERNEL_LOCK(1, NULL);
	}
	error = (*(mp->mnt_op->vfs_unmount))(mp, a);
	if ((mp->mnt_iflag & IMNT_MPSAFE) == 0) {
		KERNEL_UNLOCK_ONE(NULL);
	}

	return error;
}

int
VFS_ROOT(struct mount *mp, int lktype, struct vnode **a)
{
	int error;

	if ((mp->mnt_iflag & IMNT_MPSAFE) == 0) {
		KERNEL_LOCK(1, NULL);
	}
	error = (*(mp->mnt_op->vfs_root))(mp, lktype, a);
	if ((mp->mnt_iflag & IMNT_MPSAFE) == 0) {
		KERNEL_UNLOCK_ONE(NULL);
	}

	return error;
}

int
VFS_QUOTACTL(struct mount *mp, struct quotactl_args *args)
{
	int error;

	if ((mp->mnt_iflag & IMNT_MPSAFE) == 0) {
		KERNEL_LOCK(1, NULL);
	}
	error = (*(mp->mnt_op->vfs_quotactl))(mp, args);
	if ((mp->mnt_iflag & IMNT_MPSAFE) == 0) {
		KERNEL_UNLOCK_ONE(NULL);
	}

	return error;
}

int
VFS_STATVFS(struct mount *mp, struct statvfs *a)
{
	int error;

	if ((mp->mnt_iflag & IMNT_MPSAFE) == 0) {
		KERNEL_LOCK(1, NULL);
	}
	error = (*(mp->mnt_op->vfs_statvfs))(mp, a);
	if ((mp->mnt_iflag & IMNT_MPSAFE) == 0) {
		KERNEL_UNLOCK_ONE(NULL);
	}

	return error;
}

int
VFS_SYNC(struct mount *mp, int a, struct kauth_cred *b)
{
	int error;

	if ((mp->mnt_iflag & IMNT_MPSAFE) == 0) {
		KERNEL_LOCK(1, NULL);
	}
	error = (*(mp->mnt_op->vfs_sync))(mp, a, b);
	if ((mp->mnt_iflag & IMNT_MPSAFE) == 0) {
		KERNEL_UNLOCK_ONE(NULL);
	}

	return error;
}

int
VFS_FHTOVP(struct mount *mp, struct fid *a, int b, struct vnode **c)
{
	int error;

	if ((mp->mnt_iflag & IMNT_MPSAFE) == 0) {
		KERNEL_LOCK(1, NULL);
	}
	error = (*(mp->mnt_op->vfs_fhtovp))(mp, a, b, c);
	if ((mp->mnt_iflag & IMNT_MPSAFE) == 0) {
		KERNEL_UNLOCK_ONE(NULL);
	}

	return error;
}

int
VFS_VPTOFH(struct vnode *vp, struct fid *a, size_t *b)
{
	int error;

	if ((vp->v_vflag & VV_MPSAFE) == 0) {
		KERNEL_LOCK(1, NULL);
	}
	error = (*(vp->v_mount->mnt_op->vfs_vptofh))(vp, a, b);
	if ((vp->v_vflag & VV_MPSAFE) == 0) {
		KERNEL_UNLOCK_ONE(NULL);
	}

	return error;
}

int
VFS_SNAPSHOT(struct mount *mp, struct vnode *a, struct timespec *b)
{
	int error;

	if ((mp->mnt_iflag & IMNT_MPSAFE) == 0) {
		KERNEL_LOCK(1, NULL);
	}
	error = (*(mp->mnt_op->vfs_snapshot))(mp, a, b);
	if ((mp->mnt_iflag & IMNT_MPSAFE) == 0) {
		KERNEL_UNLOCK_ONE(NULL);
	}

	return error;
}

int
VFS_EXTATTRCTL(struct mount *mp, int a, struct vnode *b, int c, const char *d)
{
	int error;

	KERNEL_LOCK(1, NULL);		/* XXXSMP check ffs */
	error = (*(mp->mnt_op->vfs_extattrctl))(mp, a, b, c, d);
	KERNEL_UNLOCK_ONE(NULL);	/* XXX */

	return error;
}

int
VFS_SUSPENDCTL(struct mount *mp, int a)
{
	int error;

	if ((mp->mnt_iflag & IMNT_MPSAFE) == 0) {
		KERNEL_LOCK(1, NULL);
	}
	error = (*(mp->mnt_op->vfs_suspendctl))(mp, a);
	if ((mp->mnt_iflag & IMNT_MPSAFE) == 0) {
		KERNEL_UNLOCK_ONE(NULL);
	}

	return error;
}

#if defined(DDB) || defined(DEBUGPRINT)
static const char buf_flagbits[] = BUF_FLAGBITS;

void
vfs_buf_print(struct buf *bp, int full, void (*pr)(const char *, ...))
{
	char bf[1024];

	(*pr)("  vp %p lblkno 0x%"PRIx64" blkno 0x%"PRIx64" rawblkno 0x%"
	    PRIx64 " dev 0x%x\n",
	    bp->b_vp, bp->b_lblkno, bp->b_blkno, bp->b_rawblkno, bp->b_dev);

	snprintb(bf, sizeof(bf),
	    buf_flagbits, bp->b_flags | bp->b_oflags | bp->b_cflags);
	(*pr)("  error %d flags %s\n", bp->b_error, bf);

	(*pr)("  bufsize 0x%lx bcount 0x%lx resid 0x%lx\n",
	    bp->b_bufsize, bp->b_bcount, bp->b_resid);
	(*pr)("  data %p saveaddr %p\n",
	    bp->b_data, bp->b_saveaddr);
	(*pr)("  iodone %p objlock %p\n", bp->b_iodone, bp->b_objlock);
}

void
vfs_vnode_print(struct vnode *vp, int full, void (*pr)(const char *, ...))
{

	uvm_object_printit(&vp->v_uobj, full, pr);
	(*pr)("\n");
	vprint_common(vp, "", pr);
	if (full) {
		struct buf *bp;

		(*pr)("clean bufs:\n");
		LIST_FOREACH(bp, &vp->v_cleanblkhd, b_vnbufs) {
			(*pr)(" bp %p\n", bp);
			vfs_buf_print(bp, full, pr);
		}

		(*pr)("dirty bufs:\n");
		LIST_FOREACH(bp, &vp->v_dirtyblkhd, b_vnbufs) {
			(*pr)(" bp %p\n", bp);
			vfs_buf_print(bp, full, pr);
		}
	}
}

void
vfs_vnode_lock_print(void *vlock, int full, void (*pr)(const char *, ...))
{
	struct mount *mp;
	vnode_impl_t *vip;

	for (mp = _mountlist_next(NULL); mp; mp = _mountlist_next(mp)) {
		TAILQ_FOREACH(vip, &mp->mnt_vnodelist, vi_mntvnodes) {
			if (&vip->vi_lock == vlock ||
			    VIMPL_TO_VNODE(vip)->v_interlock == vlock)
				vfs_vnode_print(VIMPL_TO_VNODE(vip), full, pr);
		}
	}
}

void
vfs_mount_print_all(int full, void (*pr)(const char *, ...))
{
	struct mount *mp;
	for (mp = _mountlist_next(NULL); mp; mp = _mountlist_next(mp))
		vfs_mount_print(mp, full, pr);
}

void
vfs_mount_print(struct mount *mp, int full, void (*pr)(const char *, ...))
{
	char sbuf[256];

	(*pr)("vnodecovered = %p data = %p\n",
	    mp->mnt_vnodecovered, mp->mnt_data);

	(*pr)("fs_bshift %d dev_bshift = %d\n",
	    mp->mnt_fs_bshift, mp->mnt_dev_bshift);

	snprintb(sbuf, sizeof(sbuf), __MNT_FLAG_BITS, mp->mnt_flag);
	(*pr)("flag = %s\n", sbuf);

	snprintb(sbuf, sizeof(sbuf), __IMNT_FLAG_BITS, mp->mnt_iflag);
	(*pr)("iflag = %s\n", sbuf);

	(*pr)("refcnt = %d updating @ %p\n", mp->mnt_refcnt, mp->mnt_updating);

	(*pr)("statvfs cache:\n");
	(*pr)("\tbsize = %lu\n", mp->mnt_stat.f_bsize);
	(*pr)("\tfrsize = %lu\n", mp->mnt_stat.f_frsize);
	(*pr)("\tiosize = %lu\n", mp->mnt_stat.f_iosize);

	(*pr)("\tblocks = %"PRIu64"\n", mp->mnt_stat.f_blocks);
	(*pr)("\tbfree = %"PRIu64"\n", mp->mnt_stat.f_bfree);
	(*pr)("\tbavail = %"PRIu64"\n", mp->mnt_stat.f_bavail);
	(*pr)("\tbresvd = %"PRIu64"\n", mp->mnt_stat.f_bresvd);

	(*pr)("\tfiles = %"PRIu64"\n", mp->mnt_stat.f_files);
	(*pr)("\tffree = %"PRIu64"\n", mp->mnt_stat.f_ffree);
	(*pr)("\tfavail = %"PRIu64"\n", mp->mnt_stat.f_favail);
	(*pr)("\tfresvd = %"PRIu64"\n", mp->mnt_stat.f_fresvd);

	(*pr)("\tf_fsidx = { 0x%"PRIx32", 0x%"PRIx32" }\n",
	    mp->mnt_stat.f_fsidx.__fsid_val[0],
	    mp->mnt_stat.f_fsidx.__fsid_val[1]);

	(*pr)("\towner = %"PRIu32"\n", mp->mnt_stat.f_owner);
	(*pr)("\tnamemax = %lu\n", mp->mnt_stat.f_namemax);

	snprintb(sbuf, sizeof(sbuf), __MNT_FLAG_BITS, mp->mnt_stat.f_flag);

	(*pr)("\tflag = %s\n", sbuf);
	(*pr)("\tsyncwrites = %" PRIu64 "\n", mp->mnt_stat.f_syncwrites);
	(*pr)("\tasyncwrites = %" PRIu64 "\n", mp->mnt_stat.f_asyncwrites);
	(*pr)("\tsyncreads = %" PRIu64 "\n", mp->mnt_stat.f_syncreads);
	(*pr)("\tasyncreads = %" PRIu64 "\n", mp->mnt_stat.f_asyncreads);
	(*pr)("\tfstypename = %s\n", mp->mnt_stat.f_fstypename);
	(*pr)("\tmntonname = %s\n", mp->mnt_stat.f_mntonname);
	(*pr)("\tmntfromname = %s\n", mp->mnt_stat.f_mntfromname);

	{
		int cnt = 0;
		vnode_t *vp;
		vnode_impl_t *vip;
		(*pr)("locked vnodes =");
		TAILQ_FOREACH(vip, &mp->mnt_vnodelist, vi_mntvnodes) {
			vp = VIMPL_TO_VNODE(vip);
			if (VOP_ISLOCKED(vp)) {
				if ((++cnt % 6) == 0) {
					(*pr)(" %p,\n\t", vp);
				} else {
					(*pr)(" %p,", vp);
				}
			}
		}
		(*pr)("\n");
	}

	if (full) {
		int cnt = 0;
		vnode_t *vp;
		vnode_impl_t *vip;

		(*pr)("all vnodes =");
		TAILQ_FOREACH(vip, &mp->mnt_vnodelist, vi_mntvnodes) {
			vp = VIMPL_TO_VNODE(vip);
			if (!TAILQ_NEXT(vip, vi_mntvnodes)) {
				(*pr)(" %p", vp);
			} else if ((++cnt % 6) == 0) {
				(*pr)(" %p,\n\t", vp);
			} else {
				(*pr)(" %p,", vp);
			}
		}
		(*pr)("\n");
	}
}

/*
 * List all of the locked vnodes in the system.
 */
void printlockedvnodes(void);

void
printlockedvnodes(void)
{
	struct mount *mp;
	vnode_t *vp;
	vnode_impl_t *vip;

	printf("Locked vnodes\n");
	for (mp = _mountlist_next(NULL); mp; mp = _mountlist_next(mp)) {
		TAILQ_FOREACH(vip, &mp->mnt_vnodelist, vi_mntvnodes) {
			vp = VIMPL_TO_VNODE(vip);
			if (VOP_ISLOCKED(vp))
				vprint(NULL, vp);
		}
	}
}

#endif /* DDB || DEBUGPRINT */
