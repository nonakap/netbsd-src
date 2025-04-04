/*	$NetBSD: ldc.c,v 1.10 2025/02/06 19:24:37 palle Exp $	*/
/*	$OpenBSD: ldc.c,v 1.12 2015/03/21 18:02:58 kettenis Exp $	*/
/*
 * Copyright (c) 2009 Mark Kettenis
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

#include <sys/kmem.h>
#include <sys/param.h>
#include <sys/systm.h>

#include <sys/bus.h>
#include <machine/hypervisor.h>

#include <uvm/uvm_extern.h>

#include <sparc64/dev/ldcvar.h>

#ifdef LDC_DEBUG
#define DPRINTF(x)	printf x
#else
#define DPRINTF(x)
#endif

void	ldc_rx_ctrl_vers(struct ldc_conn *, struct ldc_pkt *);
void	ldc_rx_ctrl_rtr(struct ldc_conn *, struct ldc_pkt *);
void	ldc_rx_ctrl_rts(struct ldc_conn *, struct ldc_pkt *);
void	ldc_rx_ctrl_rdx(struct ldc_conn *, struct ldc_pkt *);

int	ldc_send_ack(struct ldc_conn *);
int	ldc_send_rtr(struct ldc_conn *);
int	ldc_send_rts(struct ldc_conn *);
int	ldc_send_rdx(struct ldc_conn *);

void
ldc_rx_ctrl(struct ldc_conn *lc, struct ldc_pkt *lp)
{
	switch (lp->ctrl) {
	case LDC_VERS:
		ldc_rx_ctrl_vers(lc, lp);
		break;

	case LDC_RTS:
		ldc_rx_ctrl_rts(lc, lp);
		break;

	case LDC_RTR:
		ldc_rx_ctrl_rtr(lc, lp);
		break;

	case LDC_RDX:
		ldc_rx_ctrl_rdx(lc, lp);
		break;

	default:
		DPRINTF(("CTRL/0x%02x/0x%02x\n", lp->stype, lp->ctrl));
		ldc_reset(lc);
		break;
	}
}

void
ldc_rx_ctrl_vers(struct ldc_conn *lc, struct ldc_pkt *lp)
{
	switch (lp->stype) {
	case LDC_INFO:
		DPRINTF(("CTRL/INFO/VERS major %d minor %d\n", lp->major, lp->minor));
		if (lp->major == LDC_VERSION_MAJOR &&
		    lp->minor == LDC_VERSION_MINOR)
			ldc_send_ack(lc);
		else {
			/* XXX do nothing for now. */
			DPRINTF(("CTRL/INFO/VERS unsupported major/minor\n"));
		}
		break;

	case LDC_ACK:
		DPRINTF(("CTRL/ACK/VERS\n"));
		if (lc->lc_state != LDC_SND_VERS) {
			DPRINTF(("Spurious CTRL/ACK/VERS: state %d major %d minor %d (ignored)\n",
					 lc->lc_state, lp->major, lp->minor));
		}
		else {		
			ldc_send_rts(lc);
		}
		break;

	case LDC_NACK:
		DPRINTF(("CTRL/NACK/VERS\n"));
		ldc_reset(lc);
		break;

	default:
		DPRINTF(("CTRL/0x%02x/VERS\n", lp->stype));
		ldc_reset(lc);
		break;
	}
}

void
ldc_rx_ctrl_rts(struct ldc_conn *lc, struct ldc_pkt *lp)
{
	switch (lp->stype) {
	case LDC_INFO:
		if (lc->lc_state != LDC_RCV_VERS) {
			DPRINTF(("Spurious CTRL/INFO/RTS: state %d\n",
			    lc->lc_state));
			ldc_reset(lc);
			return;
		}
		DPRINTF(("CTRL/INFO/RTS\n"));
		ldc_send_rtr(lc);
		break;

	case LDC_ACK:
		DPRINTF(("CTRL/ACK/RTS\n"));
		ldc_reset(lc);
		break;

	case LDC_NACK:
		DPRINTF(("CTRL/NACK/RTS\n"));
		ldc_reset(lc);
		break;

	default:
		DPRINTF(("CTRL/0x%02x/RTS\n", lp->stype));
		ldc_reset(lc);
		break;
	}
}

void
ldc_rx_ctrl_rtr(struct ldc_conn *lc, struct ldc_pkt *lp)
{
	switch (lp->stype) {
	case LDC_INFO:
		if (lc->lc_state != LDC_SND_RTS) {
			DPRINTF(("Spurious CTRL/INFO/RTR: state %d\n",
			    lc->lc_state));
			ldc_reset(lc);
			return;
		}
		DPRINTF(("CTRL/INFO/RTR\n"));
		ldc_send_rdx(lc);
		lc->lc_start(lc);
		break;

	case LDC_ACK:
		DPRINTF(("CTRL/ACK/RTR\n"));
		ldc_reset(lc);
		break;

	case LDC_NACK:
		DPRINTF(("CTRL/NACK/RTR\n"));
		ldc_reset(lc);
		break;

	default:
		DPRINTF(("CTRL/0x%02x/RTR\n", lp->stype));
		ldc_reset(lc);
		break;
	}
}

void
ldc_rx_ctrl_rdx(struct ldc_conn *lc, struct ldc_pkt *lp)
{
	switch (lp->stype) {
	case LDC_INFO:
		if (lc->lc_state != LDC_SND_RTR) {
			DPRINTF(("Spurious CTRL/INFO/RTR: state %d\n",
			    lc->lc_state));
			ldc_reset(lc);
			return;
		}
		DPRINTF(("CTRL/INFO/RDX\n"));
		lc->lc_start(lc);
		break;

	case LDC_ACK:
		DPRINTF(("CTRL/ACK/RDX\n"));
		ldc_reset(lc);
		break;

	case LDC_NACK:
		DPRINTF(("CTRL/NACK/RDX\n"));
		ldc_reset(lc);
		break;

	default:
		DPRINTF(("CTRL/0x%02x/RDX\n", lp->stype));
		ldc_reset(lc);
		break;
	}
}

void
ldc_rx_data(struct ldc_conn *lc, struct ldc_pkt *lp)
{
	size_t len;

	if (lp->stype != LDC_INFO) {
		DPRINTF(("DATA/0x%02x\n", lp->stype));
		ldc_reset(lc);
		return;
	}

	if (lc->lc_state != LDC_SND_RTR &&
	    lc->lc_state != LDC_SND_RDX) {
		DPRINTF(("Spurious DATA/INFO: state %d\n", lc->lc_state));
		ldc_reset(lc);
		return;
	}

	if (lp->env & LDC_FRAG_START) {
		lc->lc_len = (lp->env & LDC_LEN_MASK) + 8;
		KASSERT(lc->lc_len <= sizeof(lc->lc_msg));
		memcpy((uint8_t *)lc->lc_msg, lp, lc->lc_len);
	} else {
		len = (lp->env & LDC_LEN_MASK);
		if (lc->lc_len + len > sizeof(lc->lc_msg)) {
			DPRINTF(("Buffer overrun\n"));
			ldc_reset(lc);
			return;
		}
		memcpy(((uint8_t *)lc->lc_msg) + lc->lc_len, &lp->major, len);
		lc->lc_len += len;
	}

	if (lp->env & LDC_FRAG_STOP)
		lc->lc_rx_data(lc, (struct ldc_pkt *)lc->lc_msg);
}

int
ldc_send_vers(struct ldc_conn *lc)
{
	struct ldc_pkt *lp;
	uint64_t tx_head, tx_tail, tx_state;
	int err;

	mutex_enter(&lc->lc_txq->lq_mtx);
	err = hv_ldc_tx_get_state(lc->lc_id, &tx_head, &tx_tail, &tx_state);
	if (err != H_EOK || tx_state != LDC_CHANNEL_UP) {
		mutex_exit(&lc->lc_txq->lq_mtx);
		return EIO;
	}

	lp = (struct ldc_pkt *)(uintptr_t)(lc->lc_txq->lq_va + tx_tail);
	bzero(lp, sizeof(struct ldc_pkt));
	lp->type = LDC_CTRL;
	lp->stype = LDC_INFO;
	lp->ctrl = LDC_VERS;
	lp->major = LDC_VERSION_MAJOR;
	lp->minor = LDC_VERSION_MINOR;
	DPRINTF(("ldc_send_vers() major %d minor %d\n", lp->major, lp->minor));

	tx_tail += sizeof(*lp);
	tx_tail &= ((lc->lc_txq->lq_nentries * sizeof(*lp)) - 1);
	err = hv_ldc_tx_set_qtail(lc->lc_id, tx_tail);
	if (err != H_EOK) {
		printf("%s: hv_ldc_tx_set_qtail: %d\n", __func__, err);
		mutex_exit(&lc->lc_txq->lq_mtx);
		return EIO;
	}

	lc->lc_state = LDC_SND_VERS;
	DPRINTF(("ldc_send_vers() setting lc->lc_state to %d\n", lc->lc_state));
	mutex_exit(&lc->lc_txq->lq_mtx);
	return 0;
}

int
ldc_send_ack(struct ldc_conn *lc)
{
	struct ldc_pkt *lp;
	uint64_t tx_head, tx_tail, tx_state;
	int err;

	mutex_enter(&lc->lc_txq->lq_mtx);
	err = hv_ldc_tx_get_state(lc->lc_id, &tx_head, &tx_tail, &tx_state);
	if (err != H_EOK || tx_state != LDC_CHANNEL_UP) {
		mutex_exit(&lc->lc_txq->lq_mtx);
		printf("ldc_send_ack() err %d tx_state %lu\n", err, (long unsigned int)tx_state);
		return EIO;
	}

	lp = (struct ldc_pkt *)(uintptr_t)(lc->lc_txq->lq_va + tx_tail);
	bzero(lp, sizeof(struct ldc_pkt));
	lp->type = LDC_CTRL;
	lp->stype = LDC_ACK;
	lp->ctrl = LDC_VERS;
	lp->major = 1;
	lp->minor = 0;

	tx_tail += sizeof(*lp);
	tx_tail &= ((lc->lc_txq->lq_nentries * sizeof(*lp)) - 1);
	err = hv_ldc_tx_set_qtail(lc->lc_id, tx_tail);
	if (err != H_EOK) {
		printf("%s: hv_ldc_tx_set_qtail: %d\n", __func__, err);
		mutex_exit(&lc->lc_txq->lq_mtx);
		return EIO;
	}

	lc->lc_state = LDC_RCV_VERS;
	DPRINTF(("ldc_send_ack() setting lc->lc_state to %d\n", lc->lc_state));
	mutex_exit(&lc->lc_txq->lq_mtx);
	return 0;
}

int
ldc_send_rts(struct ldc_conn *lc)
{
	struct ldc_pkt *lp;
	uint64_t tx_head, tx_tail, tx_state;
	int err;

	mutex_enter(&lc->lc_txq->lq_mtx);
	err = hv_ldc_tx_get_state(lc->lc_id, &tx_head, &tx_tail, &tx_state);
	if (err != H_EOK || tx_state != LDC_CHANNEL_UP) {
		mutex_exit(&lc->lc_txq->lq_mtx);
		printf("ldc_send_rts() err %d tx_state %lu\n", err, (long unsigned int)tx_state);
		return EIO;
	}

	lp = (struct ldc_pkt *)(uintptr_t)(lc->lc_txq->lq_va + tx_tail);
	bzero(lp, sizeof(struct ldc_pkt));
	lp->type = LDC_CTRL;
	lp->stype = LDC_INFO;
	lp->ctrl = LDC_RTS;
	lp->env = LDC_MODE_UNRELIABLE;
	lp->seqid = lc->lc_tx_seqid++;

	tx_tail += sizeof(*lp);
	tx_tail &= ((lc->lc_txq->lq_nentries * sizeof(*lp)) - 1);
	err = hv_ldc_tx_set_qtail(lc->lc_id, tx_tail);
	if (err != H_EOK) {
		printf("%s: hv_ldc_tx_set_qtail: %d\n", __func__, err);
		mutex_exit(&lc->lc_txq->lq_mtx);
		return EIO;
	}

	lc->lc_state = LDC_SND_RTS;
	DPRINTF(("ldc_send_rts() setting lc->lc_state to %d\n", lc->lc_state));
	mutex_exit(&lc->lc_txq->lq_mtx);
	return 0;
}

int
ldc_send_rtr(struct ldc_conn *lc)
{
	struct ldc_pkt *lp;
	uint64_t tx_head, tx_tail, tx_state;
	int err;

	mutex_enter(&lc->lc_txq->lq_mtx);
	err = hv_ldc_tx_get_state(lc->lc_id, &tx_head, &tx_tail, &tx_state);
	if (err != H_EOK || tx_state != LDC_CHANNEL_UP) {
		mutex_exit(&lc->lc_txq->lq_mtx);
		printf("ldc_send_rtr() err %d state %lu\n", err, (long unsigned int)tx_state);
		return EIO;
	}

	lp = (struct ldc_pkt *)(uintptr_t)(lc->lc_txq->lq_va + tx_tail);
	bzero(lp, sizeof(struct ldc_pkt));
	lp->type = LDC_CTRL;
	lp->stype = LDC_INFO;
	lp->ctrl = LDC_RTR;
	lp->env = LDC_MODE_UNRELIABLE;
	lp->seqid = lc->lc_tx_seqid++;

	tx_tail += sizeof(*lp);
	tx_tail &= ((lc->lc_txq->lq_nentries * sizeof(*lp)) - 1);
	err = hv_ldc_tx_set_qtail(lc->lc_id, tx_tail);
	if (err != H_EOK) {
		printf("%s: hv_ldc_tx_set_qtail: %d\n", __func__, err);
		mutex_exit(&lc->lc_txq->lq_mtx);
		return EIO;
	}

	lc->lc_state = LDC_SND_RTR;
	DPRINTF(("ldc_send_rtr() setting lc->lc_state to %d\n", lc->lc_state));
	mutex_exit(&lc->lc_txq->lq_mtx);
	return 0;
}

int
ldc_send_rdx(struct ldc_conn *lc)
{
	struct ldc_pkt *lp;
	uint64_t tx_head, tx_tail, tx_state;
	int err;

	mutex_enter(&lc->lc_txq->lq_mtx);
	err = hv_ldc_tx_get_state(lc->lc_id, &tx_head, &tx_tail, &tx_state);
	if (err != H_EOK || tx_state != LDC_CHANNEL_UP) {
		mutex_exit(&lc->lc_txq->lq_mtx);
		printf("ldc_send_rdx() err %d state %lu\n", err, (long unsigned int)tx_state);
		return EIO;
	}

	lp = (struct ldc_pkt *)(uintptr_t)(lc->lc_txq->lq_va + tx_tail);
	bzero(lp, sizeof(struct ldc_pkt));
	lp->type = LDC_CTRL;
	lp->stype = LDC_INFO;
	lp->ctrl = LDC_RDX;
	lp->env = LDC_MODE_UNRELIABLE;
	lp->seqid = lc->lc_tx_seqid++;

	tx_tail += sizeof(*lp);
	tx_tail &= ((lc->lc_txq->lq_nentries * sizeof(*lp)) - 1);
	err = hv_ldc_tx_set_qtail(lc->lc_id, tx_tail);
	if (err != H_EOK) {
		printf("%s: hv_ldc_tx_set_qtail: %d\n", __func__, err);
		mutex_exit(&lc->lc_txq->lq_mtx);
		return EIO;
	}

	lc->lc_state = LDC_SND_RDX;
	DPRINTF(("ldc_send_rdx() setting lc->lc_state to %d\n", lc->lc_state));
	mutex_exit(&lc->lc_txq->lq_mtx);
	return 0;
}

int
ldc_send_unreliable(struct ldc_conn *lc, void *msg, size_t len)
{
	struct ldc_pkt *lp;
	uint64_t tx_head, tx_tail, tx_state;
	uint64_t tx_avail;
	uint8_t *p = msg;
	int err;

	mutex_enter(&lc->lc_txq->lq_mtx);
	err = hv_ldc_tx_get_state(lc->lc_id, &tx_head, &tx_tail, &tx_state);
	if (err != H_EOK || tx_state != LDC_CHANNEL_UP) {
		mutex_exit(&lc->lc_txq->lq_mtx);
		printf("ldc_send_unrealiable() err %d state %lu\n", err, (long unsigned int)tx_state);
		return (EIO);
	}

	tx_avail = (tx_head - tx_tail) / sizeof(*lp) +
	    lc->lc_txq->lq_nentries - 1;
	tx_avail %= lc->lc_txq->lq_nentries;
	if (len > tx_avail * LDC_PKT_PAYLOAD) {
		mutex_exit(&lc->lc_txq->lq_mtx);
		return (EWOULDBLOCK);
	}

	while (len > 0) {
		lp = (struct ldc_pkt *)(uintptr_t)(lc->lc_txq->lq_va + tx_tail);
		bzero(lp, sizeof(struct ldc_pkt));
		lp->type = LDC_DATA;
		lp->stype = LDC_INFO;
		lp->env = uimin(len, LDC_PKT_PAYLOAD);
		if (p == msg)
			lp->env |= LDC_FRAG_START;
		if (len <= LDC_PKT_PAYLOAD)
			lp->env |= LDC_FRAG_STOP;
		lp->seqid = lc->lc_tx_seqid++;
		bcopy(p, &lp->major, uimin(len, LDC_PKT_PAYLOAD));

		tx_tail += sizeof(*lp);
		tx_tail &= ((lc->lc_txq->lq_nentries * sizeof(*lp)) - 1);
		err = hv_ldc_tx_set_qtail(lc->lc_id, tx_tail);
		if (err != H_EOK) {
			printf("%s: hv_ldc_tx_set_qtail: %d\n", __func__, err);
			mutex_exit(&lc->lc_txq->lq_mtx);
			return (EIO);
		}
		p += uimin(len, LDC_PKT_PAYLOAD);
		len -= uimin(len, LDC_PKT_PAYLOAD);
	}

	mutex_exit(&lc->lc_txq->lq_mtx);
	return (0);
}

void
ldc_reset(struct ldc_conn *lc)
{
	int err;
	vaddr_t va;
	paddr_t pa;

	DPRINTF(("Resetting connection\n"));

	mutex_enter(&lc->lc_txq->lq_mtx);

#if OPENBSD_BUSDMA
	err = hv_ldc_tx_qconf(lc->lc_id,
	    lc->lc_txq->lq_map->dm_segs[0].ds_addr, lc->lc_txq->lq_nentries);
#else
        va = lc->lc_txq->lq_va;
	pa = 0;
	if (pmap_extract(pmap_kernel(), va, &pa) == FALSE)
	  panic("pmap_extract failed %lx\n", va);
	err = hv_ldc_tx_qconf(lc->lc_id, pa, lc->lc_txq->lq_nentries);
#endif
	if (err != H_EOK)
		printf("%s: hv_ldc_tx_qconf %d\n", __func__, err);

#if OPENBSD_BUSDMA
	err = hv_ldc_rx_qconf(lc->lc_id,
	    lc->lc_rxq->lq_map->dm_segs[0].ds_addr, lc->lc_rxq->lq_nentries);
#else
        va = lc->lc_rxq->lq_va;
	pa = 0;
	if (pmap_extract(pmap_kernel(), va, &pa) == FALSE)
	  panic("pmap_extract failed %lx\n", va);
	err = hv_ldc_tx_qconf(lc->lc_id, pa, lc->lc_rxq->lq_nentries);
#endif
	if (err != H_EOK)
		printf("%s: hv_ldc_rx_qconf %d\n", __func__, err);

	lc->lc_tx_seqid = 0;
	lc->lc_state = 0;
	lc->lc_tx_state = lc->lc_rx_state = LDC_CHANNEL_DOWN;
	mutex_exit(&lc->lc_txq->lq_mtx);

	lc->lc_reset(lc);
}
#if OPENBSD_BUSDMA
struct ldc_queue *
ldc_queue_alloc(bus_dma_tag_t t, int nentries)
#else
struct ldc_queue *
ldc_queue_alloc(int nentries)
#endif
{
	struct ldc_queue *lq;
	bus_size_t size;
	vaddr_t va = 0;
#if OPENBSD_BUSDMA
	int nsegs;
#endif

	lq = kmem_zalloc(sizeof(struct ldc_queue), KM_SLEEP);

	mutex_init(&lq->lq_mtx, MUTEX_DEFAULT, IPL_TTY);

	size = roundup(nentries * sizeof(struct ldc_pkt), PAGE_SIZE);
#if OPENBSD_BUSDMA
	if (bus_dmamap_create(t, size, 1, size, 0,
	    BUS_DMA_NOWAIT | BUS_DMA_ALLOCNOW, &lq->lq_map) != 0)
		return (NULL);

	if (bus_dmamem_alloc(t, size, PAGE_SIZE, 0, &lq->lq_seg, 1,
	    &nsegs, BUS_DMA_NOWAIT) != 0)
		goto destroy;

	if (bus_dmamem_map(t, &lq->lq_seg, 1, size, (void *)&va,
	    BUS_DMA_NOWAIT) != 0)
		goto free;

	 if (bus_dmamap_load(t, lq->lq_map, (void*)va, size, NULL,
	    BUS_DMA_NOWAIT) != 0)
		goto unmap;
#else
	va = (vaddr_t)kmem_zalloc(size, KM_SLEEP);
#endif
	lq->lq_va = (vaddr_t)va;
	lq->lq_nentries = nentries;
	return (lq);
#if OPENBSD_BUSDMA
unmap:
	bus_dmamem_unmap(t, (void*)va, size);
free:
	bus_dmamem_free(t, &lq->lq_seg, 1);
destroy:
	bus_dmamap_destroy(t, lq->lq_map);
#endif
	return (NULL);
}

void
#if OPENBSD_BUSDMA
ldc_queue_free(bus_dma_tag_t t, struct ldc_queue *lq)
#else
ldc_queue_free(struct ldc_queue *lq)
#endif
{
	bus_size_t size;

	size = roundup(lq->lq_nentries * sizeof(struct ldc_pkt), PAGE_SIZE);

#if OPENBSD_BUSDMA
	bus_dmamap_unload(t, lq->lq_map);
	bus_dmamem_unmap(t, &lq->lq_va, size);
	bus_dmamem_free(t, &lq->lq_seg, 1);
	bus_dmamap_destroy(t, lq->lq_map);
#else
	kmem_free((void *)lq->lq_va, size);
#endif
	kmem_free(lq, size);
}

#if OPENBSD_BUSDMA
struct ldc_map *
ldc_map_alloc(bus_dma_tag_t t, int nentries)
#else
struct ldc_map *
ldc_map_alloc(int nentries)
#endif
{
	struct ldc_map *lm;
	bus_size_t size;
	vaddr_t va = 0;

#if OPENBSD_BUSDMA
	int nsegs;
#endif
	lm = kmem_zalloc(sizeof(struct ldc_map), KM_SLEEP);
	size = roundup(nentries * sizeof(struct ldc_map_slot), PAGE_SIZE);

#if OPENBSD_BUSDMA
	if (bus_dmamap_create(t, size, 1, size, 0,
			      BUS_DMA_NOWAIT | BUS_DMA_ALLOCNOW, &lm->lm_map) != 0) {
		DPRINTF(("ldc_map_alloc() - bus_dmamap_create() failed\n"));
		return (NULL);
	}

	if (bus_dmamem_alloc(t, size, PAGE_SIZE, 0, &lm->lm_seg, 1,
			     &nsegs, BUS_DMA_NOWAIT) != 0) {
		DPRINTF(("ldc_map_alloc() - bus_dmamem_alloc() failed\n"));
		goto destroy;
	}

	if (bus_dmamem_map(t, &lm->lm_seg, 1, size, (void *)&va,
			   BUS_DMA_NOWAIT) != 0) {
		DPRINTF(("ldc_map_alloc() - bus_dmamem_map() failed\n"));
		goto free;
	}
	if (bus_dmamap_load(t, lm->lm_map, (void*)va, size, NULL,
			    BUS_DMA_NOWAIT) != 0) {
		DPRINTF(("ldc_map_alloc() - bus_dmamap_load() failed\n"));
		goto unmap;
	}
#else
	va = (vaddr_t)kmem_zalloc(size, KM_SLEEP);
#endif
	lm->lm_slot = (struct ldc_map_slot *)va;
	lm->lm_nentries = nentries;
	bzero(lm->lm_slot, nentries * sizeof(struct ldc_map_slot));
	return (lm);

#if OPENBSD_BUSDMA
unmap:
	bus_dmamem_unmap(t, (void*)va, size);
free:
	bus_dmamem_free(t, &lm->lm_seg, 1);
destroy:
	bus_dmamap_destroy(t, lm->lm_map);
#endif
	return (NULL);
}

#if OPENBSD_BUSDMA
void
ldc_map_free(bus_dma_tag_t t, struct ldc_map *lm)
#else
void
ldc_map_free(struct ldc_map *lm)
#endif
{
	bus_size_t size;

	size = lm->lm_nentries * sizeof(struct ldc_map_slot);
	size = roundup(size, PAGE_SIZE);

#if OPENBSD_BUSDMA
	bus_dmamap_unload(t, lm->lm_map);
	bus_dmamem_unmap(t, lm->lm_slot, size);
	bus_dmamem_free(t, &lm->lm_seg, 1);
	bus_dmamap_destroy(t, lm->lm_map);
#else
	kmem_free(lm->lm_slot, size);
#endif
	kmem_free(lm, size);
}
