/*	$NetBSD: bwivar.h,v 1.11 2025/01/19 00:29:28 jmcneill Exp $	*/
/*	$OpenBSD: bwivar.h,v 1.23 2008/02/25 20:36:54 mglocker Exp $	*/

/*
 * Copyright (c) 2007 The DragonFly Project.  All rights reserved.
 * 
 * This code is derived from software contributed to The DragonFly Project
 * by Sepherosa Ziehau <sepherosa@gmail.com>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * $DragonFly: src/sys/dev/netif/bwi/if_bwivar.h,v 1.1 2007/09/08 06:15:54 sephe Exp $
 */

#ifndef _DEV_IC_BWIVAR_H
#define _DEV_IC_BWIVAR_H

#define BWI_ALIGN		0x1000
#define BWI_RING_ALIGN		BWI_ALIGN
#define BWI_BUS_SPACE_MAXADDR	0x3fffffff

#define BWI_TX_NRING		6
#define BWI_TXRX_NRING		6
#define BWI_TX_NDESC		128
#define BWI_RX_NDESC		64
#define BWI_TXSTATS_NDESC	64
#define BWI_TX_NSPRDESC		2
#define BWI_TX_DATA_RING	1

/* XXX Onoe/Sample/AMRR probably need different configuration */
#define BWI_SHRETRY		7
#define BWI_LGRETRY		4
#define BWI_SHRETRY_FB		3
#define BWI_LGRETRY_FB		2

#define BWI_LED_EVENT_NONE	-1
#define BWI_LED_EVENT_POLL	0
#define BWI_LED_EVENT_TX	1
#define BWI_LED_EVENT_RX	2
#define BWI_LED_SLOWDOWN(dur)	(dur) = (((dur) * 3) / 2)

enum bwi_txpwrcb_type {
	BWI_TXPWR_INIT = 0,
	BWI_TXPWR_FORCE = 1,
	BWI_TXPWR_CALIB = 2
};

#define BWI_NOISE_FLOOR		-95	/* TODO: noise floor calc */

/* [TRC: Bizarreness.  Cf. bwi_rxeof in OpenBSD's if_bwi.c and
   DragonFlyBSD's bwi.c.] */
#define BWI_FRAME_MIN_LEN(hdr)	\
	((hdr) + sizeof(struct ieee80211_frame_ack) + IEEE80211_CRC_LEN)

#define CSR_READ_4(sc, reg)			\
	_bwi_read_4(sc, reg)
#define CSR_READ_2(sc, reg)			\
	_bwi_read_2(sc, reg)
#define CSR_READ_MULTI_4(sc, reg, datap, count)	\
	_bwi_read_multi_4(sc, reg, datap, count)

#define CSR_WRITE_4(sc, reg, val)		\
	_bwi_write_4(sc, reg, val)
#define CSR_WRITE_2(sc, reg, val)		\
	_bwi_write_2(sc, reg, val)
#define CSR_WRITE_MULTI_4(sc, reg, datap, count) \
	_bwi_write_multi_4(sc, reg, datap, count)

#define CSR_SETBITS_4(sc, reg, bits)		\
	CSR_WRITE_4((sc), (reg), CSR_READ_4((sc), (reg)) | (bits))
#define CSR_SETBITS_2(sc, reg, bits)		\
	CSR_WRITE_2((sc), (reg), CSR_READ_2((sc), (reg)) | (bits))

#define CSR_FILT_SETBITS_4(sc, reg, filt, bits) \
	CSR_WRITE_4((sc), (reg), (CSR_READ_4((sc), (reg)) & (filt)) | (bits))
#define CSR_FILT_SETBITS_2(sc, reg, filt, bits)	\
	CSR_WRITE_2((sc), (reg), (CSR_READ_2((sc), (reg)) & (filt)) | (bits))

#define CSR_CLRBITS_4(sc, reg, bits)		\
	CSR_WRITE_4((sc), (reg), CSR_READ_4((sc), (reg)) & ~(bits))
#define CSR_CLRBITS_2(sc, reg, bits)		\
	CSR_WRITE_2((sc), (reg), CSR_READ_2((sc), (reg)) & ~(bits))

struct pool_cache;
struct workqueue;

struct bwi_desc32 {
	/* Little endian */
	uint32_t	ctrl;
	uint32_t	addr;	/* BWI_DESC32_A_ */
} __packed;

#define BWI_DESC32_A_FUNC_TXRX		0x1
#define BWI_DESC32_A_FUNC_MASK		0xc0000000
#define BWI_DESC32_A_ADDR_MASK		0x3fffffff

#define BWI_DESC32_C_BUFLEN_MASK	0x00001fff
#define BWI_DESC32_C_ADDRHI_MASK	0x00030000
#define BWI_DESC32_C_EOR		(1 << 28)
#define BWI_DESC32_C_INTR		(1 << 29)
#define BWI_DESC32_C_FRAME_END		(1 << 30)
#define BWI_DESC32_C_FRAME_START	(1 << 31)

struct bwi_desc64 {
	/* Little endian */
	uint32_t	ctrl0;
	uint32_t	ctrl1;
	uint32_t	addr_lo;
	uint32_t	addr_hi;
} __packed;

struct bwi_rxbuf_hdr {
	/* Little endian */
	uint16_t	rxh_buflen;	/* exclude bwi_rxbuf_hdr */
	uint8_t		rxh_pad1[2];
	uint16_t	rxh_flags1;
	uint8_t		rxh_rssi;
	uint8_t		rxh_sq;
	uint16_t	rxh_phyinfo;	/* BWI_RXH_PHYINFO_ */
	uint16_t	rxh_flags3;
	uint16_t	rxh_flags2;	/* BWI_RXH_F2_ */
	uint16_t	rxh_tsf;
	uint8_t		rxh_pad3[14];	/* Padded to 30bytes */
} __packed;

#define BWI_RXH_F1_BCM2053_RSSI (1 << 14)
#define BWI_RXH_F1_OFDM		(1 << 0)

#define BWI_RXH_F2_TYPE2FRAME	(1 << 2)
#define BWI_RXH_F2_INVALID	(1 << 0)

#define BWI_RXH_F3_BCM2050_RSSI	(1 << 10)

#define BWI_RXH_PHYINFO_LNAGAIN	(3 << 14)

struct bwi_txbuf_hdr {
	/* Little endian */
	uint32_t	txh_mac_ctrl;	/* BWI_TXH_MAC_C_ */
	uint8_t		txh_fc[2];
	uint16_t	txh_unknown1;
	uint16_t	txh_phy_ctrl;	/* BWI_TXH_PHY_C_ */
	uint8_t		txh_ivs[16];
	uint8_t		txh_addr1[IEEE80211_ADDR_LEN];
	uint16_t	txh_unknown2;
	uint8_t		txh_rts_fb_plcp[4];
	uint16_t	txh_rts_fb_duration;
	uint8_t		txh_fb_plcp[4];
	uint16_t	txh_fb_duration;
	uint8_t		txh_pad2[2];
	uint16_t	txh_id;		/* BWI_TXH_ID_ */
	uint16_t	txh_unknown3;
	uint8_t		txh_rts_plcp[6];
	uint8_t		txh_rts_fc[2];
	uint16_t	txh_rts_duration;
	uint8_t		txh_rts_ra[IEEE80211_ADDR_LEN];
	uint8_t		txh_rts_ta[IEEE80211_ADDR_LEN];
	uint8_t		txh_pad3[2];
	uint8_t		txh_plcp[6];
} __packed;

#define BWI_TXH_ID_RING_MASK		0xe000
#define BWI_TXH_ID_IDX_MASK		0x1fff

#define BWI_TXH_PHY_C_OFDM		(1 << 0)
#define BWI_TXH_PHY_C_SHPREAMBLE	(1 << 4)
#define BWI_TXH_PHY_C_ANTMODE_MASK	0x0300

#define BWI_TXH_MAC_C_ACK		(1 << 0)
#define BWI_TXH_MAC_C_FIRST_FRAG	(1 << 3)
#define BWI_TXH_MAC_C_HWSEQ		(1 << 4)
#define BWI_TXH_MAC_C_FB_OFDM		(1 << 8)

struct bwi_txstats {
	/* Little endian */
	uint8_t		txs_pad1[4];
	uint16_t	txs_id;
	uint8_t		txs_flags;
	uint8_t		txs_retry_cnt;
	uint8_t		txs_pad2[2];
	uint16_t	txs_seq;
	uint16_t	txs_unknown;
	uint8_t		txs_pad3[2];	/* Padded to 16bytes */
} __packed;

struct bwi_ring_data {
	uint32_t		 rdata_txrx_ctrl;
	bus_dma_segment_t	 rdata_seg;
	bus_dmamap_t		 rdata_dmap;
	bus_addr_t		 rdata_paddr;
	void			*rdata_desc;
};

struct bwi_txbuf_data;

struct bwi_txbuf {
	struct mbuf		*tb_mbuf;
	bus_dmamap_t		 tb_dmap;

	struct ieee80211_node	*tb_ni;
	int			 tb_rate_idx[2];

	struct bwi_txbuf_data	*tb_data;
	STAILQ_ENTRY(bwi_txbuf)	 tb_entry;
};

struct bwi_txbuf_data {
	struct bwi_txbuf	tbd_buf[BWI_TX_NDESC];
	int			tbd_used;
	int			tbd_idx;
};

struct bwi_rxbuf {
	struct mbuf		*rb_mbuf;
	bus_addr_t		 rb_paddr;
	bus_dmamap_t		 rb_dmap;
};

struct bwi_rxbuf_data {
	struct bwi_rxbuf	rbd_buf[BWI_RX_NDESC];
	bus_dmamap_t		rbd_tmp_dmap;
	int			rbd_idx;
};

struct bwi_txstats_data {
	bus_dma_segment_t	 stats_ring_seg;
	bus_dmamap_t		 stats_ring_dmap;
	bus_addr_t		 stats_ring_paddr;
	void			*stats_ring;

	bus_dma_segment_t	 stats_seg;
	bus_dmamap_t		 stats_dmap;
	bus_addr_t		 stats_paddr;
	struct bwi_txstats	*stats;

	uint32_t		 stats_ctrl_base;
	int			 stats_idx;
};

struct bwi_fwhdr {
	/* Big endian */
	uint8_t		fw_type;	/* BWI_FW_T_ */
	uint8_t		fw_gen;		/* BWI_FW_GEN */
	uint8_t		fw_pad[2];
	uint32_t	fw_size;
#define fw_iv_cnt	fw_size
} __packed;

#define BWI_FWHDR_SZ		sizeof(struct bwi_fwhdr)
#define BWI_FW_VERSION3		3
#define BWI_FW_VERSION4		4
#define BWI_FW_VERSION3_REVMAX	0x128
#define BWI_FW_T_UCODE          'u'
#define BWI_FW_T_PCM            'p'
#define BWI_FW_T_IV             'i'
#define BWI_FW_GEN_1            1
#define BWI_FW_IV_OFS_MASK	0x7fff
#define BWI_FW_IV_IS_32BIT	(1 << 15)

#define BWI_FW_NAME_FORMAT	"v%d/%s%d.fw"
#define BWI_FW_UCODE_PREFIX	"ucode"
#define BWI_FW_PCM_PREFIX	"pcm"
#define BWI_FW_IV_PREFIX	"b0g0initvals"
#define BWI_FW_IV_EXT_PREFIX	"b0g0bsinitvals"

struct bwi_fw_image {
	char	 fwi_name[64];
	uint8_t	*fwi_data;
	size_t	 fwi_size;
};

struct bwi_fw_iv {
	/* Big endian */
	uint16_t		iv_ofs;
	union {
		uint32_t	val32;
		uint16_t	val16;
	}			iv_val;
} __packed;

struct bwi_led {
	uint8_t			l_flags;	/* BWI_LED_F_ */
	uint8_t			l_act;		/* BWI_LED_ACT_ */
	uint8_t			l_mask;
};

#define BWI_LED_F_ACTLOW	0x1
#define BWI_LED_F_BLINK		0x2
#define BWI_LED_F_POLLABLE	0x4
#define BWI_LED_F_SLOW		0x8

enum bwi_clock_mode {
	BWI_CLOCK_MODE_SLOW,
	BWI_CLOCK_MODE_FAST,
	BWI_CLOCK_MODE_DYN
};

struct bwi_regwin {
	uint32_t		rw_flags;	/* BWI_REGWIN_F_ */
	uint16_t		rw_type;	/* BWI_REGWIN_T_ */
	uint8_t			rw_id;
	uint8_t			rw_rev;
};

#define BWI_REGWIN_F_EXIST	0x1

#define BWI_CREATE_REGWIN(rw, id, type, rev)	\
do {						\
	(rw)->rw_flags = BWI_REGWIN_F_EXIST;	\
	(rw)->rw_type = (type);			\
	(rw)->rw_id = (id);			\
	(rw)->rw_rev = (rev);			\
} while (0)

#define BWI_REGWIN_EXIST(rw)	((rw)->rw_flags & BWI_REGWIN_F_EXIST)
#define BWI_GPIO_REGWIN(sc)				\
	(BWI_REGWIN_EXIST(&(sc)->sc_com_regwin) ?	\
	&(sc)->sc_com_regwin : &(sc)->sc_bus_regwin)

struct bwi_mac;

struct bwi_phy {
	enum ieee80211_phymode	phy_mode;
	int			phy_rev;
	int			phy_version;

	uint32_t		phy_flags;		/* BWI_PHY_F_ */
	uint16_t		phy_tbl_ctrl;
	uint16_t		phy_tbl_data_lo;
	uint16_t		phy_tbl_data_hi;

	void			(*phy_init)(struct bwi_mac *);
};

#define BWI_PHY_F_CALIBRATED	0x1
#define BWI_PHY_F_LINKED	0x2
#define BWI_CLEAR_PHY_FLAGS	(BWI_PHY_F_CALIBRATED)

/* TX power control */
struct bwi_tpctl {
	uint16_t		bbp_atten;	/* BBP attenuation: 4bits */
	uint16_t		rf_atten;	/* RF attenuation */
	uint16_t		tp_ctrl1;	/* ??: 3bits */
	uint16_t		tp_ctrl2;	/* ??: 4bits */
};

#define BWI_RF_ATTEN_FACTOR	4
#define BWI_RF_ATTEN_MAX0	9
#define BWI_RF_ATTEN_MAX1	31
#define BWI_BBP_ATTEN_MAX	11
#define BWI_TPCTL1_MAX		7

struct bwi_rf_lo {
	int8_t			ctrl_lo;
	int8_t			ctrl_hi;
};

struct bwi_rf {
	uint16_t		rf_type;	/* BWI_RF_T_ */
	uint16_t		rf_manu;
	int			rf_rev;

	uint32_t		rf_flags;	/* BWI_RF_F_ */

#define BWI_RFLO_MAX		56
	struct bwi_rf_lo	rf_lo[BWI_RFLO_MAX];
	uint8_t			rf_lo_used[8];

#define BWI_INVALID_NRSSI	-1000
	int16_t			rf_nrssi[2];	/* Narrow RSSI */
	int32_t			rf_nrssi_slope;

#define BWI_NRSSI_TBLSZ		64
	int8_t			rf_nrssi_table[BWI_NRSSI_TBLSZ];

	uint16_t		rf_lo_gain;	/* loopback gain */
	uint16_t		rf_rx_gain;	/* TRSW RX gain */

	uint16_t		rf_calib;	/* RF calibration value */
	uint			rf_curchan;	/* current channel */

	uint16_t		rf_ctrl_rd;
	int			rf_ctrl_adj;
	void			(*rf_off)(struct bwi_mac *);
	void			(*rf_on)(struct bwi_mac *);

	void			(*rf_set_nrssi_thr)(struct bwi_mac *);
	void			(*rf_calc_nrssi_slope)(struct bwi_mac *);
	int			(*rf_calc_rssi)
				(struct bwi_mac *,
				 const struct bwi_rxbuf_hdr *);

	void			(*rf_lo_update)(struct bwi_mac *);

#define BWI_TSSI_MAX		64
	int8_t			rf_txpower_map0[BWI_TSSI_MAX];
						/* Indexed by TSSI */
	int			rf_idle_tssi0;

	int8_t			rf_txpower_map[BWI_TSSI_MAX];
	int			rf_idle_tssi;

	int			rf_base_tssi;

	int			rf_txpower_max;	/* dBm */

	int			rf_ant_mode;	/* BWI_ANT_MODE_ */
};

#define BWI_RF_F_INITED		0x1
#define BWI_RF_F_ON		0x2
#define BWI_RF_CLEAR_FLAGS	(BWI_RF_F_INITED)

#define BWI_ANT_MODE_0		0
#define BWI_ANT_MODE_1		1
#define BWI_ANT_MODE_UNKN	2
#define BWI_ANT_MODE_AUTO	3

struct fw_image;

struct bwi_mac {
	struct bwi_regwin	 mac_regwin;	/* MUST be first field */
#define mac_rw_flags		 mac_regwin.rw_flags
#define mac_type		 mac_regwin.rw_type
#define mac_id			 mac_regwin.rw_id
#define mac_rev			 mac_regwin.rw_rev
	struct bwi_softc	*mac_sc;

	struct bwi_phy		 mac_phy;	/* PHY I/F */
	struct bwi_rf		 mac_rf;	/* RF I/F */

	struct bwi_tpctl	 mac_tpctl;	/* TX power control */
	uint32_t		 mac_flags;	/* BWI_MAC_F_ */

	struct bwi_fw_image	 mac_ucode_fwi;
	struct bwi_fw_image	 mac_pcm_fwi;
	struct bwi_fw_image	 mac_iv_fwi;
	struct bwi_fw_image	 mac_iv_ext_fwi;
};

#define mac_ucode mac_ucode_fwi.fwi_data
#define mac_ucode_size mac_ucode_fwi.fwi_size
#define mac_pcm mac_pcm_fwi.fwi_data
#define mac_pcm_size mac_pcm_fwi.fwi_size
#define mac_iv mac_iv_fwi.fwi_data
#define mac_iv_size mac_iv_fwi.fwi_size
#define mac_iv_ext mac_iv_ext_fwi.fwi_data
#define mac_iv_ext_size mac_iv_ext_fwi.fwi_size

#define BWI_MAC_F_BSWAP		0x1
#define BWI_MAC_F_TPCTL_INITED	0x2
#define BWI_MAC_F_HAS_TXSTATS	0x4
#define BWI_MAC_F_INITED	0x8
#define BWI_MAC_F_ENABLED	0x10
#define BWI_MAC_F_LOCKED	0x20	/* for debug */
#define BWI_MAC_F_TPCTL_ERROR	0x40
#define BWI_MAC_F_PHYE_RESET	0x80

#define BWI_CREATE_MAC(mac, sc, id, rev)	\
do {						\
	BWI_CREATE_REGWIN(&(mac)->mac_regwin,	\
	    (id), BWI_REGWIN_T_MAC, (rev));	\
	(mac)->mac_sc = (sc);			\
} while (0)

#define BWI_MAC_MAX		2
#define BWI_LED_MAX		4

enum bwi_bus_space {
	BWI_BUS_SPACE_30BIT = 1,
	BWI_BUS_SPACE_32BIT,
	BWI_BUS_SPACE_64BIT
};

#define BWI_TX_RADIOTAP_PRESENT 		\
	((1 << IEEE80211_RADIOTAP_FLAGS) |	\
	 (1 << IEEE80211_RADIOTAP_RATE) |	\
	 (1 << IEEE80211_RADIOTAP_CHANNEL))

struct bwi_tx_radiotap_hdr {
	struct ieee80211_radiotap_header wt_ihdr;
	uint8_t		wt_flags;
	uint8_t		wt_rate;
	uint16_t	wt_chan_freq;
	uint16_t	wt_chan_flags;
};

#define BWI_RX_RADIOTAP_PRESENT				\
	((1 << IEEE80211_RADIOTAP_TSFT) |		\
	 (1 << IEEE80211_RADIOTAP_FLAGS) |		\
	 (1 << IEEE80211_RADIOTAP_RATE) |		\
	 (1 << IEEE80211_RADIOTAP_CHANNEL) |		\
	 (1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL) |	\
	 (1 << IEEE80211_RADIOTAP_DBM_ANTNOISE))

struct bwi_rx_radiotap_hdr {
	struct ieee80211_radiotap_header wr_ihdr;
	uint64_t	wr_tsf;
	uint8_t		wr_flags;
	uint8_t		wr_rate;
	uint16_t	wr_chan_freq;
	uint16_t	wr_chan_flags;
	int8_t		wr_antsignal;
	int8_t		wr_antnoise;
	/* TODO: sq */
};

/* [TRC: XXX amrr] */
struct bwi_node {
	struct ieee80211_node		ni;
	struct ieee80211_amrr_node	amn;
};

enum bwi_task_cmd {
	BWI_TASK_NEWSTATE,
	BWI_TASK_UPDATESLOT,
	BWI_TASK_TX,
	BWI_TASK_INIT,
	BWI_TASK_CALIBRATE,
};

#define BWI_TASK_COUNT		64

struct bwi_task {
	struct work		 t_work;
	struct ieee80211com	*t_ic;
	enum bwi_task_cmd	 t_cmd;
	union {
		struct {
			enum ieee80211_state state;
			int	 arg;
		} t_newstate;
	};
};

struct bwi_softc {
	device_t		 sc_dev;
	struct ethercom		 sc_ec;
	struct ieee80211com	 sc_ic;
#define sc_if sc_ec.ec_if
	uint32_t		 sc_flags;	/* BWI_F_ */
	void			*sc_ih;		/* [TRC: interrupt handler] */
	void			*sc_soft_ih;

	uint32_t		 sc_cap;	/* BWI_CAP_ */
	uint16_t		 sc_bbp_id;	/* BWI_BBPID_ */
	uint8_t			 sc_bbp_rev;
	uint8_t			 sc_bbp_pkg;

	uint8_t			 sc_pci_revid;
	uint16_t		 sc_pci_did;
	uint16_t		 sc_pci_subvid;
	uint16_t		 sc_pci_subdid;

	uint16_t		 sc_card_flags;	/* BWI_CARD_F_ */
	uint16_t		 sc_pwron_delay;
	int			 sc_locale;

	/* [TRC: No clue what these are for.]
	int			 sc_irq_rid;
	struct resource		*sc_irq_res;
	void			*sc_irq_handle;
	*/

	/* [TRC: Likewise.]
	int			 sc_mem_rid;
	struct resource		*sc_mem_res;
	*/
	bus_dma_tag_t		 sc_dmat;
	bus_space_tag_t		 sc_mem_bt;
	bus_space_handle_t	 sc_mem_bh;

	struct callout		 sc_scan_ch;
	struct callout		 sc_calib_ch;

	/* [TRC: XXX amrr] */
	struct callout		 sc_amrr_ch;
	struct ieee80211_amrr	 sc_amrr;

	struct bwi_regwin	*sc_cur_regwin;
	struct bwi_regwin	 sc_com_regwin;
	struct bwi_regwin	 sc_bus_regwin;

	int			 sc_nmac;
	struct bwi_mac		 sc_mac[BWI_MAC_MAX];

	int			 sc_rx_rate;
	int			 sc_tx_rate;
	enum bwi_txpwrcb_type	 sc_txpwrcb_type;

	int			 sc_led_blinking;
	int			 sc_led_ticks;
	struct bwi_led		*sc_blink_led;
	struct callout		 sc_led_blink_ch;
	int			 sc_led_blink_offdur;
	struct bwi_led		 sc_leds[BWI_LED_MAX];
 
	enum bwi_bus_space	 sc_bus_space;

	struct bwi_txbuf_data	 sc_tx_bdata[BWI_TX_NRING];
	struct bwi_rxbuf_data	 sc_rx_bdata;

	struct bwi_ring_data	 sc_tx_rdata[BWI_TX_NRING];
	struct bwi_ring_data	 sc_rx_rdata;

	struct bwi_txstats_data	*sc_txstats;

	int			 sc_tx_timer;

	int			 (*sc_newstate)
				 (struct ieee80211com *,
				     enum ieee80211_state, int);

	int			 (*sc_init_tx_ring)(struct bwi_softc *, int);
	void			 (*sc_free_tx_ring)(struct bwi_softc *, int);

	int			 (*sc_init_rx_ring)(struct bwi_softc *);
	void			 (*sc_free_rx_ring)(struct bwi_softc *);

	int			 (*sc_init_txstats)(struct bwi_softc *);
	void			 (*sc_free_txstats)(struct bwi_softc *);

	void			 (*sc_setup_rxdesc)
				 (struct bwi_softc *, int, bus_addr_t, int);
	int			 (*sc_rxeof)(struct bwi_softc *);

	void			 (*sc_setup_txdesc)
				 (struct bwi_softc *, struct bwi_ring_data *,
				     int, bus_addr_t, int);
	void			 (*sc_start_tx)
				 (struct bwi_softc *, uint32_t, int);

	void			 (*sc_txeof_status)(struct bwi_softc *);

	int			 (*sc_enable)(struct bwi_softc *, int);
	void			 (*sc_disable)(struct bwi_softc *, int);

	void			 (*sc_conf_write)(void *, uint32_t, uint32_t);
	uint32_t		 (*sc_conf_read)(void *, uint32_t);

	void			 (*sc_reg_write_2)(void *, uint32_t, uint16_t);
	uint16_t		 (*sc_reg_read_2)(void *, uint32_t);
	void			 (*sc_reg_write_4)(void *, uint32_t, uint32_t);
	uint32_t		 (*sc_reg_read_4)(void *, uint32_t);

	void			 (*sc_reg_write_multi_4)(void *, uint32_t,
				     const uint32_t *, size_t);
	void			 (*sc_reg_read_multi_4)(void *, uint32_t,
				     uint32_t *, size_t);

	struct pool_cache	*sc_freetask;
	struct workqueue	*sc_taskq;
	uint8_t			*sc_pio_databuf;
	kmutex_t		 sc_pio_txlock;
	STAILQ_HEAD(, bwi_txbuf) sc_pio_txpend;
	size_t			 sc_pio_fifolen;
	size_t			 sc_pio_fifoavail;

	struct sysctllog	*sc_sysctllog;

	/* Sysctl variables */
	int			 sc_fw_version;	/* BWI_FW_VERSION[34] */
	int			 sc_dwell_time;	/* milliseconds */
	int			 sc_led_idle;
	int			 sc_led_blink;
	int			 sc_txpwr_calib;
	int			 sc_debug;	/* BWI_DBG_ */

	struct bpf_if		*sc_drvbpf;
 
	union {
		struct bwi_rx_radiotap_hdr th;
		uint8_t pad[64];
	}			 sc_rxtapu;
#define sc_rxtap		 sc_rxtapu.th
	int			 sc_rxtap_len;
 
	union {
		struct bwi_tx_radiotap_hdr th;
		uint8_t pad[64];
	}			 sc_txtapu;
#define sc_txtap		 sc_txtapu.th
	int			 sc_txtap_len;
};

static inline void
_bwi_read_multi_4(struct bwi_softc *sc, bus_size_t reg, uint32_t *datap,
    bus_size_t count)
{
	if (sc->sc_reg_read_multi_4 != NULL) {
		return sc->sc_reg_read_multi_4(sc, reg, datap, count);
	} else {
		return bus_space_read_multi_4(sc->sc_mem_bt, sc->sc_mem_bh,
		    reg, datap, count);
	}
}

static inline uint16_t
_bwi_read_2(struct bwi_softc *sc, bus_size_t reg)
{
	if (sc->sc_reg_read_2 != NULL) {
		return sc->sc_reg_read_2(sc, reg);
	} else {
		return bus_space_read_2(sc->sc_mem_bt, sc->sc_mem_bh, reg);
	}
}

static inline uint32_t
_bwi_read_4(struct bwi_softc *sc, bus_size_t reg)
{
	if (sc->sc_reg_read_4 != NULL) {
		return sc->sc_reg_read_4(sc, reg);
	} else {
		return bus_space_read_4(sc->sc_mem_bt, sc->sc_mem_bh, reg);
	}
}

static inline void
_bwi_write_multi_4(struct bwi_softc *sc, bus_size_t reg, const uint32_t *datap,
    bus_size_t count)
{
	if (sc->sc_reg_read_multi_4 != NULL) {
		return sc->sc_reg_write_multi_4(sc, reg, datap, count);
	} else {
		return bus_space_write_multi_4(sc->sc_mem_bt, sc->sc_mem_bh,
		    reg, datap, count);
	}
}

static inline void
_bwi_write_2(struct bwi_softc *sc, bus_size_t reg, uint16_t val)
{
	if (sc->sc_reg_write_2 != NULL) {
		sc->sc_reg_write_2(sc, reg, val);
	} else {
		bus_space_write_2(sc->sc_mem_bt, sc->sc_mem_bh, reg, val);
	}
}

static inline void
_bwi_write_4(struct bwi_softc *sc, bus_size_t reg, uint32_t val)
{
	if (sc->sc_reg_write_4 != NULL) {
		sc->sc_reg_write_4(sc, reg, val);
	} else {
		bus_space_write_4(sc->sc_mem_bt, sc->sc_mem_bh, reg, val);
	}
}

#define BWI_F_BUS_INITED	0x1
#define BWI_F_PROMISC		0x2
#define BWI_F_SDIO		0x4
#define BWI_F_PIO		0x8

#define BWI_IS_SDIO(sc)		ISSET((sc)->sc_flags, BWI_F_SDIO)
#define BWI_IS_PIO(sc)		ISSET((sc)->sc_flags, BWI_F_PIO)

#define BWI_DBG_MAC		0x00000001
#define BWI_DBG_RF		0x00000002
#define BWI_DBG_PHY		0x00000004
#define BWI_DBG_MISC		0x00000008

#define BWI_DBG_ATTACH		0x00000010
#define BWI_DBG_INIT		0x00000020
#define BWI_DBG_FIRMWARE	0x00000040
#define BWI_DBG_80211		0x00000080
#define BWI_DBG_TXPOWER		0x00000100
#define BWI_DBG_INTR		0x00000200
#define BWI_DBG_RX		0x00000400
#define BWI_DBG_TX		0x00000800
#define BWI_DBG_TXEOF		0x00001000
#define BWI_DBG_LED		0x00002000
#define BWI_DBG_STATION		0x00004000

#define abs(a)	__builtin_abs(a)

#define MOBJ_WRITE_2(mac, objid, ofs, val)			\
	bwi_memobj_write_2((mac), (objid), (ofs), (val))
#define MOBJ_WRITE_4(mac, objid, ofs, val)			\
	bwi_memobj_write_4((mac), (objid), (ofs), (val))
#define MOBJ_READ_2(mac, objid, ofs)				\
	bwi_memobj_read_2((mac), (objid), (ofs))
#define MOBJ_READ_4(mac, objid, ofs)				\
	bwi_memobj_read_4((mac), (objid), (ofs))

#define MOBJ_SETBITS_4(mac, objid, ofs, bits)			\
	MOBJ_WRITE_4((mac), (objid), (ofs),			\
	MOBJ_READ_4((mac), (objid), (ofs)) | (bits))
#define MOBJ_CLRBITS_4(mac, objid, ofs, bits)			\
	MOBJ_WRITE_4((mac), (objid), (ofs),			\
	MOBJ_READ_4((mac), (objid), (ofs)) & ~(bits))

#define MOBJ_FILT_SETBITS_2(mac, objid, ofs, filt, bits)	\
	MOBJ_WRITE_2((mac), (objid), (ofs),			\
	(MOBJ_READ_2((mac), (objid), (ofs)) & (filt)) | (bits))

#define TMPLT_WRITE_4(mac, ofs, val)	bwi_tmplt_write_4((mac), (ofs), (val))

#define HFLAGS_WRITE(mac, flags)	bwi_hostflags_write((mac), (flags))
#define HFLAGS_READ(mac)		bwi_hostflags_read((mac))
#define HFLAGS_CLRBITS(mac, bits)				\
	HFLAGS_WRITE((mac), HFLAGS_READ((mac)) | (bits))
#define HFLAGS_SETBITS(mac, bits)				\
	HFLAGS_WRITE((mac), HFLAGS_READ((mac)) & ~(bits))

/* PHY */

struct bwi_gains {
	int16_t	tbl_gain1;
	int16_t	tbl_gain2;
	int16_t	phy_gain;
};

static __inline void
bwi_phy_init(struct bwi_mac *_mac)
{
	_mac->mac_phy.phy_init(_mac);
}

#define PHY_WRITE(mac, ctrl, val)	bwi_phy_write((mac), (ctrl), (val))
#define PHY_READ(mac, ctrl)		bwi_phy_read((mac), (ctrl))

#define PHY_SETBITS(mac, ctrl, bits)		\
	PHY_WRITE((mac), (ctrl), PHY_READ((mac), (ctrl)) | (bits))
#define PHY_CLRBITS(mac, ctrl, bits)		\
	PHY_WRITE((mac), (ctrl), PHY_READ((mac), (ctrl)) & ~(bits))
#define PHY_FILT_SETBITS(mac, ctrl, filt, bits)	\
	PHY_WRITE((mac), (ctrl), (PHY_READ((mac), (ctrl)) & (filt)) | (bits))

static __inline void
bwi_rf_off(struct bwi_mac *_mac)
{
	_mac->mac_rf.rf_off(_mac);
	/* TODO: LED */

	_mac->mac_rf.rf_flags &= ~BWI_RF_F_ON;
}

static __inline void
bwi_rf_on(struct bwi_mac *_mac)
{
	if (_mac->mac_rf.rf_flags & BWI_RF_F_ON)
		return;

	_mac->mac_rf.rf_on(_mac);
	/* TODO: LED */

	_mac->mac_rf.rf_flags |= BWI_RF_F_ON;
}

static __inline void
bwi_rf_calc_nrssi_slope(struct bwi_mac *_mac)
{
	_mac->mac_rf.rf_calc_nrssi_slope(_mac);
}

static __inline void
bwi_rf_set_nrssi_thr(struct bwi_mac *_mac)
{
	_mac->mac_rf.rf_set_nrssi_thr(_mac);
}

static __inline int
bwi_rf_calc_rssi(struct bwi_mac *_mac, const struct bwi_rxbuf_hdr *_hdr)
{
	return (_mac->mac_rf.rf_calc_rssi(_mac, _hdr));
}

static __inline void
bwi_rf_lo_update(struct bwi_mac *_mac)
{
	_mac->mac_rf.rf_lo_update(_mac);
}

#define RF_WRITE(mac, ofs, val)		bwi_rf_write((mac), (ofs), (val))
#define RF_READ(mac, ofs)		bwi_rf_read((mac), (ofs))

#define RF_SETBITS(mac, ofs, bits)		\
	RF_WRITE((mac), (ofs), RF_READ((mac), (ofs)) | (bits))
#define RF_CLRBITS(mac, ofs, bits)		\
	RF_WRITE((mac), (ofs), RF_READ((mac), (ofs)) & ~(bits))
#define RF_FILT_SETBITS(mac, ofs, filt, bits)	\
	RF_WRITE((mac), (ofs), (RF_READ((mac), (ofs)) & (filt)) | (bits))

/* [TRC: XXX Why are these visible at all externally?] */

int		bwi_intr(void *);
int		bwi_attach(struct bwi_softc *);
void		bwi_detach(struct bwi_softc *);

/* Power Management Framework */
bool		bwi_suspend(device_t, const pmf_qual_t *);
bool		bwi_resume(device_t, const pmf_qual_t *);

#endif	/* !_DEV_IC_BWIVAR_H */
