/* Copyright 2011-2014 Autronica Fire and Security AS
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * Author(s):
 *	2011-2014 Arvid Brodin, arvid.brodin@alten.se
 */

#ifndef __HSR_PRP_PRIVATE_H
#define __HSR_PRP_PRIVATE_H

#include <linux/netdevice.h>
#include <linux/list.h>
#include <linux/if_vlan.h>

/* Time constants as specified in the HSR specification (IEC-62439-3 2010)
 * Table 8.
 * All values in milliseconds.
 */
#define HSR_PRP_LIFE_CHECK_INTERVAL              2000 /* ms */
#define HSR_PRP_NODE_FORGET_TIME                60000 /* ms */
#define HSR_PRP_ANNOUNCE_INTERVAL                 100 /* ms */

/* By how much may slave1 and slave2 timestamps of latest received frame from
 * each node differ before we notify of communication problem?
 */
#define HSR_PRP_MAX_SLAVE_DIFF			 3000 /* ms */
#define HSR_PRP_SEQNR_START			(USHRT_MAX - 1024)
#define HSR_PRP_SUP_SEQNR_START		(HSR_PRP_SEQNR_START / 2)
/* How often shall we check for broken ring and remove node entries older than
 * HSR_NODE_FORGET_TIME?
 */
#define HSR_PRP_PRUNE_PERIOD			 3000 /* ms */

#define HSR_TLV_ANNOUNCE		   22
#define HSR_TLV_LIFE_CHECK		   23
/* PRP V1 life check for Duplicate discard */
#define PRP_TLV_LIFE_CHECK_DD		   20
/* PRP V1 life check for Duplicate Accept */
#define PRP_TLV_LIFE_CHECK_DA		   21

/* HSR Tag.
 * As defined in IEC-62439-3:2010, the HSR tag is really { ethertype = 0x88FB,
 * path, LSDU_size, sequence Nr }. But we let eth_header() create { h_dest,
 * h_source, h_proto = 0x88FB }, and add { path, LSDU_size, sequence Nr,
 * encapsulated protocol } instead.
 *
 * Field names as defined in the IEC:2010 standard for HSR.
 */
struct hsr_tag {
	__be16		path_and_LSDU_size;
	__be16		sequence_nr;
	__be16		encap_proto;
} __packed;

#define HSR_PRP_HLEN	6

#define HSR_PRP_V1_SUP_LSDUSIZE		52

/* The helper functions below assumes that 'path' occupies the 4 most
 * significant bits of the 16-bit field shared by 'path' and 'LSDU_size' (or
 * equivalently, the 4 most significant bits of HSR tag byte 14).
 *
 * This is unclear in the IEC specification; its definition of MAC addresses
 * indicates the spec is written with the least significant bit first (to the
 * left). This, however, would mean that the LSDU field would be split in two
 * with the path field in-between, which seems strange. I'm guessing the MAC
 * address definition is in error.
 */
static inline u16 get_hsr_tag_path(struct hsr_tag *ht)
{
	return ntohs(ht->path_and_LSDU_size) >> 12;
}

static inline u16 get_hsr_tag_LSDU_size(struct hsr_tag *ht)
{
	return ntohs(ht->path_and_LSDU_size) & 0x0FFF;
}

static inline void set_hsr_tag_path(struct hsr_tag *ht, u16 path)
{
	ht->path_and_LSDU_size =
		htons((ntohs(ht->path_and_LSDU_size) & 0x0FFF) | (path << 12));
}

static inline void set_hsr_tag_LSDU_size(struct hsr_tag *ht, u16 LSDU_size)
{
	ht->path_and_LSDU_size = htons(
				      (ntohs(ht->path_and_LSDU_size) & 0xF000) |
				      (LSDU_size & 0x0FFF));
}

struct hsr_ethhdr {
	struct ethhdr	ethhdr;
	struct hsr_tag	hsr_tag;
} __packed;

struct hsr_vlan_ethhdr {
	struct vlan_ethhdr vlanhdr;
	struct hsr_tag	hsr_tag;
} __packed;

/* HSR/PRP Supervision Frame data types.
 * Field names as defined in the IEC:2012 standard for HSR.
 */
struct hsr_prp_sup_tag {
	__be16		path_and_HSR_Ver;
	__be16		sequence_nr;
	__u8		HSR_TLV_type;
	__u8		HSR_TLV_length;
} __packed;

struct hsr_prp_sup_payload {
	unsigned char	mac_address_a[ETH_ALEN];
} __packed;

static inline u16 get_hsr_stag_path(struct hsr_prp_sup_tag *hst)
{
	return get_hsr_tag_path((struct hsr_tag *)hst);
}

static inline u16 get_hsr_stag_HSR_ver(struct hsr_prp_sup_tag *hst)
{
	return get_hsr_tag_LSDU_size((struct hsr_tag *)hst);
}

static inline void set_hsr_stag_path(struct hsr_prp_sup_tag *hst, u16 path)
{
	set_hsr_tag_path((struct hsr_tag *)hst, path);
}

static inline void set_hsr_stag_HSR_ver(struct hsr_prp_sup_tag *hst,
					u16 HSR_ver)
{
	set_hsr_tag_LSDU_size((struct hsr_tag *)hst, HSR_ver);
}

struct hsrv0_ethhdr_sp {
	struct ethhdr		ethhdr;
	struct hsr_prp_sup_tag	hsr_sup;
} __packed;

struct hsrv1_ethhdr_sp {
	struct ethhdr		ethhdr;
	struct hsr_tag		hsr;
	struct hsr_prp_sup_tag	hsr_sup;
} __packed;

enum hsr_prp_port_type {
	HSR_PRP_PT_NONE = 0,	/* Must be 0, used by framereg */
	HSR_PRP_PT_SLAVE_A,
	HSR_PRP_PT_SLAVE_B,
	HSR_PRP_PT_INTERLINK,
	HSR_PRP_PT_MASTER,
	HSR_PRP_PT_PORTS,	/* This must be the last item in the enum */
};

/* PRP Redunancy Control Trailor (RCT).
 * As defined in IEC-62439-4:2012, the PRP RCT is really { sequence Nr,
 * Lan indentifier (LanId), LSDU_size and PRP_suffix = 0x88FB }.
 *
 * Field names as defined in the IEC:2012 standard for PRP.
 */
struct prp_rct {
	__be16		sequence_nr;
	__be16		lan_id_and_LSDU_size;
	__be16		PRP_suffix;
} __packed;

static inline u16 get_prp_LSDU_size(struct prp_rct *rct)
{
	return ntohs(rct->lan_id_and_LSDU_size) & 0x0FFF;
}

static inline void set_prp_lan_id(struct prp_rct *rct, u16 lan_id)
{
	rct->lan_id_and_LSDU_size = htons(
			(ntohs(rct->lan_id_and_LSDU_size) & 0x0FFF) |
			(lan_id << 12));
}
static inline void set_prp_LSDU_size(struct prp_rct *rct, u16 LSDU_size)
{
	rct->lan_id_and_LSDU_size = htons(
			(ntohs(rct->lan_id_and_LSDU_size) & 0xF000) |
			(LSDU_size & 0x0FFF));
}

struct hsr_prp_lre_if_stats {
	u32	cnt_tx_a;
	u32	cnt_tx_b;
	u32	cnt_rx_wrong_lan_a;
	u32	cnt_rx_wrong_lan_b;
	u32	cnt_rx_a;
	u32	cnt_rx_b;
	u32	cnt_rx_errors_a;
	u32	cnt_rx_errors_b;
	u32	cnt_own_rx_a; /* For HSR only */
	u32	cnt_own_rx_b; /* For HSR only */
	u32	cnt_tx_sup;
};

struct hsr_prp_port {
	struct list_head	port_list;
	struct net_device	*dev;
	struct hsr_prp_priv	*priv;
	enum hsr_prp_port_type	type;
};

#define HSR	0
#define PRP	1

/* PRP duplicate discard modes */
#define IEC62439_3_PRP_DA	1
#define IEC62439_3_PRP_DD	2

#define IEC62439_3_HSR_MODE_H	1
#define IEC62439_3_HSR_MODE_N	2
#define IEC62439_3_HSR_MODE_T	3
#define IEC62439_3_HSR_MODE_U	4
#define IEC62439_3_HSR_MODE_M	5

struct hsr_prp_priv {
	struct rcu_head		rcu_head;
	struct list_head	ports;
	struct list_head	node_db;	/* Known HSR nodes */
	struct list_head	self_node_db;	/* MACs of slaves */
	struct timer_list	announce_timer;	/* Supervision frame dispatch */
	struct timer_list	prune_timer;
	bool			rx_offloaded;	/* lre handle in hw */
	bool			l2_fwd_offloaded; /* L2 forward in hw */
	struct	hsr_prp_lre_if_stats stats;	/* lre interface stats */
	int announce_count;
	u16 sequence_nr;
	u16 sup_sequence_nr;	/* For HSRv1 separate seq_nr for supervision */
#define HSR_V0	0
#define HSR_V1	1
#define PRP_V1	2
	u8 prot_version;	/* Indicate if HSRv0 or HSRv1 or PRPv1 */
#define PRP_LAN_ID	0x5     /* 0x1010 for A and 0x1011 for B. Bit 0 is set
				 * based on SLAVE_A or SLAVE_B
				 */
	u8 net_id;		/* for PRP, it occupies most significant 3 bits
				 * of lan_id
				 */
	u8 hsr_mode;		/* value of hsr mode */
	u8 dup_discard_mode;		/* Duplicate Discard mode for PRP */
	spinlock_t seqnr_lock;	/* locking for sequence_nr */
	unsigned char		sup_multicast_addr[ETH_ALEN];
#ifdef	CONFIG_DEBUG_FS
	struct dentry *root_dir;
	struct dentry *node_tbl_file;
	struct dentry *stats_file;
	struct dentry *hsr_mode_file;
	struct dentry *dd_mode_file;
#endif
};

#define hsr_prp_for_each_port(hsr_prp, port) \
	list_for_each_entry_rcu((port), &(hsr_prp)->ports, port_list)

struct hsr_prp_port *hsr_prp_get_port(struct hsr_prp_priv *hsr_prp,
				      enum hsr_prp_port_type pt);
int hsr_prp_netdev_notify(struct notifier_block *nb, unsigned long event,
			  void *ptr);

/* Caller must ensure skb is a valid HSR frame */
static inline u16 hsr_get_skb_sequence_nr(struct sk_buff *skb)
{
	struct hsr_ethhdr *hsr_ethhdr;

	hsr_ethhdr = (struct hsr_ethhdr *)skb_mac_header(skb);

	return ntohs(hsr_ethhdr->hsr_tag.sequence_nr);
}

static inline struct prp_rct *skb_get_PRP_rct(struct sk_buff *skb)
{
	unsigned char *tail = skb_tail_pointer(skb) - HSR_PRP_HLEN;

	struct prp_rct *rct = (struct prp_rct *)tail;

	if (rct->PRP_suffix == htons(ETH_P_PRP))
		return rct;

	return NULL;
}

/* Assume caller has confirmed this skb is PRP suffixed */
static inline u16 prp_get_skb_sequence_nr(struct prp_rct *rct)
{
	return ntohs(rct->sequence_nr);
}

static inline u16 get_prp_lan_id(struct prp_rct *rct)
{
	return ntohs(rct->lan_id_and_LSDU_size) >> 12;
}

/* assume there is a valid rct */
static inline bool prp_check_lsdu_size(struct sk_buff *skb,
				       struct prp_rct *rct,
				       bool is_sup)
{
	struct ethhdr *ethhdr;
	int expected_lsdu_size;

	if (is_sup) {
		expected_lsdu_size = HSR_PRP_V1_SUP_LSDUSIZE;
	} else {
		ethhdr = (struct ethhdr *)skb_mac_header(skb);
		expected_lsdu_size = skb->len - 14;
		if (ethhdr->h_proto == htons(ETH_P_8021Q))
			expected_lsdu_size -= 4;
	}

	return (expected_lsdu_size == get_prp_LSDU_size(rct));
}

int hsr_prp_register_notifier(u8 proto);
void hsr_prp_unregister_notifier(u8 proto);

#define INC_CNT_TX(type, priv) (((type) == HSR_PRP_PT_SLAVE_A) ? \
		priv->stats.cnt_tx_a++ : priv->stats.cnt_tx_b++)
#define INC_CNT_RX_WRONG_LAN(type, priv) (((type) == HSR_PRP_PT_SLAVE_A) ? \
		priv->stats.cnt_rx_wrong_lan_a++ : \
		priv->stats.cnt_rx_wrong_lan_b++)
#define INC_CNT_RX(type, priv) (((type) == HSR_PRP_PT_SLAVE_A) ? \
		priv->stats.cnt_rx_a++ : priv->stats.cnt_rx_b++)
#define INC_CNT_RX_ERROR(type, priv) (((type) == HSR_PRP_PT_SLAVE_A) ? \
		priv->stats.cnt_rx_errors_a++ : priv->stats.cnt_rx_errors_b++)
#define INC_CNT_OWN_RX(type, priv) (((type) == HSR_PRP_PT_SLAVE_A) ? \
		priv->stats.cnt_own_rx_a++ : priv->stats.cnt_own_rx_b++)
#define INC_CNT_TX_SUP(priv) ((priv)->stats.cnt_tx_sup++)

#if IS_ENABLED(CONFIG_DEBUG_FS)
int hsr_prp_debugfs_init(struct hsr_prp_priv *priv,
			 struct net_device *hsr_prp_dev);
void hsr_prp_debugfs_term(struct hsr_prp_priv *priv);
#else
static inline int hsr_prp_debugfs_init(struct hsr_prp_priv *priv,
				       struct net_device *hsr_prp_dev)
{
	return 0;
}

static inline void hsr_prp_debugfs_term(struct hsr_prp_priv *priv)
{}
#endif

#endif /*  __HSR_PRP_PRIVATE_H */
