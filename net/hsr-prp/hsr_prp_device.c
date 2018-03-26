/* Copyright 2011-2014 Autronica Fire and Security AS
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * Author(s):
 *	2011-2014 Arvid Brodin, arvid.brodin@alten.se
 *
 * This file contains device methods for creating, using and destroying
 * virtual HSR devices.
 */

#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include "hsr_prp_device.h"
#include "hsr_prp_slave.h"
#include "hsr_prp_framereg.h"
#include "hsr_prp_main.h"
#include "hsr_prp_forward.h"

static bool is_admin_up(struct net_device *dev)
{
	return dev && (dev->flags & IFF_UP);
}

static bool is_slave_up(struct net_device *dev)
{
	return dev && is_admin_up(dev) && netif_oper_up(dev);
}

static void __set_operstate(struct net_device *dev, int transition)
{
	write_lock_bh(&dev_base_lock);
	if (dev->operstate != transition) {
		dev->operstate = transition;
		write_unlock_bh(&dev_base_lock);
		netdev_state_change(dev);
	} else {
		write_unlock_bh(&dev_base_lock);
	}
}

static void set_operstate(struct hsr_prp_port *master, bool has_carrier)
{
	if (!is_admin_up(master->dev)) {
		__set_operstate(master->dev, IF_OPER_DOWN);
		return;
	}

	if (has_carrier)
		__set_operstate(master->dev, IF_OPER_UP);
	else
		__set_operstate(master->dev, IF_OPER_LOWERLAYERDOWN);
}

static bool hsr_prp_check_carrier(struct hsr_prp_port *master)
{
	struct hsr_prp_port *port;
	bool has_carrier;

	has_carrier = false;

	rcu_read_lock();
	hsr_prp_for_each_port(master->priv, port)
		if ((port->type != HSR_PRP_PT_MASTER) &&
		    is_slave_up(port->dev)) {
			has_carrier = true;
			break;
		}
	rcu_read_unlock();

	if (has_carrier)
		netif_carrier_on(master->dev);
	else
		netif_carrier_off(master->dev);

	return has_carrier;
}

static void hsr_prp_check_announce(struct net_device *hsr_dev,
				   unsigned char old_operstate)
{
	struct hsr_prp_priv *priv;

	priv = netdev_priv(hsr_dev);

	if ((hsr_dev->operstate == IF_OPER_UP) &&
	    (old_operstate != IF_OPER_UP)) {
		/* Went up */
		priv->announce_count = 0;
		priv->announce_timer.expires = jiffies +
				msecs_to_jiffies(HSR_PRP_ANNOUNCE_INTERVAL);
		add_timer(&priv->announce_timer);
	}

	if ((hsr_dev->operstate != IF_OPER_UP) && (old_operstate == IF_OPER_UP))
		/* Went down */
		del_timer(&priv->announce_timer);
}

void hsr_prp_check_carrier_and_operstate(struct hsr_prp_priv *priv)
{
	struct hsr_prp_port *master;
	unsigned char old_operstate;
	bool has_carrier;

	master = hsr_prp_get_port(priv, HSR_PRP_PT_MASTER);
	/* netif_stacked_transfer_operstate() cannot be used here since
	 * it doesn't set IF_OPER_LOWERLAYERDOWN (?)
	 */
	old_operstate = master->dev->operstate;
	has_carrier = hsr_prp_check_carrier(master);
	set_operstate(master, has_carrier);
	hsr_prp_check_announce(master->dev, old_operstate);
}

int hsr_prp_get_max_mtu(struct hsr_prp_priv *priv)
{
	unsigned int mtu_max;
	struct hsr_prp_port *port;

	mtu_max = ETH_DATA_LEN;
	rcu_read_lock();
	hsr_prp_for_each_port(priv, port)
		if (port->type != HSR_PRP_PT_MASTER)
			mtu_max = min(port->dev->mtu, mtu_max);
	rcu_read_unlock();

	if (mtu_max < HSR_PRP_HLEN)
		return 0;
	return mtu_max - HSR_PRP_HLEN;
}

static int hsr_prp_dev_change_mtu(struct net_device *dev, int new_mtu)
{
	struct hsr_prp_priv *priv;
	struct hsr_prp_port *master;
	int max;

	priv = netdev_priv(dev);
	master = hsr_prp_get_port(priv, HSR_PRP_PT_MASTER);
	max = hsr_prp_get_max_mtu(priv);
	if (new_mtu > max) {
		netdev_info(master->dev,
			    "HSR/PRP: Invalid MTU, expected (<= %d), Got %d.\n",
			    max, new_mtu);
		return -EINVAL;
	}

	dev->mtu = new_mtu;

	return 0;
}

static int hsr_prp_dev_open(struct net_device *dev)
{
	struct hsr_prp_priv *priv;
	struct hsr_prp_port *port;
	char designation;

	priv = netdev_priv(dev);
	designation = '\0';

	rcu_read_lock();
	hsr_prp_for_each_port(priv, port) {
		if (port->type == HSR_PRP_PT_MASTER)
			continue;
		switch (port->type) {
		case HSR_PRP_PT_SLAVE_A:
			designation = 'A';
			break;
		case HSR_PRP_PT_SLAVE_B:
			designation = 'B';
			break;
		default:
			designation = '?';
		}
		if (!is_slave_up(port->dev))
			netdev_warn(dev,
				    "HSR/PRP: Please bringup Slave %c (%s)\n",
				    designation, port->dev->name);
	}
	rcu_read_unlock();

	if (designation == '\0')
		netdev_warn(dev, "No slave devices configured\n");

	return 0;
}

static int hsr_prp_dev_close(struct net_device *dev)
{
	/* Nothing to do here. */
	return 0;
}

static netdev_features_t hsr_prp_features_recompute(struct hsr_prp_priv *priv,
						    netdev_features_t features)
{
	netdev_features_t mask;
	struct hsr_prp_port *port;

	mask = features;

	/* Mask out all features that, if supported by one device, should be
	 * enabled for all devices (see NETIF_F_ONE_FOR_ALL).
	 *
	 * Anything that's off in mask will not be enabled - so only things
	 * that were in features originally, and also is in NETIF_F_ONE_FOR_ALL,
	 * may become enabled.
	 */
	features &= ~NETIF_F_ONE_FOR_ALL;
	hsr_prp_for_each_port(priv, port)
		features = netdev_increment_features(features,
						     port->dev->features,
						     mask);

	return features;
}

static netdev_features_t hsr_prp_fix_features(struct net_device *dev,
					      netdev_features_t features)
{
	struct hsr_prp_priv *priv = netdev_priv(dev);

	return hsr_prp_features_recompute(priv, features);
}

static int hsr_prp_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct hsr_prp_priv *priv = netdev_priv(dev);
	struct hsr_prp_port *master;

	master = hsr_prp_get_port(priv, HSR_PRP_PT_MASTER);
	skb->dev = master->dev;
	hsr_prp_forward_skb(skb, master);
	master->dev->stats.tx_packets++;
	master->dev->stats.tx_bytes += skb->len;

	return NETDEV_TX_OK;
}

static const struct header_ops hsr_prp_header_ops = {
	.create	 = eth_header,
	.parse	 = eth_header_parse,
};

static void send_supervision_frame(struct hsr_prp_port *master,
				   u8 type, u8 prot_ver)
{
	struct sk_buff *skb;
	int hlen, tlen;
	struct hsr_tag *hsr_tag;
	struct prp_rct *rct;
	struct hsr_prp_sup_tag *hsr_stag;
	struct hsr_prp_sup_payload *hsr_sp;
	unsigned long irqflags;
	u16 proto;
	u8 *tail;

	hlen = LL_RESERVED_SPACE(master->dev);
	tlen = master->dev->needed_tailroom;
	/* skb size is same for PRP/HSR frames, only difference
	 * being for PRP, it is a trailor and for HSR it is a
	 * header
	 */
	skb = dev_alloc_skb(
			sizeof(struct hsr_tag) +
			sizeof(struct hsr_prp_sup_tag) +
			sizeof(struct hsr_prp_sup_payload) + hlen + tlen);
	if (!skb)
		return;

	skb_reserve(skb, hlen);
	if (!prot_ver)
		proto = ETH_P_PRP;
	else
		proto = (prot_ver == HSR_V1) ? ETH_P_HSR : ETH_P_PRP;
	skb->dev = master->dev;
	skb->protocol = htons(proto);
	skb->priority = TC_PRIO_CONTROL;

	if (dev_hard_header(skb, skb->dev, proto,
			    master->priv->sup_multicast_addr,
			    skb->dev->dev_addr, skb->len) <= 0)
		goto out;

	skb_reset_mac_header(skb);
	if (prot_ver == HSR_V1) {
		hsr_tag = (typeof(hsr_tag))skb_put(skb,
						   sizeof(struct hsr_tag));
		hsr_tag->encap_proto = htons(ETH_P_PRP);
		set_hsr_tag_LSDU_size(hsr_tag, HSR_PRP_V1_SUP_LSDUSIZE);
	}

	hsr_stag = (typeof(hsr_stag))skb_put(skb,
					     sizeof(struct hsr_prp_sup_tag));
	set_hsr_stag_path(hsr_stag, (prot_ver ? 0x0 : 0xf));
	set_hsr_stag_HSR_ver(hsr_stag, prot_ver ? 0x1 : 0x0);

	/* From HSRv1 on we have separate supervision sequence numbers. */
	spin_lock_irqsave(&master->priv->seqnr_lock, irqflags);
	if (prot_ver > 0) {
		hsr_stag->sequence_nr = htons(master->priv->sup_sequence_nr);
		master->priv->sup_sequence_nr++;
		if (prot_ver == HSR_V1) {
			hsr_tag->sequence_nr = htons(master->priv->sequence_nr);
			master->priv->sequence_nr++;
		}
	} else {
		hsr_stag->sequence_nr = htons(master->priv->sequence_nr);
		master->priv->sequence_nr++;
	}
	spin_unlock_irqrestore(&master->priv->seqnr_lock, irqflags);

	hsr_stag->HSR_TLV_type = type;
	/* TODO: Why 12 in HSRv0? */
	hsr_stag->HSR_TLV_length =
		prot_ver ? sizeof(struct hsr_prp_sup_payload) : 12;

	/* Payload: mac_address_a */
	hsr_sp = (typeof(hsr_sp))skb_put(skb,
					 sizeof(struct hsr_prp_sup_payload));
	ether_addr_copy(hsr_sp->mac_address_a, master->dev->dev_addr);
	skb_put_padto(skb, ETH_ZLEN + HSR_PRP_HLEN);

	spin_lock_irqsave(&master->priv->seqnr_lock, irqflags);
	if (prot_ver == PRP_V1) {
		tail = skb_tail_pointer(skb) - HSR_PRP_HLEN;
		rct = (struct prp_rct *)tail;
		rct->PRP_suffix = htons(ETH_P_PRP);
		set_prp_LSDU_size(rct, HSR_PRP_V1_SUP_LSDUSIZE);
		rct->sequence_nr = htons(master->priv->sequence_nr);
		master->priv->sequence_nr++;
	}
	spin_unlock_irqrestore(&master->priv->seqnr_lock, irqflags);
	hsr_prp_forward_skb(skb, master);
	INC_CNT_TX_SUP(master->priv);
	return;

out:
	WARN_ONCE(1, "HSR: Could not send supervision frame\n");
	kfree_skb(skb);
}

/* Announce (supervision frame) timer function
 */
static void hsr_prp_announce(unsigned long data)
{
	struct hsr_prp_priv *priv;
	struct hsr_prp_port *master;

	priv = (struct hsr_prp_priv *)data;

	rcu_read_lock();
	master = hsr_prp_get_port(priv, HSR_PRP_PT_MASTER);

	if (priv->announce_count < 3 && priv->prot_version == HSR_V0) {
		send_supervision_frame(master, HSR_TLV_ANNOUNCE,
				       priv->prot_version);
		priv->announce_count++;

		priv->announce_timer.expires = jiffies +
				msecs_to_jiffies(HSR_PRP_ANNOUNCE_INTERVAL);
	} else {
		if (priv->prot_version <= HSR_V1)
			send_supervision_frame(master, HSR_TLV_LIFE_CHECK,
					       priv->prot_version);
		else /* PRP */
			send_supervision_frame(master,
					       (priv->dup_discard_mode ==
						IEC62439_3_PRP_DD) ?
						PRP_TLV_LIFE_CHECK_DD :
						PRP_TLV_LIFE_CHECK_DA,
					       priv->prot_version);

		priv->announce_timer.expires = jiffies +
				msecs_to_jiffies(HSR_PRP_LIFE_CHECK_INTERVAL);
	}

	if (is_admin_up(master->dev))
		add_timer(&priv->announce_timer);

	rcu_read_unlock();
}

/* According to comments in the declaration of struct net_device, this function
 * is "Called from unregister, can be used to call free_netdev". Ok then...
 */
static void hsr_prp_dev_destroy(struct net_device *hsr_prp_dev)
{
	struct hsr_prp_priv *priv;
	struct hsr_prp_port *port;

	priv = netdev_priv(hsr_prp_dev);

	hsr_prp_debugfs_term(priv);

	rtnl_lock();
	hsr_prp_for_each_port(priv, port)
		hsr_prp_del_port(port);
	rtnl_unlock();

	del_timer_sync(&priv->prune_timer);
	del_timer_sync(&priv->announce_timer);

	synchronize_rcu();
	free_netdev(hsr_prp_dev);
}

static const struct net_device_ops hsr_prp_device_ops = {
	.ndo_change_mtu = hsr_prp_dev_change_mtu,
	.ndo_open = hsr_prp_dev_open,
	.ndo_stop = hsr_prp_dev_close,
	.ndo_start_xmit = hsr_prp_dev_xmit,
	.ndo_fix_features = hsr_prp_fix_features,
};

static void hsr_prp_dev_setup(struct net_device *ndev, struct device_type *type)
{
	random_ether_addr(ndev->dev_addr);

	ether_setup(ndev);
	ndev->header_ops = &hsr_prp_header_ops;
	ndev->netdev_ops = &hsr_prp_device_ops;
	SET_NETDEV_DEVTYPE(ndev, type);
	ndev->priv_flags |= IFF_NO_QUEUE;

	ndev->destructor = hsr_prp_dev_destroy;

	ndev->hw_features = NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_HIGHDMA |
			   NETIF_F_GSO_MASK | NETIF_F_HW_CSUM |
			   NETIF_F_HW_VLAN_CTAG_TX;

	ndev->features = ndev->hw_features;

	/* Prevent recursive tx locking */
	ndev->features |= NETIF_F_LLTX;

	/* Not sure about this. Taken from bridge code. netdev_features.h says
	 * it means "Does not change network namespaces".
	 */
	ndev->features |= NETIF_F_NETNS_LOCAL;
}

static struct device_type hsr_type = {
	.name = "hsr",
};

void hsr_dev_setup(struct net_device *dev)
{
	hsr_prp_dev_setup(dev, &hsr_type);
}

static struct device_type prp_type = {
	.name = "prp",
};

void prp_dev_setup(struct net_device *dev)
{
	hsr_prp_dev_setup(dev, &prp_type);
}

/* Return true if dev is a HSR master; return false otherwise.
 */
inline bool is_hsr_prp_master(struct net_device *dev)
{
	return (dev->netdev_ops->ndo_start_xmit == hsr_prp_dev_xmit);
}

/* Default multicast address for HSR Supervision frames */
static const unsigned char def_multicast_addr[ETH_ALEN] __aligned(2) = {
	0x01, 0x15, 0x4e, 0x00, 0x01, 0x00
};

int hsr_prp_dev_finalize(struct net_device *hsr_prp_dev,
			 struct net_device *slave[2],
			 unsigned char multicast_spec, u8 protocol_version)
{
	netdev_features_t mask =
		NETIF_F_HW_PRP_RX_OFFLOAD | NETIF_F_HW_HSR_RX_OFFLOAD;
	struct hsr_prp_priv *priv;
	struct hsr_prp_port *port;
	int res;

	priv = netdev_priv(hsr_prp_dev);
	INIT_LIST_HEAD(&priv->ports);
	INIT_LIST_HEAD(&priv->node_db);
	INIT_LIST_HEAD(&priv->self_node_db);

	ether_addr_copy(hsr_prp_dev->dev_addr, slave[0]->dev_addr);

	/* Make sure we recognize frames from ourselves in
	 * hsr_rcv() or frame is addressed to me
	 */
	res = hsr_prp_create_self_node(&priv->self_node_db,
				       hsr_prp_dev->dev_addr,
				       slave[1]->dev_addr);
	if (res < 0)
		return res;

	priv->prot_version = protocol_version;
	if (priv->prot_version == PRP_V1) {
		/* For PRP, lan_id has most significant 3 bits holding
		 * the net_id of PRP_LAN_ID and also duplicate discard
		 * mode set.
		 */
		priv->net_id = PRP_LAN_ID << 1;
		priv->dup_discard_mode = IEC62439_3_PRP_DD;
	} else {
		priv->hsr_mode = IEC62439_3_HSR_MODE_H;
	}

	spin_lock_init(&priv->seqnr_lock);
	/* Overflow soon to find bugs easier: */
	priv->sequence_nr = HSR_PRP_SEQNR_START;
	priv->sup_sequence_nr = HSR_PRP_SUP_SEQNR_START;

	setup_timer(&priv->announce_timer, hsr_prp_announce,
		    (unsigned long)priv);

	if (!priv->rx_offloaded)
		setup_timer(&priv->prune_timer, hsr_prp_prune_nodes,
			    (unsigned long)priv);

	ether_addr_copy(priv->sup_multicast_addr, def_multicast_addr);
	priv->sup_multicast_addr[ETH_ALEN - 1] = multicast_spec;

	/* FIXME: should I modify the value of these?
	 *
	 * - hsr_dev->flags - i.e.
	 *			IFF_MASTER/SLAVE?
	 * - hsr_dev->priv_flags - i.e.
	 *			IFF_EBRIDGE?
	 *			IFF_TX_SKB_SHARING?
	 *			IFF_HSR_MASTER/SLAVE?
	 */

	/* Make sure the 1st call to netif_carrier_on() gets through */
	netif_carrier_off(hsr_prp_dev);

	res = hsr_prp_add_port(priv, hsr_prp_dev, HSR_PRP_PT_MASTER);
	if (res)
		return res;

	if (priv->prot_version == PRP_V1) {
		if ((slave[0]->features & NETIF_F_HW_HSR_RX_OFFLOAD) ||
		    (slave[1]->features & NETIF_F_HW_HSR_RX_OFFLOAD)) {
			res = -EINVAL;
			goto fail;
		}
	} else {
		if ((slave[0]->features & NETIF_F_HW_PRP_RX_OFFLOAD) ||
		    (slave[1]->features & NETIF_F_HW_PRP_RX_OFFLOAD)) {
			res = -EINVAL;
			goto fail;
		}
	}

	/* HSR/PRP LRE Rx offload supported in lower device? */
	if (((slave[0]->features & NETIF_F_HW_HSR_RX_OFFLOAD) &&
	     (slave[1]->features & NETIF_F_HW_HSR_RX_OFFLOAD)) ||
	     ((slave[0]->features & NETIF_F_HW_PRP_RX_OFFLOAD) &&
	     (slave[1]->features & NETIF_F_HW_PRP_RX_OFFLOAD)))
		priv->rx_offloaded = true;

	/* Make sure offload flags match in the slave devices */
	if ((slave[0]->features & mask) ^ (slave[1]->features & mask)) {
		res = -EINVAL;
		goto fail;
	}

	/* HSR LRE L2 forward offload supported in lower device for hsr? */
	if ((priv->prot_version < PRP_V1) &&
	    ((slave[0]->features & NETIF_F_HW_L2FW_DOFFLOAD) &&
	     (slave[1]->features & NETIF_F_HW_L2FW_DOFFLOAD)))
		priv->l2_fwd_offloaded = true;

	res = register_netdevice(hsr_prp_dev);
	if (res)
		goto fail;

	res = hsr_prp_add_port(priv, slave[0], HSR_PRP_PT_SLAVE_A);
	if (res)
		goto fail;
	res = hsr_prp_add_port(priv, slave[1], HSR_PRP_PT_SLAVE_B);
	if (res)
		goto fail;

	/* For LRE rx offload, pruning is expected to happen
	 * at the hardware or firmware . So don't do this in software
	 */
	if (!priv->rx_offloaded)
		mod_timer(&priv->prune_timer,
			  jiffies + msecs_to_jiffies(HSR_PRP_PRUNE_PERIOD));
	/* for offloaded case, expect both slaves have the
	 * same MAC address configured. If not fail.
	 */
	if (priv->rx_offloaded &&
	    !ether_addr_equal(slave[0]->dev_addr,
			      slave[1]->dev_addr))
		goto fail;

	res = hsr_prp_debugfs_init(priv, hsr_prp_dev);
	if (res)
		goto fail;

	return 0;

fail:
	hsr_prp_for_each_port(priv, port)
		hsr_prp_del_port(port);

	return res;
}
