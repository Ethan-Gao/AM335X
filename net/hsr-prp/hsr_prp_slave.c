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

#include "hsr_prp_slave.h"
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include "hsr_prp_main.h"
#include "hsr_prp_device.h"
#include "hsr_prp_forward.h"
#include "hsr_prp_framereg.h"

static rx_handler_result_t hsr_prp_handle_frame(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct hsr_prp_port *port;
	struct hsr_prp_priv *priv;
	u16 protocol;

	rcu_read_lock(); /* hsr->node_db, hsr->ports */
	port = hsr_prp_port_get_rcu(skb->dev);
	priv = port->priv;

	if (!skb_mac_header_was_set(skb)) {
		WARN_ONCE(1, "%s: skb invalid", __func__);
		goto finish_pass;
	}

	if (hsr_prp_addr_is_self(priv, eth_hdr(skb)->h_source)) {
		/* Directly kill frames sent by ourselves */
		INC_CNT_OWN_RX(port->type, priv);
		kfree_skb(skb);
		goto finish_consume;
	}

	/* For HSR, non tagged frames are unexpected, but for PRP
	 * there could be non tagged frames as well.
	 */
	protocol = eth_hdr(skb)->h_proto;

	if (protocol != htons(ETH_P_PRP) &&
	    protocol != htons(ETH_P_HSR) &&
	    (port->priv->prot_version <= HSR_V1) &&
	    (!priv->rx_offloaded))
		goto finish_pass;

	/* Frame is a HSR or PRP frame or frame form a SAN. For
	 * PRP, only supervisor frame will have a PRP protocol.
	 */
	if (protocol == htons(ETH_P_HSR) || protocol == htons(ETH_P_PRP))
		skb_push(skb, ETH_HLEN);

	/* HACK: Not sure why we have to do this as some frames
	 * don't have the skb->data pointing to mac header
	 */
	if (skb_mac_header(skb) != skb->data) {
		skb_push(skb, ETH_HLEN);

		/* do one more check and bail out */
		if (skb_mac_header(skb) != skb->data) {
			INC_CNT_RX_ERROR(port->type, priv);
			goto finish_consume;
		}
	}

	INC_CNT_RX(port->type, priv);
	hsr_prp_forward_skb(skb, port);

finish_consume:
	rcu_read_unlock(); /* hsr->node_db, hsr->ports */
	return RX_HANDLER_CONSUMED;

finish_pass:
	INC_CNT_RX_ERROR(port->type, priv);
	rcu_read_unlock(); /* hsr->node_db, hsr->ports */
	return RX_HANDLER_PASS;
}

bool hsr_prp_port_exists(const struct net_device *dev)
{
	return rcu_access_pointer(dev->rx_handler) == hsr_prp_handle_frame;
}

static int hsr_prp_check_dev_ok(struct net_device *dev)
{
	/* Don't allow HSR on non-ethernet like devices */
	if ((dev->flags & IFF_LOOPBACK) || (dev->type != ARPHRD_ETHER) ||
	    (dev->addr_len != ETH_ALEN)) {
		netdev_info(dev, "Cannot use loopback or non-ethernet device as HSR slave.\n");
		return -EINVAL;
	}

	/* Don't allow enslaving hsr devices */
	if (is_hsr_prp_master(dev)) {
		netdev_info(dev, "Cannot create trees of HSR devices.\n");
		return -EINVAL;
	}

	if (hsr_prp_port_exists(dev)) {
		netdev_info(dev, "This device is already a HSR slave.\n");
		return -EINVAL;
	}

	if (dev->priv_flags & IFF_DONT_BRIDGE) {
		netdev_info(dev, "This device does not support bridging.\n");
		return -EOPNOTSUPP;
	}

	/* HSR over bonded devices has not been tested, but I'm not sure it
	 * won't work...
	 */

	return 0;
}

/* Setup device to be added to the HSR bridge. */
static int hsr_prp_portdev_setup(struct net_device *dev,
				 struct hsr_prp_port *port)
{
	int res;

	dev_hold(dev);
	res = dev_set_promiscuity(dev, 1);
	if (res)
		goto fail_promiscuity;

	/* FIXME:
	 * What does net device "adjacency" mean? Should we do
	 * res = netdev_master_upper_dev_link(port->dev, port->hsr->dev); ?
	 */

	res = netdev_rx_handler_register(dev, hsr_prp_handle_frame, port);
	if (res)
		goto fail_rx_handler;
	dev_disable_lro(dev);

	return 0;

fail_rx_handler:
	dev_set_promiscuity(dev, -1);
fail_promiscuity:
	dev_put(dev);

	return res;
}

int hsr_prp_add_port(struct hsr_prp_priv *priv, struct net_device *dev,
		     enum hsr_prp_port_type type)
{
	struct hsr_prp_port *port, *master;
	int res;

	if (type != HSR_PRP_PT_MASTER) {
		res = hsr_prp_check_dev_ok(dev);
		if (res)
			return res;
	}

	port = hsr_prp_get_port(priv, type);
	if (port)
		return -EBUSY;	/* This port already exists */

	port = kzalloc(sizeof(*port), GFP_KERNEL);
	if (!port)
		return -ENOMEM;

	if (type != HSR_PRP_PT_MASTER) {
		res = hsr_prp_portdev_setup(dev, port);
		if (res)
			goto fail_dev_setup;
	}

	port->priv = priv;
	port->dev = dev;
	port->type = type;

	list_add_tail_rcu(&port->port_list, &priv->ports);
	synchronize_rcu();

	master = hsr_prp_get_port(priv, HSR_PRP_PT_MASTER);
	netdev_update_features(master->dev);
	dev_set_mtu(master->dev, hsr_prp_get_max_mtu(priv));

	return 0;

fail_dev_setup:
	kfree(port);
	return res;
}

void hsr_prp_del_port(struct hsr_prp_port *port)
{
	struct hsr_prp_priv *priv;
	struct hsr_prp_port *master;

	priv = port->priv;
	master = hsr_prp_get_port(priv, HSR_PRP_PT_MASTER);
	list_del_rcu(&port->port_list);

	if (port != master) {
		if (master) {
			netdev_update_features(master->dev);
			dev_set_mtu(master->dev, hsr_prp_get_max_mtu(priv));
		}
		netdev_rx_handler_unregister(port->dev);
		dev_set_promiscuity(port->dev, -1);
	}

	/* FIXME?
	 * netdev_upper_dev_unlink(port->dev, port->priv->dev);
	 */

	synchronize_rcu();

	if (port != master)
		dev_put(port->dev);
}
