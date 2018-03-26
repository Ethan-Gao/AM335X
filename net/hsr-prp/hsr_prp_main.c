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

#include <linux/netdevice.h>
#include <linux/rculist.h>
#include <linux/timer.h>
#include <linux/etherdevice.h>
#include "hsr_prp_main.h"
#include "hsr_prp_device.h"
#include "hsr_netlink.h"
#include "hsr_prp_framereg.h"
#include "hsr_prp_slave.h"

static struct notifier_block hsr_nb = {
	.notifier_call = hsr_prp_netdev_notify,	/* Slave event notifications */
};

static struct notifier_block prp_nb = {
	.notifier_call = hsr_prp_netdev_notify,	/* Slave event notifications */
};

int hsr_prp_netdev_notify(struct notifier_block *nb, unsigned long event,
			  void *ptr)
{
	struct net_device *dev;
	struct hsr_prp_port *port, *master;
	struct hsr_prp_priv *priv;
	int mtu_max;
	int res;

	dev = netdev_notifier_info_to_dev(ptr);
	port = hsr_prp_port_get_rtnl(dev);
	if (!port) {
		if (!is_hsr_prp_master(dev))
			return NOTIFY_DONE;	/* Not an HSR device */
		priv = netdev_priv(dev);
		port = hsr_prp_get_port(priv, HSR_PRP_PT_MASTER);
		if (!port) {
			/* Resend of notification concerning removed device? */
			return NOTIFY_DONE;
		}
	} else {
		priv = port->priv;
	}

	if ((priv->prot_version <= HSR_V1) &&
	    (nb != &hsr_nb))
		return NOTIFY_DONE;
	else if ((priv->prot_version == PRP_V1) &&
		 (nb != &prp_nb))
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UP:		/* Administrative state DOWN */
	case NETDEV_DOWN:	/* Administrative state UP */
	case NETDEV_CHANGE:	/* Link (carrier) state changes */
		hsr_prp_check_carrier_and_operstate(priv);
		break;
	case NETDEV_CHANGEADDR:
		if (port->type == HSR_PRP_PT_MASTER) {
			/* This should not happen since there's no
			 * ndo_set_mac_address() for HSR devices - i.e. not
			 * supported.
			 */
			break;
		}

		master = hsr_prp_get_port(priv, HSR_PRP_PT_MASTER);

		if (port->type == HSR_PRP_PT_SLAVE_A) {
			ether_addr_copy(master->dev->dev_addr, dev->dev_addr);
			call_netdevice_notifiers(NETDEV_CHANGEADDR,
						 master->dev);
		}

		/* Make sure we recognize frames from ourselves in hsr_rcv() */
		port = hsr_prp_get_port(priv, HSR_PRP_PT_SLAVE_B);
		res = hsr_prp_create_self_node(&priv->self_node_db,
					       master->dev->dev_addr,
					       port ?
					       port->dev->dev_addr :
					       master->dev->dev_addr);
		if (res)
			netdev_warn(master->dev,
				    "Could not update HSR node address.\n");
		break;
	case NETDEV_CHANGEMTU:
		if (port->type == HSR_PRP_PT_MASTER)
			break; /* Handled in ndo_change_mtu() */
		mtu_max = hsr_prp_get_max_mtu(port->priv);
		master = hsr_prp_get_port(port->priv, HSR_PRP_PT_MASTER);
		master->dev->mtu = mtu_max;
		break;
	case NETDEV_UNREGISTER:
		hsr_prp_del_port(port);
		break;
	case NETDEV_PRE_TYPE_CHANGE:
		/* HSR works only on Ethernet devices. Refuse slave to change
		 * its type.
		 */
		return NOTIFY_BAD;
	}

	return NOTIFY_DONE;
}

struct hsr_prp_port *hsr_prp_get_port(struct hsr_prp_priv *priv,
				      enum hsr_prp_port_type pt)
{
	struct hsr_prp_port *port;

	hsr_prp_for_each_port(priv, port)
		if (port->type == pt)
			return port;
	return NULL;
}

int hsr_prp_register_notifier(u8 proto)
{
	if (proto == PRP)
		return register_netdevice_notifier(&prp_nb);

	return register_netdevice_notifier(&hsr_nb);
}

void hsr_prp_unregister_notifier(u8 proto)
{
	if (proto == PRP)
		unregister_netdevice_notifier(&prp_nb);

	unregister_netdevice_notifier(&hsr_nb);
}
