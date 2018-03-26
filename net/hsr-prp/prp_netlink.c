/*
 * prp_netlink.c:  Routines for handling Netlink messages for PRP.
 * This is based on hsr_netlink.c from Arvid Brodin, arvid.brodin@alten.se
 *
 * Copyright (C) 2017 Texas Instruments Incorporated
 *
 * Author(s):
 *	Murali Karicheri <m-karicheri2@ti.com?
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include "prp_netlink.h"
#include <linux/kernel.h>
#include <net/rtnetlink.h>
#include <net/genetlink.h>
#include "hsr_prp_main.h"
#include "hsr_prp_device.h"
#include "hsr_prp_framereg.h"

static const struct nla_policy prp_policy[IFLA_PRP_MAX + 1] = {
	[IFLA_PRP_SLAVE1]		= { .type = NLA_U32 },
	[IFLA_PRP_SLAVE2]		= { .type = NLA_U32 },
	[IFLA_PRP_MULTICAST_SPEC]	= { .type = NLA_U8 },
	[IFLA_PRP_SUPERVISION_ADDR]	= { .type = NLA_BINARY,
					    .len = ETH_ALEN },
	[IFLA_PRP_SEQ_NR]		= { .type = NLA_U16 },
};

/* Here, it seems a netdevice has already been allocated for us, and the
 * hsr_dev_setup routine has been executed. Nice!
 */
static int prp_newlink(struct net *src_net, struct net_device *dev,
		       struct nlattr *tb[], struct nlattr *data[])
{
	struct net_device *link[2];
	unsigned char multicast_spec;

	if (!data) {
		netdev_info(dev, "PRP: No slave devices specified\n");
		return -EINVAL;
	}
	if (!data[IFLA_PRP_SLAVE1]) {
		netdev_info(dev, "PRP: Slave1 device not specified\n");
		return -EINVAL;
	}
	link[0] = __dev_get_by_index(src_net,
				     nla_get_u32(data[IFLA_PRP_SLAVE1]));
	if (!data[IFLA_PRP_SLAVE2]) {
		netdev_info(dev, "PRP: Slave2 device not specified\n");
		return -EINVAL;
	}
	link[1] = __dev_get_by_index(src_net,
				     nla_get_u32(data[IFLA_PRP_SLAVE2]));

	if (!link[0] || !link[1])
		return -ENODEV;
	if (link[0] == link[1])
		return -EINVAL;

	if (!data[IFLA_PRP_MULTICAST_SPEC])
		multicast_spec = 0;
	else
		multicast_spec = nla_get_u8(data[IFLA_PRP_MULTICAST_SPEC]);

	return hsr_prp_dev_finalize(dev, link, multicast_spec, PRP_V1);
}

static int prp_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct hsr_prp_priv *priv;
	struct hsr_prp_port *port;
	int res;

	priv = netdev_priv(dev);

	res = 0;

	rcu_read_lock();
	port = hsr_prp_get_port(priv, HSR_PRP_PT_SLAVE_A);
	if (port)
		res = nla_put_u32(skb, IFLA_PRP_SLAVE1, port->dev->ifindex);
	rcu_read_unlock();
	if (res)
		goto nla_put_failure;

	rcu_read_lock();
	port = hsr_prp_get_port(priv, HSR_PRP_PT_SLAVE_B);
	if (port)
		res = nla_put_u32(skb, IFLA_PRP_SLAVE2, port->dev->ifindex);
	rcu_read_unlock();
	if (res)
		goto nla_put_failure;

	if (nla_put(skb, IFLA_PRP_SUPERVISION_ADDR, ETH_ALEN,
		    priv->sup_multicast_addr) ||
	    nla_put_u16(skb, IFLA_PRP_SEQ_NR, priv->sequence_nr))
		goto nla_put_failure;

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

static struct rtnl_link_ops prp_link_ops __read_mostly = {
	.kind		= "prp",
	.maxtype	= IFLA_PRP_MAX,
	.policy		= prp_policy,
	.priv_size	= sizeof(struct hsr_prp_priv),
	.setup		= prp_dev_setup,
	.newlink	= prp_newlink,
	.fill_info	= prp_fill_info,
};

/* attribute policy */
/* NLA_BINARY missing in libnl; use NLA_UNSPEC in userspace instead. */
static const struct nla_policy prp_genl_policy[PRP_A_MAX + 1] = {
	[PRP_A_NODE_ADDR] = { .type = NLA_BINARY, .len = ETH_ALEN },
	[PRP_A_NODE_ADDR_B] = { .type = NLA_BINARY, .len = ETH_ALEN },
	[PRP_A_IFINDEX] = { .type = NLA_U32 },
	[PRP_A_IF1_AGE] = { .type = NLA_U32 },
	[PRP_A_IF2_AGE] = { .type = NLA_U32 },
	[PRP_A_IF1_SEQ] = { .type = NLA_U16 },
	[PRP_A_IF2_SEQ] = { .type = NLA_U16 },
};

static struct genl_family prp_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = "PRP",
	.version = 1,
	.maxattr = PRP_A_MAX,
};

static const struct genl_multicast_group hsr_mcgrps[] = {
	{ .name = "prp-network", },
};

/* This is called if for some node with MAC address addr, we only get frames
 * over one of the slave interfaces. This would indicate an open network ring
 * (i.e. a link has failed somewhere).
 */
/* This is called when we haven't heard from the node with MAC address addr for
 * some time (just before the node is removed from the node table/list).
 */
void prp_nl_nodedown(struct hsr_prp_priv *priv, unsigned char addr[ETH_ALEN])
{
	struct sk_buff *skb;
	void *msg_head;
	struct hsr_prp_port *master;
	int res;

	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!skb)
		goto fail;

	msg_head = genlmsg_put(skb, 0, 0, &prp_genl_family, 0, PRP_C_NODE_DOWN);
	if (!msg_head)
		goto nla_put_failure;

	res = nla_put(skb, PRP_A_NODE_ADDR, ETH_ALEN, addr);
	if (res < 0)
		goto nla_put_failure;

	genlmsg_end(skb, msg_head);
	genlmsg_multicast(&prp_genl_family, skb, 0, 0, GFP_ATOMIC);

	return;

nla_put_failure:
	kfree_skb(skb);

fail:
	rcu_read_lock();
	master = hsr_prp_get_port(priv, HSR_PRP_PT_MASTER);
	netdev_warn(master->dev, "Could not send PRP node down\n");
	rcu_read_unlock();
}

/* PRP_C_GET_NODE_STATUS lets userspace query the internal PRP node table
 * about the status of a specific node in the network, defined by its MAC
 * address.
 *
 * Input: hsr ifindex, node mac address
 * Output: hsr ifindex, node mac address (copied from request),
 *	   age of latest frame from node over slave 1, slave 2 [ms]
 */
static int prp_get_node_status(struct sk_buff *skb_in, struct genl_info *info)
{
	/* For receiving */
	struct nlattr *na;
	struct net_device *hsr_dev;

	/* For sending */
	struct sk_buff *skb_out;
	void *msg_head;
	struct hsr_prp_priv *priv;
	struct hsr_prp_port *port;
	unsigned char hsr_node_addr_b[ETH_ALEN];
	int hsr_node_if1_age;
	u16 hsr_node_if1_seq;
	int hsr_node_if2_age;
	u16 hsr_node_if2_seq;
	int addr_b_ifindex;
	int res;

	if (!info)
		goto invalid;

	na = info->attrs[PRP_A_IFINDEX];
	if (!na)
		goto invalid;
	na = info->attrs[PRP_A_NODE_ADDR];
	if (!na)
		goto invalid;

	hsr_dev = __dev_get_by_index(genl_info_net(info),
				     nla_get_u32(info->attrs[PRP_A_IFINDEX]));
	if (!hsr_dev)
		goto invalid;
	if (!is_hsr_prp_master(hsr_dev))
		goto invalid;

	/* Send reply */
	skb_out = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb_out) {
		res = -ENOMEM;
		goto fail;
	}

	msg_head = genlmsg_put(skb_out, NETLINK_CB(skb_in).portid,
			       info->snd_seq, &prp_genl_family, 0,
			       PRP_C_SET_NODE_STATUS);
	if (!msg_head) {
		res = -ENOMEM;
		goto nla_put_failure;
	}

	res = nla_put_u32(skb_out, PRP_A_IFINDEX, hsr_dev->ifindex);
	if (res < 0)
		goto nla_put_failure;

	priv = netdev_priv(hsr_dev);
	res = hsr_prp_get_node_data(
			priv,
			(unsigned char *)nla_data(info->attrs[PRP_A_NODE_ADDR]),
			hsr_node_addr_b,
			&addr_b_ifindex,
			&hsr_node_if1_age,
			&hsr_node_if1_seq,
			&hsr_node_if2_age,
			&hsr_node_if2_seq);
	if (res < 0)
		goto nla_put_failure;

	res = nla_put(skb_out, PRP_A_NODE_ADDR, ETH_ALEN,
		      nla_data(info->attrs[PRP_A_NODE_ADDR]));
	if (res < 0)
		goto nla_put_failure;

	if (addr_b_ifindex > -1) {
		res = nla_put(skb_out, PRP_A_NODE_ADDR_B, ETH_ALEN,
			      hsr_node_addr_b);
		if (res < 0)
			goto nla_put_failure;

		res = nla_put_u32(skb_out, PRP_A_ADDR_B_IFINDEX,
				  addr_b_ifindex);
		if (res < 0)
			goto nla_put_failure;
	}

	res = nla_put_u32(skb_out, PRP_A_IF1_AGE, hsr_node_if1_age);
	if (res < 0)
		goto nla_put_failure;
	res = nla_put_u16(skb_out, PRP_A_IF1_SEQ, hsr_node_if1_seq);
	if (res < 0)
		goto nla_put_failure;
	rcu_read_lock();
	port = hsr_prp_get_port(priv, HSR_PRP_PT_SLAVE_A);
	if (port)
		res = nla_put_u32(skb_out, PRP_A_IF1_IFINDEX,
				  port->dev->ifindex);
	rcu_read_unlock();
	if (res < 0)
		goto nla_put_failure;

	res = nla_put_u32(skb_out, PRP_A_IF2_AGE, hsr_node_if2_age);
	if (res < 0)
		goto nla_put_failure;
	res = nla_put_u16(skb_out, PRP_A_IF2_SEQ, hsr_node_if2_seq);
	if (res < 0)
		goto nla_put_failure;
	rcu_read_lock();
	port = hsr_prp_get_port(priv, HSR_PRP_PT_SLAVE_B);
	if (port)
		res = nla_put_u32(skb_out, PRP_A_IF2_IFINDEX,
				  port->dev->ifindex);
	rcu_read_unlock();
	if (res < 0)
		goto nla_put_failure;

	genlmsg_end(skb_out, msg_head);
	genlmsg_unicast(genl_info_net(info), skb_out, info->snd_portid);

	return 0;

invalid:
	netlink_ack(skb_in, nlmsg_hdr(skb_in), -EINVAL);
	return 0;

nla_put_failure:
	kfree_skb(skb_out);
	/* Fall through */

fail:
	return res;
}

/* Get a list of MacAddressA of all nodes known to this node (including self).
 */
static int prp_get_node_list(struct sk_buff *skb_in, struct genl_info *info)
{
	/* For receiving */
	struct nlattr *na;
	struct net_device *hsr_dev;

	/* For sending */
	struct sk_buff *skb_out;
	void *msg_head;
	struct hsr_prp_priv *priv;
	void *pos;
	unsigned char addr[ETH_ALEN];
	int res;

	if (!info)
		goto invalid;

	na = info->attrs[PRP_A_IFINDEX];
	if (!na)
		goto invalid;

	hsr_dev = __dev_get_by_index(genl_info_net(info),
				     nla_get_u32(info->attrs[PRP_A_IFINDEX]));
	if (!hsr_dev)
		goto invalid;
	if (!is_hsr_prp_master(hsr_dev))
		goto invalid;

	/* Send reply */
	skb_out = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb_out) {
		res = -ENOMEM;
		goto fail;
	}

	msg_head = genlmsg_put(skb_out, NETLINK_CB(skb_in).portid,
			       info->snd_seq, &prp_genl_family, 0,
			       PRP_C_SET_NODE_LIST);
	if (!msg_head) {
		res = -ENOMEM;
		goto nla_put_failure;
	}

	res = nla_put_u32(skb_out, PRP_A_IFINDEX, hsr_dev->ifindex);
	if (res < 0)
		goto nla_put_failure;

	priv = netdev_priv(hsr_dev);

	rcu_read_lock();
	pos = hsr_prp_get_next_node(priv, NULL, addr);
	while (pos) {
		if (!hsr_prp_addr_is_self(priv, addr)) {
			res = nla_put(skb_out, PRP_A_NODE_ADDR, ETH_ALEN, addr);
			if (res < 0) {
				rcu_read_unlock();
				goto nla_put_failure;
			}
		}
		pos = hsr_prp_get_next_node(priv, pos, addr);
	}
	rcu_read_unlock();

	genlmsg_end(skb_out, msg_head);
	genlmsg_unicast(genl_info_net(info), skb_out, info->snd_portid);

	return 0;

invalid:
	netlink_ack(skb_in, nlmsg_hdr(skb_in), -EINVAL);
	return 0;

nla_put_failure:
	kfree_skb(skb_out);
	/* Fall through */

fail:
	return res;
}

static const struct genl_ops hsr_ops[] = {
	{
		.cmd = PRP_C_GET_NODE_STATUS,
		.flags = 0,
		.policy = prp_genl_policy,
		.doit = prp_get_node_status,
		.dumpit = NULL,
	},
	{
		.cmd = PRP_C_GET_NODE_LIST,
		.flags = 0,
		.policy = prp_genl_policy,
		.doit = prp_get_node_list,
		.dumpit = NULL,
	},
};

int __init prp_netlink_init(void)
{
	int rc;

	rc = rtnl_link_register(&prp_link_ops);
	if (rc)
		goto fail_rtnl_link_register;

	rc = genl_register_family_with_ops_groups(&prp_genl_family, hsr_ops,
						  hsr_mcgrps);
	if (rc)
		goto fail_genl_register_family;

	return 0;

fail_genl_register_family:
	rtnl_link_unregister(&prp_link_ops);
fail_rtnl_link_register:

	return rc;
}

void __exit prp_netlink_exit(void)
{
	genl_unregister_family(&prp_genl_family);
	rtnl_link_unregister(&prp_link_ops);
}

MODULE_ALIAS_RTNL_LINK("prp");
