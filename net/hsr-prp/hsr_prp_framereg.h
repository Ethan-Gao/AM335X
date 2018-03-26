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

#ifndef __HSR_PRP_FRAMEREG_H
#define __HSR_PRP_FRAMEREG_H

#include "hsr_prp_main.h"

struct hsr_prp_node;

struct hsr_prp_node *hsr_prp_add_node(struct list_head *node_db,
				      unsigned char addr[], u16 seq_out,
				      bool san,
				      enum hsr_prp_port_type rx_port);
struct hsr_prp_node *hsr_prp_get_node(struct list_head *node_db,
				      struct sk_buff *skb, bool is_sup,
				      enum hsr_prp_port_type rx_port);
void hsr_prp_handle_sup_frame(struct sk_buff *skb,
			      struct hsr_prp_node *node_curr,
			      struct hsr_prp_port *port);
bool hsr_prp_addr_is_self(struct hsr_prp_priv *priv, unsigned char *addr);

void hsr_addr_subst_source(struct hsr_prp_node *node, struct sk_buff *skb);
void hsr_addr_subst_dest(struct hsr_prp_node *node_src, struct sk_buff *skb,
			 struct hsr_prp_port *port);

void hsr_register_frame_in(struct hsr_prp_node *node,
			   struct hsr_prp_port *port, u16 sequence_nr);
int hsr_register_frame_out(struct hsr_prp_port *port,
			   struct hsr_prp_node *node,
			   u16 sequence_nr);

void hsr_prp_prune_nodes(unsigned long data);

int hsr_prp_create_self_node(struct list_head *self_node_db,
			     unsigned char addr_a[ETH_ALEN],
			     unsigned char addr_b[ETH_ALEN]);

void *hsr_prp_get_next_node(struct hsr_prp_priv *priv, void *_pos,
			    unsigned char addr[ETH_ALEN]);

int hsr_prp_get_node_data(struct hsr_prp_priv *priv,
			  const unsigned char *addr,
			  unsigned char addr_b[ETH_ALEN],
			  unsigned int *addr_b_ifindex,
			  int *if1_age, u16 *if1_seq,
			  int *if2_age, u16 *if2_seq);

struct hsr_prp_node {
	struct list_head	mac_list;
	unsigned char		mac_address_a[ETH_ALEN];
	unsigned char		mac_address_b[ETH_ALEN];
	/* Local slave through which AddrB frames are received from this node */
	enum hsr_prp_port_type	addr_b_port;
	u32			cnt_received_a;
	u32			cnt_received_b;
	u32			cnt_err_wrong_lan_a;
	u32			cnt_err_wrong_lan_b;
	unsigned long		time_in[HSR_PRP_PT_PORTS];
	bool			time_in_stale[HSR_PRP_PT_PORTS];
	/* if the node is a SAN */
	bool			san_a;
	bool			san_b;
	u16			seq_out[HSR_PRP_PT_PORTS];
	struct rcu_head		rcu_head;
};

#endif /* __HSR_PRP_FRAMEREG_H */
