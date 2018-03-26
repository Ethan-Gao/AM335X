/*
 * prp_netlink.h:
 * This is based on hsr_netlink.h from Arvid Brodin, arvid.brodin@alten.se
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
#ifndef __PRP_NETLINK_H
#define __PRP_NETLINK_H

#include <linux/if_ether.h>
#include <linux/module.h>
#include <uapi/linux/prp_netlink.h>

struct hsr_prp_priv;
struct hsr_prp_port;

int __init prp_netlink_init(void);
void __exit prp_netlink_exit(void);

void prp_nl_nodedown(struct hsr_prp_priv *priv, unsigned char addr[ETH_ALEN]);

#endif /* __PRP_NETLINK_H */
