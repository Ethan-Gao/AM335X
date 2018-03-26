/*
 * prp_netlink.h: This is based on hsr_netlink.h from Arvid Brodin,
 * arvid.brodin@alten.se
 *
 * Copyright (C) 2017 Texas Instruments Incorporated
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * Author(s):
 *	2017 Murali Karicheri <m-karicheri2@ti.com>
 */

#ifndef __UAPI_PRP_NETLINK_H
#define __UAPI_PRP_NETLINK_H

/* Generic Netlink PRP family definition
 */

/* attributes */
enum {
	PRP_A_UNSPEC,
	PRP_A_NODE_ADDR,
	PRP_A_IFINDEX,
	PRP_A_IF1_AGE,
	PRP_A_IF2_AGE,
	PRP_A_NODE_ADDR_B,
	PRP_A_IF1_SEQ,
	PRP_A_IF2_SEQ,
	PRP_A_IF1_IFINDEX,
	PRP_A_IF2_IFINDEX,
	PRP_A_ADDR_B_IFINDEX,
	__PRP_A_MAX,
};
#define PRP_A_MAX (__PRP_A_MAX - 1)


/* commands */
enum {
	PRP_C_UNSPEC,
	PRP_C_NODE_DOWN,
	PRP_C_GET_NODE_STATUS,
	PRP_C_SET_NODE_STATUS,
	PRP_C_GET_NODE_LIST,
	PRP_C_SET_NODE_LIST,
	__PRP_C_MAX,
};
#define PRP_C_MAX (__PRP_C_MAX - 1)

#endif /* __UAPI_PRP_NETLINK_H */
