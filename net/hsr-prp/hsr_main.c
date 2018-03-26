/*
 * hsr_main.c: hsr initialization code. This is moved from
 * hsr_prp_main.c
 *
 * Copyright (C) 2017 Texas Instruments Incorporated
 * Copyright 2011-2014 Autronica Fire and Security AS
 *
 * Author(s):
 *	2011-2014 Arvid Brodin, arvid.brodin@alten.se
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

#include <linux/netdevice.h>
#include "hsr_prp_main.h"
#include "hsr_netlink.h"

static int __init hsr_init(void)
{
	int res;

	BUILD_BUG_ON(sizeof(struct hsr_tag) != HSR_PRP_HLEN);

	res = hsr_prp_register_notifier(HSR);
	if (!res)
		res = hsr_netlink_init();

	return res;
}

static void __exit hsr_exit(void)
{
	hsr_prp_unregister_notifier(HSR);
	hsr_netlink_exit();
}

module_init(hsr_init);
MODULE_LICENSE("GPL");
