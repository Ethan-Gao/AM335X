/*
 * prp_main.c: hsr initialization code. This is based on hsr_main.c
 *
 * Copyright (C) 2017 Texas Instruments Incorporated
 *
 * Author(s):
 *	Murali Karicheri <m-karicheri2@ti.com>
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
#include "prp_netlink.h"

static int __init prp_init(void)
{
	int res;

	res = hsr_prp_register_notifier(PRP);
	if (!res)
		res = prp_netlink_init();

	return res;
}

static void __exit prp_exit(void)
{
	hsr_prp_unregister_notifier(PRP);
	prp_netlink_exit();
}

module_init(prp_init);
MODULE_LICENSE("GPL");
