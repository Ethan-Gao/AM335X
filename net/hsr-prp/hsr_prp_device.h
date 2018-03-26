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

#ifndef __HSR_PRP_DEVICE_H
#define __HSR_PRP_DEVICE_H

#include <linux/netdevice.h>
#include "hsr_prp_main.h"

void hsr_dev_setup(struct net_device *dev);
void prp_dev_setup(struct net_device *dev);
int hsr_prp_dev_finalize(struct net_device *dev, struct net_device *slave[2],
			 unsigned char multicast_spec, u8 protocol_version);
void hsr_prp_check_carrier_and_operstate(struct hsr_prp_priv *priv);
bool is_hsr_prp_master(struct net_device *dev);
int hsr_prp_get_max_mtu(struct hsr_prp_priv *priv);

#endif /* __HSR_PRP_DEVICE_H */
