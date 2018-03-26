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

#ifndef __HSR_PRP_FORWARD_H
#define __HSR_PRP_FORWARD_H

#include <linux/netdevice.h>
#include "hsr_prp_main.h"

void hsr_prp_forward_skb(struct sk_buff *skb, struct hsr_prp_port *port);

#endif /* __HSR_PRP_FORWARD_H */
