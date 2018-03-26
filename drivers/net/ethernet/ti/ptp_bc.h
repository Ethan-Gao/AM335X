/*
 * Texas Instruments Ethernet Switch Driver
 *
 * Copyright (C) 2017 Texas Instruments
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
#ifndef _TI_PTP_BC_H_
#define _TI_PTP_BC_H_

#if IS_ENABLED(CONFIG_TI_PTP_BC)
int ptp_bc_clock_register(void);
void ptp_bc_clock_unregister(int clkid);
bool ptp_bc_clock_sync_enable(int clkid, int enable);
#else
static int ptp_bc_clock_register(void)
{
	return -1;
}

static int ptp_bc_clock_unregister(int clkid)
{
}

static bool ptp_bc_clock_sync_enable(int clkid, int enable)
{
	return true;
}
#endif
#endif
