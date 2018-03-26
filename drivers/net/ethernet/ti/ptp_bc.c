/*
 * TI PTP Boundary Clock Internal Sync Monitor
 *
 * Copyright (C) 2015-2017 Texas Instruments Incorporated - http://www.ti.com

 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/module.h>
#include <linux/platform_device.h>

#include "ptp_bc.h"

#define PTP_BC_MAGIC 0x1ffffff
#define MAX_CLKS 3

static unsigned int bc_clocks_registered;
static u32 bc_clk_sync_enabled;
static spinlock_t bc_sync_lock; /* protects bc var */
static bool ptp_bc_initialized;

static inline int bc_clock_is_registered(int clkid)
{
	return (bc_clocks_registered & BIT(clkid));
}

static int ptp_bc_alloc_clk_id(void)
{
	int i;

	for (i = 0; i < MAX_CLKS; i++) {
		if (!bc_clock_is_registered(i)) {
			bc_clocks_registered |= BIT(i);
			return i;
		}
	}

	return -1;
}

static void ptp_bc_free_clk_id(int clkid)
{
	if (clkid >= 0 && clkid < MAX_CLKS)
		bc_clocks_registered &= ~BIT(clkid);
}

bool ptp_bc_clock_sync_enable(int clkid, int enable)
{
	unsigned long flags;
	bool allow = false;

	if (clkid < 0 || clkid >= MAX_CLKS)
		return false;

	spin_lock_irqsave(&bc_sync_lock, flags);

	if (!bc_clock_is_registered(clkid)) {
		spin_unlock_irqrestore(&bc_sync_lock, flags);
		return false;
	}

	if (enable) {
		if (bc_clk_sync_enabled) {
			/* request to enable but someone has already enabled
			 * regardless this someone is the requesting clkid
			 * itself or not.
			 */
			allow = false;
		} else {
			/* request to enable and none is enabled */
			bc_clk_sync_enabled |= BIT(clkid);
			allow = true;
		}
	} else {
		bc_clk_sync_enabled &= ~BIT(clkid);
		allow = true;
	}

	spin_unlock_irqrestore(&bc_sync_lock, flags);

	pr_info("ptp_bc_clk_sync_enable: Req clk=%d, %s, %s. ClkSyncEn(mask): 0x%08x\n",
		clkid,
		(enable ? "on" : "off"),
		(allow  ? "OK" : "Failed"),
		bc_clk_sync_enabled);

	return allow;
}
EXPORT_SYMBOL_GPL(ptp_bc_clock_sync_enable);

int ptp_bc_clock_register(void)
{
	unsigned long flags;
	int id = -1;

	if (!ptp_bc_initialized) {
		pr_info("ptp_bc error: NOT initialized.\n");
		return -1;
	}

	spin_lock_irqsave(&bc_sync_lock, flags);
	id = ptp_bc_alloc_clk_id();
	spin_unlock_irqrestore(&bc_sync_lock, flags);

	if (id < 0)
		pr_err("ptp_bc register error: max clocks allowed %d\n",
		       MAX_CLKS);

	return id;
}
EXPORT_SYMBOL_GPL(ptp_bc_clock_register);

void ptp_bc_clock_unregister(int clkid)
{
	unsigned long flags;

	if (!ptp_bc_initialized)
		return;

	spin_lock_irqsave(&bc_sync_lock, flags);
	ptp_bc_free_clk_id(clkid);
	spin_unlock_irqrestore(&bc_sync_lock, flags);
}
EXPORT_SYMBOL_GPL(ptp_bc_clock_unregister);

static int ptp_bc_probe(struct platform_device *pdev)
{
	spin_lock_init(&bc_sync_lock);
	bc_clk_sync_enabled = 0;
	bc_clocks_registered = 0;
	ptp_bc_initialized  = true;
	return 0;
}

static int ptp_bc_remove(struct platform_device *pdev)
{
	ptp_bc_initialized = false;
	return 0;
}

static const struct of_device_id ptp_bc_dt_match[] = {
	{ .compatible = "ti,am57-bc", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, prueth_dt_match);

static struct platform_driver ptp_bc_driver = {
	.probe = ptp_bc_probe,
	.remove = ptp_bc_remove,
	.driver = {
		.name = "ptp bc",
		.of_match_table = ptp_bc_dt_match,
	},
};
module_platform_driver(ptp_bc_driver);

MODULE_AUTHOR("WingMan Kwok <w-kwok2@ti.com>");
MODULE_DESCRIPTION("TI PTP Boundary Clock Internal Sync Monitor");
MODULE_LICENSE("GPL v2");
