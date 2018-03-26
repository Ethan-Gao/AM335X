/*
 * Copyright (C) 2015-2017 Texas Instruments Incorporated - http://www.ti.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __ICSS_SWITCH_H
#define __ICSS_SWITCH_H

/* Basic Switch Parameters
 * Used to auto compute offset addresses on L3 OCMC RAM. Do not modify these
 * without changing firmware accordingly
 */
#define SWITCH_BUFFER_SIZE	(64 * 1024)	/* L3 buffer */
#define ICSS_BLOCK_SIZE		32		/* data bytes per BD */
#define BD_SIZE			4		/* byte buffer descriptor */
#define NUM_QUEUES		4		/* Queues on Port 0/1/2 */
#define QDESC_SIZE		8		/* byte queue descriptor */

#define PORT_LINK_MASK		0x1
#define PORT_IS_HD_MASK		0x2

/* NRT Buffer descriptor definition
 * Each buffer descriptor points to a max 32 byte block and has 32 bit in size
 * to have atomic operation.
 * PRU can address bytewise into memory.
 * Definition of 32 bit descriptor is as follows
 *
 * Bits		Name			Meaning
 * =============================================================================
 * 0..7		Index		points to index in buffer queue, max 256 x 32
 *				byte blocks can be addressed
 * 8..12	Block_length	number of valid bytes in this specific block.
 *				Will be <=32 bytes on last block of packet
 * 13		More		"More" bit indicating that there are more blocks
 * 14		Shadow		indicates that "index" is pointing into shadow
 *				buffer
 * 15		TimeStamp	indicates that this packet has time stamp in
 *				separate buffer - only needed of PTCP runs on
 *				host
 * 16..17	Port		different meaning for ingress and egress,
 *				Ingress: Port = 0 indicates phy port 1 and
 *				Port = 1 indicates phy port 2.
 *				Egress: 0 sends on phy port 1 and 1 sends on
 *				phy port 2. Port = 2 goes over MAC table
 *				look-up
 * 18..28	Length		11 bit of total packet length which is put into
 *				first BD only so that host access only one BD
 * 29		VlanTag		indicates that packet has Length/Type field of
 *				0x08100 with VLAN tag in following byte
 * 30		Broadcast	indicates that packet goes out on both physical
 *				ports,  there will be two bd but only one buffer
 * 31		Error		indicates there was an error in the packet
 */
#define PRUETH_BD_START_FLAG_MASK	BIT(0)
#define PRUETH_BD_START_FLAG_SHIFT	0

#define PRUETH_BD_HSR_FRAME_MASK	BIT(4)
#define PRUETH_BD_HSR_FRAME_SHIFT	4

#define PRUETH_BD_SUP_HSR_FRAME_MASK	BIT(5)
#define PRUETH_BD_SUP_HSR_FRAME_SHIFT	5

#define PRUETH_BD_LOOKUP_SUCCESS_MASK	BIT(6)
#define PRUETH_BD_LOOKUP_SUCCESS_SHIFT	6

#define	PRUETH_BD_SHADOW_MASK		BIT(14)
#define	PRUETH_BD_SHADOW_SHIFT		14

#define	PRUETH_BD_PORT_MASK		GENMASK(17, 16)
#define PRUETH_BD_PORT_SHIFT		16

#define	PRUETH_BD_LENGTH_MASK		GENMASK(28, 18)
#define PRUETH_BD_LENGTH_SHIFT		18

#define	PRUETH_BD_BROADCAST_MASK	BIT(30)
#define PRUETH_BD_BROADCAST_SHIFT	30

#define	PRUETH_BD_ERROR_MASK		BIT(31)
#define PRUETH_BD_ERROR_SHIFT		31

/* The following offsets indicate which sections of the memory are used
 * for EMAC internal tasks
 */
#define DRAM_START_OFFSET		0x1e98
#define SRAM_START_OFFSET		0x400

/* General Purpose Statistics
 * These are present on both PRU0 and PRU1 DRAM
 */
/* base statistics offset */
#define STATISTICS_OFFSET	0x1F00
#define STAT_SIZE		0x90

/* The following offsets indicate which sections of the memory are used
 * for switch internal tasks
 */
#define SWITCH_SPECIFIC_DRAM0_START_SIZE		0x100
#define SWITCH_SPECIFIC_DRAM0_START_OFFSET		0x1F00

#define SWITCH_SPECIFIC_DRAM1_START_SIZE		0x300
#define SWITCH_SPECIFIC_DRAM1_START_OFFSET		0x1D00

/* Offset for storing
 * 1. Storm Prevention Params
 * 2. PHY Speed Offset
 * 3. Port Status Offset
 * These are present on both PRU0 and PRU1
 */
/* 4 bytes */
#define STORM_PREVENTION_OFFSET		(STATISTICS_OFFSET + STAT_SIZE)
/* 4 bytes */
#define PHY_SPEED_OFFSET		(STATISTICS_OFFSET + STAT_SIZE + 4)
/* 1 byte */
#define PORT_STATUS_OFFSET		(STATISTICS_OFFSET + STAT_SIZE + 8)
/* 1 byte */
#define COLLISION_COUNTER		(STATISTICS_OFFSET + STAT_SIZE + 9)
/* 4 bytes */
#define RX_PKT_SIZE_OFFSET		(STATISTICS_OFFSET + STAT_SIZE + 10)
/* 4 bytes */
#define PORT_CONTROL_ADDR		(STATISTICS_OFFSET + STAT_SIZE + 14)
/* 6 bytes */
#define PORT_MAC_ADDR			(STATISTICS_OFFSET + STAT_SIZE + 18)
/* 1 byte */
#define RX_INT_STATUS_OFFSET		(STATISTICS_OFFSET + STAT_SIZE + 24)

/* DRAM1 Offsets for Switch */
/* 4 queue descriptors for port 0 (host receive) */
#define P0_QUEUE_DESC_OFFSET		0x1E7C
/* collision descriptor of port 0 */
#define P0_COL_QUEUE_DESC_OFFSET	0x1E64
/* Collision Status Register
 *    P0: bit 0 is pending flag, bit 1..2 inidicates which queue,
 *    P1: bit 8 is pending flag, 9..10 is queue number
 *    P2: bit 16 is pending flag, 17..18 is queue number, remaining bits are 0.
 */
#define COLLISION_STATUS_ADDR		0x1E60

#define INTERFACE_MAC_ADDR		0x1E58
#define P2_MAC_ADDR			0x1E50
#define P1_MAC_ADDR			0x1E48

#define QUEUE_SIZE_ADDR			0x1E30
#define QUEUE_OFFSET_ADDR		0x1E18
#define QUEUE_DESCRIPTOR_OFFSET_ADDR	0x1E00

#define COL_RX_CONTEXT_P2_OFFSET_ADDR	(COL_RX_CONTEXT_P1_OFFSET_ADDR + 12)
#define COL_RX_CONTEXT_P1_OFFSET_ADDR	(COL_RX_CONTEXT_P0_OFFSET_ADDR + 12)
#define COL_RX_CONTEXT_P0_OFFSET_ADDR	(P2_Q4_RX_CONTEXT_OFFSET + 8)

/* Port 2 Rx Context */
#define P2_Q4_RX_CONTEXT_OFFSET		(P2_Q3_RX_CONTEXT_OFFSET + 8)
#define P2_Q3_RX_CONTEXT_OFFSET		(P2_Q2_RX_CONTEXT_OFFSET + 8)
#define P2_Q2_RX_CONTEXT_OFFSET		(P2_Q1_RX_CONTEXT_OFFSET + 8)
#define P2_Q1_RX_CONTEXT_OFFSET		RX_CONTEXT_P2_Q1_OFFSET_ADDR
#define RX_CONTEXT_P2_Q1_OFFSET_ADDR	(P1_Q4_RX_CONTEXT_OFFSET + 8)

/* Port 1 Rx Context */
#define P1_Q4_RX_CONTEXT_OFFSET		(P1_Q3_RX_CONTEXT_OFFSET + 8)
#define P1_Q3_RX_CONTEXT_OFFSET		(P1_Q2_RX_CONTEXT_OFFSET + 8)
#define P1_Q2_RX_CONTEXT_OFFSET		(P1_Q1_RX_CONTEXT_OFFSET + 8)
#define P1_Q1_RX_CONTEXT_OFFSET		(RX_CONTEXT_P1_Q1_OFFSET_ADDR)
#define RX_CONTEXT_P1_Q1_OFFSET_ADDR	(P0_Q4_RX_CONTEXT_OFFSET + 8)

/* Host Port Rx Context */
#define P0_Q4_RX_CONTEXT_OFFSET		(P0_Q3_RX_CONTEXT_OFFSET + 8)
#define P0_Q3_RX_CONTEXT_OFFSET		(P0_Q2_RX_CONTEXT_OFFSET + 8)
#define P0_Q2_RX_CONTEXT_OFFSET		(P0_Q1_RX_CONTEXT_OFFSET + 8)
#define P0_Q1_RX_CONTEXT_OFFSET		RX_CONTEXT_P0_Q1_OFFSET_ADDR
#define RX_CONTEXT_P0_Q1_OFFSET_ADDR	(COL_TX_CONTEXT_P2_Q1_OFFSET_ADDR + 8)

/* Port 2 Tx Collision Context */
#define COL_TX_CONTEXT_P2_Q1_OFFSET_ADDR (COL_TX_CONTEXT_P1_Q1_OFFSET_ADDR + 8)
/* Port 1 Tx Collision Context */
#define COL_TX_CONTEXT_P1_Q1_OFFSET_ADDR (P2_Q4_TX_CONTEXT_OFFSET + 8)

/* Port 2 */
#define P2_Q4_TX_CONTEXT_OFFSET		(P2_Q3_TX_CONTEXT_OFFSET + 8)
#define P2_Q3_TX_CONTEXT_OFFSET		(P2_Q2_TX_CONTEXT_OFFSET + 8)
#define P2_Q2_TX_CONTEXT_OFFSET		(P2_Q1_TX_CONTEXT_OFFSET + 8)
#define P2_Q1_TX_CONTEXT_OFFSET		TX_CONTEXT_P2_Q1_OFFSET_ADDR
#define TX_CONTEXT_P2_Q1_OFFSET_ADDR	(P1_Q4_TX_CONTEXT_OFFSET + 8)

/* Port 1 */
#define P1_Q4_TX_CONTEXT_OFFSET		(P1_Q3_TX_CONTEXT_OFFSET + 8)
#define P1_Q3_TX_CONTEXT_OFFSET		(P1_Q2_TX_CONTEXT_OFFSET + 8)
#define P1_Q2_TX_CONTEXT_OFFSET		(P1_Q1_TX_CONTEXT_OFFSET + 8)
#define P1_Q1_TX_CONTEXT_OFFSET		TX_CONTEXT_P1_Q1_OFFSET_ADDR
#define TX_CONTEXT_P1_Q1_OFFSET_ADDR	SWITCH_SPECIFIC_DRAM1_START_OFFSET

/* Shared RAM Offsets for Switch */

/* DRAM Offsets for EMAC
 * Present on Both DRAM0 and DRAM1
 */

/* 4 queue descriptors for port tx = 32 bytes */
#define TX_CONTEXT_Q1_OFFSET_ADDR	(PORT_QUEUE_DESC_OFFSET + 32)
#define PORT_QUEUE_DESC_OFFSET	(ICSS_EMAC_TTS_CYC_TX_SOF + 8)

/* EMAC Time Triggered Send Offsets */
#define ICSS_EMAC_TTS_CYC_TX_SOF	(ICSS_EMAC_TTS_PREV_TX_SOF + 8)
#define ICSS_EMAC_TTS_PREV_TX_SOF	(ICSS_EMAC_TTS_MISSED_CYCLE_CNT_OFFSET + 4)
#define ICSS_EMAC_TTS_MISSED_CYCLE_CNT_OFFSET	(ICSS_EMAC_TTS_STATUS_OFFSET + 4)
#define ICSS_EMAC_TTS_STATUS_OFFSET	(ICSS_EMAC_TTS_CFG_TIME_OFFSET + 4)
#define ICSS_EMAC_TTS_CFG_TIME_OFFSET	(ICSS_EMAC_TTS_CYCLE_PERIOD_OFFSET + 4)
#define ICSS_EMAC_TTS_CYCLE_PERIOD_OFFSET	(ICSS_EMAC_TTS_CYCLE_START_OFFSET + 8)
#define ICSS_EMAC_TTS_CYCLE_START_OFFSET	ICSS_EMAC_TTS_BASE_OFFSET
#define ICSS_EMAC_TTS_BASE_OFFSET	DRAM_START_OFFSET

/* Shared RAM offsets for EMAC */
#define EMAC_P0_Q1_DESC_OFFSET_AFTER_BD	72

/* Promiscuous mode control */
#define EMAC_P1_PROMISCUOUS_BIT		BIT(0)
#define EMAC_P2_PROMISCUOUS_BIT		BIT(1)
/* EMAC_PROMISCUOUS_MODE_OFFSET is relative to EOF_48K_BUFFER_BD. Since
 * we calculate the offsets dynamically, define it as 4 relative to
 * eof_48k_buffer_bd in prueth_mmap_sram_cfg
 */
#define EMAC_PROMISCUOUS_MODE_OFFSET	4

/* Shared RAM offsets for both Switch and EMAC */
#define P0_Q1_BD_OFFSET		SRAM_START_OFFSET

/* Memory Usage of L3 OCMC RAM */
/* L3 64KB Memory - mainly buffer Pool */
#define P0_COL_BUFFER_OFFSET    0xEE00
#define P0_Q1_BUFFER_OFFSET	0x0000

/* The below bit will be set in BD for EMAC mode in the egress
 * direction and reset for PRP mode
 */
#define PRUETH_TX_PRP_EMAC_MODE	BIT(0)

#endif /* __ICSS_SWITCH_H */
