/*
 * PRU Ethernet driver
 *
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

#ifndef __NET_TI_PRUETH_H
#define __NET_TI_PRUETH_H

#include <linux/hrtimer.h>
#include <linux/kthread.h>
#include <linux/pruss.h>
#include "icss_switch.h"
#include "icss_time_sync.h"

/**
 * struct prueth_queue_desc - Queue descriptor
 * @rd_ptr:	Read pointer, points to a buffer descriptor in Shared PRU RAM.
 * @wr_ptr:	Write pointer, points to a buffer descriptor in Shared PRU RAM.
 * @busy_s:	Slave queue busy flag, set by slave(us) to request access from
 *		master(PRU).
 * @status:	Bit field status register, Bits:
 *			0: Master queue busy flag.
 *			1: Packet has been placed in collision queue.
 *			2: Packet has been discarded due to overflow.
 * @max_fill_level:	Maximum queue usage seen.
 * @overflow_cnt:	Count of queue overflows.
 *
 * Each port has up to 4 queues with variable length. The queue is processed
 * as ring buffer with read and write pointers. Both pointers are address
 * pointers and increment by 4 for each buffer descriptor position. Queue has
 * a length defined in constants and a status.
 */
struct prueth_queue_desc {
	u16 rd_ptr;
	u16 wr_ptr;
	u8 busy_s;
	u8 status;
	u8 max_fill_level;
	u8 overflow_cnt;
} __packed;

/* status flags */
#define PRUETH_MASTER_QUEUE_BUSY		BIT(0)
#define PRUETH_PACKET_IN_COLLISION_QUEUE	BIT(1)
#define PRUETH_PACKET_DISCARD_OVFL		BIT(2)
/**
 * struct prueth_queue - Information about a queue in memory
 * @buffer_offset: buffer offset in OCMC RAM
 * @queue_desc_offset: queue descriptor offset in Shared RAM
 * @buffer_desc_offset: buffer descriptors offset in Shared RAM
 * @buffer_desc_end: end address of buffer descriptors in Shared RAM
 */
struct prueth_queue_info {
	u16 buffer_offset;
	u16 queue_desc_offset;
	u16 buffer_desc_offset;
	u16 buffer_desc_end;
} __packed;

struct prueth_col_rx_context_info {
	u16 buffer_offset;
	u16 buffer_offset2;
	u16 queue_desc_offset;
	u16 buffer_desc_offset;
	u16 buffer_desc_end;
} __packed;

struct prueth_col_tx_context_info {
	u16 buffer_offset;
	u16 buffer_offset2;
	u16 buffer_offset_end;
} __packed;

/**
 * struct prueth_packet_info - Info about a packet in buffer
 * @shadow: this packet is stored in the collision queue
 * @port: port packet is on
 * @length: length of packet
 * @broadcast: this packet is a broadcast packet
 * @error: this packet has an error
 * @sv_frame: this packet is a supper frame
 */
struct prueth_packet_info {
	bool start_offset;
	bool shadow;
	unsigned int port;
	unsigned int length;
	bool broadcast;
	bool error;
	bool sv_frame;
	bool lookup_success;
	u32 bd; /* +++WMK: dbg only: original bd */
};

/**
 * struct port_statistics - Statistics structure for capturing statistics
 *			    on PRUs
 * @tx_bcast: Number of broadcast packets sent
 * @tx_mcast:Number of multicast packets sent
 * @tx_ucast:Number of unicast packets sent
 *
 * @tx_octets:Number of undersized frames rcvd
 *
 * @rx_bcast:Number of broadcast packets rcvd
 * @rx_mcast:Number of multicast packets rcvd
 * @rx_ucast:Number of unicast packets rcvd
 *
 * @rx_octets:Number of Rx packets
 *
 * @tx64byte:Number of 64 byte packets sent
 * @tx65_127byte:Number of 65-127 byte packets sent
 * @tx128_255byte:Number of 128-255 byte packets sent
 * @tx256_511byte:Number of 256-511 byte packets sent
 * @tx512_1023byte:Number of 512-1023 byte packets sent
 * @tx1024byte:Number of 1024 and larger size packets sent
 *
 * @rx64byte:Number of 64 byte packets rcvd
 * @rx65_127byte:Number of 65-127 byte packets rcvd
 * @rx128_255byte:Number of 128-255 byte packets rcvd
 * @rx256_511byte:Number of 256-511 byte packets rcvd
 * @rx512_1023byte:Number of 512-1023 byte packets rcvd
 * @rx1024byte:Number of 1024 and larger size packets rcvd
 *
 * @late_coll:Number of late collisions(Half Duplex)
 * @single_coll:Number of single collisions (Half Duplex)
 * @multi_coll:Number of multiple collisions (Half Duplex)
 * @excess_coll:Number of excess collisions(Half Duplex)
 *
 * @rx_misalignment_frames:Number of non multiple of 8 byte frames rcvd
 * @stormprev_counter:Number of packets dropped because of Storm Prevention
 * @mac_rxerror:Number of MAC receive errors
 * @sfd_error:Number of invalid SFD
 * @def_tx:Number of transmissions deferred
 * @mac_txerror:Number of MAC transmit errors
 * @rx_oversized_frames:Number of oversized frames rcvd
 * @rx_undersized_frames:Number of undersized frames rcvd
 * @rx_crc_frames:Number of CRC error frames rcvd
 * @dropped_packets:Number of packets dropped due to link down on opposite port
 *
 * @tx_hwq_overflow:Hardware Tx Queue (on PRU) over flow count
 * @tx_hwq_underflow:Hardware Tx Queue (on PRU) under flow count
 *
 * @u32 cs_error: Number of carrier sense errors
 * @sqe_test_error: Number of MAC receive errors
 *
 * The fields here are aligned here so that it's consistent
 * with the memory layout in PRU DRAM, this is to facilitate easy
 * memcpy. Don't change the order of the fields.
 */
struct port_statistics {
	u32 tx_bcast;			/* 0x1F00 */
	u32 tx_mcast;
	u32 tx_ucast;

	u32 tx_octets;

	u32 rx_bcast;			/* 0x1F10 */
	u32 rx_mcast;
	u32 rx_ucast;

	u32 rx_octets;

	u32 tx64byte;			/* 0x1F20 */
	u32 tx65_127byte;
	u32 tx128_255byte;
	u32 tx256_511byte;
	u32 tx512_1023byte;		/* 0x1F30 */
	u32 tx1024byte;

	u32 rx64byte;
	u32 rx65_127byte;
	u32 rx128_255byte;		/* 0x1F40 */
	u32 rx256_511byte;
	u32 rx512_1023byte;
	u32 rx1024byte;

	u32 late_coll;			/* 0x1F50 */
	u32 single_coll;
	u32 multi_coll;
	u32 excess_coll;

	u32 rx_misalignment_frames;	/* 0x1F60 */
	u32 stormprev_counter;
	u32 mac_rxerror;
	u32 sfd_error;
	u32 def_tx;
	u32 mac_txerror;
	u32 rx_oversized_frames;
	u32 rx_undersized_frames;
	u32 rx_crc_frames;
	u32 dropped_packets;

	u32 tx_hwq_overflow;
	u32 tx_hwq_underflow;

	u32 cs_error;
	u32 sqe_test_error;
} __packed;

struct lre_statistics {
	u32 cnt_tx_a;
	u32 cnt_tx_b;
	u32 cnt_tx_c;

	u32 cnt_errwronglan_a;
	u32 cnt_errwronglan_b;
	u32 cnt_errwronglan_c;

	u32 cnt_rx_a;
	u32 cnt_rx_b;
	u32 cnt_rx_c;

	u32 cnt_errors_a;
	u32 cnt_errors_b;
	u32 cnt_errors_c;

	u32 cnt_nodes;
	u32 cnt_proxy_nodes;

	u32 cnt_unique_rx_a;
	u32 cnt_unique_rx_b;
	u32 cnt_unique_rx_c;

	u32 cnt_duplicate_rx_a;
	u32 cnt_duplicate_rx_b;
	u32 cnt_duplicate_rx_c;

	u32 cnt_multiple_rx_a;
	u32 cnt_multiple_rx_b;
	u32 cnt_multiple_rx_c;

	u32 cnt_own_rx_a;
	u32 cnt_own_rx_b;

	u32 duplicate_discard;
	u32 transparent_reception;

	u32 node_table_lookup_error_a;
	u32 node_table_lookup_error_b;
	u32 node_table_full;

	/* additional debug counters */
	u32 lre_total_rx_a; /* count of all frames received at port-A */
	u32 lre_total_rx_b; /* count of all frames received at port-B */
	u32 lre_overflow_pru0; /* count of overflow frames to host on PRU 0 */
	u32 lre_overflow_pru1; /* count of overflow frames to host on PRU 1 */
	u32 lre_cnt_dd_pru0; /* count of DD frames to host on PRU 0 */
	u32 lre_cnt_dd_pru1; /* count of DD frames to host on PRU 1 */
	u32 lre_cnt_sup_pru0; /* count of supervisor frames to host on PRU 0 */
	u32 lre_cnt_sup_pru1; /* count of supervisor frames to host on PRU 1 */
} __packed;

struct prueth_hsr_prp_node {
	u8 mac[6];
	u8 state;
	u8 status;

	u32 cnt_rx_a;
	u32 cnt_rx_b;

	u32 prp_lid_err_a;
	u32 prp_lid_err_b;

	u8 cnt_rx_sup_a;
	u8 cnt_rx_sup_b;
	u16 time_last_seen_sup;

	u16 time_last_seen_a;
	u16 time_last_seen_b;
} __packed;

#define OCMC_RAM_SIZE		(SZ_64K - SZ_8K)

/* Pn_COL_BUFFER_OFFSET @ 0xEE00 0xF400 0xFA00 */
#define OCMC_RAM_SIZE_SWITCH	(SZ_64K)

/* TX Minimum Inter packet gap */
#define TX_MIN_IPG		0xb8

#define TX_START_DELAY		0x40
#define TX_CLK_DELAY		0x6

/* PRUSS local memory map */
#define ICSS_LOCAL_SHARED_RAM   0x00010000

/* Netif debug messages possible */
#define PRUETH_EMAC_DEBUG	(NETIF_MSG_DRV | \
				 NETIF_MSG_PROBE | \
				 NETIF_MSG_LINK | \
				 NETIF_MSG_TIMER | \
				 NETIF_MSG_IFDOWN | \
				 NETIF_MSG_IFUP | \
				 NETIF_MSG_RX_ERR | \
				 NETIF_MSG_TX_ERR | \
				 NETIF_MSG_TX_QUEUED | \
				 NETIF_MSG_INTR | \
				 NETIF_MSG_TX_DONE | \
				 NETIF_MSG_RX_STATUS | \
				 NETIF_MSG_PKTDATA | \
				 NETIF_MSG_HW | \
				 NETIF_MSG_WOL)

#define EMAC_MAX_PKTLEN		(ETH_HLEN + VLAN_HLEN + ETH_DATA_LEN)
#define EMAC_MIN_PKTLEN		(60)

enum pruss_device {
	PRUSS_AM57XX = 0,
	PRUSS_AM4376,
	PRUSS_AM3359,
	PRUSS_K2G
};

#define PRUSS0 0
#define PRUSS1 1
#define PRUSS2 2

/* PRU Ethernet Type - Ethernet functionality (protocol
 * implemented) provided by the PRU firmware being loaded.
 */
enum pruss_ethtype {
	PRUSS_ETHTYPE_EMAC = 0,
	PRUSS_ETHTYPE_HSR,
	PRUSS_ETHTYPE_PRP,
	PRUSS_ETHTYPE_SWITCH,
	PRUSS_ETHTYPE_MAX,
};

#define HSR_TAG_LEN		(10)
#define EMAC_MAX_PKTLEN_HSR	(EMAC_MAX_PKTLEN + HSR_TAG_LEN)
#define PRUETH_IS_EMAC(p)	((p)->eth_type == PRUSS_ETHTYPE_EMAC)
#define PRUETH_IS_HSR(p)	((p)->eth_type == PRUSS_ETHTYPE_HSR)
#define PRUETH_IS_PRP(p)	((p)->eth_type == PRUSS_ETHTYPE_PRP)
#define PRUETH_IS_SWITCH(p)	((p)->eth_type == PRUSS_ETHTYPE_SWITCH)

#define PRUETH_HAS_HSR(p)	PRUETH_IS_HSR(p)
#define PRUETH_HAS_PRP(p)	PRUETH_IS_PRP(p)
#define PRUETH_HAS_RED(p)	(PRUETH_HAS_HSR(p) || PRUETH_HAS_PRP(p))

#define PRUETH_HAS_SWITCH(p) \
	(PRUETH_IS_SWITCH(p) || PRUETH_HAS_HSR(p) || PRUETH_HAS_PRP(p))

#define MS_TO_NS(msec)		((msec) * 1000 * 1000)
#define PRUETH_RED_TABLE_CHECK_PERIOD_MS	10
#define PRUETH_HAS_PTP(p)       PRUETH_HAS_PRP(p)
/* A group of PCPs are mapped to a Queue. This is the size of firmware
 * array in shared memory
 */
#define PCP_GROUP_TO_QUEUE_MAP_SIZE	8

/* In switch mode there are 3 real ports i.e. 3 mac addrs.
 * however Linux sees only the host side port. The other 2 ports
 * are the switch ports.
 * In emac mode there are 2 real ports i.e. 2 mac addrs.
 * Linux sees both the ports.
 */
enum prueth_port {
	PRUETH_PORT_HOST = 0,	/* host side port */
	PRUETH_PORT_MII0,	/* physical port MII 0 */
	PRUETH_PORT_MII1,	/* physical port MII 1 */
	PRUETH_PORT_MAX,
};

/* In both switch & emac modes there are 3 port queues
 * EMAC mode:
 *	RX packets for both MII0 & MII1 ports come on
 *	QUEUE_HOST.
 *	TX packets for MII0 go on QUEUE_MII0, TX packets
 *	for MII1 go on QUEUE_MII1.
 * Switch mode:
 *	Host port RX packets come on QUEUE_HOST
 *	TX packets might have to go on MII0 or MII1 or both.
 *	MII0 TX queue is QUEUE_MII0 and MII1 TX queue is
 *	QUEUE_MII1.
 */
enum prueth_port_queue_id {
	PRUETH_PORT_QUEUE_HOST = 0,
	PRUETH_PORT_QUEUE_MII0,
	PRUETH_PORT_QUEUE_MII1,
	PRUETH_PORT_QUEUE_MII0_RX,
	PRUETH_PORT_QUEUE_MII1_RX,
	PRUETH_PORT_QUEUE_MAX,
};

#define NUM_RX_QUEUES	(NUM_QUEUES / 2)
/* Each port queue has 4 queues and 1 collision queue */
enum prueth_queue_id {
	PRUETH_QUEUE1 = 0,
	PRUETH_QUEUE2,
	PRUETH_QUEUE3,
	PRUETH_QUEUE4,
	PRUETH_COLQ,	/* collision queue */
};

/* PRUeth memory range identifiers */
enum prueth_mem {
	PRUETH_MEM_DRAM0 = 0,
	PRUETH_MEM_DRAM1,
	PRUETH_MEM_SHARED_RAM,
	PRUETH_MEM_IEP,
	PRUETH_MEM_MII,
	PRUETH_MEM_OCMC,
	PRUETH_MEM_MAX,
};

/**
 * @fw_name: firmware names of firmware to run on PRU
 */
struct prueth_firmwares {
	const char *fw_name[PRUSS_ETHTYPE_MAX];
};

/**
 * struct prueth_private_data - PRU Ethernet private data
 * @driver_data: soc that contains the pruss
 * @fw_pru: firmware to run on each pruss
 */
struct prueth_private_data {
	enum pruss_device driver_data;
	struct prueth_firmwares fw_pru[PRUSS_NUM_PRUS];
};

/* data for each emac port */
struct prueth_emac {
	struct prueth *prueth;
	struct net_device *ndev;
	struct sk_buff *tx_ev_msg[PTP_PDLY_RSP_MSG_ID + 1]; /* tx ev needs ts */
	u8 mac_addr[6];
	u32 msg_enable;

	int link;
	int speed;
	int duplex;

	const char *phy_id;
	struct device_node *phy_node;
	int phy_if;
	struct phy_device *phydev;

	enum prueth_port port_id;
	/* emac mode irqs */
	int rx_irq;
	int tx_irq;

	struct prueth_queue_desc __iomem *rx_queue_descs;
	struct prueth_queue_desc __iomem *tx_queue_descs;
	struct prueth_queue_desc __iomem *tx_colq_descs;

	unsigned int prp_emac_mode;
	struct port_statistics stats; /* stats holder when i/f is down */
	u32 tx_collisions;
	u32 tx_collision_drops;
	u32 rx_overflows;
	u32 tx_packet_counts[NUM_QUEUES];
	u32 rx_packet_counts[NUM_RX_QUEUES];

	spinlock_t lock;	/* serialize access */
#ifdef	CONFIG_DEBUG_FS
	struct dentry *root_dir;
	struct dentry *stats_file;
	struct dentry *prp_emac_mode_file;
#endif
	int ptp_tx_enable;
	int ptp_rx_enable;
	int ptp_tx_irq;
};

struct prueth_mmap_port_cfg_basis {
	u16 queue_size[NUM_QUEUES];
	u16 queue1_bd_offset;
	u16 queue1_buff_offset;
	u16 queue1_desc_offset;
	u16 col_queue_size;
	u16 col_bd_offset;
	u16 col_buff_offset;
	u16 col_queue_desc_offset;
};

struct prueth_mmap_sram_emac {
	u16 icss_emac_firmware_release_1_offset;  /* = eof_48k_buffer_bd */
	u16 icss_emac_firmware_release_2_offset;  /* +4 */

	u16 host_q1_rx_context_offset;            /* +4 */
	u16 host_q2_rx_context_offset;            /* +8 */
	u16 host_q3_rx_context_offset;            /* +8 */
	u16 host_q4_rx_context_offset;            /* +8 */

	u16 host_queue_descriptor_offset_addr;    /* +8 */
	u16 host_queue_offset_addr;               /* +8 */
	u16 host_queue_size_addr;                 /* +8 */
	u16 host_queue_desc_offset;               /* +16 */
};

struct prueth_mmap_sram_sw {
	u16 col_bd_offset[PRUETH_PORT_MAX];
};

struct prueth_mmap_sram_cfg {
	/* P0_Q1_BD_OFFSET = SRAM_START_OFFSET */
	u16 bd_offset[PRUETH_PORT_MAX][NUM_QUEUES];

	u16 end_of_bd_pool;
	u16 port_bd_size;
	u16 host_bd_size;
	u16 eof_48k_buffer_bd;

	union {
		struct prueth_mmap_sram_sw   mmap_sram_sw;
		struct prueth_mmap_sram_emac mmap_sram_emac;
	};
};

struct prueth_mmap_ocmc_cfg {
	u16 buffer_offset[PRUETH_PORT_MAX][NUM_QUEUES];
};

/**
 * struct prueth - PRUeth structure
 * @dev: device
 * @pruss: pruss handle
 * @pru0: rproc instance to PRU0
 * @pru1: rproc instance to PRU1
 * @mem: PRUSS memory resources we need to access
 * @sram_pool: OCMC ram pool for buffers
 *
 * @eth_node: node for each emac node
 * @emac: emac data for three ports, one host and two physical
 * @registered_netdevs: net device for each registered emac
 * @fw_data: firmware names to be used with PRU remoteprocs
 * @pruss_id: PRUSS instance id
 */
struct prueth {
	struct device *dev;
	struct pruss *pruss;
	struct rproc *pru0, *pru1;
	struct pruss_mem_region mem[PRUETH_MEM_MAX];
	struct gen_pool *sram_pool;

	struct device_node *eth_node[PRUETH_PORT_MAX];
	struct device_node *prueth_np;
	struct prueth_emac *emac[PRUETH_PORT_MAX];
	struct net_device *registered_netdevs[PRUETH_PORT_MAX];
	const struct prueth_private_data *fw_data;
	int pruss_id;
	size_t ocmc_ram_size;
	unsigned int eth_type;
	unsigned int hsr_mode;
	unsigned int emac_configured;
	unsigned int tbl_check_period;
	unsigned int node_table_clear;
	unsigned int tbl_check_mask;
	struct hrtimer tbl_check_timer;
	struct prueth_mmap_port_cfg_basis mmap_port_cfg_basis[PRUETH_PORT_MAX];
	struct prueth_mmap_sram_cfg mmap_sram_cfg;
	struct prueth_mmap_ocmc_cfg mmap_ocmc_cfg;
	struct lre_statistics lre_stats;
	struct iep *iep;
	/* To provide a synchronization point to wait before proceed to port
	 * specific initialization or configuration. This is needed when
	 * concurrent device open happens.
	 */
	struct mutex mlock;
#ifdef	CONFIG_DEBUG_FS
	struct dentry *root_dir;
	struct dentry *node_tbl_file;
	struct dentry *nt_clear_file;
	struct dentry *hsr_mode_file;
	struct dentry *dlrmt_file;
	struct dentry *dd_file;
	struct dentry *tr_file;
	struct dentry *error_stats_file;
	struct dentry *new_nt_index;
	struct dentry *new_nt_bins;
#endif
	struct node_tbl	*nt;
	struct nt_queue_t *mac_queue;
	struct kthread_worker *nt_kworker;
	struct kthread_work    nt_work;
	u32		rem_cnt;
	spinlock_t	nt_lock;
};

#endif /* __NET_TI_PRUETH_H */
