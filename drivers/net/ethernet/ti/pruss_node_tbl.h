/*
 * Copyright (C) 2017 Texas Instruments Incorporated - http://www.ti.com
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
#ifndef __NET_TI_PRUSS_NODE_TBL_H
#define __NET_TI_PRUSS_NODE_TBL_H

#include <linux/kernel.h>
#include <linux/debugfs.h>
#include "prueth.h"

#define INDEX_TBL_MAX_ENTRIES	256
#define BIN_TBL_MAX_ENTRIES	256
#define NODE_TBL_MAX_ENTRIES	256
#define MAX_FORGET_TIME		0xffdf
#define NODE_FREE		0x10
#define NODE_TAKEN		0x01

#define RED_PROTO_HSR	0
#define RED_PROTO_PRP	1

#define ETHER_ADDR_LEN 6

#define RED_OK	0
#define RED_ERR	-1

#define NT_REM_NODE_TYPE_SANA         0x01 /* Node entry type of : SANA */
#define NT_REM_NODE_TYPE_SANB         0x02 /* Node entry type of : SANB */
#define NT_REM_NODE_TYPE_SANAB        0x03 /* Node entry type of : SANAB */
#define NT_REM_NODE_TYPE_DAN          0x04 /* Node entry type of : DAN */
#define NT_REM_NODE_TYPE_REDBOX       0x08 /* Node entry type of : REDBOX */
#define NT_REM_NODE_TYPE_VDAN         0x10 /* Node entry type of : VDAN */
#define NT_REM_NODE_HSR_BIT           0x20 /*  if set node is HSR */

#define MAC_QUEUE_MAX_SHIFT 6
#define MAC_QUEUE_MAX (1 << MAC_QUEUE_MAX_SHIFT)

struct node_index_tbl_t {
	u16 bin_offset;
	u16 bin_no_entries;
	u8  lin_bin;	/* 0 - linear; 1 - binary; */
	u8  res1;
} __packed;

struct bin_tbl_t {
	u8 src_mac_id[ETHER_ADDR_LEN];
	u16 node_tbl_offset;
} __packed;

struct node_tbl_t {
	u8 mac[ETHER_ADDR_LEN];
	u8  entry_state;
	u8  status;
	u32 cnt_ra;
	u32 cnt_rb;
	u32 err_wla;
	u32 err_wlb;
	u8  cnt_rx_sup_a;
	u8  cnt_rx_sup_b;
	u16 time_last_seen_s;
	u16 time_last_seen_a;
	u16 time_last_seen_b;
} __packed;

struct node_tbl {
	struct node_index_tbl_t index_tbl[INDEX_TBL_MAX_ENTRIES];
	struct bin_tbl_t	bin_tbl[BIN_TBL_MAX_ENTRIES];
	struct node_tbl_t	node_tbl[NODE_TBL_MAX_ENTRIES];
	u16 next_free_slot;
	u16 res1;
	u8  lock;
	u8  lock2;
	u8  res2[2];
} __packed;

/* NT queue definitions */
struct nt_queue_entry {
	u8 mac[ETHER_ADDR_LEN];
	int sv_frame:1;
	int proto:1;
	int port_id:6;
};

struct nt_queue_t {
	struct nt_queue_entry nt_queue[MAC_QUEUE_MAX];
	int rd_ind;
	int wr_ind;
	bool full;
};

void node_table_init(struct prueth *prueth);
void node_table_update_time(struct node_tbl *nt);
void node_table_check_and_remove(struct node_tbl *nt, u16 forget_time);
int node_table_insert(struct prueth *prueth, u8 *mac, int port, int sv_frame,
		      int proto, spinlock_t *lock);

void pop_queue_process(struct prueth *prueth, spinlock_t *lock);

extern const struct file_operations prueth_new_nt_index_fops;
extern const struct file_operations prueth_new_nt_bins_fops;

#endif /* __NET_TI_PRUSS_NODE_TBL_H */
