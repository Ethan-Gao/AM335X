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

#include <linux/debugfs.h>
#include <linux/string.h>
#include <linux/spinlock_types.h>
#include "pruss_node_tbl.h"

#define IND_BINOFS(x) nt->index_tbl[x].bin_offset
#define IND_BIN_NO(x) nt->index_tbl[x].bin_no_entries
#define BIN_NODEOFS(x) nt->bin_tbl[x].node_tbl_offset

static void pru2host_mac(u8 *mac)
{
	swap(mac[0], mac[3]);
	swap(mac[1], mac[2]);
	swap(mac[4], mac[5]);
}

static u16 get_hash(u8 *mac)
{
	int j;
	u16 hash;

	for (j = 0, hash = 0; j < ETHER_ADDR_LEN; j++)
		hash ^= mac[j];

	return hash;
}

/* TODO: ??? 2 PRUs can use the same lock2 */
static void get_lock(struct node_tbl *nt)
{
	while (1) {
		nt->lock = 1;
		if (!nt->lock2)
			break;
		nt->lock = 0;
	}
}

int node_table_insert(struct prueth *prueth, u8 *mac, int port, int sv_frame,
		      int proto, spinlock_t *lock)
{
	struct nt_queue_t *q = prueth->mac_queue;
	unsigned long flags;
	int ret = RED_OK;

	spin_lock_irqsave(lock, flags);
	if (q->full) {
		ret = RED_ERR;
	} else {
		memcpy(q->nt_queue[q->wr_ind].mac, mac, ETHER_ADDR_LEN);
		q->nt_queue[q->wr_ind].sv_frame = sv_frame;
		q->nt_queue[q->wr_ind].port_id = port;
		q->nt_queue[q->wr_ind].proto = proto;

		q->wr_ind++;
		q->wr_ind &= (MAC_QUEUE_MAX - 1);
		if (q->wr_ind == q->rd_ind)
			q->full = true;
	}
	spin_unlock_irqrestore(lock, flags);

	return ret;
}

static inline void lre_cnt_nodes_clear(struct node_tbl *nt)
{
	u32 *lre_cnt_nodes = (u32 *)((void *)nt + 192 - 0x3000);
	*lre_cnt_nodes = 0;
}

static inline void lre_cnt_nodes_inc(struct node_tbl *nt)
{
	u32 *lre_cnt_nodes = (u32 *)((void *)nt + 192 - 0x3000);
	*lre_cnt_nodes += 1;
}

static inline void lre_cnt_nodes_dec(struct node_tbl *nt)
{
	u32 *lre_cnt_nodes = (u32 *)((void *)nt + 192 - 0x3000);
	*lre_cnt_nodes -= 1;
}

static inline bool node_expired(struct node_tbl *nt, u16 node, u16 forget_time)
{
	return ((nt->node_tbl[node].time_last_seen_s > forget_time ||
		 nt->node_tbl[node].status & NT_REM_NODE_TYPE_SANAB) &&
		nt->node_tbl[node].time_last_seen_a > forget_time &&
		nt->node_tbl[node].time_last_seen_b > forget_time);
}

void node_table_init(struct prueth *prueth)
{
	int	j;
	struct node_tbl *nt = prueth->nt;
	struct nt_queue_t *q = prueth->mac_queue;

	lre_cnt_nodes_clear(nt);
	memset(nt, 0, sizeof(struct node_tbl));

	for (j = 0; j < INDEX_TBL_MAX_ENTRIES; j++)
		IND_BINOFS(j) = BIN_TBL_MAX_ENTRIES;

	for (j = 0; j < BIN_TBL_MAX_ENTRIES; j++)
		BIN_NODEOFS(j) = NODE_TBL_MAX_ENTRIES;

	for (j = 0; j < NODE_TBL_MAX_ENTRIES; j++)
		nt->node_tbl[j].entry_state = NODE_FREE;

	q->rd_ind = 0;
	q->wr_ind = 0;
	q->full = false;
}

static u16 find_free_bin(struct node_tbl *nt)
{
	u16 j;

	for (j = 0; j < BIN_TBL_MAX_ENTRIES; j++)
		if (BIN_NODEOFS(j) == NODE_TBL_MAX_ENTRIES)
			break;

	return j;
}

/* find first free node table slot and write it to the next_free_slot */
static u16 next_free_slot_update(struct node_tbl *nt)
{
	int j;

	nt->next_free_slot = NODE_TBL_MAX_ENTRIES;
	for (j = 0; j < NODE_TBL_MAX_ENTRIES; j++) {
		if (nt->node_tbl[j].entry_state == NODE_FREE) {
			nt->next_free_slot = j;
			break;
		}
	}

	return nt->next_free_slot;
}

static void inc_time(u16 *t)
{
	*t += 1;
	if (*t > MAX_FORGET_TIME)
		*t = MAX_FORGET_TIME;
}

void node_table_update_time(struct node_tbl *nt)
{
	int j;
	u16 ofs;

	for (j = 0; j < BIN_TBL_MAX_ENTRIES; j++) {
		ofs = nt->bin_tbl[j].node_tbl_offset;
		if (ofs < NODE_TBL_MAX_ENTRIES) {
			inc_time(&nt->node_tbl[ofs].time_last_seen_a);
			inc_time(&nt->node_tbl[ofs].time_last_seen_b);
			/* increment time_last_seen_s if nod is not SAN */
			if ((nt->node_tbl[ofs].status & NT_REM_NODE_TYPE_SANAB)
			    == 0)
				inc_time(&nt->node_tbl[ofs].time_last_seen_s);
		}
	}
}

static void write2node_slot(struct node_tbl *nt, u16 node, int port,
			    int sv_frame, int proto)
{
	memset(&nt->node_tbl[node], 0, sizeof(struct node_tbl_t));
	nt->node_tbl[node].entry_state = NODE_TAKEN;

	if (port == 0x01) {
		nt->node_tbl[node].status = NT_REM_NODE_TYPE_SANA;
		nt->node_tbl[node].cnt_ra = 1;
		if (sv_frame)
			nt->node_tbl[node].cnt_rx_sup_a = 1;
	} else {
		nt->node_tbl[node].status = NT_REM_NODE_TYPE_SANB;
		nt->node_tbl[node].cnt_rb = 1;
		if (sv_frame)
			nt->node_tbl[node].cnt_rx_sup_b = 1;
	}

	if (sv_frame) {
		nt->node_tbl[node].status = (proto == RED_PROTO_PRP) ?
			NT_REM_NODE_TYPE_DAN :
			NT_REM_NODE_TYPE_DAN | NT_REM_NODE_HSR_BIT;
	}
}

/* We assume that the _start_ cannot point to middle of a bin */
static void update_indexes(u16 start, u16 end, struct node_tbl *nt)
{
	u16 hash, hash_prev;

	hash_prev = 0xffff; /* invalid hash */
	for (; start <= end; start++) {
		hash = get_hash(nt->bin_tbl[start].src_mac_id);
		if (hash != hash_prev)
			IND_BINOFS(hash) = start;
		hash_prev = hash;
	}
}

/* start > end */
static void move_up(u16 start, u16 end, struct node_tbl *nt,
		    bool update)
{
	u16 j = end;

	get_lock(nt);

	for (; j < start; j++)
		memcpy(&nt->bin_tbl[j], &nt->bin_tbl[j + 1],
		       sizeof(struct bin_tbl_t));

	BIN_NODEOFS(start) = NODE_TBL_MAX_ENTRIES;

	if (update)
		update_indexes(end, start + 1, nt);

	nt->lock = 0;
}

/* start < end */
static void move_down(u16 start, u16 end, struct node_tbl *nt,
		      bool update)
{
	u16 j = end;

	get_lock(nt);

	for (; j > start; j--)
		memcpy(&nt->bin_tbl[j], &nt->bin_tbl[j - 1],
		       sizeof(struct bin_tbl_t));

	nt->bin_tbl[start].node_tbl_offset = NODE_TBL_MAX_ENTRIES;

	if (update)
		update_indexes(start + 1, end, nt);

	nt->lock = 0;
}

static int node_table_insert_from_queue(struct node_tbl *nt,
					struct nt_queue_entry *entry)
{
	u8 macid[ETHER_ADDR_LEN];
	u16 hash;
	u16 index;
	u16 free_node;
	bool not_found;
	u16 empty_slot;

	if (!nt)
		return RED_ERR;

	memcpy(macid, entry->mac, ETHER_ADDR_LEN);
	pru2host_mac(macid);

	hash = get_hash(macid);

	not_found = 1;
	if (IND_BIN_NO(hash) == 0) {
		/* there is no bin for this hash, create one */
		index = find_free_bin(nt);
		if (index == BIN_TBL_MAX_ENTRIES)
			return RED_ERR;

		IND_BINOFS(hash) = index;
	} else {
		for (index = IND_BINOFS(hash);
		     index < IND_BINOFS(hash) + IND_BIN_NO(hash); index++) {
			if ((memcmp(nt->bin_tbl[index].src_mac_id,
				    macid, ETHER_ADDR_LEN) == 0)) {
				not_found = 0;
				break;
			}
		}
	}

	if (not_found) {
		free_node = next_free_slot_update(nt);

		/* at this point we might create a new bin and set
		 * bin_offset at the index table. It was only possible
		 * if we found a free slot in the bin table.
		 * So, it also must be a free slot in the node table
		 * and we will not exit here in this case.
		 * So, be don't have to take care about fixing IND_BINOFS()
		 * on return RED_ERR
		 */
		if (free_node >= NODE_TBL_MAX_ENTRIES)
			return RED_ERR;

		/* if we are here, we have at least one empty slot in the bin
		 * table and one slot at the node table
		 */

		IND_BIN_NO(hash)++;

		/* look for an empty slot downwards */
		for (empty_slot = index;
		     (BIN_NODEOFS(empty_slot) != NODE_TBL_MAX_ENTRIES) &&
		     (empty_slot < NODE_TBL_MAX_ENTRIES);
		     empty_slot++)
			;

		/* if emptySlot != maxNodes => empty slot is found,
		 * else no space available downwards, look upwards
		 */
		if (empty_slot != NODE_TBL_MAX_ENTRIES) {
			move_down(index, empty_slot, nt, true);
		} else {
			for (empty_slot = index - 1;
			     (BIN_NODEOFS(empty_slot) != NODE_TBL_MAX_ENTRIES)
			     && (empty_slot > 0);
			     empty_slot--)
				;
			/* we're sure to get a space here as nodetable
			 * has a empty slot, so no need to check for
			 * value of emptySlot
			 */
			move_up(index, empty_slot, nt, true);
		}

		/* space created, now populate the values*/
		BIN_NODEOFS(index) = free_node;
		memcpy(nt->bin_tbl[index].src_mac_id, macid, ETHER_ADDR_LEN);
		write2node_slot(nt, free_node, entry->port_id, entry->sv_frame,
				entry->proto);

		lre_cnt_nodes_inc(nt);
	}

	return RED_OK;
}


void node_table_check_and_remove(struct node_tbl *nt, u16 forget_time)
{
	int j, end_bin;
	u16 node;
	u16 hash;

	/*loop to remove a node reaching NODE_FORGET_TIME*/
	for (j = 0; j < BIN_TBL_MAX_ENTRIES; j++) {
		node = BIN_NODEOFS(j);
		if (node >= NODE_TBL_MAX_ENTRIES)
			continue;

		if (node_expired(nt, node, forget_time)) {
			hash = get_hash(nt->bin_tbl[j].src_mac_id);

			/* remove entry from bin array */
			end_bin = IND_BINOFS(hash) + IND_BIN_NO(hash) - 1;

			move_up(end_bin, j, nt, false);
			(IND_BIN_NO(hash))--;

			if (!IND_BIN_NO(hash))
				IND_BINOFS(hash) = BIN_TBL_MAX_ENTRIES;

			nt->node_tbl[node].entry_state = NODE_FREE;
			BIN_NODEOFS(end_bin) = NODE_TBL_MAX_ENTRIES;

			lre_cnt_nodes_dec(nt);
		}
	}
}

/****************************************************************************/
static int pop_queue(struct prueth *prueth, spinlock_t *lock)
{
	unsigned long flags;
	struct node_tbl *nt = prueth->nt;
	struct nt_queue_t *q = prueth->mac_queue;
	struct nt_queue_entry one_mac;
	int ret = 0;

	spin_lock_irqsave(lock, flags);
	if (!q->full && (q->wr_ind == q->rd_ind)) { /* queue empty */
		ret = 1;
	} else {
		memcpy(&one_mac, &(q->nt_queue[q->rd_ind]),
		       sizeof(struct nt_queue_entry));
		spin_unlock_irqrestore(lock, flags);
		node_table_insert_from_queue(nt, &one_mac);
		spin_lock_irqsave(lock, flags);
		q->rd_ind++;
		q->rd_ind &= (MAC_QUEUE_MAX - 1);
		q->full = false;
	}
	spin_unlock_irqrestore(lock, flags);

	return ret;
}

void pop_queue_process(struct prueth *prueth, spinlock_t *lock)
{
	while (pop_queue(prueth, lock) == 0)
		;
}

/* indexes */
static int
prueth_new_nt_index_show(struct seq_file *sfp, void *data)
{
	struct node_tbl *nt = (struct node_tbl *)sfp->private;
	int j;
	int cnt_i = 0;
	int cnt_b = 0;

	for (j = 0; j < INDEX_TBL_MAX_ENTRIES; j++)
		if ((IND_BINOFS(j) < BIN_TBL_MAX_ENTRIES) &&
		    (IND_BIN_NO(j) > 0)) {
			seq_printf(sfp, "%3d; ofs %3d; no %3d\n", j,
				   IND_BINOFS(j), IND_BIN_NO(j));
			cnt_i++;
			cnt_b += IND_BIN_NO(j);
		}

	seq_printf(sfp, "\nTotal indexes %d; bins %d;\n", cnt_i, cnt_b);

	return 0;
}

static int
prueth_new_nt_index_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, prueth_new_nt_index_show,
			   inode->i_private);
}

const struct file_operations prueth_new_nt_index_fops = {
	.owner	= THIS_MODULE,
	.open	= prueth_new_nt_index_open,
	.read	= seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* bins */
static int
prueth_new_nt_bins_show(struct seq_file *sfp, void *data)
{
	struct node_tbl *nt = (struct node_tbl *)sfp->private;
	int j, o;
	int cnt = 0;

	for (j = 0; j < BIN_TBL_MAX_ENTRIES; j++)
		if (nt->bin_tbl[j].node_tbl_offset < NODE_TBL_MAX_ENTRIES) {
			o = nt->bin_tbl[j].node_tbl_offset;
			seq_printf(sfp, "%3d; ofs %3d; %02x-%02x-%02x-%02x-%02x-%02x %02x %02x ra %4d; rb %4d; s%5d; a%5d; b%5d\n",
				   j, nt->bin_tbl[j].node_tbl_offset,
				   nt->bin_tbl[j].src_mac_id[3],
				   nt->bin_tbl[j].src_mac_id[2],
				   nt->bin_tbl[j].src_mac_id[1],
				   nt->bin_tbl[j].src_mac_id[0],
				   nt->bin_tbl[j].src_mac_id[5],
				   nt->bin_tbl[j].src_mac_id[4],
				   nt->node_tbl[o].entry_state,
				   nt->node_tbl[o].status,
				   nt->node_tbl[o].cnt_ra,
				   nt->node_tbl[o].cnt_rb,
				   nt->node_tbl[o].time_last_seen_s,
				   nt->node_tbl[o].time_last_seen_a,
				   nt->node_tbl[o].time_last_seen_b
				   );
			cnt++;
		}
	seq_printf(sfp, "\nTotal valid entries %d\n", cnt);

	return 0;
}

static int
prueth_new_nt_bins_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, prueth_new_nt_bins_show,
			   inode->i_private);
}

const struct file_operations prueth_new_nt_bins_fops = {
	.owner	= THIS_MODULE,
	.open	= prueth_new_nt_bins_open,
	.read	= seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
