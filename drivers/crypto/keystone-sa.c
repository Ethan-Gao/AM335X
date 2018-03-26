/*
 * Keystone crypto accelerator driver
 *
 * Copyright (C) 2015, 2016 Texas Instruments Incorporated - http://www.ti.com
 *
 * Authors:	Sandeep Nair
 *		Vitaly Andrianov
 *
 * Contributors:Tinku Mannan
 *		Hao Zhang
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#include <linux/clk.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/dmapool.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/regmap.h>
#include <linux/mfd/syscon.h>
#include <linux/soc/ti/knav_dma.h>
#include <linux/soc/ti/knav_qmss.h>
#include <linux/soc/ti/knav_helpers.h>
#include <crypto/des.h>
#include "keystone-sa.h"
#include "keystone-sa-hlp.h"

#define SA_ATTR(_name, _mode, _show, _store) \
	struct sa_kobj_attribute sa_attr_##_name = \
__ATTR(_name, _mode, _show, _store)

#define to_sa_kobj_attr(_attr) \
	container_of(_attr, struct sa_kobj_attribute, attr)
#define to_crypto_data_from_stats_obj(obj) \
	container_of(obj, struct keystone_crypto_data, stats_kobj)

struct device *sa_ks2_dev;
/**
 * sa_allocate_rx_buf() - Allocate ONE receive buffer for Rx descriptors
 * @dev_data:	struct keystone_crypto_data pinter
 * @fdq:	fdq index.
 *
 * This function allocates rx buffers and push them to the free descripto
 * queue (fdq).
 *
 * An RX channel may have up to 4 free descriptor queues (fdq 0-3). Each
 * queue may keep buffer with one particular size.
 * SA crypto driver allocates buffers for the first queue with size
 * 1500 bytes. All other queues have buffers with one page size.
 * Hardware descriptors are taken from rx_pool, filled with buffer's address
 * and size and pushed to a corresponding to the fdq index rx_fdq.
 *
 * Return: function returns -ENOMEM in case of error, 0 otherwise
 */
static int sa_allocate_rx_buf(struct keystone_crypto_data *dev_data,
			       int fdq)
{
	struct device *dev = &dev_data->pdev->dev;
	struct knav_dma_desc *hwdesc;
	unsigned int buf_len, dma_sz;
	u32 desc_info, pkt_info;
	void *bufptr;
	struct page *page;
	dma_addr_t dma;
	u32 sw_data[2];

	/* Allocate descriptor */
	hwdesc = knav_pool_desc_get(dev_data->rx_pool);
	if (IS_ERR_OR_NULL(hwdesc)) {
		dev_dbg(dev, "out of rx pool desc\n");
		return -ENOMEM;
	}

	if (fdq == 0) {
		buf_len = SA_RX_BUF0_SIZE;
		bufptr = kmalloc(buf_len, GFP_ATOMIC | GFP_DMA | __GFP_COLD);
		if (unlikely(!bufptr)) {
			dev_warn_ratelimited(dev, "Primary RX buffer alloc failed\n");
			goto fail;
		}
		dma = dma_map_single(dev, bufptr, buf_len, DMA_TO_DEVICE);
		sw_data[0] = (u32)bufptr;
		sw_data[1] = 0;
	} else {
		/* Allocate a secondary receive queue entry */
		page = alloc_page(GFP_ATOMIC | GFP_DMA | __GFP_COLD);
		if (unlikely(!page)) {
			dev_warn_ratelimited(dev, "Secondary page alloc failed\n");
			goto fail;
		}
		buf_len = PAGE_SIZE;
		dma = dma_map_page(dev, page, 0, buf_len, DMA_TO_DEVICE);
		sw_data[0] = (u32)page_address(page);
		sw_data[1] = (u32)page;

		atomic_inc(&dev_data->rx_dma_page_cnt);
	}

	desc_info =  KNAV_DMA_DESC_PS_INFO_IN_DESC;
	desc_info |= buf_len & KNAV_DMA_DESC_PKT_LEN_MASK;
	pkt_info =  KNAV_DMA_DESC_HAS_EPIB;
	pkt_info |= KNAV_DMA_NUM_PS_WORDS << KNAV_DMA_DESC_PSLEN_SHIFT;
	pkt_info |= (dev_data->rx_compl_qid & KNAV_DMA_DESC_RETQ_MASK) <<
		    KNAV_DMA_DESC_RETQ_SHIFT;
	hwdesc->orig_buff = dma;
	hwdesc->orig_len = buf_len;
	hwdesc->sw_data[0] = sw_data[0];
	hwdesc->sw_data[1] = sw_data[1];
	hwdesc->desc_info = desc_info;
	hwdesc->packet_info = pkt_info;

	/* Push to FDQs */
	knav_pool_desc_map(dev_data->rx_pool, hwdesc, sizeof(*hwdesc), &dma,
			   &dma_sz);
	knav_queue_push(dev_data->rx_fdq[fdq], dma, sizeof(*hwdesc), 0);

	return 0;
fail:
	knav_pool_desc_put(dev_data->rx_pool, hwdesc);
	return -ENOMEM;
}

/* Refill Rx FDQ with descriptors & attached buffers */
static int sa_rxpool_refill(struct keystone_crypto_data *dev_data)
{
	struct device *dev = &dev_data->pdev->dev;
	u32 fdq_deficit;
	int i;
	int ret = 0;

	/* Calculate the FDQ deficit and refill */
	for (i = 0; i < KNAV_DMA_FDQ_PER_CHAN && dev_data->rx_fdq[i] && !ret;
	     i++) {
		fdq_deficit = dev_data->rx_queue_depths[i] -
			knav_queue_get_count(dev_data->rx_fdq[i]);
		while (fdq_deficit--) {
			ret = sa_allocate_rx_buf(dev_data, i);
			if (ret) {
				dev_err(dev, "cannot allocate rx_buffer\n");
				break;
			}
		}
	} /* end for fdqs */

	return ret;
}

/* Release ALL descriptors and attached buffers from Rx FDQ */
static int sa_free_rx_buf(struct keystone_crypto_data *dev_data,
			   int fdq)
{
	struct device *dev = &dev_data->pdev->dev;

	struct knav_dma_desc *desc;
	unsigned int buf_len, dma_sz;
	dma_addr_t dma;
	void *buf_ptr;

	while ((dma = knav_queue_pop(dev_data->rx_fdq[fdq], &dma_sz))) {
		desc = knav_pool_desc_unmap(dev_data->rx_pool, dma, dma_sz);
		if (unlikely(!desc)) {
			dev_err(dev, "failed to unmap Rx desc\n");
			return -EIO;
		}
		dma = desc->orig_buff;
		buf_len = desc->orig_len;
		buf_ptr = (void *)desc->sw_data[0];

		if (unlikely(!dma)) {
			dev_err(dev, "NULL orig_buff in desc\n");
			knav_pool_desc_put(dev_data->rx_pool, desc);
			return -EIO;
		}

		if (unlikely(!buf_ptr)) {
			dev_err(dev, "NULL bufptr in desc\n");
			knav_pool_desc_put(dev_data->rx_pool, desc);
			return -EIO;
		}

		if (fdq == 0) {
			dma_unmap_single(dev, dma, buf_len, DMA_FROM_DEVICE);
			kfree(buf_ptr);
		} else {
			dma_unmap_page(dev, dma, buf_len, DMA_FROM_DEVICE);
			__free_page(buf_ptr);
		}

		knav_pool_desc_put(dev_data->rx_pool, desc);
	}

	return 0;
}

static int sa_rxpool_free(struct keystone_crypto_data *dev_data)
{
	struct device *dev = &dev_data->pdev->dev;
	int i;
	int	ret = 0;

	for (i = 0; i < KNAV_DMA_FDQ_PER_CHAN && dev_data->rx_fdq[i] != NULL;
	     i++) {
		ret = sa_free_rx_buf(dev_data, i);
		WARN_ON(ret);
		if (ret)
			return ret;
	}

	if (knav_pool_count(dev_data->rx_pool) != dev_data->rx_pool_size) {
		dev_err(dev, "Lost Rx (%d) descriptors %d/%d\n",
			dev_data->rx_pool_size -
			knav_pool_count(dev_data->rx_pool),
			dev_data->rx_pool_size,
			knav_pool_count(dev_data->rx_pool));
		return -EIO;
	}

	knav_pool_destroy(dev_data->rx_pool);
	dev_data->rx_pool = NULL;
	return ret;
}

/* DMA channel rx notify callback */
static void sa_dma_notify_rx_compl(void *arg)
{
	struct keystone_crypto_data *dev_data = arg;

	knav_queue_disable_notify(dev_data->rx_compl_q);
	tasklet_schedule(&dev_data->rx_task);
}

/* Rx tast tasklet code */
static void sa_rx_task(unsigned long data)
{
	struct keystone_crypto_data *dev_data =
		(struct keystone_crypto_data *)data;

	sa_rx_completion_process(dev_data);

	sa_rxpool_refill(dev_data);
	knav_queue_enable_notify(dev_data->rx_compl_q);
}

/* DMA channel tx notify callback */
static void sa_dma_notify_tx_compl(void *arg)
{
	struct keystone_crypto_data *dev_data = arg;

	knav_queue_disable_notify(dev_data->tx_compl_q);
	tasklet_schedule(&dev_data->tx_task);
}

/* Tx task tasklet code */
static void sa_tx_task(unsigned long data)
{
	struct keystone_crypto_data *dev_data =
		(struct keystone_crypto_data *)data;

	sa_tx_completion_process(dev_data);
	knav_queue_enable_notify(dev_data->tx_compl_q);
}

static int sa_free_resources(struct keystone_crypto_data *dev_data)
{
	int	i;
	int ret = 0;

	if (!IS_ERR_OR_NULL(dev_data->tx_chan)) {
		knav_dma_close_channel(dev_data->tx_chan);
		dev_data->tx_chan = NULL;
	}

	if (!IS_ERR_OR_NULL(dev_data->rx_chan)) {
		knav_dma_close_channel(dev_data->rx_chan);
		dev_data->rx_chan = NULL;
	}

	if (!IS_ERR_OR_NULL(dev_data->tx_submit_q)) {
		knav_queue_close(dev_data->tx_submit_q);
		dev_data->tx_submit_q = NULL;
	}

	if (!IS_ERR_OR_NULL(dev_data->tx_compl_q)) {
		knav_queue_close(dev_data->tx_compl_q);
		dev_data->tx_compl_q = NULL;
	}

	if (!IS_ERR_OR_NULL(dev_data->tx_pool)) {
		knav_pool_destroy(dev_data->tx_pool);
		dev_data->tx_pool = NULL;
	}

	if (!IS_ERR_OR_NULL(dev_data->rx_compl_q)) {
		knav_queue_close(dev_data->rx_compl_q);
		dev_data->rx_compl_q = NULL;
	}

	if (!IS_ERR_OR_NULL(dev_data->rx_pool))
		ret = sa_rxpool_free(dev_data);

	for (i = 0; i < KNAV_DMA_FDQ_PER_CHAN && dev_data->rx_fdq[i] != NULL;
	     i++) {
		knav_queue_close(dev_data->rx_fdq[i]);
		dev_data->rx_fdq[i] = NULL;
	}
	return ret;
}

static int sa_setup_resources(struct keystone_crypto_data *dev_data)
{
	struct device *dev = &dev_data->pdev->dev;
	u8	name[20];
	int	ret = 0;
	int	i;

	snprintf(name, sizeof(name), "rx-pool-%s", dev_name(dev));
	dev_data->rx_pool = knav_pool_create(name, dev_data->rx_pool_size,
					     dev_data->rx_pool_region_id);
	if (IS_ERR_OR_NULL(dev_data->rx_pool)) {
		dev_err(dev, "Couldn't create rx pool\n");
		return PTR_ERR(dev_data->rx_pool);
	}

	snprintf(name, sizeof(name), "tx-pool-%s", dev_name(dev));
	dev_data->tx_pool = knav_pool_create(name, dev_data->tx_pool_size,
					     dev_data->tx_pool_region_id);
	if (IS_ERR_OR_NULL(dev_data->tx_pool)) {
		dev_err(dev, "Couldn't create tx pool\n");
		return PTR_ERR(dev_data->tx_pool);
	}

	snprintf(name, sizeof(name), "tx-subm-q-%s", dev_name(dev));
	dev_data->tx_submit_q = knav_queue_open(name,
						dev_data->tx_submit_qid,
						KNAV_QUEUE_SHARED);
	if (IS_ERR(dev_data->tx_submit_q)) {
		ret = PTR_ERR(dev_data->tx_submit_q);
		dev_err(dev, "Could not open \"%s\": %d\n", name, ret);
		return ret;
	}

	snprintf(name, sizeof(name), "tx-compl-q-%s", dev_name(dev));
	dev_data->tx_compl_q = knav_queue_open(name, dev_data->tx_compl_qid, 0);
	if (IS_ERR(dev_data->tx_compl_q)) {
		ret = PTR_ERR(dev_data->tx_compl_q);
		dev_err(dev, "Could not open \"%s\": %d\n", name, ret);
		return ret;
	}

	snprintf(name, sizeof(name), "rx-compl-q-%s", dev_name(dev));
	dev_data->rx_compl_q = knav_queue_open(name, dev_data->rx_compl_qid, 0);
	if (IS_ERR(dev_data->rx_compl_q)) {
		ret = PTR_ERR(dev_data->rx_compl_q);
		dev_err(dev, "Could not open \"%s\": %d\n", name, ret);
		return ret;
	}

	for (i = 0; i < KNAV_DMA_FDQ_PER_CHAN && dev_data->rx_queue_depths[i];
	     i++) {
		snprintf(name, sizeof(name), "rx-fdq%d-%s", i, dev_name(dev));
		dev_data->rx_fdq[i] = knav_queue_open(name, KNAV_QUEUE_GP, 0);
		if (IS_ERR_OR_NULL(dev_data->rx_fdq[i]))
			return PTR_ERR(dev_data->rx_fdq[i]);
	}
	ret = sa_rxpool_refill(dev_data);

	return ret;
}

static int sa_setup_dma(struct keystone_crypto_data *dev_data)
{
	struct device *dev = &dev_data->pdev->dev;
	struct knav_queue_notify_config notify_cfg;
	struct knav_dma_cfg config;
	int error = 0;
	int i;
	u32 last_fdq = 0;
	u8 name[16];

	error = sa_setup_resources(dev_data);
	if (error)
		goto fail;

	/* Setup Tx DMA channel */
	memset(&config, 0, sizeof(config));
	config.direction = DMA_MEM_TO_DEV;
	config.u.tx.filt_einfo = false;
	config.u.tx.filt_pswords = false;
	config.u.tx.priority = DMA_PRIO_MED_L;

	dev_data->tx_chan = knav_dma_open_channel(dev, dev_data->tx_chan_name,
						  &config);
	if (IS_ERR_OR_NULL(dev_data->tx_chan)) {
		dev_err(dev, "(%s) failed to open dmachan\n",
			dev_data->tx_chan_name);
		error = -ENODEV;
		goto fail;
	}

	notify_cfg.fn = sa_dma_notify_tx_compl;
	notify_cfg.fn_arg = dev_data;
	error = knav_queue_device_control(dev_data->tx_compl_q,
					  KNAV_QUEUE_SET_NOTIFIER,
					  (unsigned long)&notify_cfg);
	if (error)
		goto fail;

	knav_queue_enable_notify(dev_data->tx_compl_q);

	dev_dbg(dev, "opened tx channel %s\n", name);

	/* Set notification for Rx completion */
	notify_cfg.fn = sa_dma_notify_rx_compl;
	notify_cfg.fn_arg = dev_data;
	error = knav_queue_device_control(dev_data->rx_compl_q,
					  KNAV_QUEUE_SET_NOTIFIER,
					  (unsigned long)&notify_cfg);
	if (error)
		goto fail;

	knav_queue_disable_notify(dev_data->rx_compl_q);

	/* Setup Rx DMA channel */
	memset(&config, 0, sizeof(config));
	config.direction		= DMA_DEV_TO_MEM;
	config.u.rx.einfo_present	= true;
	config.u.rx.psinfo_present	= true;
	config.u.rx.err_mode		= DMA_RETRY;
	config.u.rx.desc_type		= DMA_DESC_HOST;
	config.u.rx.psinfo_at_sop	= false;
	config.u.rx.sop_offset		= 0; /* NETCP_SOP_OFFSET */
	config.u.rx.dst_q		= dev_data->rx_compl_qid;
	config.u.rx.thresh		= DMA_THRESH_NONE;

	for (i = 0; i < KNAV_DMA_FDQ_PER_CHAN; i++) {
		if (dev_data->rx_fdq[i])
			last_fdq = knav_queue_get_id(dev_data->rx_fdq[i]);
		config.u.rx.fdq[i] = last_fdq;
	}

	dev_data->rx_chan = knav_dma_open_channel(dev, dev_data->rx_chan_name,
						  &config);
	if (IS_ERR_OR_NULL(dev_data->rx_chan)) {
		dev_err(dev, "(%s) failed to open dmachan\n",
			dev_data->rx_chan_name);
		error = -ENODEV;
		goto fail;
	}

	knav_queue_enable_notify(dev_data->rx_compl_q);

	return 0;

fail:
	sa_free_resources(dev_data);

	return error;
}

/*	SYSFS interface functions    */
struct sa_kobj_attribute {
	struct attribute attr;
	ssize_t (*show)(struct keystone_crypto_data *crypto,
			struct sa_kobj_attribute *attr, char *buf);
	ssize_t	(*store)(struct keystone_crypto_data *crypto,
			 struct sa_kobj_attribute *attr, const char *, size_t);
};

static
ssize_t sa_stats_show_tx_pkts(struct keystone_crypto_data *crypto,
			      struct sa_kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n",
			atomic_read(&crypto->stats.tx_pkts));
}

static
ssize_t sa_stats_reset_tx_pkts(struct keystone_crypto_data *crypto,
			       struct sa_kobj_attribute *attr,
			       const char *buf, size_t len)
{
	atomic_set(&crypto->stats.tx_pkts, 0);
	return len;
}

static
ssize_t sa_stats_show_rx_pkts(struct keystone_crypto_data *crypto,
			      struct sa_kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n",
			 atomic_read(&crypto->stats.rx_pkts));
}

static ssize_t sa_stats_reset_rx_pkts(struct keystone_crypto_data *crypto,
				      struct sa_kobj_attribute *attr,
				      const char *buf, size_t len)
{
	atomic_set(&crypto->stats.rx_pkts, 0);
	return len;
}

static
ssize_t sa_stats_show_tx_drop_pkts(struct keystone_crypto_data *crypto,
				   struct sa_kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n",
			atomic_read(&crypto->stats.tx_dropped));
}

static
ssize_t sa_stats_reset_tx_drop_pkts(struct keystone_crypto_data *crypto,
				    struct sa_kobj_attribute *attr,
				    const char *buf, size_t len)
{
	atomic_set(&crypto->stats.tx_dropped, 0);
	return len;
}

static ssize_t
sa_stats_show_sc_tear_drop_pkts(struct keystone_crypto_data *crypto,
				struct sa_kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n",
			atomic_read(&crypto->stats.sc_tear_dropped));
}

static SA_ATTR(tx_pkts, S_IRUGO | S_IWUSR,
	       sa_stats_show_tx_pkts, sa_stats_reset_tx_pkts);
static SA_ATTR(rx_pkts, S_IRUGO | S_IWUSR,
	       sa_stats_show_rx_pkts, sa_stats_reset_rx_pkts);
static SA_ATTR(tx_drop_pkts, S_IRUGO | S_IWUSR,
	       sa_stats_show_tx_drop_pkts, sa_stats_reset_tx_drop_pkts);
static SA_ATTR(sc_tear_drop_pkts, S_IRUGO,
	       sa_stats_show_sc_tear_drop_pkts, NULL);

static struct attribute *sa_stats_attrs[] = {
	&sa_attr_tx_pkts.attr,
	&sa_attr_rx_pkts.attr,
	&sa_attr_tx_drop_pkts.attr,
	&sa_attr_sc_tear_drop_pkts.attr,
	NULL
};

static ssize_t sa_kobj_attr_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	struct sa_kobj_attribute *sa_attr = to_sa_kobj_attr(attr);
	struct keystone_crypto_data *crypto =
		to_crypto_data_from_stats_obj(kobj);
	ssize_t ret = -EIO;

	if (sa_attr->show)
		ret = sa_attr->show(crypto, sa_attr, buf);
	return ret;
}

static
ssize_t sa_kobj_attr_store(struct kobject *kobj, struct attribute *attr,
			   const char *buf, size_t len)
{
	struct sa_kobj_attribute *sa_attr = to_sa_kobj_attr(attr);
	struct keystone_crypto_data *crypto =
		to_crypto_data_from_stats_obj(kobj);
	ssize_t ret = -EIO;

	if (sa_attr->store)
		ret = sa_attr->store(crypto, sa_attr, buf, len);
	return ret;
}

static const struct sysfs_ops sa_stats_sysfs_ops = {
	.show = sa_kobj_attr_show,
	.store = sa_kobj_attr_store,
};

static struct kobj_type sa_stats_ktype = {
	.sysfs_ops = &sa_stats_sysfs_ops,
	.default_attrs = sa_stats_attrs,
};

static int sa_create_sysfs_entries(struct keystone_crypto_data *crypto)
{
	struct device *dev = &crypto->pdev->dev;
	int ret;

	ret = kobject_init_and_add(&crypto->stats_kobj, &sa_stats_ktype,
				   kobject_get(&dev->kobj), "stats");

	if (ret) {
		dev_err(dev, "failed to create sysfs entry\n");
		kobject_put(&crypto->stats_kobj);
		kobject_put(&dev->kobj);
	}

	if (!ret)
		crypto->stats_fl = 1;

	return ret;
}

static void sa_delete_sysfs_entries(struct keystone_crypto_data *crypto)
{
	if (crypto->stats_fl)
		kobject_del(&crypto->stats_kobj);
}

static int sa_read_dtb(struct device_node *node,
		       struct keystone_crypto_data *dev_data)
{
	int i, ret = 0;
	struct device *dev = &dev_data->pdev->dev;
	u32 temp[2];

	ret = of_property_read_string(node, "ti,tx-channel",
				      &dev_data->tx_chan_name);
	if (ret < 0) {
		dev_err(dev, "missing \"ti,tx-channel\" parameter\n");
		return -EINVAL;
	}

	ret = of_property_read_u32(node, "ti,tx-queue-depth",
				       &dev_data->tx_queue_depth);
	if (ret < 0) {
		dev_err(dev, "missing \"ti,tx-queue-depth\" parameter\n");
		return -EINVAL;
	}

	atomic_set(&dev_data->tx_dma_desc_cnt, dev_data->tx_queue_depth);

	ret = of_property_read_u32(node, "ti,tx-submit-queue",
				       &dev_data->tx_submit_qid);
	if (ret < 0) {
		dev_err(dev, "missing \"ti,tx-submit-queue\" parameter\n");
		return -EINVAL;
	}

	ret = of_property_read_u32(node, "ti,tx-completion-queue",
				       &dev_data->tx_compl_qid);
	if (ret < 0) {
		dev_err(dev, "missing \"ti,tx-completion-queue\" parameter\n");
		return -EINVAL;
	}

	ret = of_property_read_string(node, "ti,rx-channel",
				      &dev_data->rx_chan_name);
	if (ret < 0) {
		dev_err(dev, "missing \"ti,rx-channel\" parameter\n");
		return -EINVAL;
	}

	ret = of_property_read_u32_array(node, "ti,rx-queue-depth",
					 dev_data->rx_queue_depths,
					 KNAV_DMA_FDQ_PER_CHAN);
	if (ret < 0) {
		dev_err(dev, "missing \"ti,rx-queue-depth\" parameter\n");
		return -EINVAL;
	}
	for (i = 0; i < KNAV_DMA_FDQ_PER_CHAN; i++)
		dev_dbg(dev, "rx-queue-depth[%d]= %u\n", i,
			dev_data->rx_queue_depths[i]);

	atomic_set(&dev_data->rx_dma_page_cnt, 0);

	ret = of_property_read_u32(node, "ti,rx-compl-queue",
				       &dev_data->rx_compl_qid);
	if (ret < 0) {
		dev_err(dev, "missing \"ti,rx-compl-queue\" parameter\n");
		return -EINVAL;
	}

	ret = of_property_read_u32_array(node, "ti,tx-pool", temp, 2);
	if (ret < 0) {
		dev_err(dev, "missing \"ti,tx-pool\" parameter\n");
		return -EINVAL;
	}
	dev_data->tx_pool_size = temp[0];
	dev_data->tx_pool_region_id = temp[1];

	ret = of_property_read_u32_array(node, "ti,rx-pool", temp, 2);
	if (ret < 0) {
		dev_err(dev, "missing \"ti,rx-pool\" parameter\n");
		return -EINVAL;
	}
	dev_data->rx_pool_size = temp[0];
	dev_data->rx_pool_region_id = temp[1];

	ret = of_property_read_u32_array(node, "ti,sc-id", temp, 2);
	if (ret < 0) {
		dev_err(dev, "missing \"ti,sc-id\" parameter\n");
		return -EINVAL;
	}
	dev_data->sc_id_start = temp[0];
	dev_data->sc_id_end = temp[1];
	dev_data->sc_id = dev_data->sc_id_start;

	dev_data->sa_regmap = syscon_regmap_lookup_by_phandle(node,
							      "syscon-subsys");

	if (IS_ERR(dev_data->sa_regmap)) {
		dev_err(dev, "syscon_regmap_lookup_by_phandle failed\n");
		return -EINVAL;
	}

	return 0;
}

static int keystone_crypto_remove(struct platform_device *pdev)
{
	struct keystone_crypto_data *dev_data = platform_get_drvdata(pdev);
	int ret = 0;

	/* un-register crypto algorithms */
	sa_unregister_algos(&pdev->dev);

	/* Delete SYSFS entries */
	sa_delete_sysfs_entries(dev_data);
	/* Release DMA resources */
	ret = sa_free_resources(dev_data);
	/* Kill tasklets */
	tasklet_kill(&dev_data->rx_task);
	tasklet_kill(&dev_data->tx_task);
	/* Free memory pools used by the driver */
	dma_pool_destroy(dev_data->sc_pool);
	kmem_cache_destroy(dev_data->dma_req_ctx_cache);

	pm_runtime_put_sync(&pdev->dev);
	pm_runtime_disable(&pdev->dev);

	return ret;
}

static int sa_request_firmware(struct device *dev)
{
	const struct firmware *fw;
	int	ret;

	ret = request_firmware(&fw, "sa_mci.fw", dev);
	if (ret < 0) {
		dev_err(dev, "request_firmware failed\n");
		return ret;
	}

	memcpy(&sa_mci_tbl, fw->data, fw->size);

	release_firmware(fw);
	return 0;
}

static int keystone_crypto_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *node = pdev->dev.of_node;
	struct keystone_crypto_data *dev_data;
	u32 value;
	int ret;

	sa_ks2_dev = dev;

	dev_data = devm_kzalloc(dev, sizeof(*dev_data), GFP_KERNEL);
	if (!dev_data)
		return -ENOMEM;

	dev_data->pdev = pdev;

	pm_runtime_enable(dev);
	ret = pm_runtime_get_sync(dev);
	if (ret < 0) {
		dev_err(dev, "Failed to enable SA power-domain\n");
		pm_runtime_disable(dev);
		return ret;
	}

	/* Read configuration from device tree */
	ret = sa_read_dtb(node, dev_data);
	if (ret) {
		dev_err(dev, "Failed to get all relevant configurations from DTB...\n");
		return ret;
	}

	tasklet_init(&dev_data->rx_task, sa_rx_task, (unsigned long)dev_data);
	/* Enable the required sub-modules in SA */
	ret = regmap_read(dev_data->sa_regmap, SA_CMD_STATUS_OFS, &value);
	if (ret)
		goto err_1;

	value |= (SA_CMD_ENCSS_EN | SA_CMD_AUTHSS_EN |
		  SA_CMD_CTXCACH_EN | SA_CMD_SA1_IN_EN |
		  SA_CMD_SA0_IN_EN | SA_CMD_SA1_OUT_EN |
		  SA_CMD_SA0_OUT_EN);

	ret = regmap_write(dev_data->sa_regmap, SA_CMD_STATUS_OFS, value);
	if (ret)
		goto err_1;

	tasklet_init(&dev_data->rx_task, sa_rx_task,
		     (unsigned long)dev_data);

	tasklet_init(&dev_data->tx_task, sa_tx_task, (unsigned long)dev_data);

	/* Initialize statistic counters */
	atomic_set(&dev_data->stats.tx_dropped, 0);
	atomic_set(&dev_data->stats.sc_tear_dropped, 0);
	atomic_set(&dev_data->stats.tx_pkts, 0);
	atomic_set(&dev_data->stats.rx_pkts, 0);

	/* Initialize memory pools used by the driver */
	dev_data->sc_pool = dma_pool_create("keystone-sc", dev,
				SA_CTX_MAX_SZ, 64, 0);
	if (!dev_data->sc_pool) {
		dev_err(dev, "Failed to create dma pool");
		ret = -ENOMEM;
		goto err_1;
	}

	/* Create a cache for Tx DMA request context */
	dev_data->dma_req_ctx_cache = KMEM_CACHE(sa_dma_req_ctx, 0);
	if (!dev_data->dma_req_ctx_cache) {
		dev_err(dev, "Failed to create dma req cache");
		ret =  -ENOMEM;
		goto err_2;
	}

	/* Setup DMA channels */
	ret = sa_setup_dma(dev_data);
	if (ret) {
		dev_err(dev, "Failed to set DMA channels");
		goto err_3;
	}

	/* Initialize the SC-ID allocation lock */
	spin_lock_init(&dev_data->scid_lock);

	/* Create sysfs entries */
	ret = sa_create_sysfs_entries(dev_data);
	if (ret)
		goto err_3;

	ret = sa_request_firmware(dev);
	if (ret < 0)
		goto err_3;

	platform_set_drvdata(pdev, dev_data);

	/* Register crypto algorithms */
	sa_register_algos(dev);

	dev_info(dev, "crypto accelerator enabled\n");
	return 0;

err_3:
	kmem_cache_destroy(dev_data->dma_req_ctx_cache);
err_2:
	dma_pool_destroy(dev_data->sc_pool);

err_1:
	tasklet_kill(&dev_data->rx_task);
	tasklet_kill(&dev_data->tx_task);

	return ret;
}

static const struct of_device_id of_match[] = {
	{ .compatible = "ti,netcp-sa-crypto", },
	{},
};
MODULE_DEVICE_TABLE(of, of_match);

static struct platform_driver keystone_crypto_driver = {
	.probe	= keystone_crypto_probe,
	.remove	= keystone_crypto_remove,
	.driver	= {
		.name		= "keystone-crypto",
		.of_match_table	= of_match,
	},
};

module_platform_driver(keystone_crypto_driver);

MODULE_DESCRIPTION("Keystone crypto acceleration support.");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Sandeep Nair");
MODULE_AUTHOR("Vitaly Andrianov");

