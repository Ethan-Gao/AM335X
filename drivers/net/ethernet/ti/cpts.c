/*
 * TI Common Platform Time Sync
 *
 * Copyright (C) 2012 Richard Cochran <richardcochran@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <linux/err.h>
#include <linux/if.h>
#include <linux/hrtimer.h>
#include <linux/module.h>
#include <linux/net_tstamp.h>
#include <linux/ptp_classify.h>
#include <linux/time.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/irqreturn.h>
#include <linux/interrupt.h>
#include <linux/of_irq.h>

#include "cpts.h"
#include "ptp_bc.h"

#define CPTS_SKB_TX_WORK_TIMEOUT 1 /* jiffies */

struct cpts_skb_cb_data {
	unsigned long tmo;
};

#define cpts_read32(c, r)	readl_relaxed(&c->reg->r)
#define cpts_write32(c, v, r)	writel_relaxed(v, &c->reg->r)

#define READ_TCRR(odt) __omap_dm_timer_read((odt), OMAP_TIMER_COUNTER_REG, 0)
#define READ_TCLR(odt) __omap_dm_timer_read((odt), OMAP_TIMER_CTRL_REG, 0)
#define READ_TCAP(odt) __omap_dm_timer_read((odt), OMAP_TIMER_CAPTURE_REG, 0)
#define WRITE_TCRR(odt, val) __omap_dm_timer_write((odt), \
				OMAP_TIMER_COUNTER_REG, (val), 0)
#define WRITE_TLDR(odt, val) __omap_dm_timer_write((odt), \
				OMAP_TIMER_LOAD_REG, (val), 0)
#define WRITE_TMAR(odt, val) __omap_dm_timer_write((odt), \
				OMAP_TIMER_MATCH_REG, (val), 0)
#define WRITE_TCLR(odt, val) __omap_dm_timer_write((odt), \
				OMAP_TIMER_CTRL_REG, (val), 0)
#define WRITE_TSICR(odt, val) __omap_dm_timer_write((odt), \
				OMAP_TIMER_IF_CTRL_REG, (val), 0)

#define CPTS_TS_THRESH		98000000ULL
#define CPTS_TMR_CLK_RATE	100000000
#define CPTS_TMR_CLK_PERIOD	(1000000000/CPTS_TMR_CLK_RATE)
#define CPTS_TMR_RELOAD_CNT	(0xFFFFFFFFUL - 100000000UL/CPTS_TMR_CLK_PERIOD + 1)
#define CPTS_TMR_CMP_CNT	(CPTS_TMR_RELOAD_CNT + 10000000UL/CPTS_TMR_CLK_PERIOD)
#define CPTS_MAX_MMR_ACCESS_TIME	1000
#define CPTS_NOM_MMR_ACCESS_TIME	250
#define CPTS_NOM_MMR_ACCESS_TICK	(CPTS_NOM_MMR_ACCESS_TIME / \
					 CPTS_TMR_CLK_PERIOD)

#define CPTS_LATCH_TMR_RELOAD_CNT	(0xFFFFFFFFUL - \
					 1000000000UL / CPTS_TMR_CLK_PERIOD + 1)
#define CPTS_LATCH_TMR_CMP_CNT		(CPTS_LATCH_TMR_RELOAD_CNT + \
					 10000000UL / CPTS_TMR_CLK_PERIOD)
#define CPTS_LATCH_TICK_THRESH_MIN	(80000 / CPTS_TMR_CLK_PERIOD)
#define CPTS_LATCH_TICK_THRESH_MAX	(120000 / CPTS_TMR_CLK_PERIOD)
#define CPTS_LATCH_TICK_THRESH_MID	((CPTS_LATCH_TICK_THRESH_MIN + \
					  CPTS_LATCH_TICK_THRESH_MAX) / 2)
#define CPTS_LATCH_TICK_THRESH_UNSYNC	(1000000 / CPTS_TMR_CLK_PERIOD)

#define CPTS_TMR_LATCH_DELAY		40

static u32 tmr_reload_cnt = CPTS_TMR_RELOAD_CNT;
static u32 tmr_reload_cnt_prev = CPTS_TMR_RELOAD_CNT;
static int ts_correct;

static void cpts_tmr_init(struct cpts *cpts);
static void cpts_tmr_reinit(struct cpts *cpts);
static irqreturn_t cpts_1pps_tmr_interrupt(int irq, void *dev_id);
static irqreturn_t cpts_1pps_latch_interrupt(int irq, void *dev_id);
static void cpts_tmr_poll(struct cpts *cpts, bool cpts_poll);
static void cpts_pps_schedule(struct cpts *cpts);
static inline void cpts_latch_pps_stop(struct cpts *cpts);


static int cpts_event_port(struct cpts_event *event)
{
	return (event->high >> PORT_NUMBER_SHIFT) & PORT_NUMBER_MASK;
}

static int cpts_match(struct sk_buff *skb, unsigned int ptp_class,
		      u16 ts_seqid, u8 ts_msgtype);

static int event_expired(struct cpts_event *event)
{
	return time_after(jiffies, event->tmo);
}

static int event_type(struct cpts_event *event)
{
	return (event->high >> EVENT_TYPE_SHIFT) & EVENT_TYPE_MASK;
}

static int cpts_fifo_pop(struct cpts *cpts, u32 *high, u32 *low)
{
	u32 r = cpts_read32(cpts, intstat_raw);

	if (r & TS_PEND_RAW) {
		*high = cpts_read32(cpts, event_high);
		*low  = cpts_read32(cpts, event_low);
		cpts_write32(cpts, EVENT_POP, event_pop);
		return 0;
	}
	return -1;
}

static int cpts_purge_events(struct cpts *cpts)
{
	struct list_head *this, *next;
	struct cpts_event *event;
	int removed = 0;

	list_for_each_safe(this, next, &cpts->events) {
		event = list_entry(this, struct cpts_event, list);
		if (event_expired(event)) {
			list_del_init(&event->list);
			list_add(&event->list, &cpts->pool);
			++removed;
		}
	}

	if (removed)
		pr_debug("cpts: event pool cleaned up %d\n", removed);
	return removed ? 0 : -1;
}

static bool cpts_match_tx_ts(struct cpts *cpts, struct cpts_event *event)
{
	struct sk_buff *skb, *tmp;
	u16 seqid;
	u8 mtype;
	bool found = false;

	mtype = (event->high >> MESSAGE_TYPE_SHIFT) & MESSAGE_TYPE_MASK;
	seqid = (event->high >> SEQUENCE_ID_SHIFT) & SEQUENCE_ID_MASK;

	/* no need to grab txq.lock as access is always done under cpts->lock */
	skb_queue_walk_safe(&cpts->txq, skb, tmp) {
		struct skb_shared_hwtstamps ssh;
		unsigned int class = ptp_classify_raw(skb);
		struct cpts_skb_cb_data *skb_cb =
					(struct cpts_skb_cb_data *)skb->cb;

		if (cpts_match(skb, class, seqid, mtype)) {
			u64 ns = timecounter_cyc2time(&cpts->tc, event->low);

			memset(&ssh, 0, sizeof(ssh));
			ssh.hwtstamp = ns_to_ktime(ns);
			skb_tstamp_tx(skb, &ssh);
			found = true;
			__skb_unlink(skb, &cpts->txq);
			dev_consume_skb_any(skb);
			dev_dbg(cpts->dev, "match tx timestamp mtype %u seqid %04x\n",
				mtype, seqid);
		} else if (time_after(jiffies, skb_cb->tmo)) {
			/* timeout any expired skbs over 1s */
			dev_dbg(cpts->dev,
				"expiring tx timestamp mtype %u seqid %04x\n",
				mtype, seqid);
			__skb_unlink(skb, &cpts->txq);
			dev_consume_skb_any(skb);
		}
	}

	return found;
}

/*
 * Returns zero if matching event type was found.
 */
static int cpts_fifo_read(struct cpts *cpts, int match)
{
	int i, type = -1;
	u32 hi, lo;
	struct cpts_event *event;

	for (i = 0; i < CPTS_FIFO_DEPTH; i++) {
		if (cpts_fifo_pop(cpts, &hi, &lo))
			break;

		if (list_empty(&cpts->pool) && cpts_purge_events(cpts)) {
			pr_err("cpts: event pool empty\n");
			return -1;
		}

		event = list_first_entry(&cpts->pool, struct cpts_event, list);
		event->tmo = jiffies +
			     msecs_to_jiffies(CPTS_EVENT_RX_TX_TIMEOUT);
		event->high = hi;
		event->low = lo;
		type = event_type(event);
		switch (type) {
		case CPTS_EV_HW:
			event->tmo +=
				msecs_to_jiffies(CPTS_EVENT_HWSTAMP_TIMEOUT);
			list_del_init(&event->list);
			list_add_tail(&event->list, &cpts->events);
			break;
		case CPTS_EV_TX:
			if (cpts_match_tx_ts(cpts, event)) {
				/* if the new event matches an existing skb,
				 * then don't queue it
				 */
				break;
			}
		case CPTS_EV_PUSH:
		case CPTS_EV_RX:
			list_del_init(&event->list);
			list_add_tail(&event->list, &cpts->events);
			break;
		case CPTS_EV_ROLL:
		case CPTS_EV_HALF:
			break;
		default:
			pr_err("cpts: unknown event type\n");
			break;
		}
		if (type == match)
			break;
	}
	return type == match ? 0 : -1;
}

static cycle_t cpts_systim_read(const struct cyclecounter *cc)
{
	u64 val = 0;
	struct cpts_event *event;
	struct list_head *this, *next;
	struct cpts *cpts = container_of(cc, struct cpts, cc);

	cpts_write32(cpts, TS_PUSH, ts_push);
	if (cpts_fifo_read(cpts, CPTS_EV_PUSH))
		pr_err("cpts: unable to obtain a time stamp\n");

	list_for_each_safe(this, next, &cpts->events) {
		event = list_entry(this, struct cpts_event, list);
		if (event_type(event) == CPTS_EV_PUSH) {
			list_del_init(&event->list);
			list_add(&event->list, &cpts->pool);
			val = event->low;
			break;
		}
	}

	return val;
}

/* PTP clock operations */

static int cpts_ptp_adjfreq(struct ptp_clock_info *ptp, s32 ppb)
{
	u64 adj;
	u32 diff, mult;
	int neg_adj = 0;
	unsigned long flags;
	struct cpts *cpts = container_of(ptp, struct cpts, info);

	if (ppb < 0) {
		neg_adj = 1;
		ppb = -ppb;
	}
	mult = cpts->cc_mult;
	adj = mult;
	adj *= ppb;
	diff = div_u64(adj, 1000000000ULL);

	spin_lock_irqsave(&cpts->lock, flags);

	timecounter_read(&cpts->tc);

	cpts->cc.mult = neg_adj ? mult - diff : mult + diff;

	spin_unlock_irqrestore(&cpts->lock, flags);

	tmr_reload_cnt = neg_adj ? CPTS_TMR_RELOAD_CNT - (ppb + 0) / (CPTS_TMR_CLK_PERIOD*10) :
		CPTS_TMR_RELOAD_CNT + (ppb + 0) / (CPTS_TMR_CLK_PERIOD*10);

	return 0;
}

static int cpts_ptp_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	unsigned long flags;
	struct cpts *cpts = container_of(ptp, struct cpts, info);

	spin_lock_irqsave(&cpts->lock, flags);
	timecounter_adjtime(&cpts->tc, delta);
	spin_unlock_irqrestore(&cpts->lock, flags);

	return 0;
}

static int cpts_ptp_gettime(struct ptp_clock_info *ptp, struct timespec64 *ts)
{
	u64 ns;
	unsigned long flags;
	struct cpts *cpts = container_of(ptp, struct cpts, info);

	spin_lock_irqsave(&cpts->lock, flags);
	ns = timecounter_read(&cpts->tc);
	spin_unlock_irqrestore(&cpts->lock, flags);

	*ts = ns_to_timespec64(ns);

	return 0;
}

static int cpts_ptp_settime(struct ptp_clock_info *ptp,
			    const struct timespec64 *ts)
{
	u64 ns;
	unsigned long flags;
	struct cpts *cpts = container_of(ptp, struct cpts, info);

	ns = timespec64_to_ns(ts);

	spin_lock_irqsave(&cpts->lock, flags);
	timecounter_init(&cpts->tc, &cpts->cc, ns);
	spin_unlock_irqrestore(&cpts->lock, flags);

	return 0;
}

static int cpts_report_ts_events(struct cpts *cpts)
{
	struct list_head *this, *next;
	struct ptp_clock_event pevent;
	struct cpts_event *event;
	int reported = 0, ev;

	list_for_each_safe(this, next, &cpts->events) {
		event = list_entry(this, struct cpts_event, list);
		ev = event_type(event);
		if ((ev == CPTS_EV_HW) &&
		    (cpts->hw_ts_enable &
		     (1 << (cpts_event_port(event) - 1)))) {
			list_del_init(&event->list);
			list_add(&event->list, &cpts->pool);
			/* report the event */
			pevent.timestamp =
				timecounter_cyc2time(&cpts->tc, event->low);
			pevent.timestamp -= cpts->pps_latch_offset;
			pevent.type = PTP_CLOCK_EXTTS;
			pevent.index = cpts_event_port(event) - 1;
			if (cpts->pps_latch_receive) {
				ptp_clock_event(cpts->clock, &pevent);
				cpts->pps_latch_receive = false;
			} else {
				cpts_latch_pps_stop(cpts);
			}
			++reported;
			continue;
		}
	}
	return reported;
}

/* PPS */
static int cpts_proc_pps_ts_events(struct cpts *cpts)
{
	struct list_head *this, *next;
	struct cpts_event *event;
	int reported = 0, ev;

	list_for_each_safe(this, next, &cpts->events) {
		event = list_entry(this, struct cpts_event, list);
		ev = event_type(event);
		if ((ev == CPTS_EV_HW) && (cpts_event_port(event) == 4)) {
			list_del_init(&event->list);
			list_add(&event->list, &cpts->pool);
			/* record the timestamp only */
			cpts->hw_timestamp =
				timecounter_cyc2time(&cpts->tc, event->low);
			++reported;
			continue;
		}
	}
	return reported;
}

static void cpts_pps_kworker(struct kthread_work *work)
{
	struct cpts *cpts = container_of(work, struct cpts, pps_work.work);

	cpts_pps_schedule(cpts);
}


static inline void cpts_pps_stop(struct cpts *cpts)
{
	u32 v;

	/* disable timer */
	v = READ_TCLR(cpts->odt);
	v &= ~BIT(0);
	WRITE_TCLR(cpts->odt, v);
}

static inline void cpts_pps_start(struct cpts *cpts)
{
	u32 v;

	cpts_tmr_reinit(cpts);

	/* enable timer */
	v = READ_TCLR(cpts->odt);
	v |= BIT(0);
	WRITE_TCLR(cpts->odt, v);
}

static int cpts_pps_enable(struct cpts *cpts, int on)
{
	on = (on? 1 : 0);

	if (cpts->pps_enable == on)
		return 0;

	cpts->pps_enable = on;

	/* will stop after up coming pulse */
	if (!on)
		return 0;

	if (cpts->ref_enable == -1) {
		cpts_pps_start(cpts);
		cpts_tmr_poll(cpts, false);
	}

	return 0;
}

static int cpts_ref_enable(struct cpts *cpts, int on)
{
	on = (on ? 1 : 0);

	if (cpts->ref_enable == on)
		return 0;

	cpts->ref_enable = on;

	/* will stop after up coming pulse */
	if (!on)
		return 0;

	if (cpts->pps_enable == -1) {
		cpts_pps_start(cpts);
		cpts_tmr_poll(cpts, false);
	}

	return 0;
}

static int cpts_pps_init(struct cpts *cpts)
{
	int err;

	cpts->pps_enable = -1;
	cpts->ref_enable = -1;

#ifdef CONFIG_OMAP_DM_TIMER
	omap_dm_timer_enable(cpts->odt);
	omap_dm_timer_enable(cpts->odt2);
#endif
	cpts_tmr_init(cpts);

	kthread_init_delayed_work(&cpts->pps_work, cpts_pps_kworker);
	cpts->pps_kworker = kthread_create_worker(0, "pps0");

	if (IS_ERR(cpts->pps_kworker)) {
		err = PTR_ERR(cpts->pps_kworker);
		pr_err("failed to create cpts pps worker %d\n", err);
		// TBD:add error handling
		return -1;
	}

	return 0;
}

static void cpts_pps_schedule(struct cpts *cpts)
{
	unsigned long flags;
	bool reported;

	cpts_fifo_read(cpts, -1);

	spin_lock_irqsave(&cpts->lock, flags);
	reported = cpts_proc_pps_ts_events(cpts);
	spin_unlock_irqrestore(&cpts->lock, flags);

	if ((cpts->pps_enable >= 0) || (cpts->ref_enable >= 0)) {
		if (!cpts->pps_enable) {
			cpts->pps_enable = -1;
			pinctrl_select_state(cpts->pins,
					     cpts->pin_state_pwm_off);
		}

		if (!cpts->ref_enable) {
			cpts->ref_enable = -1;
			pinctrl_select_state(cpts->pins,
					     cpts->pin_state_ref_off);
		}

		if ((cpts->pps_enable == -1) && (cpts->ref_enable == -1)) {
			cpts_pps_stop(cpts);
		} else {
			if(reported)
				cpts_tmr_poll(cpts, true);
		}
	}

	if(reported != 1)
		pr_err("error:cpts_pps_schedule() is called with %d CPTS HW events!\n", reported);

}

/* HW TS */
static int cpts_extts_enable(struct cpts *cpts, u32 index, int on)
{
	unsigned long flags;
	u32 v;

	if (index >= cpts->info.n_ext_ts)
		return -ENXIO;

	if (((cpts->hw_ts_enable & BIT(index)) >> index) == on)
		return 0;

	spin_lock_irqsave(&cpts->lock, flags);

	v = cpts_read32(cpts, control);
	if (on) {
		v |= BIT(8 + index);
		cpts->hw_ts_enable |= BIT(index);
		pinctrl_select_state(cpts->pins, cpts->pin_state_latch_on);
	} else {
		v &= ~BIT(8 + index);
		cpts->hw_ts_enable &= ~BIT(index);
		pinctrl_select_state(cpts->pins, cpts->pin_state_latch_off);
	}
	cpts_write32(cpts, v, control);

	spin_unlock_irqrestore(&cpts->lock, flags);

	if (cpts->hw_ts_enable)
		/* poll for events faster - evry 200 ms */
		cpts->ov_check_period =
			msecs_to_jiffies(CPTS_EVENT_HWSTAMP_TIMEOUT);
	else
		cpts->ov_check_period = cpts->ov_check_period_slow;

	ptp_schedule_worker(cpts->clock, cpts->ov_check_period);

	return 0;
}

static int cpts_ptp_enable(struct ptp_clock_info *ptp,
			   struct ptp_clock_request *rq, int on)
{
	struct cpts *cpts = container_of(ptp, struct cpts, info);
	struct timespec64 ts;
	s64 ns;
	bool ok;

	switch (rq->type) {
	case PTP_CLK_REQ_EXTTS:
		pr_info("PTP_CLK_REQ_EXTTS: index = %d, on = %d\n",
			rq->extts.index,
			on);
		return cpts_extts_enable(cpts, rq->extts.index, on);
	case PTP_CLK_REQ_PPS:
		if (cpts->use_1pps) {
			ok = ptp_bc_clock_sync_enable(cpts->bc_clkid, on);
			if (!ok) {
				pr_info("cpts error: bc clk sync pps enable denied\n");
				return -EBUSY;
			}
		}
		return cpts_pps_enable(cpts, on);
	case PTP_CLK_REQ_PEROUT:
		/* this enables a pps for external measurement */
		if (rq->perout.index != 0)
			return -EINVAL;

		if (on) {
			ts.tv_sec = rq->perout.period.sec;
			ts.tv_nsec = rq->perout.period.nsec;
			ns = timespec64_to_ns(&ts);
			if (ns != NSEC_PER_SEC) {
				dev_err(cpts->dev, "Unsupported period %llu ns.Device supports only 1 sec period.\n",
					ns);
				return -EOPNOTSUPP;
			}
		}

		return cpts_ref_enable(cpts, on);
	default:
		break;
	}

	return -EOPNOTSUPP;
}

static long cpts_overflow_check(struct ptp_clock_info *ptp)
{
	struct cpts *cpts = container_of(ptp, struct cpts, info);
	unsigned long delay = cpts->ov_check_period;
	struct timespec64 ts;
	unsigned long flags;

	spin_lock_irqsave(&cpts->lock, flags);
	ts = ns_to_timespec64(timecounter_read(&cpts->tc));

	if (cpts->hw_ts_enable)
		cpts_report_ts_events(cpts);
	if (!skb_queue_empty(&cpts->txq))
		delay = CPTS_SKB_TX_WORK_TIMEOUT;
	spin_unlock_irqrestore(&cpts->lock, flags);

	pr_debug("cpts overflow check at %lld.%09lu\n", ts.tv_sec, ts.tv_nsec);
	return (long)delay;
}

static struct ptp_clock_info cpts_info = {
	.owner		= THIS_MODULE,
	.name		= "CTPS timer",
	.max_adj	= 1000000,
	.n_ext_ts	= 0,
	.n_pins		= 0,
	.pps		= 0,
	.adjfreq	= cpts_ptp_adjfreq,
	.adjtime	= cpts_ptp_adjtime,
	.gettime64	= cpts_ptp_gettime,
	.settime64	= cpts_ptp_settime,
	.enable		= cpts_ptp_enable,
	.do_aux_work	= cpts_overflow_check,
};

static int cpts_match(struct sk_buff *skb, unsigned int ptp_class,
		      u16 ts_seqid, u8 ts_msgtype)
{
	u16 *seqid;
	unsigned int offset = 0;
	u8 *msgtype, *data = skb->data;

	if (ptp_class & PTP_CLASS_VLAN)
		offset += VLAN_HLEN;

	switch (ptp_class & PTP_CLASS_PMASK) {
	case PTP_CLASS_IPV4:
		offset += ETH_HLEN + IPV4_HLEN(data + offset) + UDP_HLEN;
		break;
	case PTP_CLASS_IPV6:
		offset += ETH_HLEN + IP6_HLEN + UDP_HLEN;
		break;
	case PTP_CLASS_L2:
		offset += ETH_HLEN;
		break;
	default:
		return 0;
	}

	if (skb->len + ETH_HLEN < offset + OFF_PTP_SEQUENCE_ID + sizeof(*seqid))
		return 0;

	if (unlikely(ptp_class & PTP_CLASS_V1))
		msgtype = data + offset + OFF_PTP_CONTROL;
	else
		msgtype = data + offset;

	seqid = (u16 *)(data + offset + OFF_PTP_SEQUENCE_ID);

	return (ts_msgtype == (*msgtype & 0xf) && ts_seqid == ntohs(*seqid));
}

static u64 cpts_find_ts(struct cpts *cpts, struct sk_buff *skb, int ev_type)
{
	u64 ns = 0;
	struct cpts_event *event;
	struct list_head *this, *next;
	unsigned int class = ptp_classify_raw(skb);
	unsigned long flags;
	u16 seqid;
	u8 mtype;

	if (class == PTP_CLASS_NONE)
		return 0;

	spin_lock_irqsave(&cpts->lock, flags);
	cpts_fifo_read(cpts, -1);
	list_for_each_safe(this, next, &cpts->events) {
		event = list_entry(this, struct cpts_event, list);
		if (event_expired(event)) {
			list_del_init(&event->list);
			list_add(&event->list, &cpts->pool);
			continue;
		}
		mtype = (event->high >> MESSAGE_TYPE_SHIFT) & MESSAGE_TYPE_MASK;
		seqid = (event->high >> SEQUENCE_ID_SHIFT) & SEQUENCE_ID_MASK;
		if (ev_type == event_type(event) &&
		    cpts_match(skb, class, seqid, mtype)) {
			ns = timecounter_cyc2time(&cpts->tc, event->low);
			list_del_init(&event->list);
			list_add(&event->list, &cpts->pool);
			break;
		}
	}

	if (ev_type == CPTS_EV_TX && !ns) {
		struct cpts_skb_cb_data *skb_cb =
				(struct cpts_skb_cb_data *)skb->cb;
		/* Not found, add frame to queue for processing later.
		 * The periodic FIFO check will handle this.
		 */
		skb_get(skb);
		/* get the timestamp for timeouts */
		skb_cb->tmo = jiffies + msecs_to_jiffies(100);
		__skb_queue_tail(&cpts->txq, skb);
		ptp_schedule_worker(cpts->clock, 0);
	}
	spin_unlock_irqrestore(&cpts->lock, flags);

	return ns;
}

int cpts_rx_timestamp(struct cpts *cpts, struct sk_buff *skb)
{
	u64 ns;
	struct skb_shared_hwtstamps *ssh;

	if (!cpts->rx_enable)
		return -EPERM;
	ns = cpts_find_ts(cpts, skb, CPTS_EV_RX);
	if (!ns)
		return -ENOENT;
	ssh = skb_hwtstamps(skb);
	memset(ssh, 0, sizeof(*ssh));
	ssh->hwtstamp = ns_to_ktime(ns);

	return 0;
}
EXPORT_SYMBOL_GPL(cpts_rx_timestamp);

int cpts_tx_timestamp(struct cpts *cpts, struct sk_buff *skb)
{
	u64 ns;
	struct skb_shared_hwtstamps ssh;

	if (!(skb_shinfo(skb)->tx_flags & SKBTX_IN_PROGRESS))
		return -EPERM;
	ns = cpts_find_ts(cpts, skb, CPTS_EV_TX);
	if (!ns)
		return -ENOENT;
	memset(&ssh, 0, sizeof(ssh));
	ssh.hwtstamp = ns_to_ktime(ns);
	skb_tstamp_tx(skb, &ssh);

	return 0;
}
EXPORT_SYMBOL_GPL(cpts_tx_timestamp);

int cpts_register(struct cpts *cpts)
{
	int err, i;

	skb_queue_head_init(&cpts->txq);
	INIT_LIST_HEAD(&cpts->events);
	INIT_LIST_HEAD(&cpts->pool);
	for (i = 0; i < CPTS_MAX_EVENTS; i++)
		list_add(&cpts->pool_data[i].list, &cpts->pool);

	clk_enable(cpts->refclk);

	cpts_write32(cpts, CPTS_EN, control);
	cpts_write32(cpts, TS_PEND_EN, int_enable);

	timecounter_init(&cpts->tc, &cpts->cc, ktime_to_ns(ktime_get_real()));

	cpts->clock = ptp_clock_register(&cpts->info, cpts->dev);
	if (IS_ERR(cpts->clock)) {
		err = PTR_ERR(cpts->clock);
		cpts->clock = NULL;
		goto err_ptp;
	}
	cpts->phc_index = ptp_clock_index(cpts->clock);

	ptp_schedule_worker(cpts->clock, cpts->ov_check_period);
	cpts_write32(cpts, cpts_read32(cpts, control) |
		     HW4_TS_PUSH_EN, control);

	if (cpts->use_1pps)
		cpts->bc_clkid = ptp_bc_clock_register();

	pr_info("cpts ptp bc clkid %d\n", cpts->bc_clkid);
	return 0;

err_ptp:
	clk_disable(cpts->refclk);
	return err;
}
EXPORT_SYMBOL_GPL(cpts_register);

void cpts_unregister(struct cpts *cpts)
{
	if (WARN_ON(!cpts->clock))
		return;

	ptp_clock_unregister(cpts->clock);
	cpts->clock = NULL;

	cpts_write32(cpts, 0, int_enable);
	cpts_write32(cpts, 0, control);

	/* Drop all packet */
	skb_queue_purge(&cpts->txq);

	clk_disable(cpts->refclk);
}
EXPORT_SYMBOL_GPL(cpts_unregister);

static void cpts_calc_mult_shift(struct cpts *cpts)
{
	u64 frac, maxsec, ns;
	u32 freq;

	freq = clk_get_rate(cpts->refclk);

	/* Calc the maximum number of seconds which we can run before
	 * wrapping around.
	 */
	maxsec = cpts->cc.mask;
	do_div(maxsec, freq);
	/* limit conversation rate to 10 sec as higher values will produce
	 * too small mult factors and so reduce the conversion accuracy
	 */
	if (maxsec > 10)
		maxsec = 10;

	/* Calc overflow check period (maxsec / 2) */
	cpts->ov_check_period = (HZ * maxsec) / 2;
	cpts->ov_check_period_slow = cpts->ov_check_period;

	dev_info(cpts->dev, "cpts: overflow check period %lu (jiffies)\n",
		 cpts->ov_check_period);

	if (cpts->cc.mult || cpts->cc.shift)
		return;

	clocks_calc_mult_shift(&cpts->cc.mult, &cpts->cc.shift,
			       freq, NSEC_PER_SEC, maxsec);

	frac = 0;
	ns = cyclecounter_cyc2ns(&cpts->cc, freq, cpts->cc.mask, &frac);

	dev_info(cpts->dev,
		 "CPTS: ref_clk_freq:%u calc_mult:%u calc_shift:%u error:%lld nsec/sec\n",
		 freq, cpts->cc.mult, cpts->cc.shift, (ns - NSEC_PER_SEC));
}

static int cpts_of_1pps_parse(struct cpts *cpts, struct device_node *node)
{
	struct device_node *np = NULL;
	struct device_node *np2 = NULL;

	np = of_parse_phandle(node, "timers", 0);
	if (!np) {
		dev_err(cpts->dev, "device node lookup for pps timer failed\n");
		return -ENXIO;
	}

	np2 = of_parse_phandle(node, "timers", 1);
	if (!np2) {
		dev_err(cpts->dev, "device node lookup for pps timer input failed\n");
		return -ENXIO;
	}

	cpts->pps_tmr_irqn = of_irq_get(np, 0);
	if (!cpts->pps_tmr_irqn)
		dev_err(cpts->dev, "cannot get 1pps timer interrupt number\n");

	cpts->pps_latch_irqn = of_irq_get(np2, 0);
	if (!cpts->pps_latch_irqn)
		dev_err(cpts->dev, "cannot get 1pps latch interrupt number\n");

#ifdef CONFIG_OMAP_DM_TIMER
	cpts->odt = omap_dm_timer_request_by_node(np);
	cpts->odt2 = omap_dm_timer_request_by_node(np2);
#endif
	if (IS_ERR(cpts->odt)) {
		dev_err(cpts->dev, "request for 1pps timer failed: %ld\n",
			PTR_ERR(cpts->odt));
		return PTR_ERR(cpts->odt);
	}

	if (IS_ERR(cpts->odt2)) {
		dev_err(cpts->dev, "request for 1pps timer input failed: %ld\n",
			PTR_ERR(cpts->odt2));
		return PTR_ERR(cpts->odt2);
	}

	cpts->pins = devm_pinctrl_get(cpts->dev);
	if (IS_ERR(cpts->pins)) {
		dev_err(cpts->dev, "request for 1pps pins failed: %ld\n",
			PTR_ERR(cpts->pins));
		return PTR_ERR(cpts->pins);
	}

	cpts->pin_state_pwm_on = pinctrl_lookup_state(cpts->pins, "pwm_on");
	if (IS_ERR(cpts->pin_state_pwm_on)) {
		dev_err(cpts->dev, "lookup for pwm_on pin state failed: %ld\n",
			PTR_ERR(cpts->pin_state_pwm_on));
		return PTR_ERR(cpts->pin_state_pwm_on);
	}

	cpts->pin_state_pwm_off = pinctrl_lookup_state(cpts->pins, "pwm_off");
	if (IS_ERR(cpts->pin_state_pwm_off)) {
		dev_err(cpts->dev, "lookup for pwm_off pin state failed: %ld\n",
			PTR_ERR(cpts->pin_state_pwm_off));
		return PTR_ERR(cpts->pin_state_pwm_off);
	}

	cpts->pin_state_ref_on = pinctrl_lookup_state(cpts->pins, "ref_on");
	if (IS_ERR(cpts->pin_state_ref_on)) {
		dev_err(cpts->dev, "lookup for ref_on pin state failed: %ld\n",
			PTR_ERR(cpts->pin_state_ref_on));
		return PTR_ERR(cpts->pin_state_ref_on);
	}

	cpts->pin_state_ref_off = pinctrl_lookup_state(cpts->pins, "ref_off");
	if (IS_ERR(cpts->pin_state_ref_off)) {
		dev_err(cpts->dev, "lookup for ref_off pin state failed: %ld\n",
			PTR_ERR(cpts->pin_state_ref_off));
		return PTR_ERR(cpts->pin_state_ref_off);
	}

	cpts->pin_state_latch_on = pinctrl_lookup_state(cpts->pins,
							"latch_on");
	if (IS_ERR(cpts->pin_state_latch_on)) {
		dev_err(cpts->dev, "lookup for latch_on pin state failed: %ld\n",
			PTR_ERR(cpts->pin_state_latch_on));
		return PTR_ERR(cpts->pin_state_latch_on);
	}

	cpts->pin_state_latch_off = pinctrl_lookup_state(cpts->pins,
							 "latch_off");
	if (IS_ERR(cpts->pin_state_latch_off)) {
		dev_err(cpts->dev, "lookup for latch_off pin state failed: %ld\n",
			PTR_ERR(cpts->pin_state_latch_off));
		return PTR_ERR(cpts->pin_state_latch_off);
	}

	return 0;
}

static int cpts_of_parse(struct cpts *cpts, struct device_node *node)
{
	int ret = -EINVAL;
	u32 prop;

	if (!of_property_read_u32(node, "cpts_clock_mult", &prop))
		cpts->cc.mult = prop;

	if (!of_property_read_u32(node, "cpts_clock_shift", &prop))
		cpts->cc.shift = prop;

	if ((cpts->cc.mult && !cpts->cc.shift) ||
	    (!cpts->cc.mult && cpts->cc.shift))
		goto of_error;

	if (!of_property_read_u32(node, "cpts-rftclk-sel", &prop)) {
		if (prop & ~CPTS_RFTCLK_SEL_MASK) {
			dev_err(cpts->dev, "cpts: invalid cpts_rftclk_sel.\n");
			goto of_error;
		}
		cpts->caps |= CPTS_CAP_RFTCLK_SEL;
		cpts->rftclk_sel = prop & CPTS_RFTCLK_SEL_MASK;
	}

	if (!of_property_read_u32(node, "cpts-ext-ts-inputs", &prop))
		cpts->ext_ts_inputs = prop;

	/* get timer for 1PPS */
	ret = cpts_of_1pps_parse(cpts, node);
	cpts->use_1pps = (ret == 0);

	return 0;

of_error:
	dev_err(cpts->dev, "CPTS: Missing property in the DT.\n");
	return ret;
}

struct cpts *cpts_create(struct device *dev, void __iomem *regs,
			 struct device_node *node)
{
	struct cpts *cpts;
	int ret;

	cpts = devm_kzalloc(dev, sizeof(*cpts), GFP_KERNEL);
	if (!cpts)
		return ERR_PTR(-ENOMEM);

	cpts->dev = dev;
	cpts->reg = (struct cpsw_cpts __iomem *)regs;
	spin_lock_init(&cpts->lock);

	ret = cpts_of_parse(cpts, node);
	if (ret)
		return ERR_PTR(ret);

	cpts->refclk = devm_clk_get(dev, "cpts");
	if (IS_ERR(cpts->refclk)) {
		dev_err(dev, "Failed to get cpts refclk\n");
		return ERR_PTR(PTR_ERR(cpts->refclk));
	}

	clk_prepare(cpts->refclk);

	if (cpts->caps & CPTS_CAP_RFTCLK_SEL)
		cpts_write32(cpts, cpts->rftclk_sel, rftclk_sel);

	cpts->cc.read = cpts_systim_read;
	cpts->cc.mask = CLOCKSOURCE_MASK(32);
	cpts->info = cpts_info;

	if (cpts->ext_ts_inputs)
		cpts->info.n_ext_ts = cpts->ext_ts_inputs;

	cpts_calc_mult_shift(cpts);
	/* save cc.mult original value as it can be modified
	 * by cpts_ptp_adjfreq().
	 */
	cpts->cc_mult = cpts->cc.mult;

	if (cpts->pps_tmr_irqn) {
		ret = devm_request_irq(dev, cpts->pps_tmr_irqn,
				       cpts_1pps_tmr_interrupt,
				       0, "1pps_timer", cpts);
		if (ret < 0) {
			dev_err(dev, "unable to request 1pps timer IRQ %d (%d)\n",
				cpts->pps_tmr_irqn, ret);
			return ERR_PTR(ret);
		}
	}

	if (cpts->pps_latch_irqn) {
		ret = devm_request_irq(dev, cpts->pps_latch_irqn,
				       cpts_1pps_latch_interrupt,
				       0, "1pps_latch", cpts);
		if (ret < 0) {
			dev_err(dev, "unable to request 1pps latch IRQ %d (%d)\n",
				cpts->pps_latch_irqn, ret);
			return ERR_PTR(ret);
		}
	}

	if (cpts->use_1pps) {
		ret = cpts_pps_init(cpts);

		if (ret < 0) {
			dev_err(dev, "unable to init PPS resource (%d)\n",
				ret);
			return ERR_PTR(ret);
		}

		/* Enable 1PPS related features	*/
		cpts->info.pps		= 1;
		cpts->info.n_ext_ts	= CPTS_MAX_LATCH;
		cpts->info.n_per_out	= 1;
	}

	return cpts;
}
EXPORT_SYMBOL_GPL(cpts_create);

void cpts_release(struct cpts *cpts)
{
	if (!cpts)
		return;

#ifdef CONFIG_OMAP_DM_TIMER
	pinctrl_select_state(cpts->pins, cpts->pin_state_latch_off);

	if (cpts->odt) {
		omap_dm_timer_disable(cpts->odt);
		omap_dm_timer_free(cpts->odt);
	}

	if (cpts->odt2) {
		omap_dm_timer_disable(cpts->odt2);
		omap_dm_timer_free(cpts->odt2);
	}

	if (cpts->odt || cpts->odt2) {
		devm_pinctrl_put(cpts->pins);
	}

#endif
	if (cpts->pps_kworker) {
		kthread_cancel_delayed_work_sync(&cpts->pps_work);
		kthread_destroy_worker(cpts->pps_kworker);
	}

	if (WARN_ON(!cpts->refclk))
		return;

	clk_unprepare(cpts->refclk);
}
EXPORT_SYMBOL_GPL(cpts_release);

static u64 cpts_ts_read(struct cpts *cpts)
{
	u64 ns = 0;
	struct cpts_event *event;
	struct list_head *this, *next;

	if (cpts_fifo_read(cpts, CPTS_EV_PUSH))
		pr_err("cpts: ts_read: unable to obtain a time stamp\n");

	list_for_each_safe(this, next, &cpts->events) {
		event = list_entry(this, struct cpts_event, list);
		if (event_type(event) == CPTS_EV_PUSH) {
			list_del_init(&event->list);
			list_add(&event->list, &cpts->pool);
			ns = timecounter_cyc2time(&cpts->tc, event->low);
			break;
		}
	}

	return ns;
}

enum cpts_1pps_state {
	/* Initial state: try to SYNC to the CPTS timestamp */
	INIT = 0,
	/* Sync State: track the clock drift, trigger timer
	 * adjustment when the clock drift exceed 1 clock
	 * boundary declare out of sync if the clock difference is more
	 * than a 1ms
	 */
	SYNC = 1,
	/* Adjust state: Wait for time adjust to take effect at the
	 * timer reload time
	 */
	ADJUST = 2,
	/* Wait state: PTP timestamp has been verified,
	 * wait for next check period
	 */
	WAIT = 3
};

static void cpts_tmr_reinit(struct cpts *cpts)
{
	/* re-initialize timer16 for 1pps generator */
	WRITE_TCLR(cpts->odt, 0);
	WRITE_TLDR(cpts->odt, CPTS_TMR_RELOAD_CNT);
	WRITE_TCRR(cpts->odt, CPTS_TMR_RELOAD_CNT);
	WRITE_TMAR(cpts->odt, CPTS_TMR_CMP_CNT);       /* 10 ms */
	WRITE_TCLR(cpts->odt, BIT(12) | 2 << 10 | BIT(6) | BIT(1));
	WRITE_TSICR(cpts->odt, BIT(2));

	cpts->count_prev = 0xFFFFFFFF;
	cpts->pps_state = INIT;
}

static void cpts_latch_tmr_init(struct cpts *cpts)
{
	/* re-initialize timer16 for 1pps generator */
	WRITE_TCLR(cpts->odt2, 0);
	WRITE_TLDR(cpts->odt2, CPTS_LATCH_TMR_RELOAD_CNT);
	WRITE_TCRR(cpts->odt2, CPTS_LATCH_TMR_RELOAD_CNT);
	WRITE_TMAR(cpts->odt2, CPTS_LATCH_TMR_CMP_CNT);       /* 10 ms */
	WRITE_TCLR(cpts->odt2, BIT(14) | BIT(12) | BIT(8) | BIT(6) | BIT(1) |
		   BIT(0));
	WRITE_TSICR(cpts->odt2, BIT(2));

	cpts->pps_latch_state = INIT;
	cpts->pps_latch_offset = 0;
}

static void cpts_tmr_init(struct cpts *cpts)
{
	struct clk *parent;
	int ret;

	if (!cpts)
		return;

	parent = clk_get(&cpts->odt->pdev->dev, "abe_giclk_div");
	if (IS_ERR(parent)) {
		pr_err("%s: %s not found\n", __func__, "abe_giclk_div");
		return;
	}

	ret = clk_set_parent(cpts->odt->fclk, parent);
	if (ret < 0)
		pr_err("%s: failed to set %s as parent\n", __func__,
		       "abe_giclk_div");

	parent = clk_get(&cpts->odt2->pdev->dev, "abe_giclk_div");
	if (IS_ERR(parent)) {
		pr_err("%s: %s not found\n", __func__, "abe_giclk_div");
		return;
	} else {
		ret = clk_set_parent(cpts->odt2->fclk, parent);
		if (ret < 0)
			pr_err("%s: failed to set %s as parent\n", __func__,
				   "abe_giclk_div");
	}

	/* initialize timer16 for 1pps generator */
	cpts_tmr_reinit(cpts);

	/* initialize timer15 for 1pps latch */
	cpts_latch_tmr_init(cpts);

	writel_relaxed(OMAP_TIMER_INT_OVERFLOW, cpts->odt->irq_ena);
	__omap_dm_timer_write(cpts->odt, OMAP_TIMER_WAKEUP_EN_REG,
			      OMAP_TIMER_INT_OVERFLOW, 0);

	writel_relaxed(OMAP_TIMER_INT_CAPTURE, cpts->odt2->irq_ena);
	__omap_dm_timer_write(cpts->odt2, OMAP_TIMER_WAKEUP_EN_REG,
			      OMAP_TIMER_INT_CAPTURE, 0);

	pinctrl_select_state(cpts->pins, cpts->pin_state_pwm_off);
	pinctrl_select_state(cpts->pins, cpts->pin_state_ref_off);
	pinctrl_select_state(cpts->pins, cpts->pin_state_latch_off);
}

static void inline cpts_turn_on_off_1pps_output(struct cpts *cpts, u64 ts)
{
	if (ts > 905000000) {
		if (cpts->pps_enable == 1)
			pinctrl_select_state(cpts->pins,
					     cpts->pin_state_pwm_on);

		if (cpts->ref_enable == 1)
			pinctrl_select_state(cpts->pins,
					     cpts->pin_state_ref_on);

		pr_debug("1pps on at %llu\n", ts);
	} else if ((ts < 100000000) && (ts >= 5000000)) {
		if (cpts->pps_enable == 1)
			pinctrl_select_state(cpts->pins,
					     cpts->pin_state_pwm_off);

		if (cpts->ref_enable == 1)
			pinctrl_select_state(cpts->pins,
					     cpts->pin_state_ref_off);
	}
}

/* The reload counter value is going to affect all cycles after the next SYNC
 * check. Therefore, we need to change the next expected drift value by
 * updating the ts_correct value
 */
static void update_ts_correct(void)
{
	if (tmr_reload_cnt > tmr_reload_cnt_prev)
		ts_correct -= (tmr_reload_cnt - tmr_reload_cnt_prev) * CPTS_TMR_CLK_PERIOD;
	else
		ts_correct += (tmr_reload_cnt_prev - tmr_reload_cnt) * CPTS_TMR_CLK_PERIOD;
}

static void cpts_tmr_poll(struct cpts *cpts, bool cpts_poll)
{
	unsigned long flags;
	u32 tmr_count, tmr_count2, count_exp, tmr_diff_abs;
	s32 tmr_diff = 0;
	int ts_val;
	static int ts_val_prev;
	u64 cpts_ts_short, cpts_ts, tmp64;
	static u64 cpts_ts_trans;
	bool updated = false;
	static bool first;

	if (!cpts)
		return;

	spin_lock_irqsave(&cpts->lock, flags);

	tmr_count = READ_TCRR(cpts->odt);
	cpts_write32(cpts, TS_PUSH, ts_push);
	tmr_count2 = READ_TCRR(cpts->odt);
	tmp64 = cpts_ts_read(cpts);
	cpts_ts = tmp64;
	cpts_ts_short = do_div(tmp64, 1000000000UL);

	cpts_turn_on_off_1pps_output(cpts, cpts_ts_short);

	tmp64 = cpts_ts;
	cpts_ts_short = do_div(tmp64, 100000000UL);

	/* Timer poll state machine */
	switch (cpts->pps_state) {
	case INIT:
		if ((cpts_ts_short < CPTS_TS_THRESH) &&
			((tmr_count2 - tmr_count) < CPTS_MAX_MMR_ACCESS_TIME/CPTS_TMR_CLK_PERIOD)) {
			/* The nominal delay of this operation about 9 ticks
			 * We are able to compensate for the normal range 8-17
			 * However, the simple compensation fials when the delay
			 * is getting big, just skip this sample
			 *
			 * Calculate the expected tcrr value and update to it
			 */
			tmp64 = (100000000UL - cpts_ts_short);
				do_div(tmp64, CPTS_TMR_CLK_PERIOD);
			count_exp = (u32)tmp64;
			count_exp = 0xFFFFFFFFUL - count_exp + 1;

			WRITE_TCRR(cpts->odt, count_exp +
				   READ_TCRR(cpts->odt) - tmr_count2 +
				   CPTS_NOM_MMR_ACCESS_TICK);

			{
				WRITE_TLDR(cpts->odt, tmr_reload_cnt);
				WRITE_TMAR(cpts->odt, CPTS_TMR_CMP_CNT);

				cpts->pps_state = WAIT;
				first = true;
				tmr_reload_cnt_prev = tmr_reload_cnt;
				cpts_ts_trans = (cpts_ts - cpts_ts_short) +
					100000000ULL;
				pr_info("cpts_tmr_poll: exit INIT state\n");
			}
		}
		break;

	case ADJUST:
		/* Wait for the ldr load to take effect */
		if (cpts_ts >= cpts_ts_trans) {
			u64 ts = cpts->hw_timestamp;
			u32 ts_offset;

			ts_offset = do_div(ts, 100000000UL);

			ts_val = (ts_offset >= 50000000UL) ?
				-(100000000UL - ts_offset) :
				(ts_offset);

			/* restore the timer period to 100ms */
			WRITE_TLDR(cpts->odt, tmr_reload_cnt);

			if (tmr_reload_cnt != tmr_reload_cnt_prev)
				update_ts_correct();

			cpts_ts_trans += 100000000ULL;
			cpts->pps_state = WAIT;

			tmr_reload_cnt_prev = tmr_reload_cnt;
			ts_val_prev = ts_val;
		}
		break;

	case WAIT:
		/* Wait for the next poll period when the adjustment
		 * has been taken effect
		 */
		if (cpts_ts < cpts_ts_trans)
			break;

		cpts->pps_state = SYNC;
		/* pass through */

	case SYNC:
		{
			u64 ts = cpts->hw_timestamp;
			u32 ts_offset;
			int tsAdjust;

			ts_offset = do_div(ts, 100000000UL);
			ts_val = (ts_offset >= 50000000UL) ?
				-(100000000UL - ts_offset) :
				(ts_offset);
			/* tsAjust should include the current error and the expected
			 * drift for the next two cycles
			 */
			if (first) {
				tsAdjust = ts_val;
				first = false;
			} else
				tsAdjust = ts_val +
					(ts_val - ts_val_prev + ts_correct) * 2;

			tmr_diff = (tsAdjust < 0) ? (tsAdjust - CPTS_TMR_CLK_PERIOD/2) / CPTS_TMR_CLK_PERIOD :
				(tsAdjust + CPTS_TMR_CLK_PERIOD/2) / CPTS_TMR_CLK_PERIOD;

			/* adjust for the error in the current cycle due to the old (incorrect) reload count
			 * we only make the adjustment if the counter change is more than 1 because the
			 * couner will change back and forth at the frequency tick boundary
			 */
			if (tmr_reload_cnt != tmr_reload_cnt_prev) {
				if (tmr_reload_cnt > tmr_reload_cnt_prev)
					tmr_diff += (tmr_reload_cnt -
						     tmr_reload_cnt_prev - 1);
				else
					tmr_diff -= (tmr_reload_cnt_prev -
						     tmr_reload_cnt - 1);
			}

			pr_debug("cpts_tmr_poll: ts_val = %d, ts_val_prev = %d\n",
				 ts_val, ts_val_prev);

			ts_correct = tmr_diff * CPTS_TMR_CLK_PERIOD;
			ts_val_prev = ts_val;
			tmr_diff_abs = abs(tmr_diff);

			if (tmr_diff_abs || (tmr_reload_cnt != tmr_reload_cnt_prev)) {
				updated = true;
				if (tmr_diff_abs < (1000000 / CPTS_TMR_CLK_PERIOD)) {
					/* adjust ldr time for one period
					 * instead of updating the tcrr directly
					 */
					WRITE_TLDR(cpts->odt, tmr_reload_cnt +
						   (u32)tmr_diff);
					cpts->pps_state = ADJUST;
				} else {
					/* The error is more than 1 ms,
					 * declare it is out of sync
					 */
					cpts->pps_state = INIT;
					pr_info("cpts_tmr_poll: enter INIT state\n");
					break;
				}
			} else {
				cpts->pps_state = WAIT;
			}

			cpts_ts_trans = (cpts_ts - cpts_ts_short) + 100000000ULL;
			tmr_reload_cnt_prev = tmr_reload_cnt;

			break;
		} /* case SYNC */

	} /* switch */

	spin_unlock_irqrestore(&cpts->lock, flags);

	cpts->count_prev = tmr_count;

	if(updated)
		pr_debug("cpts_tmr_poll(updated = %u): tmr_diff = %d, tmr_reload_cnt = %u, cpts_ts = %llu\n", updated, tmr_diff, tmr_reload_cnt, cpts_ts);

}

static inline void cpts_latch_pps_stop(struct cpts *cpts)
{
	u32 v;

	/* disable timer PWM (TRIG = 0) */
	v = READ_TCLR(cpts->odt2);
	v &= ~BIT(11);
	WRITE_TCLR(cpts->odt2, v);

	cpts->pps_latch_state = INIT;
}

static inline void cpts_latch_pps_start(struct cpts *cpts)
{
	u32 v;

	/* enable timer PWM (TRIG = 2) */
	v = READ_TCLR(cpts->odt2);
	v |= BIT(11);
	WRITE_TCLR(cpts->odt2, v);
}

static void cpts_latch_proc(struct cpts *cpts, u32 latch_cnt)
{
	u32 offset = 0xFFFFFFFFUL - latch_cnt + 1;
	u32 reload_cnt = CPTS_LATCH_TMR_RELOAD_CNT;
	static bool skip;

	if (!cpts)
		return;

	cpts->pps_latch_offset = offset * CPTS_TMR_CLK_PERIOD +
				 CPTS_TMR_LATCH_DELAY;
	cpts->pps_latch_receive = true;

	/* Timer poll state machine */
	switch (cpts->pps_latch_state) {
	case INIT:
		if (!skip) {
			if (offset < CPTS_LATCH_TICK_THRESH_MIN) {
				reload_cnt -= (CPTS_LATCH_TICK_THRESH_MID -
					       offset);
			} else if (offset > CPTS_LATCH_TICK_THRESH_MAX) {
				reload_cnt += (offset -
					       CPTS_LATCH_TICK_THRESH_MID);
			} else {
				/* latch offset is within the range,
				 * enter SYNC state
				 */
				cpts_latch_pps_start(cpts);
				cpts->pps_latch_state = SYNC;
				break;
			}

			skip = true;
		} else {
			skip = false;
		}

		WRITE_TLDR(cpts->odt2, reload_cnt);
		break;

	case ADJUST:
		/* Restore the LDR value */
		WRITE_TLDR(cpts->odt2, reload_cnt);
		cpts->pps_latch_state = SYNC;
		break;

	case SYNC:
		{
			if (offset > CPTS_LATCH_TICK_THRESH_UNSYNC) {
				/* latch offset is well out of the range,
				 * enter INIT (Out of Sync) state
				 */
				cpts_latch_pps_stop(cpts);
				cpts->pps_latch_state = INIT;
				break;
			} else if (offset < CPTS_LATCH_TICK_THRESH_MIN) {
				reload_cnt -= (CPTS_LATCH_TICK_THRESH_MID -
					       offset);
			} else if (offset > CPTS_LATCH_TICK_THRESH_MAX) {
				reload_cnt += (offset -
					       CPTS_LATCH_TICK_THRESH_MID);
			} else {
				/* latch offset is within the range,
				 * no adjustment is required
				 */
				break;
			}

			cpts->pps_latch_state = ADJUST;
			WRITE_TLDR(cpts->odt2, reload_cnt);
			break;
		}

	default:
		/* Error handling */
		break;

	} /* switch */
	pr_debug("cpts_latch_proc(%d): offset = %u(0x%x)\n",
		 cpts->pps_latch_state, offset, offset);
}

static int int_cnt;
static irqreturn_t cpts_1pps_tmr_interrupt(int irq, void *dev_id)
{
	struct cpts *cpts = (struct cpts*)dev_id;

	writel_relaxed(OMAP_TIMER_INT_OVERFLOW, cpts->odt->irq_stat);
	kthread_queue_delayed_work(cpts->pps_kworker, &cpts->pps_work,
				   msecs_to_jiffies(10));

	if(int_cnt <= 1000)
		int_cnt++;
	if ((int_cnt % 100) == 0)
		printk("cpts_1pps_tmr_interrupt %d\n", int_cnt);

	return IRQ_HANDLED;
}

static int latch_cnt;
static irqreturn_t cpts_1pps_latch_interrupt(int irq, void *dev_id)
{
	struct cpts *cpts = (struct cpts *)dev_id;

	writel_relaxed(OMAP_TIMER_INT_CAPTURE, cpts->odt2->irq_stat);

	cpts_latch_proc(cpts, READ_TCAP(cpts->odt2));

	if (latch_cnt <= 100)
		latch_cnt++;
	if ((latch_cnt % 10) == 0)
		pr_info("cpts_1pps_latch_interrupt %d\n", latch_cnt);

	return IRQ_HANDLED;
}

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("TI CPTS driver");
MODULE_AUTHOR("Richard Cochran <richardcochran@gmail.com>");
