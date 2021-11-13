// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/sch_hull.c Phantom queue
 *
 * Author:	Kristjon Ciko
 */

#include "linux/pkt_sched.h"
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/sch_generic.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>

#define HULL_SCALE 8

/*	Simple Token Bucket Filter.
	=======================================

	SOURCE.
	-------

	None.

	Description.
	------------

	A data flow obeys TBF with rate R and depth B, if for any
	time interval t_i...t_f the number of transmitted bits
	does not exceed B + R*(t_f-t_i).

	Packetized version of this definition:
	The sequence of packets of sizes s_i served at moments t_i
	obeys TBF, if for any i<=k:

	s_i+....+s_k <= B + R*(t_k - t_i)

	Algorithm.
	----------

	Let N(t_i) be B/R initially and N(t) grow continuously with time as:

	N(t+delta) = min{B/R, N(t) + delta}

	If the first packet in queue has length S, it may be
	transmitted only at the time t_* when S/R <= N(t_*),
	and in this case N(t) jumps:

	N(t_* + 0) = N(t_* - 0) - S/R.



	Actually, QoS requires two TBF to be applied to a data stream.
	One of them controls steady state burst size, another
	one with rate P (peak rate) and depth M (equal to link MTU)
	limits bursts at a smaller time scale.

	It is easy to see that P>R, and B>M. If P is infinity, this double
	TBF is equivalent to a single one.

	When TBF works in reshaping mode, latency is estimated as:

	lat = max ((L-B)/R, (L-M)/P)


	NOTES.
	------

	If TBF throttles, it starts a watchdog timer, which will wake it up
	when it is ready to transmit.
	Note that the minimal timer resolution is 1/HZ.
	If no new packets arrive during this period,
	or if the device is not awaken by EOI for some previous packet,
	TBF can stop its activity for 1/HZ.


	This means, that with depth B, the maximal rate is

	R_crit = B*HZ

	F.e. for 10Mbit ethernet and HZ=100 the minimal allowed B is ~10Kbytes.

	Note that the peak rate TBF is much more tough: with MTU 1500
	P_crit = 150Kbytes/sec. So, if you need greater peak
	rates, use alpha with HZ=1000 :-)

	With classful TBF, limit is just kept for backwards compatibility.
	It is passed to the default bfifo qdisc - if the inner qdisc is
	changed the limit is not effective anymore.
*/

/* parameters used */
struct hull_params {
	u32 limit;	/* Maximal length of backlog: bytes */
	u32 drate; 	/* drain rate of PQ */
	u32 markth;	/* ECN marking threshold */
};

/* statistics gathering */
struct hull_stats {
	u32 avg_rate;		/* current average rate */
	u64 qdelay;		/* current queuing delay */
	u32 packets_in;		/* total number of packets enqueued */
	u32 dropped;		/* packets dropped due to hull_action */
	u32 overlimit;		/* dropped due to lack of space in queue */
	u16 maxq;		/* maximum queue size ever seen */
	u32 ecn_mark;		/* packets marked with ECN */
};

/* variables used */
struct hull_vars {
	u64 t_c;	/* Time check-point */
	u64 freq;	/* dequeue frequency */
	u32 counter;	/* PQ counter */
	u32 mtu;	/* MTU of interface */
};

struct hull_sched_data {
	struct hull_params params;	/* HULL parameters */
	struct hull_vars vars;		/* HULL variables */
	struct hull_stats stats;	/* HULL statistics */
	struct qdisc_watchdog watchdog;	/* Watchdog timer */
	struct Qdisc	*qdisc;		/* Inner qdisc, default - bfifo queue */
};

static void hull_params_init(struct hull_params *params)
{
	params->limit  = 1000U;		   /* default of 1000 packets */
	params->drate  = 12500000U;	   /* default 100Mbps */
	params->markth = 1514U;		   /* default 1 pkt */
}

static void hull_vars_init(struct hull_vars *vars)
{
	vars->t_c = ktime_get_ns();
	vars->freq = 0ULL;
	vars->counter = 0U;
	vars->mtu = 0U;
}

/* Calculates the frequency in ns of dequeueing a packet based on drain rate
 */
static inline u64 psched_ns_freq(u32 drate, u32 mtu)
{
	u64 div = (u64)(1ULL * mtu * NSEC_PER_SEC);

	do_div(div, drate);

	return div;
}

/* GSO packet is too big, segment it so that hull can transmit
 * each segment in time
 */
static int hull_segment(struct sk_buff *skb, struct Qdisc *sch,
			struct sk_buff **to_free)
{
	struct hull_sched_data *q = qdisc_priv(sch);
	struct sk_buff *segs, *nskb;
	netdev_features_t features = netif_skb_features(skb);
	unsigned int len = 0, prev_len = qdisc_pkt_len(skb);
	int ret, nb;

	segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);

	if (IS_ERR_OR_NULL(segs))
		return qdisc_drop(skb, sch, to_free);

	nb = 0;
	while (segs) {
		nskb = segs->next;
		skb_mark_not_on_list(segs);
		qdisc_skb_cb(segs)->pkt_len = segs->len;
		len += segs->len;
		ret = qdisc_enqueue(segs, q->qdisc, to_free);
		if (ret != NET_XMIT_SUCCESS) {
			if (net_xmit_drop_count(ret))
				qdisc_qstats_drop(sch);
		} else {
			nb++;
		}
		segs = nskb;
	}
	sch->q.qlen += nb;
	if (nb > 1)
		qdisc_tree_reduce_backlog(sch, 1 - nb, prev_len - len);
	consume_skb(skb);
	return nb > 0 ? NET_XMIT_SUCCESS : NET_XMIT_DROP;
}

static int hull_enqueue(struct sk_buff *skb, struct Qdisc *sch,
		        struct sk_buff **to_free)
{
	struct hull_sched_data *q = qdisc_priv(sch);
	unsigned int len = qdisc_pkt_len(skb);
	int ret;

	if (qdisc_pkt_len(skb) > q->vars.mtu) {
		if (skb_is_gso(skb) &&
		    skb_gso_validate_mac_len(skb, q->vars.mtu))
			return hull_segment(skb, sch, to_free);
		return qdisc_drop(skb, sch, to_free);
	}

	/* Timestamp the packet in order to calculate
	 * * the queuing delay in the dequeue process.
	 * */
	__net_timestamp(skb);

	if (q->vars.counter + len > q->params.markth) {
		if (INET_ECN_set_ce(skb)) {
			/* If packet is ecn capable, mark it with a prob. */
			q->stats.ecn_mark++;
		}
	}

	ret = qdisc_enqueue(skb, q->qdisc, to_free);
	if (ret != NET_XMIT_SUCCESS) {
		if (net_xmit_drop_count(ret))
			qdisc_qstats_drop(sch);
		return ret;
	}

	sch->qstats.backlog += len;
	sch->q.qlen++;
	if (qdisc_qlen(sch) > q->stats.maxq)
		q->stats.maxq = qdisc_qlen(sch);
	q->vars.counter += len;
	q->stats.packets_in++;
	return NET_XMIT_SUCCESS;
}

static struct sk_buff *hull_dequeue(struct Qdisc *sch)
{
	struct hull_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	u64 qdelay = 0ULL;

	skb = q->qdisc->ops->peek(q->qdisc);

	if (skb) {
		u64 now, delta;

		now = ktime_get_ns();
		delta = now - q->vars.t_c;

		if (delta >= q->vars.freq) {
			skb = qdisc_dequeue_peeked(q->qdisc);
			if (unlikely(!skb))
				return NULL;

			q->vars.t_c = now;
			qdisc_qstats_backlog_dec(sch, skb);
			q->vars.counter -= qdisc_pkt_len(skb);
			sch->q.qlen--;
			qdisc_bstats_update(sch, skb);
			/* >> 10 is approx /1000 */
			qdelay = ((__force __u64)(ktime_get_real_ns() -
					ktime_to_ns(skb_get_ktime(skb)))) >> 10;
			q->stats.qdelay = qdelay;

			return skb;
		}

		qdisc_watchdog_schedule_ns(&q->watchdog, q->vars.t_c + q->vars.freq);

		qdisc_qstats_overlimit(sch);
	}
	return NULL;
}

static void hull_reset(struct Qdisc *sch)
{
	struct hull_sched_data *q = qdisc_priv(sch);

	/* Only cancel watchdog if it's been initialized. */
	if (q->watchdog.qdisc == sch)
		qdisc_watchdog_cancel(&q->watchdog);

	qdisc_reset_queue(sch);

	hull_vars_init(&q->vars);
}

static const struct nla_policy hull_policy[TCA_HULL_MAX + 1] = {
	[TCA_HULL_LIMIT]  = { .type = NLA_U32 },
	[TCA_HULL_DRATE] = { .type = NLA_U32 },
	[TCA_HULL_MARKTH] = { .type = NLA_U32 },
};

static int hull_change(struct Qdisc *sch, struct nlattr *opt,
		       struct netlink_ext_ack *extack)
{
	struct hull_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_HULL_MAX + 1];
	u32 limit, qlen,dropped;
	int err;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested_deprecated(tb, TCA_HULL_MAX, opt, shq_policy,
			NULL);
	if (err < 0)
		return err;

	sch_tree_lock(sch);

	if (tb[TCA_HULL_LIMIT]) {
		limit = nla_get_u32(tb[TCA_HULL_LIMIT]);

		q->params.limit = limit;
		sch->limit = limit;
	}

	if (tb[TCA_HULL_DRATE])
		q->params.drate = nla_get_u32(tb[TCA_HULL_DRATE]);

	if (tb[TCA_HULL_MARKTH])
		q->params.markth = nla_get_u32(tb[TCA_HULL_MARKTH]);

	/* Drop excess packets if new limit is lower */
	qlen = sch->q.qlen;
	while (sch->q.qlen > sch->limit) {
		struct sk_buff *skb = __qdisc_dequeue_head(&sch->q);

		dropped += qdisc_pkt_len(skb);
		qdisc_qstats_backlog_dec(sch, skb);
		rtnl_qdisc_drop(skb, sch);
	}
	qdisc_tree_reduce_backlog(sch, qlen - sch->q.qlen, dropped);

	sch_tree_unlock(sch);
	return 0;
}

static int hull_init(struct Qdisc *sch, struct nlattr *opt,
		     struct netlink_ext_ack *extack)
{
	struct hull_sched_data *q = qdisc_priv(sch);

	hull_params_init(&q->params);
	hull_vars_init(&q->vars);
	sch->limit = q->params.limit;

	q->qdisc = sch;
	qdisc_watchdog_init(&q->watchdog, sch);
	q->vars.mtu = psched_mtu(qdisc_dev(sch));

	if (!opt)
		return -EINVAL;

	return hull_change(sch, opt, extack);
}

static void hull_destroy(struct Qdisc *sch)
{
	struct hull_sched_data *q = qdisc_priv(sch);

	/* Only cancel watchdog if it's been initialized. */
	if (q->watchdog.qdisc == sch)
		qdisc_watchdog_cancel(&q->watchdog);
}

static int hull_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct hull_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts = nla_nest_start_noflag(skb, TCA_OPTIONS);

	if (!opts)
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_HULL_LIMIT, sch->limit) ||
	    nla_put_u32(skb, TCA_HULL_DRATE, q->params.drate) ||
	    nla_put_u32(skb, TCA_HULL_MARKTH, q->params.markth))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	nla_nest_cancel(skb, opts);
	return -1;
}

static int hull_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct hull_sched_data *q = qdisc_priv(sch);
	struct tc_hull_xstats st = {
		/* unscale and return dq_rate in bytes per sec */
		.avg_rate	= q->stats.avg_rate * (PSCHED_TICKS_PER_SEC) >> HULL_SCALE,
		.qdelay         = q->stats.qdelay,
		.packets_in	= q->stats.packets_in,
		.dropped	= q->stats.dropped,
		.overlimit	= q->stats.overlimit,
		.maxq		= q->stats.maxq,
		.ecn_mark	= q->stats.ecn_mark,
	};

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static struct Qdisc_ops hull_qdisc_ops __read_mostly = {
	.id		=	"hull",
	.priv_size	=	sizeof(struct hull_sched_data),
	.enqueue	=	hull_enqueue,
	.dequeue	=	hull_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	hull_init,
	.reset		=	hull_reset,
	.destroy	=	hull_destroy,
	.change		=	hull_change,
	.dump		=	hull_dump,
	.dump_stats	=	hull_dump_stats,
	.owner		=	THIS_MODULE,
};

static int __init hull_module_init(void)
{
	return register_qdisc(&hull_qdisc_ops);
}

static void __exit hull_module_exit(void)
{
	unregister_qdisc(&hull_qdisc_ops);
}

module_init(hull_module_init)
module_exit(hull_module_exit)

MODULE_LICENSE("GPL");
