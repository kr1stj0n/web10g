// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) University of Oslo, Norway, 2021.
 *
 * Author: Kr1stj0n C1k0 <kristjoc@ifi.uio.no>
 *
 * References:
 * https://www.usenix.org/system/files/nsdi20-paper-goyal.pdf
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>

#define ABC_SCALE 16
#define ONE (1U<<16)

/* parameters used */
struct abc_params {
	u32 limit;		/* number of packets that can be enqueued */
	u32 bandwidth;		/* bandwidth interface bytes/sec */
	psched_time_t interval;	/* user specified interval in pschedtime */
	u32 ita;		/* ita is the scaled ita value [0,1] */
	psched_time_t delta;	/* user specified delta in pschedtime */
	psched_time_t rqdelay;	/* reference queuing delay */
	u32 tokens;		/* default tokens available 5 */
};

/* variables used */
struct abc_vars {
	u64 avg_qlen;		/* average length of the queue */
	u64 cur_qlen;		/* current length of the queue */
	u32 avg_rate;		/* bytes per pschedtime tick, scaled */
	psched_time_t r_time;	/* last time prob. was calculated */
};

/* statistics gathering */
struct abc_stats {
	u32 avg_rate;		/* current average rate */
	u64 qdelay;		/* current queuing delay */
	u32 packets_in;		/* total number of packets enqueued */
	u32 dropped;		/* packets dropped due to abc_action */
	u32 overlimit;		/* dropped due to lack of space in queue */
	u16 maxq;		/* maximum queue size ever seen */
	u32 ecn_mark;		/* packets marked with ECN */
};

/* private data for the Qdisc */
struct abc_sched_data {
	struct abc_params params;
	struct abc_vars vars;
	struct abc_stats stats;
	struct Qdisc *sch;
};

static void abc_params_init(struct abc_params *params)
{
	params->limit     = 1000U;		/* default of 1000 packets */
	params->bandwidth = 125000U;		/* 1000Mbps */
	params->interval  = PSCHED_NS2TICKS(10 * NSEC_PER_MSEC);      /* 10ms */
	params->ita       = 1U;
	params->delta     = PSCHED_NS2TICKS(10 * NSEC_PER_MSEC);      /* 10ms */
	params->rqdelay   = PSCHED_NS2TICKS(10 * NSEC_PER_MSEC);      /* 10ms */
	params->tokens    = 5U;
}

static void abc_vars_init(struct abc_vars *vars)
{
	vars->avg_qlen = 0ULL;
	vars->cur_qlen = 0ULL;
	vars->avg_rate = 0U;
	vars->r_time   = psched_get_time();
}


static int abc_qdisc_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			     struct sk_buff **to_free)
{
	struct abc_sched_data *q = qdisc_priv(sch);

	if (unlikely(qdisc_qlen(sch) >= sch->limit)) {
		q->stats.overlimit++;
		goto out;
	}

	/* enqueue the packet */
	q->stats.packets_in++;
	if (qdisc_qlen(sch) > q->stats.maxq)
		q->stats.maxq = qdisc_qlen(sch);

	/* Timestamp the packet in order to calculate
	 * * the queuing delay in the dequeue process.
	 * */
	__net_timestamp(skb);
	return qdisc_enqueue_tail(skb, sch);
out:
	q->stats.dropped++;
	return qdisc_drop(skb, sch, to_free);
}

static const struct nla_policy abc_policy[TCA_ABC_MAX + 1] = {
	[TCA_ABC_LIMIT]     = {.type = NLA_U32},
	[TCA_ABC_BANDWIDTH] = {.type = NLA_U32},
	[TCA_ABC_INTERVAL]  = {.type = NLA_U32},
	[TCA_ABC_ITA]       = {.type = NLA_U32},
	[TCA_ABC_DELTA]     = {.type = NLA_U32},
	[TCA_ABC_RQDELAY]   = {.type = NLA_U32},
	[TCA_ABC_TOKENS]    = {.type = NLA_U32},
};

static int abc_change(struct Qdisc *sch, struct nlattr *opt,
		      struct netlink_ext_ack *extack)
{
	struct abc_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_ABC_MAX + 1];
	u32 qlen, us, dropped = 0U;
	int err;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested_deprecated(tb, TCA_ABC_MAX, opt, abc_policy,
			NULL);
	if (err < 0)
		return err;

	sch_tree_lock(sch);

	/* limit */
	if (tb[TCA_ABC_LIMIT]) {
		u32 limit = nla_get_u32(tb[TCA_ABC_LIMIT]);

		q->params.limit = limit;
		sch->limit = limit;
	}

	/* bandwidth */
	if (tb[TCA_ABC_BANDWIDTH])
		q->params.bandwidth = nla_get_u32(tb[TCA_ABC_BANDWIDTH]);

	/* interval is in us */
	if (tb[TCA_ABC_INTERVAL]) {
		us = nla_get_u32(tb[TCA_ABC_INTERVAL]);
		q->params.interval = PSCHED_NS2TICKS((u64)us * NSEC_PER_USEC);
	}

	/* scaled ita */
	if (tb[TCA_ABC_ITA])
		q->params.ita = nla_get_u32(tb[TCA_ABC_ITA]);

	/* delta is in us */
	if (tb[TCA_ABC_DELTA]) {
		us = nla_get_u32(tb[TCA_ABC_DELTA]);
		q->params.delta = PSCHED_NS2TICKS((u64)us * NSEC_PER_USEC);
	}

	/* rqdelay is in us */
	if (tb[TCA_ABC_RQDELAY]) {
		us = nla_get_u32(tb[TCA_ABC_RQDELAY]);
		q->params.rqdelay = PSCHED_NS2TICKS((u64)us * NSEC_PER_USEC);
	}

	if (tb[TCA_SHQ_TOKENS])
		q->params.tokens = nla_get_u32(tb[TCA_ABC_TOKENS]);

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

static int abc_init(struct Qdisc *sch, struct nlattr *opt,
		    struct netlink_ext_ack *extack)
{
	struct abc_sched_data *q = qdisc_priv(sch);
	int err;

	abc_params_init(&q->params);
	abc_vars_init(&q->vars);
	sch->limit = q->params.limit;

	q->sch = sch;

	if (opt) {
		err = abc_change(sch, opt, extack);
		if (err)
			return err;
	}

	return 0;
}

static int abc_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct abc_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts = nla_nest_start_noflag(skb, TCA_OPTIONS);

	if (!opts)
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_ABC_LIMIT, sch->limit) ||
	    nla_put_u32(skb, TCA_ABC_BANDWIDTH, q->params.bandwidth) ||
	    nla_put_u32(skb, TCA_ABC_INTERVAL, ((u32)PSCHED_TICKS2NS(q->params.interval)) / NSEC_PER_USEC) ||
	    nla_put_u32(skb, TCA_ABC_ITA, q->params.ita) ||
	    nla_put_u32(skb, TCA_ABC_DELTA, ((u32)PSCHED_TICKS2NS(q->params.delta)) / NSEC_PER_USEC) ||
	    nla_put_u32(skb, TCA_ABC_RQDELAY, ((u32)PSCHED_TICKS2NS(q->params.rqdelay)) / NSEC_PER_USEC) ||
	    nla_put_u32(skb, TCA_ABC_TOKENS, q->params.tokens))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	nla_nest_cancel(skb, opts);
	return -1;
}

static int abc_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct abc_sched_data *q = qdisc_priv(sch);
	struct tc_abc_xstats st = {
		.avg_rate	= q->vars.avg_rate,
		.qdelay         = q->stats.qdelay,
		.packets_in	= q->stats.packets_in,
		.dropped	= q->stats.dropped,
		.overlimit	= q->stats.overlimit,
		.maxq		= q->stats.maxq,
		.ecn_mark	= q->stats.ecn_mark,
	};

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static struct sk_buff *abc_qdisc_dequeue(struct Qdisc *sch)
{
	struct abc_sched_data *q = qdisc_priv(sch);
	u64 qdelay = 0ULL;
	struct sk_buff *skb = qdisc_dequeue_head(sch);

	if (unlikely(!skb))
		return NULL;

	/* >> 10 is approx /1000 */
	qdelay = ((__force __u64)(ktime_get_real_ns() -
				ktime_to_ns(skb_get_ktime(skb)))) >> 10;
	q->stats.qdelay = qdelay;

	return skb;
}

static void abc_reset(struct Qdisc *sch)
{
	struct abc_sched_data *q = qdisc_priv(sch);

	qdisc_reset_queue(sch);
	abc_vars_init(&q->vars);
}

static void abc_destroy(struct Qdisc *sch)
{
	struct abc_sched_data *q = qdisc_priv(sch);

	q->params.interval = UINT_MAX;
}

static struct Qdisc_ops abc_qdisc_ops __read_mostly = {
	.id		= "abc",
	.priv_size	= sizeof(struct abc_sched_data),
	.enqueue	= abc_qdisc_enqueue,
	.dequeue	= abc_qdisc_dequeue,
	.peek		= qdisc_peek_dequeued,
	.init		= abc_init,
	.destroy	= abc_destroy,
	.reset		= abc_reset,
	.change		= abc_change,
	.dump		= abc_dump,
	.dump_stats	= abc_dump_stats,
	.owner		= THIS_MODULE,
};

static int __init abc_module_init(void)
{
	return register_qdisc(&abc_qdisc_ops);
}

static void __exit abc_module_exit(void)
{
	unregister_qdisc(&abc_qdisc_ops);
}

module_init(abc_module_init);
module_exit(abc_module_exit);

MODULE_DESCRIPTION("ABC scheduler");
MODULE_AUTHOR("Kr1stj0n C1k0");
MODULE_LICENSE("GPL");
