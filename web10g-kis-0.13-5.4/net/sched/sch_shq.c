// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) University of Oslo, Norway, 2021.
 *
 * Author: Peyman Teymoori <peymant@ifi.uio.no>
 * Author: Kr1stj0n C1k0 <kristjoc@ifi.uio.no>
 *
 * References:
 * TODO
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <net/inet_ecn.h>

#define SHQ_SCALE 24
#define SHQ_SCALE2 8
#define ONE (1U<<SHQ_SCALE)

/* parameters used */
struct shq_params {
        u32 limit;		/* number of packets that can be enqueued */
	psched_time_t interval;	/* user specified interval in pschedtime */
	u32 maxp;		/* maxp is the scaled maximum prob. [0,1] */
	u32 alpha;		/* alpha is between 0 and 1 */
	u32 bandwidth;		/* bandwidth interface bytes/sec */
	bool ecn;		/* true if ecn is enabled */
};

/* variables used */
struct shq_vars {
	u32 prob;		/* probability but scaled by u64 limit. */
	u32 avg_qlen;	        /* average length of the queue */
	u32 cur_qlen;	        /* current length of the queue */
        u32 avg_rate;           /* bytes per pschedtime tick, scaled */
        psched_time_t r_time;
};

/* statistics gathering */
struct shq_stats {
        u32 prob;               /* current probability */
        u64 qdelay;             /* current queuing delay */
        u32 avg_rate;           /* current average rate */
	u32 packets_in;		/* total number of packets enqueued */
	u32 dropped;		/* packets dropped due to shq_action */
	u32 overlimit;		/* dropped due to lack of space in queue */
	u32 maxq;		/* maximum queue size ever seen */
	u32 ecn_mark;		/* packets marked with ECN */
};

/* private data for the Qdisc */
struct shq_sched_data {
	struct shq_params params;
	struct shq_vars vars;
	struct shq_stats stats;
	struct Qdisc *sch;
};

static void shq_params_init(struct shq_params *params)
{
        params->limit     = 1000;	           /* default of 1000 packets */
        params->interval  = PSCHED_NS2TICKS(10 * NSEC_PER_MSEC);     /* 10 ms */
	params->maxp      = 0;
	params->alpha     = 0;
	params->bandwidth = 0;
	params->ecn       = true;
}

static void shq_vars_init(struct shq_vars *vars)
{
        vars->prob     = 0;
	vars->avg_qlen = 0;
	vars->cur_qlen = 0;
        vars->avg_rate = 0;
	vars->r_time   = psched_get_time();
}

static bool should_mark(struct Qdisc *sch)
{
	struct shq_sched_data *q = qdisc_priv(sch);
        u32 rand = 0U;
        /* Generate a random 4-byte number */
	prandom_bytes(&rand, 3);
        if (rand < q->vars.prob)
		return true;

	return false;
}

static void calc_probability(struct Qdisc *sch, psched_time_t delta)
{
	struct shq_sched_data *q = qdisc_priv(sch);
        u64 avg_qlen, cur_qlen;
        u64 max_bytes;
        u32 prob32;

        q->vars.cur_qlen += sch->qstats.backlog;       /* queue size in bytes */
        cur_qlen = (u64)(q->vars.cur_qlen << SHQ_SCALE2);
        avg_qlen = (u64)q->vars.avg_qlen;

        avg_qlen = (u64)((u64)(ONE - q->params.alpha) * avg_qlen) +
                        (u64)((u64)(q->params.alpha) * (u64)(cur_qlen));
        avg_qlen >>= SHQ_SCALE;
        q->vars.avg_qlen = (u32)avg_qlen;

        max_bytes = (u64)((q->params.bandwidth / MSEC_PER_SEC) *
                          (u64)(PSCHED_TICKS2NS(delta)));
        do_div(max_bytes, NSEC_PER_MSEC);

        avg_qlen *= (u64)(q->params.maxp);
        do_div(avg_qlen, (u32)max_bytes);
        prob32 = (u32)(avg_qlen >> SHQ_SCALE2);
        if (prob32 > q->params.maxp)
                prob32 = q->params.maxp;

        /* Reset time and cur_qlen */
        q->vars.r_time   = psched_get_time();
        q->vars.cur_qlen = 0U;

        /* Update vars and stats */
        q->vars.prob  = prob32;
        q->stats.prob = prob32;
}

static int shq_qdisc_enqueue(struct sk_buff *skb, struct Qdisc *sch,
                             struct sk_buff **to_free)
{
	struct shq_sched_data *q = qdisc_priv(sch);
        psched_time_t delta;
	bool enqueue = false;

        /* Timestamp the packet in order to calculate
         * the queue stats in the dequeue process.
         */
        __net_timestamp(skb);

	if (unlikely(qdisc_qlen(sch) >= sch->limit)) {
		q->stats.overlimit++;
		goto out;
	}

        q->vars.cur_qlen += skb->len;
        delta = psched_get_time() - q->vars.r_time;

        if (delta >= q->params.interval)
                calc_probability(sch, delta);

	if (!should_mark(sch)) {
                /* Don't mark the packet; enqueue since the queue is not full */
                enqueue = true;
        } else {
                if (q->params.ecn && INET_ECN_set_ce(skb)) {
		        /* If packet is ecn capable, mark it with a prob. */
	                q->stats.ecn_mark++;
		        enqueue = true;
                }
        }

	/* we can enqueue the packet */
	if (enqueue) {
		q->stats.packets_in++;
		if (qdisc_qlen(sch) > q->stats.maxq)
			q->stats.maxq = qdisc_qlen(sch);

		return qdisc_enqueue_tail(skb, sch);
	}

out:
	q->stats.dropped++;
	return qdisc_drop(skb, sch, to_free);
}

static const struct nla_policy shq_policy[TCA_SHQ_MAX + 1] = {
	[TCA_SHQ_LIMIT]     = {.type = NLA_U32},
	[TCA_SHQ_INTERVAL]  = {.type = NLA_U32},
	[TCA_SHQ_MAXP]      = {.type = NLA_U32},
	[TCA_SHQ_ALPHA]     = {.type = NLA_U32},
	[TCA_SHQ_BANDWIDTH] = {.type = NLA_U32},
	[TCA_SHQ_ECN]       = {.type = NLA_U32},
};

static int shq_change(struct Qdisc *sch, struct nlattr *opt,
                      struct netlink_ext_ack *extack)
{
	struct shq_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_SHQ_MAX + 1];
	u32 qlen, us, dropped = 0;
	int err;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested_deprecated(tb, TCA_SHQ_MAX, opt, shq_policy,
                                          NULL);
	if (err < 0)
		return err;

	sch_tree_lock(sch);

	if (tb[TCA_SHQ_LIMIT]) {
		u32 limit = nla_get_u32(tb[TCA_SHQ_LIMIT]);

		q->params.limit = limit;
		sch->limit = limit;
	}

	/* interval is in us */
	if (tb[TCA_SHQ_INTERVAL]) {
                us = nla_get_u32(tb[TCA_SHQ_INTERVAL]);
		q->params.interval = PSCHED_NS2TICKS((u64)us * NSEC_PER_USEC);
        }
	if (tb[TCA_SHQ_MAXP])
		q->params.maxp = nla_get_u32(tb[TCA_SHQ_MAXP]);

	if (tb[TCA_SHQ_ALPHA])
		q->params.alpha = nla_get_u32(tb[TCA_SHQ_ALPHA]);

	if (tb[TCA_SHQ_BANDWIDTH])
		q->params.bandwidth = nla_get_u32(tb[TCA_SHQ_BANDWIDTH]);

	if (tb[TCA_SHQ_ECN])
		q->params.ecn = nla_get_u32(tb[TCA_SHQ_ECN]);

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

static int shq_init(struct Qdisc *sch, struct nlattr *opt,
                    struct netlink_ext_ack *extack)
{
	struct shq_sched_data *q = qdisc_priv(sch);
        int err;

	shq_params_init(&q->params);
	shq_vars_init(&q->vars);
	sch->limit = q->params.limit;

	q->sch = sch;

	if (opt) {
		err = shq_change(sch, opt, extack);
		if (err)
			return err;
	}

	return 0;
}

static int shq_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct shq_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts = nla_nest_start_noflag(skb, TCA_OPTIONS);

        if (!opts)
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_SHQ_LIMIT, sch->limit) ||
	    nla_put_u32(skb, TCA_SHQ_INTERVAL,
                        ((u32)PSCHED_TICKS2NS(q->params.interval)) /
                        NSEC_PER_USEC) ||
	    nla_put_u32(skb, TCA_SHQ_MAXP, q->params.maxp) ||
	    nla_put_u32(skb, TCA_SHQ_ALPHA, q->params.alpha) ||
	    nla_put_u32(skb, TCA_SHQ_BANDWIDTH, q->params.bandwidth) ||
	    nla_put_u32(skb, TCA_SHQ_ECN, q->params.ecn))
		goto nla_put_failure;

	return nla_nest_end(skb, opts);

nla_put_failure:
	nla_nest_cancel(skb, opts);
	return -1;
}

static int shq_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct shq_sched_data *q = qdisc_priv(sch);
	struct tc_shq_xstats st = {
		.prob		= q->vars.prob,
                .qdelay         = q->stats.qdelay,
		/* unscale and return avg_rate in bytes per sec */
		.avg_rate	= q->vars.avg_rate *
				  (PSCHED_TICKS_PER_SEC) >> SHQ_SCALE,
		.packets_in	= q->stats.packets_in,
		.dropped	= q->stats.dropped,
		.overlimit	= q->stats.overlimit,
		.maxq		= q->stats.maxq,
		.ecn_mark	= q->stats.ecn_mark,
	};

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static struct sk_buff *shq_qdisc_dequeue(struct Qdisc *sch)
{
        struct shq_sched_data *q = qdisc_priv(sch);
        u64 qdelay = 0;
	struct sk_buff *skb = qdisc_dequeue_head(sch);

	if (!skb)
		return NULL;

        /* >> 10 is approx /1000 */
        qdelay = ((__force __u64)(ktime_get_real_ns() -
                                ktime_to_ns(skb_get_ktime(skb)))) >> 10;
        q->stats.qdelay = qdelay;

	return skb;
}

static void shq_reset(struct Qdisc *sch)
{
	struct shq_sched_data *q = qdisc_priv(sch);

	qdisc_reset_queue(sch);
	shq_vars_init(&q->vars);
}

static void shq_destroy(struct Qdisc *sch)
{
	struct shq_sched_data *q = qdisc_priv(sch);

	q->params.interval = 0;
}

static struct Qdisc_ops shq_qdisc_ops __read_mostly = {
	.id             = "shq",
	.priv_size	= sizeof(struct shq_sched_data),
	.enqueue	= shq_qdisc_enqueue,
	.dequeue	= shq_qdisc_dequeue,
	.peek		= qdisc_peek_dequeued,
	.init		= shq_init,
	.destroy	= shq_destroy,
	.reset		= shq_reset,
	.change		= shq_change,
	.dump		= shq_dump,
	.dump_stats	= shq_dump_stats,
	.owner		= THIS_MODULE,
};

static int __init shq_module_init(void)
{
	return register_qdisc(&shq_qdisc_ops);
}

static void __exit shq_module_exit(void)
{
	unregister_qdisc(&shq_qdisc_ops);
}

module_init(shq_module_init);
module_exit(shq_module_exit);

MODULE_DESCRIPTION("Shadow Queue scheduler");
MODULE_AUTHOR("Kr1stj0n C1k0");
MODULE_LICENSE("GPL");
