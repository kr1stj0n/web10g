// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/sched/sch_hull.c HULL
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
	u64 last;	/* time when last packet was dequeued */
	u64 freq;	/* dequeuing frequency */
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

static void hull_params_init(struct hull_sched_data *q)
{
	q->params.limit  = 1000U;		/* default of 1000 packets */
	q->params.drate  = 12500000U;		/* default 100Mbps */
	q->params.markth = 1514U;		/* default 1 pkt */
}

static void hull_vars_init(struct hull_sched_data *q)
{
	q->vars.last	= ktime_get_ns();
	q->vars.freq	= 120000ULL;
	q->vars.counter = 0U;
	q->vars.mtu	= 1514U;
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
	unsigned int len;
	int ret;

	if (qdisc_pkt_len(skb) > q->vars.mtu) {
		if (skb_is_gso(skb) &&
		    skb_gso_validate_mac_len(skb, q->vars.mtu))
			return hull_segment(skb, sch, to_free);
		return qdisc_drop(skb, sch, to_free);
	}

	len = qdisc_pkt_len(skb);
	if (q->vars.counter + len > q->params.markth) {
		if (INET_ECN_set_ce(skb)) {
			/* If packet is ecn capable, mark it with a prob. */
			q->stats.ecn_mark++;
		}
	}

	/* Timestamp the packet in order to calculate
	 * * the queuing delay in the dequeue process.
	 * */
	__net_timestamp(skb);

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
	unsigned int len;
	u64 qdelay = 0ULL;

	skb = q->qdisc->ops->peek(q->qdisc);

	if (skb) {
		if (ktime_get_ns() >= q->vars.last + q->vars.freq) {
			skb = qdisc_dequeue_peeked(q->qdisc);
			if (unlikely(!skb))
				return NULL;

			q->vars.last = ktime_get_ns();
			qdisc_qstats_backlog_dec(sch, skb);
			len = qdisc_pkt_len(skb);
			if (q->vars.counter > len)
				q->vars.counter -= len;
			else
				q->vars.counter = 0U;
			sch->q.qlen--;
			qdisc_bstats_update(sch, skb);
			/* >> 10 is approx /1000 */
			qdelay = ((__force __u64)(ktime_get_real_ns() -
					ktime_to_ns(skb_get_ktime(skb)))) >> 10;
			q->stats.qdelay = qdelay;

			return skb;
		}

		qdisc_watchdog_schedule_ns(&q->watchdog,
					   q->vars.last + q->vars.freq);
		qdisc_qstats_overlimit(sch);
	}
	return NULL;
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
	struct Qdisc *child = NULL;
	int err;

	err = nla_parse_nested_deprecated(tb, TCA_HULL_MAX, opt, hull_policy,
			NULL);
	if (err < 0)
		return err;

	err = -EINVAL;
	if (tb[TCA_HULL_LIMIT] == NULL)
		goto done;
	q->params.limit = nla_get_u32(tb[TCA_HULL_LIMIT]);

	if (tb[TCA_HULL_DRATE]) {
		q->params.drate = nla_get_u32(tb[TCA_HULL_DRATE]);
		q->vars.freq = psched_ns_freq(q->params.drate, q->vars.mtu);
	}

	if (tb[TCA_HULL_MARKTH])
		q->params.markth = nla_get_u32(tb[TCA_HULL_MARKTH]);

	if (q->qdisc != &noop_qdisc) {
		err = fifo_set_limit(q->qdisc, q->params.limit);
		if (err)
			goto done;
	} else if (q->params.limit > 0) {
		child = fifo_create_dflt(sch, &bfifo_qdisc_ops, q->params.limit,
					 extack);
		if (IS_ERR(child)) {
			err = PTR_ERR(child);
			goto done;
		}

		/* child is fifo, no need to check for noop_qdisc */
		qdisc_hash_add(child, true);
	}
	sch_tree_lock(sch);
	if (child) {
		qdisc_tree_flush_backlog(q->qdisc);
		qdisc_put(q->qdisc);
		q->qdisc = child;
	}
	sch_tree_unlock(sch);
	err = 0;
done:
	return err;
}

static int hull_init(struct Qdisc *sch, struct nlattr *opt,
		     struct netlink_ext_ack *extack)
{
	struct hull_sched_data *q = qdisc_priv(sch);

	qdisc_watchdog_init(&q->watchdog, sch);
	q->qdisc = &noop_qdisc;

	if (!opt)
		return -EINVAL;

	hull_params_init(q);
	hull_vars_init(q);
	q->vars.mtu = psched_mtu(qdisc_dev(sch));

	return hull_change(sch, opt, extack);
}


static int hull_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct hull_sched_data *q = qdisc_priv(sch);
	struct nlattr *opts = nla_nest_start_noflag(skb, TCA_OPTIONS);

	sch->qstats.backlog = q->qdisc->qstats.backlog;
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
		.avg_rate	= q->stats.avg_rate,
		.qdelay 	= q->stats.qdelay,
		.packets_in	= q->stats.packets_in,
		.dropped	= q->stats.dropped,
		.overlimit	= q->stats.overlimit,
		.maxq		= q->stats.maxq,
		.ecn_mark	= q->stats.ecn_mark,
	};

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static void hull_reset(struct Qdisc *sch)
{
	struct hull_sched_data *q = qdisc_priv(sch);

	qdisc_reset(q->qdisc);
	sch->qstats.backlog = 0;
	sch->q.qlen = 0;

	/* Reset vars */
	hull_vars_init(q);

	/* Only cancel watchdog if it's been initialized. */
	if (q->watchdog.qdisc == sch)
		qdisc_watchdog_cancel(&q->watchdog);
}

static void hull_destroy(struct Qdisc *sch)
{
	struct hull_sched_data *q = qdisc_priv(sch);

	/* Only cancel watchdog if it's been initialized. */
	if (q->watchdog.qdisc == sch)
		qdisc_watchdog_cancel(&q->watchdog);
	qdisc_put(q->qdisc);
}

static int hull_dump_class(struct Qdisc *sch, unsigned long cl,
			   struct sk_buff *skb, struct tcmsg *tcm)
{
	struct hull_sched_data *q = qdisc_priv(sch);

	tcm->tcm_handle |= TC_H_MIN(1);
	tcm->tcm_info = q->qdisc->handle;

	return 0;
}

static int hull_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
		      struct Qdisc **old, struct netlink_ext_ack *extack)
{
	struct hull_sched_data *q = qdisc_priv(sch);

	if (new == NULL)
		new = &noop_qdisc;

	*old = qdisc_replace(sch, new, &q->qdisc);
	return 0;
}

static struct Qdisc *hull_leaf(struct Qdisc *sch, unsigned long arg)
{
	struct hull_sched_data *q = qdisc_priv(sch);
	return q->qdisc;
}

static unsigned long hull_find(struct Qdisc *sch, u32 classid)
{
	return 1;
}

static void hull_walk(struct Qdisc *sch, struct qdisc_walker *walker)
{
	if (!walker->stop) {
		if (walker->count >= walker->skip)
			if (walker->fn(sch, 1, walker) < 0) {
				walker->stop = 1;
				return;
			}
		walker->count++;
	}
}

static const struct Qdisc_class_ops hull_class_ops = {
	.graft		=	hull_graft,
	.leaf		=	hull_leaf,
	.find		=	hull_find,
	.walk		=	hull_walk,
	.dump		=	hull_dump_class,
};

static struct Qdisc_ops hull_qdisc_ops __read_mostly = {
	.next		=	NULL,
	.cl_ops		=	&hull_class_ops,
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
