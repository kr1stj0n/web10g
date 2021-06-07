// SPDX-License-Identifier: GPL-2.0-or-later
/* Logistic Growth Control (LGC) congestion control.
 *
 * https://www.mn.uio.no/ifi/english/research/projects/ocarina/
 *
 * This is an implementation of LGC over Reno, an enhancement to the
 * TCP congestion control algorithm designed for data centers. LGC
 * leverages Explicit Congestion Notification (ECN) in the network to
 * provide multi-bit feedback to the end hosts. LGC's goal is to meet
 * the following three data center transport requirements:
 *
 *  -
 *  -
 *
 * The algorithm is described in detail in the following two papers:
 *
 * 1) Peyman Teymoori, ...
 *
 * 2) Peyman Teymoori, ...
 *
 * Initial prototype on OMNet++ by Peyman Teymoori
 *
 * Author:
 *
 *	Kr1stj0n C1k0 <kristjoc@ifi.uio.no>
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>
#include "tcp_lgc.h"

/* Scale factor for rate in pkt/uSec unit to avoid truncation in bandwidth
 * estimation. The rate unit ~= (1500 bytes / 1 usec / 2^24) ~= 715 bps.
 * This handles bandwidths from 0.06pps (715bps) to 256Mpps (3Tbps) in a u32.
 * Since the minimum window is >=4 packets, the lower bound isn't
 * an issue. The upper bound isn't an issue with existing technologies.
 */
#define BW_SCALE_24 24
#define BW_UNIT_24 (1 << BW_SCALE_24)

#define LGC_SCALE_8 8	/* scaling factor for fractions in LGC (e.g. gains) */
#define LGC_UNIT_8 (1 << LGC_SCALE_8)

#define LGC_SHIFT_16	16
#define ONE		(1U<<16)
#define THRESSH		((9U<<16)/10U)    /* ~0.9  */
#define FRAC_LIMIT	((99U<<16)/100U)  /* ~0.99 */

struct lgc {
	u32 old_delivered;
	u32 old_delivered_ce;
	u32 next_seq;
	u32 max_rate;		/* link capacity in pkts/uSec << LGC_SHIFT_16 */
	u32 rate;		/* current rate in pkts/uSec << BW_SCALE_24 */
	u32 pacing_gain;
	u32 minRTT;
	u32 fraction;
	u8  rate_eval:1;
};

/* Module parameters */
/* lgc_logPhi_11 = log2(2.78) * 2^11 */
static unsigned int lgc_logPhi_11 __read_mostly = 3020u;
module_param(lgc_logPhi_11, uint, 0644);
MODULE_PARM_DESC(lgc_logPhi_11, "scaled log(phi)");

/* lgc_alpha_16 = alpha << 16 = 0.25 * 2^16 */
static unsigned int lgc_alpha_16 __read_mostly = 16384u;
module_param(lgc_alpha_16, uint, 0644);
MODULE_PARM_DESC(lgc_alpha_16, "scaled alpha");

/* lgc_logP_16 = loge(1.4) * 2^16 */
static unsigned int lgc_logP_16 __read_mostly = 22051u;
module_param(lgc_logP_16, uint, 0644);
MODULE_PARM_DESC(lgc_logP_16, "scaled logP");

/* lgc_coef = 20 */
static unsigned int lgc_coef __read_mostly = 20u;
module_param(lgc_coef, uint, 0644);
MODULE_PARM_DESC(lgc_coef, "lgc_coef");

/* lgc_max_rate = 100Mbps */
static unsigned int lgc_max_rate __read_mostly = 100u;
module_param(lgc_max_rate, uint, 0644);
MODULE_PARM_DESC(lgc_max_rate, "lgc_max_rate");
/* End of Module parameters */

/* Pace at ~1% below estimated bw, on average, to reduce queue at bottleneck.
 * In order to help drive the network toward lower queues and low latency while
 * maintaining high utilization, the average pacing rate aims to be slightly
 * lower than the estimated bandwidth. This is an important aspect of the
 * design.
 */
static const u32 lgc_pacing_margin_percent = 1;

/* We use a high_gain value of 2/ln(2) because it's the smallest pacing gain
 * that will allow a smoothly increasing pacing rate that will double each RTT
 * and send the same number of packets per RTT that an un-paced, slow-starting
 * Reno or CUBIC flow would:
 */
static const u32 lgc_high_gain = LGC_UNIT_8 * 2885 / 1000 + 1;

/*
 * Mehh 1/ln(2)
 */
static const u32 lgc_low_gain  = LGC_UNIT_8 * 1442 / 1000 + 1;


/* The pacing gain of 1/high_gain in LGC_DRAIN is calculated to typically drain
 * the queue created in LGC_STARTUP in a single round:
 */
static const u32 lgc_drain_gain = LGC_UNIT_8 * 1000 / 2885;
/*
 * Used for init_rate only and when sender is fully utilizing the link.
 */
static const u32 lgc_no_gain = LGC_UNIT_8;

static struct tcp_congestion_ops lgc_reno;

static void lgc_reset(const struct tcp_sock *tp, struct lgc *ca)
{
	ca->next_seq = tp->snd_nxt;

	ca->old_delivered = tp->delivered;
	ca->old_delivered_ce = tp->delivered_ce;
}

/* Convert lgx_max_rate to pkts/uSec << LGC_SHIFT_16.
 */
static u32 lgc_max_rate_to_rate(struct sock *sk)
{
	unsigned int mss = tcp_sk(sk)->mss_cache;
	u64 max_rate = (u64)lgc_max_rate;

	max_rate <<= LGC_SHIFT_16;
	do_div(max_rate, mss);	/* from bytes to pkts */
	max_rate >>= 3;		/* from bits to bytes*/

	return (u32)max_rate;
}

static void tcp_lgc_init(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	if ((sk->sk_state == TCP_LISTEN || sk->sk_state == TCP_CLOSE)
                                        || (tp->ecn_flags & TCP_ECN_OK)) {
		struct lgc *ca = inet_csk_ca(sk);

		ca->rate_eval	= 0;
		ca->max_rate	= lgc_max_rate_to_rate(sk);
		ca->rate	= 1U;
		ca->pacing_gain	= lgc_high_gain;
		ca->minRTT	= 1U<<20; /* reference RTT ~1s */
		ca->fraction	= 0U;
		lgc_reset(tp, ca);

		return;
	}

	/* No ECN support? Fall back to Reno. Also need to clear
	 * ECT from sk since it is set during 3WHS for LGC.
	 */
	inet_csk(sk)->icsk_ca_ops = &lgc_reno;
	INET_ECN_dontxmit(sk);
}

/* Return rate in bytes per second, optionally with a gain.
 * The order here is chosen carefully to avoid overflow of u64. This should
 * work for input rates of up to 2.9Tbit/sec and gain of 2.89x.
 */
static u64 lgc_rate_bytes_per_sec(struct sock *sk, u64 rate, u32 gain)
{
	unsigned int mss = tcp_sk(sk)->mss_cache;

	rate *= mss;
	rate *= gain;
	rate >>= LGC_SCALE_8;
	rate *= USEC_PER_SEC / 100 * (100 - lgc_pacing_margin_percent);
	return rate >> BW_SCALE_24;
}

/* Convert a LGC bw and gain factor to a pacing rate in bytes per second. */
static unsigned long lgc_bw_to_pacing_rate(struct sock *sk, u32 bw, u32 gain)
{
	u64 rate = (u64)bw;

	rate = lgc_rate_bytes_per_sec(sk, rate, gain);
	rate = min_t(u64, rate, sk->sk_max_pacing_rate);
	return rate;
}

static void lgc_update_pacing_rate(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgc *ca = inet_csk_ca(sk);
	unsigned long pacing_rate;

	if (unlikely(!ca->rate_eval && ca->minRTT)) {
		/* Calculate the initial rate in pkts/uSec << BW_SCALE_24 */
		u64 init_rate = (u64)tp->snd_cwnd * BW_UNIT_24;
		do_div(init_rate, ca->minRTT);
		ca->rate = (u32)init_rate;
		ca->rate_eval = 1;
	}

	pacing_rate = lgc_bw_to_pacing_rate(sk, ca->rate, ca->pacing_gain);

	/* WRITE_ONCE() is needed because sch_fq fetches sk_pacing_rate
	 * without any lock. We want to make sure compiler wont store
	 * intermediate values in this location.
	 */
	WRITE_ONCE(sk->sk_pacing_rate, min_t(u64, pacing_rate,
					     sk->sk_max_pacing_rate));
}

static void lgc_update_rate(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgc *ca = inet_csk_ca(sk);
	u64 rate = (u64)ca->rate;

	u32 delivered_ce = tp->delivered_ce - ca->old_delivered_ce;
	u32 delivered = tp->delivered - ca->old_delivered;

	delivered_ce <<= LGC_SHIFT_16;
	delivered_ce /= max(1U, delivered);

	u32 fraction = 0U;
	if (delivered_ce >= THRESSH) {
		fraction = ((ONE - lgc_alpha_16) * ca->fraction) +
			(lgc_alpha_16 * delivered_ce);
		ca->fraction = fraction >> LGC_SHIFT_16;
	} else {
		fraction = (ONE - lgc_alpha_16) * ca->fraction;
		ca->fraction = fraction >> LGC_SHIFT_16;
	}
	if (ca->fraction == ONE)
		ca->fraction = FRAC_LIMIT;

	/* At this point, we have a ca->fraction = [0,1) << LGC_SHIFT_16 */

	/* after the division, q is FP << 16 */
	u32 q = 0U;
	if (ca->fraction)
		q = lgc_log_lut_lookup(ca->fraction) / lgc_logPhi_11;

	/* Calculate gradient */
	u64 c_rate = rate << LGC_SCALE_8;
	do_div(c_rate, ca->max_rate);
	s32 gradient = (s32)((s32)(ONE) - (s32)c_rate - (s32)q);

	u32 gr = 1U<<30;
	if (delivered_ce == ONE)
		gr /= lgc_coef;
	else {
		if (delivered_ce)
			gr = lgc_exp_lut_lookup(delivered_ce); /* 30bit scaled */
	}

	s64 gr_rate_gradient = 1LL;
	gr_rate_gradient *= gr;
	gr_rate_gradient *= lgc_logP_16;
	gr_rate_gradient >>= 30;	/* 16-bit scaled at this point */
	gr_rate_gradient *= rate;
	gr_rate_gradient >>= 16;	/* back to 24-bit scaled */
	gr_rate_gradient *= gradient;
	gr_rate_gradient >>= 16;	/* back to 24-bit scaled */

	u64 new_rate = rate + gr_rate_gradient;

	/* new rate shouldn't increase more than twice */
	if (new_rate > (rate << 1)) {
		rate <<= 1;
		ca->pacing_gain = lgc_low_gain;
	} else {
		if (new_rate < rate)
			ca->pacing_gain = lgc_low_gain;
		else if (new_rate > rate)
			ca->pacing_gain = lgc_low_gain;
		rate = new_rate;
	}

	/* Check if the new rate exceeds the link capacity */
	u64 max_rate = (u64)ca->max_rate;
	max_rate <<= LGC_SCALE_8;
	if (rate > max_rate) {
		rate = max_rate;
		ca->pacing_gain = lgc_low_gain;
	}

	/* lgc_rate can be read from lgc_get_info() without
	 * synchro, so we ask compiler to not use rate
	 * as a temporary variable in prior operations.
	 */
	WRITE_ONCE(ca->rate, (u32)rate);
}

/* Calculate bdp based on min RTT and the estimated bottleneck bandwidth:
 *
 * bdp = ceil(bw * min_rtt * gain)
 *
 * The key factor, gain, controls the amount of queue. While a small gain
 * builds a smaller queue, it becomes more vulnerable to noise in RTT
 * measurements (e.g., delayed ACKs or other ACK compression effects). This
 * noise may cause LGC to under-estimate the rate.
 */
static u32 lgc_bdp(struct sock *sk, u32 bw, u32 gain)
{
	struct lgc *ca = inet_csk_ca(sk);
	u32 bdp;
	u64 w;

	w = (u64)bw * ca->minRTT;

	/* Apply a gain to the given value, remove the BW_SCALE_24 shift, and
	 * round the value up to avoid a negative feedback loop.
	 */
	bdp = (((w * gain) >> LGC_SCALE_8) + BW_UNIT_24 - 1) / BW_UNIT_24;

	return bdp;
}

static void tcp_lgc_main(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgc *ca = inet_csk_ca(sk);
        ca->minRTT = min_not_zero(tcp_min_rtt(tp), ca->minRTT);

	/*
	 * Update pacing rate upon every ACK.
	 * This seems better way, because it will react to minRTT.
	 */
	lgc_update_pacing_rate(sk);

	/* Expired RTT */
	if (!before(tp->snd_una, ca->next_seq)) {

		lgc_update_rate(sk);

		tp->snd_cwnd = max(lgc_bdp(sk, ca->rate, lgc_no_gain), 2U);

		if (tp->snd_cwnd > tp->snd_cwnd_clamp)
			tp->snd_cwnd = tp->snd_cwnd_clamp;

		lgc_reset(tp, ca);
	}
}

static size_t tcp_lgc_get_info(struct sock *sk, u32 ext, int *attr,
                           union tcp_cc_info *info)
{
	const struct lgc *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	/* Fill it also in case of VEGASINFO due to req struct limits.
	 * We can still correctly retrieve it later.
	 */
	if (ext & (1 << (INET_DIAG_LGCINFO - 1)) ||
	    ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		memset(&info->lgc, 0, sizeof(info->lgc));
		if (inet_csk(sk)->icsk_ca_ops != &lgc_reno) {
			info->lgc.lgc_enabled = 1;
			info->lgc.lgc_rate = ca->rate;
			info->lgc.lgc_ab_ecn = tp->mss_cache *
				      (tp->delivered_ce - ca->old_delivered_ce);
			info->lgc.lgc_ab_tot = tp->mss_cache *
					    (tp->delivered - ca->old_delivered);
		}

		*attr = INET_DIAG_LGCINFO;
		return sizeof(info->lgc);
	}
	return 0;
}

static struct tcp_congestion_ops lgc __read_mostly = {
	.init		= tcp_lgc_init,
	.cong_control	= tcp_lgc_main,
	.ssthresh	= tcp_reno_ssthresh,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.get_info	= tcp_lgc_get_info,
	.flags		= TCP_CONG_NEEDS_ECN,
	.owner		= THIS_MODULE,
	.name		= "lgc",
};

static struct tcp_congestion_ops lgc_reno __read_mostly = {
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.get_info	= tcp_lgc_get_info,
	.owner		= THIS_MODULE,
	.name		= "lgc-reno",
};

static int __init lgc_register(void)
{
	BUILD_BUG_ON(sizeof(struct lgc) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&lgc);
}

static void __exit lgc_unregister(void)
{
	tcp_unregister_congestion_control(&lgc);
}

module_init(lgc_register);
module_exit(lgc_unregister);

MODULE_AUTHOR("Peyman Teymoori <peymant@ifi.uio.no>");
MODULE_AUTHOR("Kr1stj0n C1k0 <kristjoc@ifi.uio.no>");
MODULE_LICENSE("GPL");
MODULE_VERSION("2.0");
MODULE_DESCRIPTION("Logistic Growth Control(LGC) Congestion Control");
