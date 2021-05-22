// SPDX-License-Identifier: GPL-2.0-or-later
/* Logistic Growth Control (LGC) congestion control.
 *
 * https://uio.no
 *
 * This is an implementation of DCTCP over Reno, an enhancement to the
 * TCP congestion control algorithm designed for data centers. DCTCP
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

#define LGC_SHIFT	16
#define ONE             (1U<<16)
#define THRESSH         ((9U<<16)/10U)    /* ~0.9 */

struct lgc {
	u32 old_delivered;
	u32 old_delivered_ce;
	u32 next_seq;
        u32 rate;                                 /* rate = snd_cwnd / minrtt */
        u32 fraction;
        u8  rate_eval:1;                /* indicates initial rate calculation */
	u8  doing_lgc_now:1;	/* if true, do vegas for this RTT */
	u16 cntRTT;		/* # of RTTs measured within last RTT */
	u32 minRTT;	/* min of RTTs measured within last RTT (in usec) */
	u32 baseRTT;	/* the min of all LGC RTT measurements seen (in usec) */
};

/* Module parameters */
/* lgc_logPhi_scaled = log2(2.78)*pow(2, 11) */
static unsigned int lgc_logPhi_scaled __read_mostly = 3020;
module_param(lgc_logPhi_scaled, uint, 0644);
MODULE_PARM_DESC(lgc_logPhi_scaled, "scaled log(phi)");

/* lgc_alpha_scaled = alpha = 0.25*2^16 */
static unsigned int lgc_alpha_scaled __read_mostly = 16384;
module_param(lgc_alpha_scaled, uint, 0644);
MODULE_PARM_DESC(lgc_alpha_scaled, "scaled alpha");

/* lgc_logP_scaled = log(1.4) * pow(2, 16) */
static unsigned int lgc_logP_scaled __read_mostly = 22051;
module_param(lgc_logP_scaled, uint, 0644);
MODULE_PARM_DESC(lgc_logP_scaled, "scaled logP");

/* default coef. = 20 */
static unsigned int lgc_coef __read_mostly = 20;
module_param(lgc_coef, uint, 0644);
MODULE_PARM_DESC(lgc_coef, "lgc_coef");

/* default lgc_max_rate = 1250 bpms or 10Mbps */
static unsigned int lgc_max_rate __read_mostly = 1250;
module_param(lgc_max_rate, uint, 0644);
MODULE_PARM_DESC(lgc_max_rate, "lgc_max_rate");
/* End of Module parameters */

static struct tcp_congestion_ops lgc_reno;

/* There are several situations when we must "re-start" LGC:
 *
 *  o when a connection is established
 *  o after an RTO
 *  o after fast recovery
 *  o when we send a packet and there is no outstanding
 *    unacknowledged data (restarting an idle connection)
 *
 * In these circumstances we cannot do a LGC calculation at the
 * end of the first RTT, because any calculation we do is using
 * stale info -- both the saved cwnd and congestion feedback are
 * stale.
 *
 * Instead we must wait until the completion of an RTT during
 * which we actually receive ACKs.
 */
static void lgc_enable(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct lgc *ca = inet_csk_ca(sk);

	/* Begin taking LGC samples next time we send something. */
	ca->doing_lgc_now = 1;

	/* Set the beginning of the next send window. */
	ca->next_seq = tp->snd_nxt;

	ca->cntRTT = 0;
	ca->minRTT = 0x7fffffff;
}

/* Stop taking LGC samples for now. */
static inline void lgc_disable(struct sock *sk)
{
	struct lgc *ca = inet_csk_ca(sk);

	ca->doing_lgc_now = 0;
}

static void lgc_reset(const struct tcp_sock *tp, struct lgc *ca)
{
	ca->next_seq = tp->snd_nxt;

	ca->old_delivered = tp->delivered;
	ca->old_delivered_ce = tp->delivered_ce;

	ca->cntRTT = 0;
	ca->minRTT = 0x7fffffff;
}

static void tcp_lgc_init(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	if ((sk->sk_state == TCP_LISTEN || sk->sk_state == TCP_CLOSE)
                                        || (tp->ecn_flags & TCP_ECN_OK)) {
		struct lgc *ca = inet_csk_ca(sk);

                ca->rate_eval = 0;
                ca->fraction  = 0U;
		ca->baseRTT = 0x7fffffff;
		ca->doing_lgc_now = 1;
		lgc_reset(tp, ca);
		return;
	}

	/* No ECN support? Fall back to Reno. Also need to clear
	 * ECT from sk since it is set during 3WHS for LGC.
	 */
	inet_csk(sk)->icsk_ca_ops = &lgc_reno;
	INET_ECN_dontxmit(sk);
}

/* Do RTT sampling needed for LGC.
 * Basically we:
 *   o min-filter RTT samples from within an RTT to get the current
 *     propagation delay + queuing delay (we are min-filtering to try to
 *     avoid the effects of delayed ACKs)
 *   o min-filter RTT samples from a much longer window (forever for now)
 *     to find the propagation delay (baseRTT)
 */
static void tcp_lgc_pkts_acked(struct sock *sk, const struct ack_sample *sample)
{
	struct lgc *ca = inet_csk_ca(sk);
	u32 vrtt;

	if (sample->rtt_us < 0)
		return;

	/* Never allow zero rtt or baseRTT */
	vrtt = sample->rtt_us + 1;

	/* Filter to find propagation delay: */
	if (vrtt < ca->baseRTT)
		ca->baseRTT = vrtt;

	/* Find the min RTT during the last RTT to find
	 * the current prop. delay + queuing delay:
	 */
	ca->minRTT = min(ca->minRTT, vrtt);
	ca->cntRTT++;
}

static void tcp_lgc_state(struct sock *sk, u8 ca_state)
{
	if (ca_state == TCP_CA_Open)
		lgc_enable(sk);
	else
		lgc_disable(sk);
}

/*
 * If the connection is idle and we are restarting,
 * then we don't want to do any LGC calculations
 * until we get fresh RTT samples.  So when we
 * restart, we reset our LGC state to a clean
 * slate. After we get acks for this flight of
 * packets, _then_ we can make LGC calculations
 * again.
 */
static void tcp_lgc_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	struct lgc *ca = inet_csk_ca(sk);

	if (event == CA_EVENT_CWND_RESTART || event == CA_EVENT_TX_START) {
		ca->baseRTT = 0x7fffffff;
		lgc_enable(sk);
}

static inline u32 tcp_lgc_ssthresh(struct tcp_sock *tp)
{
	return  min(tp->snd_ssthresh, tp->snd_cwnd);
}

static void tcp_lgc_update_rate(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgc *ca = inet_csk_ca(sk);
        u32 init_rate;
        u32 rtt;

	if (!ca->doing_lgc_now) {
		tcp_reno_cong_avoid(sk, ack, acked);
		return;
	}

	/* Expired RTT */
	if (after(ack, ca->next_seq)) {
		/* We do the LGC calculations only if we got enough RTT
		 * samples that we can be reasonably sure that we got
		 * at least one RTT sample that wasn't from a delayed ACK.
		 * If we only had 2 samples total,
		 * then that means we're getting only 1 ACK per RTT, which
		 * means they're almost certainly delayed ACKs.
		 * If  we have 3 samples, we should be OK.
		 */

		if (ca->cntRTT <= 2) {
			/* We don't have enough RTT samples to do the LGC
			 * calculation, so we'll behave like Reno.
			 */
			tcp_reno_cong_avoid(sk, ack, acked);
		} else {
			if (!ca->rate_eval) {
				/* Calculate the initial rate in bytes/msec */
				init_rate = tp->snd_cwnd * tp->mss_cache * USEC_PER_MSEC;
				rtt = ca->baseRTT;
				ca->rate = init_rate / rtt;
				ca->rate <<= LGC_SHIFT;
				ca->rate_eval = 1;
			}

			u32 delivered = tp->delivered - ca->old_delivered;
			u32 delivered_ce = tp->delivered_ce - ca->old_delivered_ce;

			delivered_ce <<= LGC_SHIFT;
			delivered_ce /= max(1U, delivered);

			u32 fraction = 0U;
			if (delivered_ce >= THRESSH) {
				fraction = (ONE - lgc_alpha_scaled) * ca->fraction +
					(lgc_alpha_scaled * delivered_ce);
				ca->fraction = fraction >> LGC_SHIFT;
			} else {
				fraction = (ONE - lgc_alpha_scaled) * ca->fraction;
				ca->fraction = fraction >> LGC_SHIFT;
			}
			if (ca->fraction >= ONE)
				ca->fraction = (99U * ONE) / 100U;

			/* At this point we have a ca->fraction = [0,1) << LGC_SHIFT */

			/* after the division, q is FP << 16 */
			u32 q = 0U;
			if (ca->fraction)
				q = lgc_log_lut_lookup(ca->fraction) / lgc_logPhi_scaled;

			u32 rate = ca->rate;
			s32 gradient = (s32)((s32)ONE - (s32)(rate / lgc_max_rate) - (s32)q);

			u32 gr = 1U << 30;
			if (delivered_ce == ONE)
				gr /= lgc_coef;
			else {
				if (delivered_ce)
					gr = lgc_exp_lut_lookup(delivered_ce); /* gr is 30-bit scaled */
			}

			u64 rate64 = (u64)rate;
			u64 grXrateXgradient = (u64)gr * (u64)lgc_logP_scaled;
			grXrateXgradient >>= 30;       /* 16-bit scaled at this point */
			grXrateXgradient *= rate64;
			s64 grXrateXgradient64 = (s64)grXrateXgradient;
			grXrateXgradient64 *= (s64)gradient;
			/* rate64 <<= 16; */
			grXrateXgradient64 >>= 32;
			grXrateXgradient64 += rate64;
			/* u32 newRate = (u32)(grXrateXgradient64 >> LGC_SHIFT); */
			u64 newRate64 = (u64)(grXrateXgradient64);
			u32 newRate = (u32)newRate64;

			u32 scaled_rate = (rate);
			if (newRate > (scaled_rate << 1))
				scaled_rate <<= 1;
			else
				scaled_rate = newRate;

			if (scaled_rate <= 0U)
				scaled_rate = 2U << 16;
			if (scaled_rate > (lgc_max_rate << LGC_SHIFT))
				scaled_rate = (lgc_max_rate << LGC_SHIFT);

			rtt = ca->baseRTT;
			u64 cwnd_B = (u64)scaled_rate * (u64)rtt;
			cwnd_B /= USEC_PER_MSEC;
			cwnd_B >>= 16;
			do_div(cwnd_B, tp->mss_cache);
			tp->snd_cwnd = max((u32)cwnd_B, 2U);

			/* lgc_rate can be read from lgc_get_info() without
			 * synchro, so we ask compiler to not use rate
			 * as a temporary variable in prior operations.
			 */
			WRITE_ONCE(ca->rate, scaled_rate);
			tcp_lgc_reset(tp, ca);
		}
	}
	/* Use normal slow start */
	else if (tcp_in_slow_start(tp))
		tcp_slow_start(tp, acked);
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
	.ssthresh	= tcp_reno_ssthresh,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.cwnd_event	= tcp_lgc_cwnd_event,
	.cong_avoid	= tcp_lgc_update_rate,,
	.pkts_acked»    = tcp_lgc_pkts_acked,
	.set_state	= tcp_lgc_state,
	.get_info	= tcp_lgc_get_info,

	.flags		= TCP_CONG_NEEDS_ECN,
	.owner		= THIS_MODULE,
	.name		= "lgc",
};

static struct tcp_congestion_ops lgc_reno __read_mostly = {
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.get_info	= lgc_get_info,
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
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("Logistic Growth Control(LGC) Congestion Control");
