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

#define LGC_SHIFT	16
#define ONE		(1U<<16)
#define THRESSH		((9U<<16)/10U)    /* ~0.9 */

struct lgc {
	u32 old_delivered;
	u32 old_delivered_ce;
	u32 next_seq;
	u32 rate;                                 /* rate = snd_cwnd / minrtt */
	u32 fraction;
	u8  rate_eval:1;                /* indicates initial rate calculation */
	u16 cntRTT;			/* # of RTTs measured within last RTT */
	u32 minRTT;	    /* min of RTTs measured within last RTT (in usec) */
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
		lgc_reset(tp, ca);

		return;
	}

	/* No ECN support? Fall back to Reno. Also need to clear
	 * ECT from sk since it is set during 3WHS for LGC.
	 */
	inet_csk(sk)->icsk_ca_ops = &lgc_reno;
	INET_ECN_dontxmit(sk);
}

/* Do RTT sampling needed for LGC. */
static void tcp_lgc_pkts_acked(struct sock *sk, const struct ack_sample *sample)
{
	struct lgc *ca = inet_csk_ca(sk);
	u32 rtt;

	if (sample->rtt_us < 0)
		return;

	/* Never allow zero rtt */
	rtt = sample->rtt_us + 1;

	/* Find min RTT */
	if (rtt < ca->minRTT)
		ca->minRTT = rtt;

	ca->cntRTT++;
}

/*
 * In case of loss, reset to default values
 */
static void tcp_lgc_state(struct sock *sk, u8 new_state)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgc *ca = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		ca->minRTT  = 0x7fffffff;
		ca->cntRTT = 0;
		tp->snd_ssthresh = max(tp->snd_cwnd >> 1U, 2U);
	}
}

static void lgc_update_rate(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgc *ca = inet_csk_ca(sk);
	u32 rate = ca->rate;

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
	grXrateXgradient64 >>= 32;

	u64 newRate64 = (u64)(grXrateXgradient64) + rate64;
	u32 newRate = (u32)newRate64;

	if (newRate > (rate << 1))
		rate <<= 1;
	else
		rate = newRate;

	if (rate <= 0U)
		rate = 2U << 16;
	if (rate > (lgc_max_rate << LGC_SHIFT))
		rate = (lgc_max_rate << LGC_SHIFT);

	/* lgc_rate can be read from lgc_get_info() without
	 * synchro, so we ask compiler to not use rate
	 * as a temporary variable in prior operations.
	 */
	WRITE_ONCE(ca->rate, rate);
}

static void tcp_lgc_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgc *ca = inet_csk_ca(sk);
        u32 init_rate = 0U;
        u32 rtt = 0U;

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
				rtt = ca->minRTT;
				ca->rate = init_rate / rtt;
				ca->rate <<= LGC_SHIFT;
				ca->rate_eval = 1;
			}

			lgc_update_rate(sk);

			rtt = ca->minRTT;
			u64 target_cwnd = (u64)(ca->rate) * (u64)rtt;
			target_cwnd /= USEC_PER_MSEC;
			target_cwnd >>= 16;
			do_div(target_cwnd, tp->mss_cache);
			tp->snd_cwnd = max((u32)target_cwnd + 1, 2U);

			if (tp->snd_cwnd > tp->snd_cwnd_clamp)
				tp->snd_cwnd = tp->snd_cwnd_clamp;
		}

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
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_lgc_cong_avoid,
	.set_state	= tcp_lgc_state,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.pkts_acked	= tcp_lgc_pkts_acked,
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
