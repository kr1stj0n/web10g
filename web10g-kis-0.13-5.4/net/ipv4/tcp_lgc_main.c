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
#define ONE             (1U<<LGC_SHIFT)
#define THRESSH         ((9*ONE)/10)    /* ~0.9 */

struct lgc {
	u32 old_delivered;
	u32 old_delivered_ce;
	u32 prior_rcv_nxt;
	u32 next_seq;
	u32 loss_cwnd;
        u32 rate;                                 /* rate = snd_cwnd / minrtt */
        u32 fraction;
        u8  rate_eval:1;                /* indicates initial rate calculation */
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

/* default lgc_max_rate = 125000000 bpms */
static unsigned int lgc_max_rate __read_mostly = 125000;
module_param(lgc_max_rate, uint, 0644);
MODULE_PARM_DESC(lgc_max_rate, "lgc_max_rate");
/* End of Module parameters */

static struct tcp_congestion_ops lgc_reno;

static void lgc_reset(const struct tcp_sock *tp, struct lgc *ca)
{
	ca->next_seq = tp->snd_nxt;

	ca->old_delivered = tp->delivered;
	ca->old_delivered_ce = tp->delivered_ce;
}

static void lgc_init(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	if ((sk->sk_state == TCP_LISTEN || sk->sk_state == TCP_CLOSE)
                                        || (tp->ecn_flags & TCP_ECN_OK)) {
		struct lgc *ca = inet_csk_ca(sk);

		ca->prior_rcv_nxt = tp->rcv_nxt;
		ca->loss_cwnd = 0;
                ca->rate_eval = 0;
		lgc_reset(tp, ca);
		return;
	}

	/* No ECN support? Fall back to Reno. Also need to clear
	 * ECT from sk since it is set during 3WHS for LGC.
	 */
	inet_csk(sk)->icsk_ca_ops = &lgc_reno;
	INET_ECN_dontxmit(sk);
}

static u32 lgc_ssthresh(struct sock *sk)
{
        const struct tcp_sock *tp = tcp_sk(sk);
	struct lgc *ca = inet_csk_ca(sk);

	ca->loss_cwnd = tp->snd_cwnd;

	return max(tp->snd_cwnd >> 1U, 2U);
}

static void lgc_update_rate(struct sock *sk, u32 flags)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgc *ca = inet_csk_ca(sk);
        u64 cwnd_B;
        u32 rtt;

	/* Expired RTT */
	if (!before(tp->snd_una, ca->next_seq)) {
                if (!ca->rate_eval) {
                        /* Calculate initial rate in bytes/msec */
                        cwnd_B = (u64)tp->snd_cwnd * (u64)tp->mss_cache *
                                          USEC_PER_MSEC;
                        rtt = max(tp->srtt_us >> 3, 1U);
                        do_div(cwnd_B, rtt);
                        ca->rate = (u32)cwnd_B + 1;
                        ca->rate_eval = 1;
                }

		u32 delivered = tp->delivered - ca->old_delivered;
		u32 delivered_ce = tp->delivered_ce - ca->old_delivered_ce;

                delivered_ce <<= LGC_SHIFT;
		delivered_ce /= max(1U, delivered);

                u32 fraction = 0U;
                if (delivered_ce >= THRESSH) {
                        fraction = (ONE - lgc_alpha_scaled) * ca->fraction +
                                   lgc_alpha_scaled * delivered_ce;
                        ca->fraction = fraction >> LGC_SHIFT;
                } else {
                        fraction = (ONE - lgc_alpha_scaled) * ca->fraction;
                        ca->fraction = fraction >> LGC_SHIFT;
                }

                if (ca->fraction >= ONE)
                        ca->fraction = (98 * ONE) / 100;

                /* after the division, q is FP << 16 */
                u32 q = 0U;
                if (ca->fraction)
                        q = lgc_log_lut_lookup(ca->fraction) / lgc_logPhi_scaled;
                else
                        q = 0U;

                u32 rate = ca->rate;
                s32 gradient = (ONE) - ((rate<<LGC_SHIFT) / lgc_max_rate) - q;

                u32 gr = 0U;
                if (delivered_ce)
                        gr = lgc_exp_lut_lookup(delivered_ce);
                else
                        gr = 1U << 30;

                u64 rate64 = (u64)rate;
                u64 grXrateXgradient = (u64)gr * (u64)lgc_logP_scaled;
                grXrateXgradient >>= 30;       /* 16-bit scaled at this point */
                grXrateXgradient *= rate64;
                s64 grXrateXgradient64 = (s64)grXrateXgradient;
                grXrateXgradient64 *= (s64)gradient;
                rate64 <<= 32;
                grXrateXgradient64 += rate64;
                u32 newRate = (u32)(grXrateXgradient64 >> 32);

                if (newRate > 2 * lgc_max_rate)
                        rate <<= 1;
                else
                        rate = newRate;

                if (rate <= 0U)
                        rate = 2U;
                if (rate > lgc_max_rate)
                        rate = lgc_max_rate;

                rtt = max(tp->srtt_us >> 3, 1U);
                rtt <<= 8; rtt /= USEC_PER_MSEC;
                cwnd_B = (u64)rate * (u64)rtt;
                cwnd_B >>= 8;
		do_div(cwnd_B, tp->mss_cache);
                tp->snd_cwnd = max((u32)cwnd_B, 2U);

		/* lgc_rate can be read from lgc_get_info() without
		 * synchro, so we ask compiler to not use rate
		 * as a temporary variable in prior operations.
		 */
		WRITE_ONCE(ca->rate, rate);
		lgc_reset(tp, ca);
	}
}

static void lgc_react_to_loss(struct sock *sk)
{
        struct tcp_sock *tp = tcp_sk(sk);
	struct lgc *ca = inet_csk_ca(sk);

	ca->loss_cwnd = tp->snd_cwnd;
	tp->snd_ssthresh = max(tp->snd_cwnd >> 1U, 2U);
}

static void lgc_state(struct sock *sk, u8 new_state)
{
	if (new_state == TCP_CA_Recovery &&
            new_state != inet_csk(sk)->icsk_ca_state)
		lgc_react_to_loss(sk);
	/* We handle RTO in lgc_cwnd_event to ensure that we perform only
	 * one loss-adjustment per RTT.
	 */
}

static void lgc_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	switch (ev) {
	case CA_EVENT_LOSS:
		lgc_react_to_loss(sk);
		break;
	default:
		/* Don't care for the rest. */
		break;
	}
}

static size_t lgc_get_info(struct sock *sk, u32 ext, int *attr,
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

static u32 lgc_cwnd_undo(struct sock *sk)
{
	const struct lgc *ca = inet_csk_ca(sk);

	return max(tcp_sk(sk)->snd_cwnd, ca->loss_cwnd);
}

static struct tcp_congestion_ops lgc __read_mostly = {
	.init		= lgc_init,
	.in_ack_event   = lgc_update_rate,
	.cwnd_event	= lgc_cwnd_event,
	.ssthresh	= lgc_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.undo_cwnd	= lgc_cwnd_undo,
	.set_state	= lgc_state,
	.get_info	= lgc_get_info,
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
