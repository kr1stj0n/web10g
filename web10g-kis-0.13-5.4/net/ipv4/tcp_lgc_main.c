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
#define THRESSH		((9U<<16)/10U)    /* ~0.9  */
#define FRAC_LIMIT	((99U<<16)/100U)  /* ~0.99 */

struct lgc {
	u32 old_delivered;
	u32 old_delivered_ce;
	u32 next_seq;
	u32 rate;                                 /* rate = snd_cwnd / minrtt */
	u32 fraction;
	u8  rate_eval:1;                /* indicates initial rate calculation */
};

/* Module parameters */
/* lgc_logPhi_11 = log2(2.78)*pow(2, 11) */
static unsigned int lgc_logPhi_11 __read_mostly = 3020;
module_param(lgc_logPhi_11, uint, 0644);
MODULE_PARM_DESC(lgc_logPhi_11, "scaled log(phi)");

/* lgc_alpha_16 = alpha << 16 = 0.25*2^16 */
static unsigned int lgc_alpha_16 __read_mostly = 16384;
module_param(lgc_alpha_16, uint, 0644);
MODULE_PARM_DESC(lgc_alpha_16, "scaled alpha");

/* lgc_logP_16 = loge(1.4) * pow(2, 16) */
static unsigned int lgc_logP_16 __read_mostly = 22051;
module_param(lgc_logP_16, uint, 0644);
MODULE_PARM_DESC(lgc_logP_16, "scaled logP");

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

static void lgc_update_rate(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgc *ca = inet_csk_ca(sk);
	u32 rate = ca->rate;

	u32 delivered_ce = tp->delivered_ce - ca->old_delivered_ce;
	u32 delivered = tp->delivered - ca->old_delivered;

	delivered_ce <<= LGC_SHIFT;
	delivered_ce /= max(1U, delivered);

	u32 fraction = 0U;
	if (delivered_ce >= THRESSH) {
		fraction = ((ONE - lgc_alpha_16) * ca->fraction) +
			(lgc_alpha_16 * delivered_ce);
		ca->fraction = fraction >> LGC_SHIFT;
	} else {
		fraction = (ONE - lgc_alpha_16) * ca->fraction;
		ca->fraction = fraction >> LGC_SHIFT;
	}
	if (ca->fraction >= ONE)
		ca->fraction = FRAC_LIMIT;

	/* At this point, we have a ca->fraction = [0,1) << LGC_SHIFT */

	/* after the division, q is FP << 16 */
	u32 q = 0U;
	if (ca->fraction)
		q = lgc_log_lut_lookup(ca->fraction) / lgc_logPhi_11;

	s32 gradient = (s32)((s32)(ONE) - (s32)(rate / lgc_max_rate) - (s32)q);

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
	gr_rate_gradient *= gradient;
	gr_rate_gradient >>= 32;	/* 16-bit scaled at this point */

	u32 new_rate = (u32)(rate + gr_rate_gradient);

	if (new_rate > (rate << 1))
		rate <<= 1;
	else
		rate = new_rate;

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
        u32 rtt_us = 0U;

	/* Expired RTT */
	if (after(ack, ca->next_seq)) {
		rtt_us = tp->srtt_us >> 3;

		if (unlikely(!ca->rate_eval)) {
			/* Calculate the initial rate in bytes/msec */
			u32 init_rate = tp->snd_cwnd * tp->mss_cache * USEC_PER_MSEC;
			ca->rate = init_rate / rtt_us;
			ca->rate <<= LGC_SHIFT;      /* scale rate to 16 bits */
			ca->rate_eval = 1;
		}

		lgc_update_rate(sk);

		u64 target_cwnd = (u64)(ca->rate) * (u64)rtt_us;
		target_cwnd >>= LGC_SHIFT;
		do_div(target_cwnd, tp->mss_cache * USEC_PER_MSEC);

		tp->snd_cwnd = max((u32)target_cwnd + 1, 2U);

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
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_lgc_cong_avoid,
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
