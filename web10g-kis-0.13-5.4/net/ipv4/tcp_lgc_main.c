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
#define BIG_ONE		(1LL<<16)
#define THRESSH		((9U<<16)/10U)		/* ~0.9  */
#define FRAC_LIMIT	((99U<<16)/100U)	/* ~0.99 */
#define BW_GAIN		((120U<<16)/100U)	/* ~1.3 */

struct lgc {
	u32 old_delivered;
	u32 old_delivered_ce;
	u32 next_seq;
	u64 rate;
	u64 max_rate;
	u32 minRTT;
	u32 fraction;
	u8  rate_eval:1;
};

/* Module parameters */
/* lgc_alpha_16 = alpha << 16 = 0.05 * 2^16 */
static unsigned int lgc_alpha_16 __read_mostly = 3277;
module_param(lgc_alpha_16, uint, 0644);
MODULE_PARM_DESC(lgc_alpha_16, "scaled alpha");

/* lgc_max_rate = 12500 bytes/msec = 100Mbps */
static unsigned int lgc_max_rate __read_mostly = 12500;
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
	u64 max_rate_scaled = (u64)lgc_max_rate;

	if ((sk->sk_state == TCP_LISTEN || sk->sk_state == TCP_CLOSE)
                                        || (tp->ecn_flags & TCP_ECN_OK)) {
		struct lgc *ca = inet_csk_ca(sk);

		max_rate_scaled <<= LGC_SHIFT;
		ca->max_rate  = max_rate_scaled;
		ca->rate_eval = 0;
		ca->rate      = 12500ULL;
		ca->minRTT    = 1U<<20;	/* reference of minRTT ever seen ~1s */
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

/* Calculate the initial rate of the flow in bytes/mSec
 * rate = cwnd * mss / rtt_ms
 */
static void lgc_init_rate(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct lgc *ca = inet_csk_ca(sk);

	u64 init_rate = (u64)(tp->snd_cwnd * tp->mss_cache * USEC_PER_MSEC);
	init_rate <<= LGC_SHIFT;
	do_div(init_rate, ca->minRTT);

	ca->rate = init_rate;
	ca->rate_eval = 1;
}

static void lgc_update_pacing_rate(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	u64 rate;

	/* set sk_pacing_rate to 100 % of current rate (mss * cwnd / rtt) */
	rate = (u64)tp->mss_cache * ((USEC_PER_SEC / 100) << 3);

	/* current rate is (cwnd * mss) / srtt
	 * In Slow Start [1], set sk_pacing_rate to 200 % the current rate.
	 * In Congestion Avoidance phase, set it to 120 % the current rate.
	 *
	 * [1] : Normal Slow Start condition is (tp->snd_cwnd < tp->snd_ssthresh)
	 *	 If snd_cwnd >= (tp->snd_ssthresh / 2), we are approaching
	 *	 end of slow start and should slow down.
	 */

	rate *= 100U;

	rate *= max(tp->snd_cwnd, tp->packets_out);

	if (likely(tp->srtt_us))
		do_div(rate, tp->srtt_us);

	/* WRITE_ONCE() is needed because sch_fq fetches sk_pacing_rate
	 * without any lock. We want to make sure compiler wont store
	 * intermediate values in this location.
	 */
	WRITE_ONCE(sk->sk_pacing_rate, min_t(u64, rate, sk->sk_max_pacing_rate));
}

static void lgc_update_rate(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgc *ca = inet_csk_ca(sk);
	s64 gr_rate_gradient = 1LL;
	u64 rate = ca->rate; u64 rateo = ca->rate, new_rate = 0ULL;
	u32 fraction = 0U, gr;

	u32 delivered_ce = tp->delivered_ce - ca->old_delivered_ce;
	u32 delivered = tp->delivered - ca->old_delivered;

	delivered_ce <<= LGC_SHIFT;
	delivered_ce /= max(delivered, 1U);

	if (delivered_ce >= THRESSH)
		fraction = ((ONE - lgc_alpha_16) * ca->fraction) + (lgc_alpha_16 * delivered_ce);
	else
		fraction = (ONE - lgc_alpha_16) * ca->fraction;

	ca->fraction = fraction >> LGC_SHIFT;
	if (ca->fraction == ONE)
		ca->fraction = FRAC_LIMIT;

	/* At this point, we have a ca->fraction = [0,1) << LGC_SHIFT */

	/* Calculate gradient

	 *            - log2(rate/max_rate)    -log2(1-fraction)
	 * gradient = --------------------- - ------------------
         *                 log2(phi1)             log2(phi2)
	 */

	do_div(rateo, lgc_max_rate);
	s32 first_term = (s32)lgc_log_lut_lookup((u32)rateo);
	s32 second_term = (s32)lgc_log_lut_lookup((u32)(ONE - ca->fraction));
	s32 gradient = first_term - second_term;

	/* s64 gradient = (s64)((s64)(BIG_ONE) - (s64)(rateo) - (s64)q); */

	gr = lgc_exp_lut_lookup(delivered_ce); /* 16bit scaled */

	gr_rate_gradient *= gr;
	gr_rate_gradient *= rate;	/* rate: bpms << 16 */
	gr_rate_gradient *= gradient;
	gr_rate_gradient >>= 32;	/* back to 16-bit scaled */

	new_rate = (u64)(rate + gr_rate_gradient);

	/* new rate shouldn't increase more than twice */
	if (new_rate > (rate << 1))
		rate <<= 1;
	else if (new_rate == 0)
		rate = 65536U;
	else
		rate = new_rate;

	/* Check if the new rate exceeds the link capacity */
	if (rate > ca->max_rate)
		rate = ca->max_rate;

	/* lgc_rate can be read from lgc_get_info() without
	 * synchro, so we ask compiler to not use rate
	 * as a temporary variable in prior operations.
	 */
	WRITE_ONCE(ca->rate, rate);
}

/* Calculate cwnd based on current rate and minRTT
 * cwnd = rate * minRT / mss
 */
static void lgc_set_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgc *ca = inet_csk_ca(sk);

	u64 target_cwnd = ca->rate * ca->minRTT;
	target_cwnd >>= LGC_SHIFT;
	do_div(target_cwnd, tp->mss_cache * USEC_PER_MSEC);

	tp->snd_cwnd = max_t(u32, (u32)target_cwnd + 1, 10U);
	/* Add a small gain to avoid truncation in bandwidth - disabled 4 now */
	/* tp->snd_cwnd *= BW_GAIN; */
	/* tp->snd_cwnd >>= 16; */

	if (tp->snd_cwnd > tp->snd_cwnd_clamp)
		tp->snd_cwnd = tp->snd_cwnd_clamp;
}

static void tcp_lgc_main(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct lgc *ca = inet_csk_ca(sk);

	/* Expired RTT */
	if (!before(tp->snd_una, ca->next_seq)) {
		ca->minRTT = min_not_zero(tcp_min_rtt(tp), ca->minRTT);
		if (unlikely(!ca->rate_eval))
			lgc_init_rate(sk);

		lgc_update_rate(sk);
		lgc_set_cwnd(sk);
		lgc_reset(tp, ca);
	}

	lgc_update_pacing_rate(sk);
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
			info->lgc.lgc_rate = ca->rate >> LGC_SHIFT;
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
MODULE_VERSION("1.31");
MODULE_DESCRIPTION("Logistic Growth Congestion Control (LGC)");
