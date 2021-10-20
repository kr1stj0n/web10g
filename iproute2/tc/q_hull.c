/*
 * q_hull.c		HULL - Phantom queue
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Kristjon Ciko
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "utils.h"
#include "tc_util.h"

static void explain(void)
{
	fprintf(stderr,
		"Usage: hull limit BYTES rate BPS burst BYTES markth BYTES\n");
}

static void explain1(const char *arg, const char *val)
{
	fprintf(stderr, "hull: illegal value for \"%s\": \"%s\"\n", arg, val);
}

static int hull_parse_opt(struct qdisc_util *qu, int argc, char **argv,
			  struct nlmsghdr *n, const char *dev)
{
        int ok = 0;
	struct tc_hull_qopt opt = {};
        __u32 rtab[256];
	unsigned burst = 0, mtu = 1500, mpu = 0;
	int Rcell_log =  -1;
	unsigned short overhead = 0;
	unsigned int linklayer = LINKLAYER_ETHERNET;	/* Assume ethernet */
	struct rtattr *tail;
	__u64 rate64 = 0;

	while (argc > 0) {
		if (matches(*argv, "limit") == 0) {
			NEXT_ARG();
			if (opt.limit) {
				fprintf(stderr, "hull: duplicate \"limit\" specification\n");
				return -1;
			}
			if (get_size(&opt.limit, *argv)) {
				explain1("limit", *argv);
				return -1;
			}
			ok++;
                } else if (strcmp(*argv, "rate") == 0) {
			NEXT_ARG();
			if (rate64) {
				fprintf(stderr, "hull: duplicate \"rate\" specification\n");
				return -1;
			}
			if (strchr(*argv, '%')) {
				if (get_percent_rate64(&rate64, *argv, dev)) {
					explain1("rate", *argv);
					return -1;
				}
			} else if (get_rate64(&rate64, *argv)) {
				explain1("rate", *argv);
				return -1;
			}
			ok++;
		} else if (matches(*argv, "markth") == 0) {
			NEXT_ARG();
			if (opt.markth) {
				fprintf(stderr, "hull: duplicate \"markth\" specification\n");
				return -1;
			}
			if (get_size(&opt.markth, *argv)) {
				explain1("markth", *argv);
				return -1;
			}
			ok++;
		} else if (matches(*argv, "burst") == 0) {
			const char *parm_name = *argv;

			NEXT_ARG();
			if (burst) {
				fprintf(stderr, "hull: duplicate \"burst\" specification\n");
				return -1;
			}
			if (get_size_and_cell(&burst, &Rcell_log, *argv) < 0) {
				explain1(parm_name, *argv);
				return -1;
			}
			ok++;
		}  else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "hull: unknown parameter \"%s\"\n", *argv);
			explain();
			return -1;
		}
		argc--; argv++;
	}

	int verdict = 0;

	/* Be nice to the user: try to emit all error messages in
	 * one go rather than reveal one more problem when a
	 * previous one has been fixed.
	 */
        if (opt.limit == 0) {
            fprintf(stderr, "hull: \"limit\" is required.\n");
            verdict = -1;
        }
	if (rate64 == 0) {
		fprintf(stderr, "hull: the \"rate\" parameter is mandatory.\n");
		verdict = -1;
	}
	if (!burst) {
		fprintf(stderr, "hull: the \"burst\" parameter is mandatory.\n");
		verdict = -1;
	}
	if (!opt.markth) {
		fprintf(stderr, "hull: the \"markth\" parameter is mandatory.\n");
		verdict = -1;
	}
	if (verdict != 0) {
		explain();
		return verdict;
	}

	opt.rate.rate = (rate64 >= (1ULL << 32)) ? ~0U : rate64;

	opt.rate.mpu = mpu;
	opt.rate.overhead = overhead;
	if (tc_calc_rtable(&opt.rate, rtab, Rcell_log, mtu, linklayer) < 0) {
		fprintf(stderr, "hull: failed to calculate rate table.\n");
		return -1;
	}
	opt.burst = tc_calc_xmittime(opt.rate.rate, burst);

	tail = addattr_nest(n, 1024, TCA_OPTIONS);
	addattr_l(n, 2024, TCA_HULL_PARMS, &opt, sizeof(opt));
	addattr_l(n, 2124, TCA_HULL_BURST, &burst, sizeof(burst));
	if (rate64 >= (1ULL << 32))
		addattr_l(n, 2124, TCA_HULL_RATE64, &rate64, sizeof(rate64));
	addattr_l(n, 3024, TCA_HULL_RTAB, rtab, 1024);
	addattr_nest_end(n, tail);
	return 0;
}

static int hull_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	struct rtattr *tb[TCA_TBF_MAX+1];
	struct tc_hull_qopt *qopt;
	double burst;
	double latency;
	__u64 rate64 = 0;

	SPRINT_BUF(b1);
	SPRINT_BUF(b2);

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_HULL_MAX, opt);

	if (tb[TCA_HULL_PARMS] == NULL)
		return -1;

	qopt = RTA_DATA(tb[TCA_HULL_PARMS]);
	if (RTA_PAYLOAD(tb[TCA_HULL_PARMS])  < sizeof(*qopt))
		return -1;

	fprintf(f, "limit %s ", sprint_size(qopt->limit, b1));

	rate64 = qopt->rate.rate;
	if (tb[TCA_HULL_RATE64] &&
	    RTA_PAYLOAD(tb[TCA_HULL_RATE64]) >= sizeof(rate64))
		rate64 = rta_getattr_u64(tb[TCA_HULL_RATE64]);
	fprintf(f, "rate %s ", sprint_rate(rate64, b1));

	burst = tc_calc_xmitsize(rate64, qopt->burst);
	if (show_details) {
		fprintf(f, "burst %s/%u mpu %s ", sprint_size(burst, b1),
			1<<qopt->rate.cell_log, sprint_size(qopt->rate.mpu, b2));
	} else {
		fprintf(f, "burst %s ", sprint_size(burst, b1));
	}
	if (show_raw)
		fprintf(f, "[%08x] ", qopt->burst);

	latency = TIME_UNITS_PER_SEC*(qopt->limit/(double)rate64) - tc_core_tick2time(qopt->burst);
	if (latency >= 0.0)
		fprintf(f, "latency %s ", sprint_time(latency, b1));

	fprintf(f, "markth %s ", sprint_size(qopt->markth, b1));

	if (qopt->rate.overhead) {
		fprintf(f, "overhead %d", qopt->rate.overhead);
	}

	return 0;
}

static int hull_print_xstats(struct qdisc_util *qu, FILE *f,
			     struct rtattr *xstats)
{
	struct tc_hull_xstats *st;

	if (xstats == NULL)
		return 0;

	if (RTA_PAYLOAD(xstats) < sizeof(*st))
		return -1;

	st = RTA_DATA(xstats);

	if (st->avg_rate)
		print_uint(PRINT_ANY, "avg_rate", " avg_rate %u", st->avg_rate);

	fprintf(f, " delay %lluus ", (unsigned long long) st->qdelay);

	print_nl();
	print_uint(PRINT_ANY, "packets_in", " packets_in %u", st->packets_in);
	print_uint(PRINT_ANY, "dropped", " dropped %u", st->dropped);
        print_uint(PRINT_ANY, "overlimit", " overlimit %u", st->overlimit);
	print_uint(PRINT_ANY, "maxq", " maxq %hu", st->maxq);
	print_uint(PRINT_ANY, "ecn_mark", " ecn_mark %u", st->ecn_mark);

	return 0;
}

struct qdisc_util hull_qdisc_util = {
	.id		= "hull",
	.parse_qopt	= hull_parse_opt,
	.print_qopt	= hull_print_opt,
	.print_xstats	= hull_print_xstats,
};
