/* Copyright (C) 2013 Cisco Systems, Inc, 2013.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Author: Vijay Subramanian <vijaynsu@cisco.com>
 * Author: Mythili Prabhu <mysuryan@cisco.com>
 * Adapted for HULL by: Kr1stj0n C1k0 <kristjoc@ifi.uio.no>
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
#include <math.h>

#include "utils.h"
#include "tc_util.h"

static void explain(void)
{
	fprintf(stderr,
		"Usage: ... hull limit BYTES drate BPS markth BYTES\n");
}

static int hull_parse_opt(struct qdisc_util *qu, int argc, char **argv,
                         struct nlmsghdr *n, const char *dev)
{
	unsigned int limit = 1500000;		/* default: 1000p */
	unsigned int drate = 12500000;		/* default: 100mbit in bps */
	unsigned int markth = 1500;		/* default: 1p */
	struct rtattr *tail;

	while (argc > 0) {
		if (strcmp(*argv, "limit") == 0) {
			NEXT_ARG();
			if (get_size(&limit, *argv)) {
				fprintf(stderr, "Illegal \"limit\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "drate") == 0) {
			NEXT_ARG();
			if (strchr(*argv, '%')) {
				if (get_percent_rate(&drate, *argv, dev)) {
					fprintf(stderr,
                                                "Illegal \"drate\"\n");
					return -1;
				}
			} else if (get_rate(&drate, *argv)) {
				fprintf(stderr, "Illegal \"drate\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "markth") == 0) {
			NEXT_ARG();
			if (get_size(&markth, *argv)) {
				fprintf(stderr, "Illegal \"markth\"\n");
				return -1;
			}
		} else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "What is \"%s\"?\n", *argv);
			explain();
			return -1;
		}
		argc--;
		argv++;
	}

	tail = addattr_nest(n, 1024, TCA_OPTIONS);
	if (limit)
		addattr_l(n, 1024, TCA_HULL_LIMIT, &limit, sizeof(limit));
	if (!drate) {
		get_rate(&drate, "100Mbit");
		/* fprintf(stderr, "HULL: set bandwidth to 100Mbit\n"); */
	}
        if (drate)
                addattr_l(n, 1024, TCA_HULL_DRATE, &drate, sizeof(drate));
	if (markth)
		addattr_l(n, 1024, TCA_HULL_MARKTH, &markth, sizeof(markth));
	addattr_nest_end(n, tail);

	return 0;
}

static int hull_print_opt(struct qdisc_util *qu, FILE *f, struct rtattr *opt)
{
	struct rtattr *tb[TCA_HULL_MAX + 1];
	unsigned int limit;
	unsigned int drate;
	unsigned int markth;
	SPRINT_BUF(b1);

	if (opt == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_HULL_MAX, opt);

	if (tb[TCA_HULL_LIMIT] &&
            RTA_PAYLOAD(tb[TCA_HULL_LIMIT]) >= sizeof(__u32)) {
		limit = rta_getattr_u32(tb[TCA_HULL_LIMIT]);
		fprintf(f, "limit %s ", sprint_size(limit, b1));
	}
	if (tb[TCA_HULL_DRATE] &&
            RTA_PAYLOAD(tb[TCA_HULL_DRATE]) >= sizeof(__u32)) {
		drate = rta_getattr_u32(tb[TCA_HULL_DRATE]);
		fprintf(f, "drate %s ", sprint_size(drate, b1));
	}
	if (tb[TCA_HULL_MARKTH] &&
            RTA_PAYLOAD(tb[TCA_HULL_MARKTH]) >= sizeof(__u32)) {
		markth = rta_getattr_u32(tb[TCA_HULL_MARKTH]);
		fprintf(f, "markth %s ", sprint_size(markth, b1));
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

	fprintf(f, " delay %lluus", (unsigned long long) st->qdelay);


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
