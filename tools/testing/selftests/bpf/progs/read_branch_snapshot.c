// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

__u64 test_hits = 0;
__u64 address_low = 0;
__u64 address_high = 0;
int wasted_entries = 0;
long total_entries = 0;

#define ENTRY_CNT 32
struct perf_branch_entry entries[ENTRY_CNT] = {};

static inline bool gbs_in_range(__u64 val)
{
	return (val >= address_low) && (val < address_high);
}

static inline int test_branch_snapshot(void *ctx)
{
	long i;

	total_entries = bpf_read_branch_snapshot(ctx, entries, sizeof(entries));
	total_entries /= sizeof(struct perf_branch_entry);

	for (i = 0; i < ENTRY_CNT; i++) {
		if (i >= total_entries)
			break;
		if (gbs_in_range(entries[i].from) && gbs_in_range(entries[i].to))
			test_hits++;
		else if (!test_hits)
			wasted_entries++;
	}
	return 0;
}

SEC("fentry/bpf_testmod_loop_test")
int BPF_PROG(test_fentry, int n)
{
	return test_branch_snapshot(ctx);
}

SEC("fexit/bpf_testmod_loop_test")
int BPF_PROG(test_fexit, int n, int ret)
{
	return test_branch_snapshot(ctx);
}
