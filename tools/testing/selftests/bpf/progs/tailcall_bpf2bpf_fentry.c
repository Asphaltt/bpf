// SPDX-License-Identifier: GPL-2.0
/* Copyright Leon Hwang */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

int count = 0;

SEC("fentry/subprog_tail")
int BPF_PROG(fentry, struct sk_buff *skb)
{
	count++;

	return 0;
}
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 2);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} jmp_table SEC(".maps");

SEC("fentry")
int BPF_PROG(main)
{
	bpf_tail_call_static(ctx, &jmp_table, 0);
	return BPF_OK;
}

static void subprog(void *ctx)
{
	__sink(ctx);
}

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(main1)
{
	subprog(ctx);
	return BPF_OK;
}

char _license[] SEC("license") = "GPL";
