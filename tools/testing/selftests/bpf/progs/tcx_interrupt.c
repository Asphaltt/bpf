// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

int interrupt_igr;
int interrupt_egr;

SEC("tc/ingress")
int tc_igr(struct __sk_buff *skb)
{
	interrupt_igr = bpf_in_interrupt();
	return TCX_NEXT;
}

SEC("tc/egress")
int tc_egr(struct __sk_buff *skb)
{
	interrupt_egr = bpf_in_interrupt();
	return TCX_NEXT;
}

