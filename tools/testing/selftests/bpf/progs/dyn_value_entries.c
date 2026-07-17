// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

typedef __u64 dyn_value_t[0];

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_DYN_VALUE_ENTRIES);
	__type(key, __u32);
	__type(value, dyn_value_t);
} dyn_array SEC(".maps");

int expected_entries;
int observed_entries;
__u64 observed_sum;
__u64 observed_last;

int bpf_map_value_entries(const struct bpf_map *map) __ksym __weak;

SEC("?raw_tp/sys_enter")
int read_dyn_array(const void *ctx)
{
	int entries = bpf_map_value_entries((const struct bpf_map *)&dyn_array);
	__u64 *values, sum = 0;
	__u32 key = 0, i;

	observed_entries = entries;
	if (entries != expected_entries)
		return 1;

	values = bpf_map_lookup_elem(&dyn_array, &key);
	if (!values)
		return 2;

	for (i = 0; i < entries; i++)
		sum += values[i];

	observed_sum = sum;
	observed_last = values[entries - 1];
	return 0;
}

char _license[] SEC("license") = "GPL";

