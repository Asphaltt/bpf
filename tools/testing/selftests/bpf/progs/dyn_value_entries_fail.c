// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>

typedef __u64 dyn_value_t[0];

#define DYN_ENTRIES 8

struct bpf_map {
	enum bpf_map_type map_type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 dyn_value_entries;
} __attribute__((preserve_access_index));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_DYN_VALUE_ENTRIES);
	__type(key, __u32);
	__type(value, dyn_value_t);
} dyn_array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG | BPF_F_DYN_VALUE_ENTRIES);
	__type(key, __u32);
	__type(value, dyn_value_t);
} dyn_array_rdonly SEC(".maps");

int bpf_map_value_entries(const struct bpf_map *map) __ksym;

SEC("?raw_tp/sys_enter")
int read_past_dyn_array(const void *ctx)
{
	int entries = bpf_map_value_entries((const struct bpf_map *)&dyn_array);
	__u32 key = 0;
	__u64 *values;

	values = bpf_map_lookup_elem(&dyn_array, &key);
	if (!values)
		return 0;

	return values[entries];
}

SEC("?raw_tp/sys_enter")
int update_dyn_array_small_value(const void *ctx)
{
	__u64 values[DYN_ENTRIES / 2] = {};
	__u32 key = 0;

	return bpf_map_update_elem(&dyn_array, &key, values, BPF_ANY);
}

SEC("?raw_tp/sys_enter")
int update_dyn_array_rdonly(const void *ctx)
{
	__u64 values[DYN_ENTRIES] = {};
	__u32 key = 0;

	return bpf_map_update_elem(&dyn_array_rdonly, &key, values, BPF_ANY);
}

char _license[] SEC("license") = "GPL";
