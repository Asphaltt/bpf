// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>

typedef __u64 dyn_value_t[0];

#define DYN_ENTRIES 8

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
	__type(key, __u32);
	__type(value, __u64);
} normal_array SEC(".maps");

int expected_entries;
volatile int data_value = 1;
const volatile int rodata_value = 2;
int observed_entries;
int observed_normal_entries;
__u64 observed_sum;
__u64 observed_last;
__u64 update_value_sum;
__u64 update_value_last;

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
	if (data_value != 1 || rodata_value != 2)
		return 2;

	values = bpf_map_lookup_elem(&dyn_array, &key);
	if (!values)
		return 3;

	for (i = 0; i < entries; i++)
		sum += values[i];

	observed_sum = sum;
	observed_last = values[entries - 1];
	return 0;
}

SEC("?raw_tp/sys_enter")
int update_dyn_array(const void *ctx)
{
	int entries = bpf_map_value_entries((const struct bpf_map *)&dyn_array);
	__u64 values[DYN_ENTRIES];
	__u32 key = 0, i;

	if (entries != DYN_ENTRIES)
		return 1;

	for (i = 0; i < DYN_ENTRIES; i++)
		values[i] = 10 + i;

	update_value_sum = 0;
	for (i = 0; i < DYN_ENTRIES; i++)
		update_value_sum += values[i];
	update_value_last = values[DYN_ENTRIES - 1];

	return bpf_map_update_elem(&dyn_array, &key, values, BPF_ANY);
}

SEC("?raw_tp/sys_enter")
int entries_without_flag(const void *ctx)
{
	int entries = bpf_map_value_entries((const struct bpf_map *)&normal_array);

	observed_normal_entries = entries;
	return entries == -EINVAL ? 0 : 1;
}

char _license[] SEC("license") = "GPL";
