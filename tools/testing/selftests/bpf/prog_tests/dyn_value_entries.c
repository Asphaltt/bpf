// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "dyn_value_entries.skel.h"

#define DYN_ENTRIES 8

static void test_array_map_dyn_value_entries(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct dyn_value_entries *skel;
	__u64 values[DYN_ENTRIES];
	struct bpf_map *map;
	__u32 key = 0;
	int err, i;

	skel = dyn_value_entries__open();
	if (!ASSERT_OK_PTR(skel, "dyn_value_entries__open"))
		return;

	bpf_program__set_autoload(skel->progs.read_dyn_array, true);

	err = bpf_map__set_entries_number(skel->maps.dyn_array, DYN_ENTRIES);
	if (!ASSERT_OK(err, "bpf_map__set_entries_number"))
		goto cleanup;

	ASSERT_EQ(bpf_map__value_size(skel->maps.dyn_array), sizeof(values), "dyn_value_size");
	skel->bss->expected_entries = DYN_ENTRIES;

	err = dyn_value_entries__load(skel);
	if (!ASSERT_OK(err, "dyn_value_entries__load"))
		goto cleanup;

	for (i = 0; i < DYN_ENTRIES; i++)
		values[i] = i + 1;

	map = skel->maps.dyn_array;
	err = bpf_map__update_elem(map, &key, sizeof(key), values, sizeof(values), 0);
	if (!ASSERT_OK(err, "bpf_map__update_elem"))
		goto cleanup;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.read_dyn_array), &topts);
	if (!ASSERT_OK(err, "bpf_prog_test_run_opts"))
		goto cleanup;
	if (!ASSERT_OK(topts.retval, "retval"))
		goto cleanup;

	ASSERT_EQ(skel->bss->observed_entries, DYN_ENTRIES, "observed_entries");
	ASSERT_EQ(skel->bss->observed_sum, 36, "observed_sum");
	ASSERT_EQ(skel->bss->observed_last, DYN_ENTRIES, "observed_last");

cleanup:
	dyn_value_entries__destroy(skel);
}

void test_dyn_value_entries(void)
{
	if (test__start_subtest("array_map_dyn_value_entries"))
		test_array_map_dyn_value_entries();
}

