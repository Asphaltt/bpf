// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <bpf/btf.h>
#include "dyn_value_entries.skel.h"
#include "dyn_value_entries_fail.skel.h"

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

static void test_dyn_value_entries_bpf_update_elem(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct dyn_value_entries *skel;
	int err;

	skel = dyn_value_entries__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;
	bpf_program__set_autoload(skel->progs.read_dyn_array, true);
	bpf_program__set_autoload(skel->progs.update_dyn_array, true);

	err = bpf_map__set_entries_number(skel->maps.dyn_array, DYN_ENTRIES);
	if (!ASSERT_OK(err, "set_entries_number"))
		goto cleanup;

	skel->bss->expected_entries = DYN_ENTRIES;

	err = dyn_value_entries__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.update_dyn_array),
				     &topts);
	if (!ASSERT_OK(err, "update_prog_run"))
		goto cleanup;
	if (!ASSERT_OK(topts.retval, "update_prog_ret"))
		goto cleanup;

	ASSERT_EQ(skel->bss->update_value_sum, 108, "update_value_sum");
	ASSERT_EQ(skel->bss->update_value_last, 17, "update_value_last");

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.read_dyn_array),
				     &topts);
	if (!ASSERT_OK(err, "read_prog_run"))
		goto cleanup;
	if (!ASSERT_OK(topts.retval, "read_prog_ret"))
		goto cleanup;

	ASSERT_EQ(skel->bss->observed_entries, DYN_ENTRIES, "observed_entries");
	ASSERT_EQ(skel->bss->observed_sum, 108, "observed_sum");
	ASSERT_EQ(skel->bss->observed_last, 17, "observed_last");

cleanup:
	dyn_value_entries__destroy(skel);
}

static void test_dyn_value_entries_kfunc_without_flag(void)
{
	struct dyn_value_entries *skel;
	int err;

	skel = dyn_value_entries__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;
	bpf_program__set_autoload(skel->progs.entries_without_flag, true);

	err = bpf_map__set_entries_number(skel->maps.dyn_array, DYN_ENTRIES);
	if (!ASSERT_OK(err, "set_entries_number"))
		goto cleanup;

	err = dyn_value_entries__load(skel);
	ASSERT_EQ(err, -EINVAL, "skel_load");

cleanup:
	dyn_value_entries__destroy(skel);
}

static void test_dyn_value_entries_libbpf_rejects_bad_input(void)
{
	struct dyn_value_entries *skel;
	int err;

	skel = dyn_value_entries__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	err = bpf_map__set_entries_number(skel->maps.dyn_array, 0);
	ASSERT_EQ(err, -EINVAL, "zero_entries");

	err = bpf_map__set_map_flags(skel->maps.normal_array, BPF_F_DYN_VALUE_ENTRIES);
	ASSERT_EQ(err, -EINVAL, "scalar_value_type");

	err = bpf_map__set_entries_number(skel->maps.normal_array, DYN_ENTRIES);
	ASSERT_EQ(err, -EINVAL, "set_entries_without_flag");

	err = bpf_map__set_map_flags(skel->maps.bss, BPF_F_DYN_VALUE_ENTRIES);
	ASSERT_EQ(err, -EINVAL, "bss_dyn_entries");

	err = bpf_map__set_map_flags(skel->maps.data, BPF_F_DYN_VALUE_ENTRIES);
	ASSERT_EQ(err, -EINVAL, "data_dyn_entries");

	err = bpf_map__set_map_flags(skel->maps.rodata,
				     BPF_F_RDONLY_PROG | BPF_F_DYN_VALUE_ENTRIES);
	ASSERT_EQ(err, -EINVAL, "rodata_dyn_entries");

	dyn_value_entries__destroy(skel);
}

static void test_dyn_value_entries_kernel_rejects_global_data(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts,
		.map_flags = BPF_F_DYN_VALUE_ENTRIES,
	);
	struct dyn_value_entries *skel;
	struct bpf_map *maps[3];
	struct btf *btf;
	int err, fd, i;

	skel = dyn_value_entries__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	btf = bpf_object__btf(skel->obj);
	err = btf__load_into_kernel(btf);
	if (!ASSERT_OK(err, "btf_load"))
		goto cleanup;

	opts.btf_fd = btf__fd(btf);
	maps[0] = skel->maps.bss;
	maps[1] = skel->maps.data;
	maps[2] = skel->maps.rodata;

	for (i = 0; i < ARRAY_SIZE(maps); i++) {
		opts.btf_value_type_id = bpf_map__btf_value_type_id(maps[i]);
		fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, bpf_map__name(maps[i]),
				    sizeof(__u32), bpf_map__value_size(maps[i]),
				    1, &opts);
		if (!ASSERT_ERR_FD(fd, "map_create_global_data"))
			close(fd);
		else
			ASSERT_EQ(errno, EINVAL, "map_create_errno");
	}

cleanup:
	dyn_value_entries__destroy(skel);
}

enum dyn_value_entries_fail_prog {
	FAIL_PROG_OOB,
	FAIL_PROG_UPDATE_SMALL_VALUE,
	FAIL_PROG_UPDATE_RDONLY,
};

static void test_dyn_value_entries_fail_prog(const char *name,
					     enum dyn_value_entries_fail_prog prog)
{
	struct dyn_value_entries_fail *skel;
	int err;

	skel = dyn_value_entries_fail__open();
	if (!ASSERT_OK_PTR(skel, "fail_skel_open"))
		return;

	switch (prog) {
	case FAIL_PROG_OOB:
		bpf_program__set_autoload(skel->progs.read_past_dyn_array, true);
		break;
	case FAIL_PROG_UPDATE_SMALL_VALUE:
		bpf_program__set_autoload(skel->progs.update_dyn_array_small_value, true);
		break;
	case FAIL_PROG_UPDATE_RDONLY:
		bpf_program__set_autoload(skel->progs.update_dyn_array_rdonly, true);
		break;
	}

	err = bpf_map__set_entries_number(skel->maps.dyn_array, DYN_ENTRIES);
	if (!ASSERT_OK(err, "set_entries_number"))
		goto cleanup;
	err = bpf_map__set_entries_number(skel->maps.dyn_array_rdonly, DYN_ENTRIES);
	if (!ASSERT_OK(err, "set_rdonly_entries_number"))
		goto cleanup;

	err = dyn_value_entries_fail__load(skel);
	ASSERT_ERR(err, name);

cleanup:
	dyn_value_entries_fail__destroy(skel);
}

static void test_dyn_value_entries_verifier_rejects_oob(void)
{
	test_dyn_value_entries_fail_prog("oob_load", FAIL_PROG_OOB);
}

static void test_dyn_value_entries_rejects_update_small_value(void)
{
	test_dyn_value_entries_fail_prog("update_small_value_load", FAIL_PROG_UPDATE_SMALL_VALUE);
}

static void test_dyn_value_entries_rejects_update_rdonly(void)
{
	test_dyn_value_entries_fail_prog("update_rdonly_load", FAIL_PROG_UPDATE_RDONLY);
}

void test_dyn_value_entries(void)
{
	if (test__start_subtest("array_map_dyn_value_entries"))
		test_array_map_dyn_value_entries();
	if (test__start_subtest("bpf_update_elem"))
		test_dyn_value_entries_bpf_update_elem();
	if (test__start_subtest("kfunc_without_flag"))
		test_dyn_value_entries_kfunc_without_flag();
	if (test__start_subtest("libbpf_rejects_bad_input"))
		test_dyn_value_entries_libbpf_rejects_bad_input();
	if (test__start_subtest("kernel_rejects_global_data"))
		test_dyn_value_entries_kernel_rejects_global_data();
	if (test__start_subtest("verifier_rejects_oob"))
		test_dyn_value_entries_verifier_rejects_oob();
	if (test__start_subtest("rejects_update_small_value"))
		test_dyn_value_entries_rejects_update_small_value();
	if (test__start_subtest("rejects_update_rdonly"))
		test_dyn_value_entries_rejects_update_rdonly();
}
