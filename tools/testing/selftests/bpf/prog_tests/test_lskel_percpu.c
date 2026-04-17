// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf_gen_internal.h>
#include <bpf/skel_internal.h>

void test_lskel_percpu(void)
{
	struct bpf_map_create_opts map_opts = { .sz = sizeof(map_opts) };
	struct bpf_load_and_run_opts load_attr = { .ctx = NULL };
	struct gen_loader_opts opts = { .sz = sizeof(opts) };
	struct bpf_gen gen = { .opts = &opts };
	int err, nr_maps = 1, map_idx = 0;
	__u32 val = 0xdeadbeef;
	int nr_cpus, i;
	struct {
		struct bpf_loader_ctx ctx;
		struct bpf_map_desc map1;
	} skel = {};

	nr_cpus = libbpf_num_possible_cpus();
	if (!ASSERT_GT(nr_cpus, 0, "libbpf_num_possible_cpus"))
		return;

	bpf_gen__init(&gen, 2, 0, nr_maps);

	bpf_gen__map_create(&gen, BPF_MAP_TYPE_PERCPU_ARRAY, "pcpu_map", sizeof(int), sizeof(int),
			    1, &map_opts, map_idx);

	bpf_gen__map_update_elem(&gen, map_idx, &val, sizeof(val));

	err = bpf_gen__finish(&gen, 0, nr_maps);
	if (!ASSERT_OK(err, "bpf_gen__finish"))
		return;

	skel.ctx.sz = sizeof(skel);
	skel.ctx.flags |= BPF_SKEL_KERNEL;
	skel.map1.map_fd = -1;

	memset(&load_attr, 0, sizeof(load_attr));
	load_attr.ctx = &skel.ctx;
	load_attr.data = gen.data_start;
	load_attr.data_sz = gen.data_cur - gen.data_start;
	load_attr.insns = gen.insn_start;
	load_attr.insns_sz = gen.insn_cur - gen.insn_start;

	err = bpf_load_and_run(&load_attr);
	ASSERT_OK(err, "bpf_load_and_run");
	if (!ASSERT_NULL(load_attr.errstr, "bpf_load_and_run errstr"))
		ASSERT_STREQ(load_attr.errstr, "", "bpf_load_and_run errstr");

	for (i = 0; i < nr_cpus; i++) {
		__u64 flags = ((__u64) i << 32) | BPF_F_CPU;
		int key = 0, value;

		err = bpf_map_lookup_elem_flags(skel.map1.map_fd, &key, &value, flags);
		if (!ASSERT_OK(err, "bpf_map_lookup_elem"))
			continue;
		ASSERT_EQ(value, val, "percpu value");
	}

	if (skel.map1.map_fd >= 0)
		close(skel.map1.map_fd);
}
