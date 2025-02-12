// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#include <test_progs.h>
#include "get_branch_snapshot.skel.h"
#include "read_branch_snapshot.skel.h"

static int *pfd_array;
static int cpu_cnt;

static bool is_hypervisor(void)
{
	char *line = NULL;
	bool ret = false;
	size_t len;
	FILE *fp;

	fp = fopen("/proc/cpuinfo", "r");
	if (!fp)
		return false;

	while (getline(&line, &len, fp) != -1) {
		if (!strncmp(line, "flags", 5)) {
			if (strstr(line, "hypervisor") != NULL)
				ret = true;
			break;
		}
	}

	free(line);
	fclose(fp);
	return ret;
}

static int create_perf_events(void)
{
	struct perf_event_attr attr = {0};
	int cpu;

	/* create perf event */
	attr.size = sizeof(attr);
	attr.type = PERF_TYPE_HARDWARE;
	attr.config = PERF_COUNT_HW_CPU_CYCLES;
	attr.sample_type = PERF_SAMPLE_BRANCH_STACK;
	attr.branch_sample_type = PERF_SAMPLE_BRANCH_KERNEL |
		PERF_SAMPLE_BRANCH_USER | PERF_SAMPLE_BRANCH_ANY;

	cpu_cnt = libbpf_num_possible_cpus();
	pfd_array = malloc(sizeof(int) * cpu_cnt);
	if (!pfd_array) {
		cpu_cnt = 0;
		return 1;
	}

	for (cpu = 0; cpu < cpu_cnt; cpu++) {
		pfd_array[cpu] = syscall(__NR_perf_event_open, &attr,
					 -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
		if (pfd_array[cpu] < 0)
			break;
	}

	return cpu == 0;
}

static void close_perf_events(void)
{
	int cpu, fd;

	for (cpu = 0; cpu < cpu_cnt; cpu++) {
		fd = pfd_array[cpu];
		if (fd < 0)
			break;
		close(fd);
	}
	free(pfd_array);
}

void serial_test_get_branch_snapshot(void)
{
	struct get_branch_snapshot *skel = NULL;
	int err;

	/* Skip the test before we fix LBR snapshot for hypervisor. */
	if (is_hypervisor()) {
		test__skip();
		return;
	}

	if (create_perf_events()) {
		test__skip();  /* system doesn't support LBR */
		goto cleanup;
	}

	skel = get_branch_snapshot__open_and_load();
	if (!ASSERT_OK_PTR(skel, "get_branch_snapshot__open_and_load"))
		goto cleanup;

	err = kallsyms_find("bpf_testmod_loop_test", &skel->bss->address_low);
	if (!ASSERT_OK(err, "kallsyms_find"))
		goto cleanup;

	/* Just a guess for the end of this function, as module functions
	 * in /proc/kallsyms could come in any order.
	 */
	skel->bss->address_high = skel->bss->address_low + 128;

	err = get_branch_snapshot__attach(skel);
	if (!ASSERT_OK(err, "get_branch_snapshot__attach"))
		goto cleanup;

	trigger_module_test_read(100);

	if (skel->bss->total_entries < 16) {
		/* too few entries for the hit/waste test */
		test__skip();
		goto cleanup;
	}

	ASSERT_GT(skel->bss->test1_hits, 6, "find_looptest_in_lbr");

	/* Given we stop LBR in software, we will waste a few entries.
	 * But we should try to waste as few as possible entries. We are at
	 * about 7 on x86_64 systems.
	 * Add a check for < 10 so that we get heads-up when something
	 * changes and wastes too many entries.
	 */
	ASSERT_LT(skel->bss->wasted_entries, 10, "check_wasted_entries");

cleanup:
	get_branch_snapshot__destroy(skel);
	close_perf_events();
}

static bool test_read_branch_snapshot(struct read_branch_snapshot *skel,
				      const bool test_fentry,
				      const bool test_fexit)
{
	int total_entries = 0, test_hits = 0, wasted_entries = 0;
	struct bpf_link *fentry_link = NULL, *fexit_link = NULL;
	bool passed = false;

	skel->bss->test_hits = 0;
	skel->bss->wasted_entries = 0;
	skel->bss->total_entries = 0;

	if (test_fentry) {
		fentry_link = bpf_program__attach_trace(skel->progs.test_fentry);
		if (!ASSERT_OK_PTR(fentry_link, "fentry bpf_program__attach_trace"))
			goto out;
	}

	if (test_fexit) {
		fexit_link = bpf_program__attach_trace(skel->progs.test_fexit);
		if (!ASSERT_OK_PTR(fexit_link, "fexit bpf_program__attach_trace"))
			goto out;
	}

	trigger_module_test_read(100);

	total_entries += test_fentry ? 16 : 0;
	total_entries += test_fexit ? 16 : 0;
	if (skel->bss->total_entries < total_entries) {
		/* too few entries for the hit/waste test */
		test__skip();
		goto out;
	}

	test_hits += test_fentry ? 6 : 0;
	test_hits += test_fexit ? 6 : 0;
	ASSERT_GT(skel->bss->test_hits, test_hits, "find_looptest_in_lbr");

	/* Given we stop LBR in software, we will waste a few entries.
	 * But we should try to waste as few as possible entries. We are at
	 * about 7 on x86_64 systems.
	 * Add a check for < 10 so that we get heads-up when something
	 * changes and wastes too many entries.
	 */
	wasted_entries += test_fentry ? 10 : 0;
	wasted_entries += test_fexit ? 10 : 0;
	ASSERT_LT(skel->bss->wasted_entries, wasted_entries, "check_wasted_entries");

	passed = true;
out:
	bpf_link__destroy(fentry_link);
	bpf_link__destroy(fexit_link);
	return passed;
}

void serial_test_read_branch_snapshot(void)
{
	struct read_branch_snapshot *skel = NULL;
	int err;

	/* Skip the test before we fix LBR snapshot for hypervisor. */
	if (is_hypervisor()) {
		test__skip();
		return;
	}

	if (create_perf_events()) {
		test__skip();  /* system doesn't support LBR */
		goto cleanup;
	}

	skel = read_branch_snapshot__open_and_load();
	if (!ASSERT_OK_PTR(skel, "read_branch_snapshot__open_and_load"))
		goto cleanup;

	err = kallsyms_find("bpf_testmod_loop_test", &skel->bss->address_low);
	if (!ASSERT_OK(err, "kallsyms_find"))
		goto cleanup;

	/* Just a guess for the end of this function, as module functions
	 * in /proc/kallsyms could come in any order.
	 */
	skel->bss->address_high = skel->bss->address_low + 128;

	if (!test_read_branch_snapshot(skel, true, false))
		goto cleanup;
	if (!test_read_branch_snapshot(skel, false, true))
		goto cleanup;
	test_read_branch_snapshot(skel, true, true);

cleanup:
	read_branch_snapshot__destroy(skel);
	close_perf_events();
}
