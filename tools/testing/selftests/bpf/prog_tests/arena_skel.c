// SPDX-License-Identifier: GPL-2.0
#include <bpftool_helpers.h>
#include <test_progs.h>

#define BPF_FILE "arena_atomics.bpf.o"
#define MAX_BPFTOOL_OUTPUT_LEN 1024

static void test_gen_lskel(void)
{
	char output[MAX_BPFTOOL_OUTPUT_LEN] = {};
	char cmd[MAX_BPFTOOL_CMD_LEN];
	int err;

	err = snprintf(cmd, sizeof(cmd), "gen skeleton -L %s 2>&1", BPF_FILE);
	if (!ASSERT_GT(err, 0, "format command"))
		return;

	err = get_bpftool_command_output(cmd, output, sizeof(output));
	if (!ASSERT_NEQ(err, 0, "generate skeleton"))
		return;

	ASSERT_HAS_SUBSTR(output,
			  "light skeletons do not support arena maps with global data",
			  "error message");
}

void test_arena_skel(void)
{
	if (test__start_subtest("lskel"))
		test_gen_lskel();
}
