// SPDX-License-Identifier: GPL-2.0
/*
 * BPF instruction-kprobe reproduction of a corrupted optimized jump.
 * On affected kernels, attaching C while disabled B hides optimized A,
 * then executing the target crashes the VM.
 */
#include <test_progs.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "kprobe_write_ctx.skel.h"

#define OPT_SYSCTL "/proc/sys/debug/kprobes-optimization"
#define TESTMOD_FILE "/sys/kernel/bpf_testmod"
#define TARGET "bpf_testmod_kprobe_overlap"
#define OFFSET_FILE_POS 4096
#define OPCODE_FILE_POS 4097
#define JMP32_OPCODE 0xe9

static int read_value(const char *path)
{
	char buf[32];
	int fd, n;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return n < 0 ? -errno : -EIO;
	buf[n] = '\0';
	return buf[0] == '1' ? 1 : 0;
}

static int write_value(const char *path, const char *value, bool append)
{
	int fd, n, len = strlen(value);

	fd = open(path, O_WRONLY | O_CLOEXEC | (append ? O_APPEND : 0));
	if (fd < 0)
		return -errno;
	n = write(fd, value, len);
	if (n < 0) {
		int err = -errno;

		close(fd);
		return err;
	}
	close(fd);
	return n == len ? 0 : -EIO;
}

static int read_testmod_number(off_t pos, unsigned int max)
{
	char buf[32], *end;
	unsigned long value;
	int fd, n;

	fd = open(TESTMOD_FILE, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	n = pread(fd, buf, sizeof(buf) - 1, pos);
	close(fd);
	if (n <= 0)
		return n < 0 ? -errno : -EIO;
	buf[n] = '\0';
	value = strtoul(buf, &end, 10);
	if (end == buf || (*end != '\n' && *end != '\0') || value > max)
		return -EINVAL;
	return value;
}

void test_kprobe_opt_overlap(void)
{
	DECLARE_LIBBPF_OPTS(bpf_kprobe_opts, opts);
	struct bpf_link *first = NULL, *last = NULL;
	struct kprobe_write_ctx *skel = NULL;
	const char *tracefs;
	char path[256], command[160];
	struct utsname uts;
	bool middle_registered = false;
	int original, offset, state, i, err;

	if (!env.has_testmod || uname(&uts) || strcmp(uts.machine, "x86_64")) {
		test__skip();
		return;
	}
	if (!access("/sys/kernel/tracing/kprobe_events", W_OK))
		tracefs = "/sys/kernel/tracing";
	else if (!access("/sys/kernel/debug/tracing/kprobe_events", W_OK))
		tracefs = "/sys/kernel/debug/tracing";
	else {
		test__skip();
		return;
	}
	if ((original = read_value(OPT_SYSCTL)) < 0) {
		test__skip();
		return;
	}
	if (original == 0 && !ASSERT_OK(write_value(OPT_SYSCTL, "1\n", false),
					     "enable_optprobes"))
		return;

	/* First call is safe and publishes the compiled NOP offset. */
	err = write_value(TESTMOD_FILE, "kprobe-opt-overlap\n", false);
	if (!ASSERT_OK(err, "prime_target"))
		goto cleanup;
	offset = read_testmod_number(OFFSET_FILE_POS, 128);
	if (!ASSERT_GT(offset, 0, "first_insn_offset"))
		goto cleanup;

	skel = kprobe_write_ctx__open();
	if (!ASSERT_OK_PTR(skel, "open_dummy_kprobe"))
		goto cleanup;
	bpf_program__set_autoload(skel->progs.kprobe_dummy, true);
	err = kprobe_write_ctx__load(skel);
	if (!ASSERT_OK(err, "load_dummy_kprobe"))
		goto cleanup;

	/* Keep B registered but disabled, as in the bpfsnoop detach window. */
	snprintf(path, sizeof(path), "%s/kprobe_events", tracefs);
	snprintf(command, sizeof(command), "p:opt_overlap/middle " TARGET "+%d\n",
		 offset + 2);
	err = write_value(path, command, true);
	if (!ASSERT_OK(err, "register_middle"))
		goto cleanup;
	middle_registered = true;

	opts.offset = offset;
	first = bpf_program__attach_kprobe_opts(skel->progs.kprobe_dummy,
						TARGET, &opts);
	if (!ASSERT_OK_PTR(first, "attach_first_bpf_kprobe")) {
		first = NULL;
		goto cleanup;
	}

	/* The OPTIMIZED flag is set before the worker patches the jump. */
	state = -ENOENT;
	for (i = 0; i < 500; i++) {
		state = read_testmod_number(OPCODE_FILE_POS, 255);
		if (state == JMP32_OPCODE)
			break;
		usleep(20000);
	}
	if (!ASSERT_EQ(state, JMP32_OPCODE, "first_probe_optimized"))
		goto cleanup;

	/* C lands on the final byte of A's five-byte optimized jump. */
	opts.offset = offset + 4;
	last = bpf_program__attach_kprobe_opts(skel->progs.kprobe_dummy,
					       TARGET, &opts);
	if (!ASSERT_OK_PTR(last, "attach_last_bpf_kprobe")) {
		last = NULL;
		goto cleanup;
	}

	/* On a broken kernel, the corrupted jump faults in this call. */
	ASSERT_OK(write_value(TESTMOD_FILE, "kprobe-opt-overlap\n", false),
		  "execute_overlap_target");

cleanup:
	bpf_link__destroy(last);
	bpf_link__destroy(first);
	kprobe_write_ctx__destroy(skel);
	if (middle_registered) {
		snprintf(path, sizeof(path), "%s/kprobe_events", tracefs);
		ASSERT_OK(write_value(path, "-:opt_overlap/middle\n", true),
			  "unregister_middle");
	}
	if (original == 0)
		ASSERT_OK(write_value(OPT_SYSCTL, "0\n", false), "restore_optprobes");
}
