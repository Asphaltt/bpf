/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __BPF_DISASM_H_
#define __BPF_DISASM_H_

struct bpf_jit_func_meta {
	int body_insn_off; /* Skip some entry insns */
	int body_insn_cnt; /* Number of insns to be copied */
};

/*
 * Validate whether the function follows BPF fastcall convention:
 * The registers used for the function parameters are allowed to be
 * touched.
 * The register used for retval is allowed to be touched, only if the
 * function has valid retval.
 *
 * @func_addr: The address of the function.
 * @meta: Update it if success.
 * @return: 0, not fastcall.
 *          >0, registers bitmask indicates which registers are touch in the
 *              function.
 *          <0, error.
 */
int bpf_jit_validate_func_fastcall(void *func_addr, struct bpf_jit_func_meta *meta);

/*
 * Copy @meta->body_insn_cnt insns from @func_addr +
 * @meta->body_insn_off to @ctx.
 *
 * @ctx: JIT context.
 * @func_addr: The address of the function.
 * @meta: The function metadata used for inlining kfuncs.
 * @return: 0, success.
 *          <0, error.
 */
int bpf_jit_copy_func(__le32 *image, void *func_addr, struct bpf_jit_func_meta *meta);

#endif // __BPF_DISASM_H_
