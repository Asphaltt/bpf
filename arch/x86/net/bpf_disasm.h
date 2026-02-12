/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __BPF_DISASM_H_
#define __BPF_DISASM_H_

struct bpf_jit_func_meta {
	int body_insn_off; /* Skip some entry insns. */
	int body_insn_cnt; /* Number of bytes for func main body. */
};

/*
 * Validate whether a function body is safe for JIT inlining.
 *
 * @func_addr: Function address.
 * @meta: Updated on success.
 * @return: 0, not inlineable.
 *          >0, bitmask of touched x86 GPR ids.
 *          <0, error.
 */
int bpf_jit_validate_func_fastcall(void *func_addr, struct bpf_jit_func_meta *meta);

/*
 * Copy some bytes from @func_addr + @meta->body_insn_off to @image.
 *
 * @image: Destination buffer.
 * @func_addr: Function address.
 * @meta: Metadata from bpf_jit_validate_func_fastcall().
 * @return: >=0 copied bytes; <0 on error.
 */
int bpf_jit_copy_func(u8 *image, void *func_addr, struct bpf_jit_func_meta *meta);

#endif /* __BPF_DISASM_H_ */
