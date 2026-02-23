// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/types.h>

#include <asm/insn.h>

#include "bpf_disasm.h"

/*
 * Maximum number of instructions to analyze, as the function to be
 * inlined should be short.
 * If the function is too long, fall back to a normal function call.
 */
#define BPF_JIT_FUNC_MAX_INSNS	128

static bool aarch64_insn_is_mov_x9_x30(u32 insn)
{
	static u32 mov_x9_x30;

	if (!mov_x9_x30)
		mov_x9_x30 = aarch64_insn_gen_add_sub_imm(AARCH64_INSN_REG_9,
							  AARCH64_INSN_REG_30,
							  0,
							  AARCH64_INSN_VARIANT_64BIT,
							  AARCH64_INSN_ADSB_ADD);

	return insn == mov_x9_x30;
}

static bool bpf_jit_is_body_prefix_insn(u32 insn, int idx)
{
	/*
	 * With KCFI enabled, a 32-bit type hash word may precede function
	 * entry and is not executable body code.
	 */
	if (IS_ENABLED(CONFIG_CFI) && idx == 0)
		return true;

	/* Skip non-body entry hints. */
	if (aarch64_insn_is_hint(insn) ||
	    aarch64_insn_is_bti(insn) ||
	    aarch64_insn_is_nop(insn) ||
	    aarch64_insn_is_mov_x9_x30(insn))
		return true;

	return false;
}

static inline int bpf_jit_reg_bit(u32 reg)
{
	if (reg >= AARCH64_INSN_REG_ZR)
		return 0;

	return BIT(reg);
}

static int bpf_jit_insn_touched_mask(u32 insn)
{
	int mask = 0;

	if (aarch64_insn_is_mrs(insn)) {
		mask |= bpf_jit_reg_bit(aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RT,
							     insn));
		return mask;
	}

	if (aarch64_insn_is_load_pair(insn)) {
		mask |= bpf_jit_reg_bit(aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RT,
							     insn));
		mask |= bpf_jit_reg_bit(aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RT2,
							     insn));
		return mask;
	}

	if (aarch64_insn_is_load_single(insn) ||
	    aarch64_insn_is_ldr_lit(insn) ||
	    aarch64_insn_is_ldrsw_lit(insn)) {
		mask |= bpf_jit_reg_bit(aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RT,
							     insn));
		return mask;
	}

	if (aarch64_insn_is_store_single(insn) ||
	    aarch64_insn_is_store_pair(insn))
		return 0;

	if (!aarch64_insn_is_branch(insn) &&
	    !aarch64_insn_is_msr_imm(insn) &&
	    !aarch64_insn_is_msr_reg(insn) &&
	    !aarch64_insn_is_exception(insn) &&
	    !aarch64_insn_is_eret(insn) &&
	    !aarch64_insn_is_eret_auth(insn))
		mask |= bpf_jit_reg_bit(aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RD,
							     insn));

	return mask;
}

int bpf_jit_validate_func_fastcall(void *func_addr, struct bpf_jit_func_meta *meta)
{
	u32 *insn_ptr = func_addr;
	bool body_started = false;
	int touched_mask = 0;
	int i;

	if (!func_addr || !meta)
		return -EINVAL;

	meta->body_insn_off = 0;
	meta->body_insn_cnt = 0;

	for (i = 0; i < BPF_JIT_FUNC_MAX_INSNS; i++) {
		u32 insn = READ_ONCE(insn_ptr[i]);

		if (!body_started && bpf_jit_is_body_prefix_insn(insn, i)) {
			meta->body_insn_off++;
			continue;
		}
		body_started = true;

		if (aarch64_insn_is_ret(insn) || aarch64_insn_is_ret_auth(insn)) {
			meta->body_insn_cnt = i - meta->body_insn_off;
			return touched_mask ?: 1;
		}

		if (aarch64_insn_is_bl(insn) ||
		    aarch64_insn_is_blr(insn) ||
		    aarch64_insn_is_blr_auth(insn) ||
		    aarch64_insn_is_b(insn) ||
		    aarch64_insn_is_br(insn) ||
		    aarch64_insn_is_br_auth(insn) ||
		    aarch64_insn_is_bcond(insn) ||
		    aarch64_insn_is_cbz(insn) ||
		    aarch64_insn_is_cbnz(insn) ||
		    aarch64_insn_is_tbz(insn) ||
		    aarch64_insn_is_tbnz(insn) ||
		    aarch64_insn_uses_literal(insn) ||
		    aarch64_insn_is_exclusive(insn) ||
		    aarch64_insn_is_mops(insn) ||
		    aarch64_insn_is_exception(insn) ||
		    aarch64_insn_is_eret(insn) ||
		    aarch64_insn_is_eret_auth(insn) ||
		    aarch64_insn_is_msr_imm(insn) ||
		    aarch64_insn_is_msr_reg(insn))
			return 0;

		touched_mask |= bpf_jit_insn_touched_mask(insn);
	}

	return 0;
}

int bpf_jit_copy_func(__le32 *image, void *func_addr,
		      struct bpf_jit_func_meta *meta)
{
	u32 *insn_ptr;
	int i;

	if (!image || !func_addr || !meta)
		return -EINVAL;
	if (meta->body_insn_off < 0 || meta->body_insn_cnt <= 0)
		return -EINVAL;

	insn_ptr = func_addr;
	insn_ptr += meta->body_insn_off;

	for (i = 0; i < meta->body_insn_cnt; i++) {
		u32 insn = READ_ONCE(insn_ptr[i]);

		if (aarch64_insn_is_ret(insn) || aarch64_insn_is_ret_auth(insn))
			return -EINVAL;

		image[i] = cpu_to_le32(insn);
	}

	return 0;
}
