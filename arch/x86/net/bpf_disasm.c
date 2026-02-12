// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/unaligned.h>

#include <asm/insn.h>
#include <asm/nospec-branch.h>

#include "bpf_disasm.h"

/*
 * Maximum number of instructions to analyze, as the function to be
 * inlined should be short. If the function is too long, fall back to
 * a normal function call.
 */
#define BPF_JIT_FUNC_MAX_INSNS	128

/* x86 GPR id from ModRM/SIB bit-fields plus REX/REX2 extensions. */
enum insn_reg_ext {
	INSN_REG_EXT_NONE,
	INSN_REG_EXT_R,	/* ModRM.reg */
	INSN_REG_EXT_X,	/* SIB.index */
	INSN_REG_EXT_B,	/* ModRM.rm / SIB.base / opcode+rd */
};

static inline u8 insn_rex_ext_byte(const struct insn *insn)
{
	return insn->rex_prefix.nbytes == 2 ?
		insn->rex_prefix.bytes[1] : insn->rex_prefix.bytes[0];
}

static inline u8 insn_reg_id(const struct insn *insn, u8 reg3, enum insn_reg_ext ext)
{
	u8 id = reg3 & 0x7;
	u8 rex = insn_rex_ext_byte(insn);
	bool rex2 = insn->rex_prefix.nbytes == 2;

	switch (ext) {
	case INSN_REG_EXT_R:
		if (X86_REX_R(rex))
			id |= BIT(3);
		if (rex2 && X86_REX2_R(rex))
			id |= BIT(4);
		break;
	case INSN_REG_EXT_X:
		if (X86_REX_X(rex))
			id |= BIT(3);
		if (rex2 && X86_REX2_X(rex))
			id |= BIT(4);
		break;
	case INSN_REG_EXT_B:
		if (X86_REX_B(rex))
			id |= BIT(3);
		if (rex2 && X86_REX2_B(rex))
			id |= BIT(4);
		break;
	case INSN_REG_EXT_NONE:
	default:
		break;
	}

	return id;
}

static inline int insn_reg_bit(u8 reg)
{
	return reg < 32 ? BIT(reg) : 0;
}

static bool x86_insn_is_endbr(const struct insn *insn)
{
	return insn->length == 4 &&
		get_unaligned_le32(insn->kaddr) == cpu_to_le32(0xFA1E0FF3);
}

static bool x86_insn_is_ret(const struct insn *insn)
{
	u8 op = insn->opcode.bytes[0];

	return op == 0xC3 || op == 0xC2;
}

static bool x86_insn_is_leave(const struct insn *insn)
{
	return insn->length == 1 && insn->opcode.bytes[0] == 0xC9;
}

static bool x86_insn_is_fp_push(const struct insn *insn)
{
	u8 op = insn->opcode.bytes[0];

	return insn->length == 1 && op == 0x55;
}

static bool x86_insn_is_fp_pop(const struct insn *insn)
{
	u8 op = insn->opcode.bytes[0];

	return insn->length == 1 && op == 0x5D;
}

static bool x86_insn_is_fp_setup(const struct insn *insn)
{
	return IS_ENABLED(CONFIG_FRAME_POINTER) && insn->opcode.bytes[0] == 0x89 &&
		insn->modrm.nbytes && X86_MODRM_MOD(insn->modrm.bytes[0]) == 3 &&
		X86_MODRM_REG(insn->modrm.bytes[0]) == 4 && X86_MODRM_RM(insn->modrm.bytes[0]) == 5;
}

static bool x86_insn_is_prologue(const struct insn *insn)
{
	if (x86_insn_is_endbr(insn))
		return true;

	if (IS_ENABLED(CONFIG_FRAME_POINTER) && x86_insn_is_fp_push(insn))
		return true;

	/* Single-byte NOP. */
	if (insn->length == 1 && insn->opcode.bytes[0] == 0x90)
		return true;

	/* Multi-byte NOP forms (0F 1F /0). */
	if (insn->opcode.nbytes == 2 && insn->opcode.bytes[0] == 0x0F &&
	    insn->opcode.bytes[1] == 0x1F)
		return true;

	return false;
}

static bool x86_insn_is_epilogue(const struct insn *insn)
{
	if (IS_ENABLED(CONFIG_FRAME_POINTER) && x86_insn_is_fp_pop(insn))
		return true;

	if (x86_insn_is_ret(insn))
		return true;

	if (x86_insn_is_leave(insn))
		return true;

	return false;
}

static bool x86_insn_is_rel_jmp(const struct insn *insn)
{
	u8 op = insn->opcode.bytes[0];

	return op == 0xE9 || op == 0xEB;
}

static bool x86_insn_is_cond_rel_jmp(const struct insn *insn)
{
	u8 op = insn->opcode.bytes[0];

	if (op >= 0x70 && op <= 0x7F)
		return true;
	if (op == 0x0F) {
		u8 op2 = insn->opcode.bytes[1];

		return op2 >= 0x80 && op2 <= 0x8F;
	}

	return false;
}

static bool x86_insn_rel_jmp_target(const struct insn *insn, unsigned long *target)
{
	long rel;

	if (!x86_insn_is_rel_jmp(insn) && !x86_insn_is_cond_rel_jmp(insn))
		return false;

	switch (insn->immediate.nbytes) {
	case 1:
		rel = (s8)insn->immediate.value;
		break;
	case 2:
		rel = (s16)insn->immediate.value;
		break;
	case 4:
		rel = (s32)insn->immediate.value;
		break;
	default:
		return false;
	}

	*target = (unsigned long)insn->kaddr + insn->length + rel;
	return true;
}

static bool x86_insn_is_unsupported(const struct insn *insn);

struct x86_fastcall_layout {
	int body_off;
	int epilogue_off;
	int end_off; /* start offset of terminal insn, excluded from copied body */
};

static bool x86_target_is_return_thunk(unsigned long target)
{
	return target == (unsigned long)x86_return_thunk ||
		target == (unsigned long)__x86_return_thunk ||
		target == (unsigned long)its_return_thunk;
}

/*
 * Pass 1: find body start, first epilogue offset and terminal instruction.
 * Terminal instruction is either RET or a relative JMP to return thunk.
 */
static bool x86_find_fastcall_layout(const u8 *func, struct x86_fastcall_layout *layout)
{
	bool body_started = false;
	unsigned long target;
	int off = 0, i, ret;
	struct insn insn;

	layout->body_off = 0;
	layout->epilogue_off = -1;
	layout->end_off = -1;

	for (i = 0; i < BPF_JIT_FUNC_MAX_INSNS; i++) {
		ret = insn_decode_kernel(&insn, func + off);
		if (ret < 0 || !insn.length)
			return false;

		if (!body_started && x86_insn_is_prologue(&insn)) {
			layout->body_off += insn.length;
			off += insn.length;
			continue;
		}
		body_started = true;

		if (x86_insn_is_fp_setup(&insn)) {
			off += insn.length;
			continue;
		}

		if (layout->epilogue_off < 0 && x86_insn_is_epilogue(&insn))
			layout->epilogue_off = off;

		if (x86_insn_is_ret(&insn)) {
			layout->end_off = off;
			return true;
		}

		if (x86_insn_is_rel_jmp(&insn) &&
		    x86_insn_rel_jmp_target(&insn, &target) &&
		    x86_target_is_return_thunk(target)) {
			layout->end_off = off;
			return true;
		}

		if (x86_insn_is_unsupported(&insn))
			return false;

		off += insn.length;
	}

	return false;
}

static bool x86_insn_is_unsupported(const struct insn *insn)
{
	u8 op = insn->opcode.bytes[0];

	/*
	 * Memory operands are allowed.
	 * Safety is enforced by register-touch masking: if memory addressing
	 * uses disallowed registers (base/index/destination), inlining is
	 * rejected later.
	 */

	/* Calls/loops/int/syscall and friends are not inline-safe here. */
	if (op == 0xE8 || op == 0xEA ||
	    op == 0x9A || op == 0xCC || op == 0xCD || op == 0xCE ||
	    op == 0xCF ||
	    (op >= 0xE0 && op <= 0xE3))
		return true;
	/* Indirect jmp/call forms (e.g. FF /4, /5) are rejected. */
	if (op == 0xFF)
		return true;

	if (op == 0x0F) {
		u8 op2 = insn->opcode.bytes[1];

		if (op2 == 0x05 || /* SYSCALL */
		    op2 == 0x07 || /* SYSRET */
		    op2 == 0x0B || /* UD2 */
		    op2 == 0x34 || /* SYSENTER */
		    op2 == 0x35)   /* SYSEXIT */
			return true;
	}

	return false;
}

static int x86_insn_reg_touched_mask(const struct insn *insn)
{
	u8 op = insn->opcode.bytes[0];
	int mask = 0;

	/*
	 * Conservatively mark all registers encoded by opcode fields as touched.
	 * Over-estimation is acceptable (it only disables inlining).
	 */
	if (insn->modrm.nbytes) {
		u8 modrm = insn->modrm.bytes[0];

		mask |= insn_reg_bit(insn_reg_id(insn, X86_MODRM_REG(modrm), INSN_REG_EXT_R));
		mask |= insn_reg_bit(insn_reg_id(insn, X86_MODRM_RM(modrm), INSN_REG_EXT_B));
	}

	if (insn->sib.nbytes) {
		u8 sib = insn->sib.bytes[0];

		mask |= insn_reg_bit(insn_reg_id(insn, X86_SIB_INDEX(sib), INSN_REG_EXT_X));
		mask |= insn_reg_bit(insn_reg_id(insn, X86_SIB_BASE(sib), INSN_REG_EXT_B));
	}

	/* Opcodes with low 3 bits encoding register id. */
	if ((op >= 0x40 && op <= 0x5F) ||
	    (op >= 0x90 && op <= 0x97) ||
	    (op >= 0xB0 && op <= 0xBF))
		mask |= insn_reg_bit(insn_reg_id(insn, op & 0x7, INSN_REG_EXT_B));

	return mask;
}

static bool x86_body_branch_is_valid(const struct insn *insn, const u8 *func,
				     const struct x86_fastcall_layout *layout)
{
	unsigned long target;

	if (!x86_insn_is_rel_jmp(insn) && !x86_insn_is_cond_rel_jmp(insn))
		return true;

	if (!x86_insn_rel_jmp_target(insn, &target))
		return false;
	if (x86_target_is_return_thunk(target))
		return false;
	if (layout->epilogue_off < 0)
		return false;
	if (target < (unsigned long)func + layout->epilogue_off)
		return false;
	if (target > (unsigned long)func + layout->end_off)
		return false;

	return true;
}

static bool x86_terminal_branch_is_valid(const struct insn *insn, const u8 *func,
					 const struct x86_fastcall_layout *layout)
{
	unsigned long target;

	if (!x86_insn_is_rel_jmp(insn))
		return x86_insn_is_epilogue(insn);

	if (!x86_insn_rel_jmp_target(insn, &target))
		return false;

	if (x86_target_is_return_thunk(target))
		return true;

	if (layout->epilogue_off < 0)
		return false;
	if (target < (unsigned long)func + layout->epilogue_off)
		return false;
	if (target > (unsigned long)func + layout->end_off)
		return false;

	return true;
}

int bpf_jit_validate_func_fastcall(void *func_addr, struct bpf_jit_func_meta *meta)
{
	struct x86_fastcall_layout layout;
	const u8 *func = func_addr;
	int off, ret, end_off;
	int touched_mask = 0;
	struct insn insn;

	if (!func_addr || !meta)
		return -EINVAL;

	/* Pass 1: discover layout. */
	if (!x86_find_fastcall_layout(func, &layout))
		return 0;

	end_off = layout.epilogue_off >= 0 ? layout.epilogue_off : layout.end_off;
	if (end_off <= layout.body_off)
		return 0;

	/* Pass 2: validate body and branch targets. */
	off = layout.body_off;
	while (off < end_off) {
		ret = insn_decode_kernel(&insn, func + off);
		if (ret < 0 || !insn.length)
			return 0;

		if (x86_insn_is_fp_setup(&insn)) {
			off += insn.length;
			continue;
		}

		if (!x86_body_branch_is_valid(&insn, func, &layout))
			return 0;

		if (x86_insn_is_unsupported(&insn))
			return 0;

		touched_mask |= x86_insn_reg_touched_mask(&insn);
		off += insn.length;
	}

	/* Validate terminal insn at layout.end_off. */
	ret = insn_decode_kernel(&insn, func + layout.end_off);
	if (ret < 0 || !insn.length)
		return 0;
	if (!x86_terminal_branch_is_valid(&insn, func, &layout))
		return 0;

	meta->body_insn_off = layout.body_off;
	meta->body_insn_cnt = end_off - layout.body_off;
	return touched_mask ?: 1;
}

int bpf_jit_copy_func(u8 *image, void *func_addr, struct bpf_jit_func_meta *meta)
{
	int off = 0, copied = 0, ret;
	struct insn insn;
	const u8 *src;

	if (!image || !func_addr || !meta)
		return -EINVAL;
	if (meta->body_insn_off < 0 || meta->body_insn_cnt <= 0)
		return -EINVAL;

	src  = func_addr;
	src += meta->body_insn_off;

	while (off < meta->body_insn_cnt) {
		ret = insn_decode(&insn, src + off, meta->body_insn_cnt - off, INSN_MODE_64);
		if (ret < 0 || !insn.length)
			return -EINVAL;
		if (off + insn.length > meta->body_insn_cnt)
			return -EINVAL;

		/*
		 * Skip frame-pointer setup when frame pointers are enabled.
		 * movq %rsp, %rbp => 48 89 e5 (or APX/REX2 equivalent)
		 */
		if (x86_insn_is_fp_setup(&insn)) {
			off += insn.length;
			continue;
		}

		memcpy(image + copied, src + off, insn.length);
		copied += insn.length;
		off += insn.length;
	}

	return copied;
}
