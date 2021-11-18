#include <disasm/capstone_disasm.h>

b_capstone_dis::b_capstone_dis(unsigned char *buffer, uint64_t address,
                               size_t size)
{
	b_capstone_instr *instr;
	int i;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &disas_handle) != CS_ERR_OK) {
		/* FIXME */
		return;
	}

	cs_option(disas_handle, CS_OPT_DETAIL, CS_OPT_ON);

	insn_count = cs_disasm(disas_handle, buffer,
	                       size, address, 0, &csinsn);

	for (i = 0; i < insn_count; i++) {
		instr = new b_capstone_instr(&disas_handle, &csinsn[i]);

		insn.push_back(instr);
	}
}

b_capstone_dis::~b_capstone_dis()
{
	int i;

	for (i = 0; i < insn_count; i++) {
		delete insn[i];
	}

	cs_free(csinsn, insn_count);
	cs_close(&disas_handle);
}

void b_capstone_instr::init_op(cs_x86_op *op)
{
	int i, j;
	int n;
	int64_t shift;
	bool found = false;
	b_capstone_op *bop = new b_capstone_op(op);

	ops.push_back((b_op *) bop);

	switch (op->type) {
	case X86_OP_MEM:
		if (op->mem.base != X86_REG_RIP) {
			goto bad_op;
		}

		shift = op->mem.disp;

		break;
	case X86_OP_IMM:
		if (!cs_insn_group(*disas_handle, ins, CS_GRP_JUMP) &&
		        !cs_insn_group(*disas_handle, ins, CS_GRP_CALL)) {
			goto bad_op;
		}

		shift = op->imm - (ins->address + ins->size);

		break;
	default:
bad_op:
		return;
	}

	/* FIXME op->size is not valid in capstone, so we calculate
	 * operand's size manually. */
	if (abs(shift) > 0xfffffffful) {
		n = 8;
	} else if (abs(shift) > 0xfffful) {
		n = 4;
	} else if (abs(shift) > 0xfful) {
		n = 2;
	} else {
		n = 1;
	}

    /* TODO It's a workaround to find op.imm or op.mem.disp.
     * AFAIK, capstone cannot assemble the modified instruction. */
	for (i = 0; i < ins->size; i++) {
		uint8_t b;

		for (j = 0; j < n; j++) {
			b = (shift >> (8 * j)) & 0xff;

			if ((ins->bytes + i)[j] != b) {
				break;
			}
		}

		if (j == n) {
			found = true;

			break;
		}
	}

	if (found) {
		bop->set_relative(true);
		bop->set_val(shift);
		bop->set_bytes(ins->bytes + i);
		bop->set_size(n);
	}
}

b_capstone_instr::b_capstone_instr(csh *disas_handle, cs_insn *ins)
{
	b_capstone_op *op;
	cs_x86 *x86;
	int i;

	this->disas_handle = disas_handle;
	this->ins = ins;

	x86 = &(ins->detail->x86);

	for (i = 0; i < x86->op_count; i++) {
		init_op(&(x86->operands[i]));
	}
}

b_capstone_instr::~b_capstone_instr()
{
	int i;

	for (i = 0; i < ops.size(); i++) {
		delete (b_capstone_op *)ops[i];
	}
}

uint64_t b_capstone_instr::address()
{
	return ins->address;
}

size_t b_capstone_instr::size()
{
	return ins->size;
}

bool b_capstone_instr::is_endbr64()
{
	return ins->id == X86_INS_ENDBR64;
}

uint8_t *b_capstone_instr::bytes()
{
	return ins->bytes;
}

b_capstone_op::b_capstone_op(cs_x86_op *op)
{
	this->op = op;
}

int b_capstone_op::extract_val(int64_t *val)
{
	if (!is_relative() || !val) {
		return -1;
	}

	*val = this->val;

	return 0;
}

void b_capstone_op::deposit_val(int64_t val)
{
	int i;

	this->val = val;

	for (i = 0; i < size; i++) {
		bytes[i] = (val >> (8 * i)) & 0xff;
	}
}
