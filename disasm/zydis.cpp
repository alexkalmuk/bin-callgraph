#include <disasm/zydis_disasm.h>

b_zydis_dis::b_zydis_dis(unsigned char *buffer, uint64_t address, size_t size)
{
	ZydisDecoder decoder;
	ZydisDecodedInstruction *zinstr;
	b_zydis_instr *instr;

	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	zinstr = new (ZydisDecodedInstruction);

	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, buffer,
	                                             size, zinstr))) {
		instr = new b_zydis_instr(zinstr, address);
		insn.push_back(instr);

		buffer += zinstr->length;
		address += zinstr->length;
		size -= zinstr->length;
		zinstr = new (ZydisDecodedInstruction);
	}

	delete zinstr;
}

b_zydis_dis::~b_zydis_dis()
{
	int i;

	for (i = 0; i < insn.size(); i++) {
		delete (b_zydis_instr *)insn[i];
	}
}

b_zydis_instr::b_zydis_instr(ZydisDecodedInstruction *zinstr, uint64_t addr)
{
	int i;

	this->ins = zinstr;
	this->addr = addr;
	this->instr_size = zinstr->length;

	if (!ZYAN_SUCCESS(ZydisEncoderDecodedInstructionToEncoderRequest(
	                  ins, &enc_req))) {
		/* TODO */
	}

	for (i = 0; i < enc_req.operand_count; i++) {
		b_zydis_op *bop = new b_zydis_op(&enc_req.operands[i]);

		ops.push_back((b_op *) bop);
	}
}

b_zydis_instr::~b_zydis_instr()
{
	int i;

	for (i = 0; i < ops.size(); i++) {
		delete (b_zydis_op *)ops[i];
	}

	delete ins;
}

uint64_t b_zydis_instr::address()
{
	return addr;
}

size_t b_zydis_instr::size()
{
	return ins->length;
}

bool b_zydis_instr::is_endbr64()
{
	return ins->mnemonic == ZYDIS_MNEMONIC_ENDBR64;
}

uint8_t *b_zydis_instr::bytes()
{
	if (!ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(
	                  &enc_req, instr_bytes, &instr_size))) {
		return nullptr;
	}

	/* Zydis can encode an instruction to another bytes,
	 * smaller in number (i.e. 8 -> 4). In that case, we add
	 * missing NOP's to maintain initial instuction length. */
	if (instr_size != ins->length) {
		int i;

		for (i = instr_size; i < ins->length; i++) {
			/* Insert NOP's */
			instr_bytes[i] = 0x90;
		}
	}

	return instr_bytes;
}

b_zydis_op::b_zydis_op(ZydisEncoderOperand *op)
{
	this->op = op;
}

bool b_zydis_op::is_relative()
{
	switch (op->type) {
	case ZYDIS_OPERAND_TYPE_IMMEDIATE:
		return true;
	case ZYDIS_OPERAND_TYPE_MEMORY:
		if (op->mem.base == ZYDIS_REGISTER_RIP ||
				op->mem.base == ZYDIS_REGISTER_IP ||
				op->mem.base == ZYDIS_REGISTER_EIP) {
			return true;
		}
		break;
	default:
		break;
	}

	return false;
}

int b_zydis_op::extract_val(int64_t *rel)
{
	int ret = -1;

	if (!rel) {
		return -1;
	}

	switch (op->type) {
	case ZYDIS_OPERAND_TYPE_IMMEDIATE:
		ret = 0;
		*rel = op->imm.u;

		break;
	case ZYDIS_OPERAND_TYPE_MEMORY:
		ret = 0;
		*rel = op->mem.displacement;

		break;
	default:
		break;
	}

	return ret;
}

void b_zydis_op::deposit_val(int64_t rel)
{
	switch (op->type) {
	case ZYDIS_OPERAND_TYPE_IMMEDIATE:
		op->imm.u = rel;

		break;
	case ZYDIS_OPERAND_TYPE_MEMORY:
		op->mem.displacement = rel;

		break;
	default:
		break;
	}
}
