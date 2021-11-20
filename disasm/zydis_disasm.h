#ifndef ZYDIS_DISASM_H
#define ZYDIS_DISASM_H

#include <disasm/disasm.h>
#include <Zycore/LibC.h>
#include <Zydis/Zydis.h>

class b_zydis_op : public b_op {
public:
	b_zydis_op(ZydisEncoderOperand *op);

	bool is_relative();
	int extract_val(int64_t *rel);
	void deposit_val(int64_t rel);

private:
	ZydisEncoderOperand *op;
};

class b_zydis_instr : public b_instr {
public:
	b_zydis_instr(ZydisDecodedInstruction *instr, uint64_t addr);
	~b_zydis_instr();

	uint64_t address();
	size_t size();
	uint8_t *bytes();
	bool is_endbr64();

private:
	ZydisDecodedInstruction *ins;
	ZydisEncoderRequest enc_req;
	uint64_t addr;
	uint8_t instr_bytes[16];
	size_t instr_size;
};

class b_zydis_dis : public b_dis {
public:
	b_zydis_dis(unsigned char *buffer, uint64_t address, size_t size);
	~b_zydis_dis();
};

#endif /* ZYDIS_DISASM_H */
