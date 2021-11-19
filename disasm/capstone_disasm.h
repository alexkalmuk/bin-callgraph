#ifndef CAPSTONE_DISASM_H
#define CAPSTONE_DISASM_H

#include <disasm/disasm.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>

class b_capstone_op : public b_op {
public:
	b_capstone_op(cs_x86_op *op);

	bool is_relative()
	{
		return this->rel;
	}
	int extract_val(int64_t *rel);
	void deposit_val(int64_t rel);

	void set_relative(bool rel)
	{
		this->rel = rel;
	}
	void set_val(int64_t val)
	{
		this->val = val;
	}
	void set_bytes(uint8_t *bytes)
	{
		this->bytes = bytes;
	}
	void set_size(size_t size)
	{
		this->size = size;
	}

private:
	cs_x86_op *op;

	bool rel;
	int64_t val;
	uint8_t *bytes;
	size_t size;
};

class b_capstone_instr : public b_instr {
public:
	b_capstone_instr(csh *disas_handle, cs_insn *ins);
	~b_capstone_instr();

	uint64_t address();
	size_t size();
	uint8_t *bytes();
	bool is_endbr64();

private:
	void init_op(cs_x86_op *op);

	cs_insn *ins;
	csh *disas_handle;
};

class b_capstone_dis : public b_dis {
public:
	b_capstone_dis(unsigned char *buffer, uint64_t address, size_t size);
	~b_capstone_dis();

private:
	csh disas_handle;
	int insn_count;
	cs_insn *csinsn;
};

#endif /* CAPSTONE_DISASM_H */
