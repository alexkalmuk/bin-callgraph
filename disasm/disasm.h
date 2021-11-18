#ifndef DISASM_H
#define DISASM_H

#include <cstddef>
#include <cstdint>
#include <vector>

class b_op {
public:
	virtual bool is_relative() = 0; /* true iff it's val(RIP), jmp or call */
	virtual int extract_val(int64_t *rel) = 0;
	virtual void deposit_val(int64_t rel) = 0;
};

class b_instr {
public:
	virtual uint64_t address() = 0;
	virtual size_t size() = 0;
	virtual uint8_t *bytes() = 0;
	virtual bool is_endbr64() = 0;

	std::vector<b_op*> ops;
};

class b_dis {
public:
	std::vector<b_instr*> insn;
};

#endif /* DISASM_H */
