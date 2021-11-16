#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <regex>

#include <capstone/platform.h>
#include <capstone/capstone.h>

/* TODO Remove hardcoded address and instructions */
#define TEXT_START  0x1000
#define TEXT_END    0x2000

static uint64_t glob_instr_addr = 0x115c;
static unsigned char glob_instr[5] = { 0xb9, 0x78, 0x56, 0x34, 0x12 };

static Elf64_Shdr *elf_get_section(unsigned char *v, const char *sh_name);

/* TODO It's a workaround to find op.imm or op.mem.disp.
 * AFAIK, capstone cannot assemble the modified instruction. */
static uint8_t *get_op_pos(csh *disas_handle, cs_insn *ins,
                           cs_x86_op *op, int64_t *shiftp, int *op_size)
{
	int i, j;
	int n;
	int64_t shift;
	bool found = false;

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
		return nullptr;
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
		*shiftp = shift;
		*op_size = n;
	}

	return found ? ins->bytes + i : nullptr;
}

static void modify_ins(csh *disas_handle, cs_insn *ins)
{
	int i, j;
	cs_x86 *x86;
	cs_x86_op *op;
	int op_size;
	uint8_t *op_pos;
	uint64_t dst_addr;
	int64_t shift;

	printf("0x%" PRIx64 ":\t%s\t%s\n",
		ins->address, ins->mnemonic, ins->op_str);

	x86 = &(ins->detail->x86);

	for (i = 0; i < x86->op_count; i++) {
		op = &(x86->operands[i]);

		op_pos = get_op_pos(disas_handle, ins, op, &shift, &op_size);

		if (!op_pos) {
			continue;
		}

		dst_addr = ins->address + ins->size + shift;

		if (dst_addr < TEXT_END) {
			if ((ins->address < glob_instr_addr) &&
					(dst_addr > glob_instr_addr)) {
				shift += sizeof (glob_instr);
			} else if ((ins->address > glob_instr_addr) &&
			           (dst_addr < glob_instr_addr)) {
				shift -= sizeof (glob_instr);
			}
		} else if (ins->address + ins->size > glob_instr_addr) {
			shift -= sizeof (glob_instr);
		}

		/* modify instuction */
		for (j = 0; j < op_size; j++) {
			op_pos[j] = (shift >> (8 * j)) & 0xff;
		}
	}
}

static int insert_profiler_code(std::vector<char> &v, std::vector<char> &outv)
{
	csh disas_handle;
	cs_insn *insn;
	cs_x86 *x86;
	size_t insn_count;
	Elf64_Shdr *code_shdr;
	char *vd = v.data();
	int i, j, k;
	uint64_t addr = 0;
	const char *sections[2] = { ".text", ".fini" };

	for (k = 0; k < 2; k++) {
		code_shdr = elf_get_section((unsigned char *)v.data(), sections[k]);
		if (!code_shdr) {
			fprintf(stderr, "failed to find the code region\n");

			return -1;
		}

		while (addr < code_shdr->sh_offset) {
			outv.push_back(v[addr]);
			addr++;
		}

		if (cs_open(CS_ARCH_X86, CS_MODE_64, &disas_handle) != CS_ERR_OK) {
			fprintf(stderr, "failed to open capstone");

			return -1;
		}

		cs_option(disas_handle, CS_OPT_DETAIL, CS_OPT_ON);

		printf("sh_offset = 0x%08lx, sh_size=0x%lx\n", 
			code_shdr->sh_offset,
			code_shdr->sh_size);

		insn_count = cs_disasm(disas_handle,
		                       (const uint8_t *)&vd[code_shdr->sh_offset],
		                       code_shdr->sh_size,
		                       code_shdr->sh_offset,
		                       0,
		                       &insn);
		if (insn_count < 1) {
			fprintf(stderr, "capstone failed to disasm\n");

			return -1;
		}

		for (i = 0; i < insn_count; i++) {
			/* push new instr */
			if (addr == glob_instr_addr) {
				for (j = 0; j < sizeof (glob_instr); j++) {
					outv.push_back(glob_instr[j]);
				}
			}

			modify_ins(&disas_handle, &insn[i]);

			for (j = 0; j < insn[i].size; j++) {
				outv.push_back(insn[i].bytes[j]);
			}
			addr += insn[i].size;
		}

		printf("\n\n");

		cs_free(insn, insn_count);
		cs_close(&disas_handle);
	}

	addr += sizeof (glob_instr);

	for (i = addr; i < v.size(); i++) {
		outv.push_back(v[i]);
	}

	return 0;
}

static Elf64_Shdr *elf_get_section(unsigned char *v, const char *sh_name)
{
	Elf64_Ehdr *elf_hdr;
	Elf64_Shdr *sh_entry;
	int i;
	char *sh_str;

	elf_hdr = (Elf64_Ehdr *) &v[0];

	sh_entry = (Elf64_Shdr *) (v + elf_hdr->e_shoff);
	sh_str = (char *) (v + sh_entry[elf_hdr->e_shstrndx].sh_offset);

	for (i = 0; i < elf_hdr->e_shnum; i++) {
		if (!strcmp(sh_name, sh_str + sh_entry[i].sh_name)) {
			return &sh_entry[i];
		}
	}

	return nullptr;
}

static void modify_elf_header(unsigned char *v)
{
	Elf64_Ehdr *elf_hdr;
	Elf64_Shdr *sh_entry;
	Elf64_Phdr *ph_entry;
	Elf64_Dyn *dyn_entry;
	int i;
	int fini_id;
	char *sh_str;

	elf_hdr = (Elf64_Ehdr *) &v[0];

#if 0
	printf("e_shentsize = %d\n", elf_hdr->e_shentsize);
	printf("e_shnum     = %d\n", elf_hdr->e_shnum);
	printf("e_shstrndx  = %d\n", elf_hdr->e_shstrndx);
	printf("e_phnum     = %d\n", elf_hdr->e_phnum);
#endif

	sh_entry = (Elf64_Shdr *) (v + elf_hdr->e_shoff);
	ph_entry = (Elf64_Phdr *) (v + elf_hdr->e_phoff);
	sh_str = (char *) (v + sh_entry[elf_hdr->e_shstrndx].sh_offset);

	for (i = 0; i < elf_hdr->e_shnum; i++) {
		if (!strcmp(".fini", sh_str + sh_entry[i].sh_name)) {
			sh_entry[i].sh_addr += sizeof (glob_instr);
			sh_entry[i].sh_offset += sizeof (glob_instr);
			sh_entry[i].sh_addralign = 0;
			fini_id = i;

			printf(".fini sh_addr      = 0x%08lx\n", sh_entry[i].sh_addr);
			printf(".fini sh_offset    = 0x%08lx\n", sh_entry[i].sh_offset);
			printf(".fini sh_addralign = 0x%08lx\n", sh_entry[i].sh_addralign);
		}

		if (!strcmp(".dynamic", sh_str + sh_entry[i].sh_name)) {
			dyn_entry = (Elf64_Dyn *) (v + sh_entry[i].sh_offset);
		}
	}

	printf("\nPhdr:\n");
	for (i = 0; i < elf_hdr->e_phnum; i++) {
		printf("  [%d] p_offset = 0x%08lx\n", i, ph_entry[i].p_offset);
		printf("  [%d] p_vaddr  = 0x%08lx\n", i, ph_entry[i].p_vaddr);
		printf("  [%d] p_paddr  = 0x%08lx\n", i, ph_entry[i].p_paddr);
		printf("  [%d] p_filesz = 0x%08lx\n", i, ph_entry[i].p_filesz);
		printf("  [%d] p_memsz  = 0x%08lx\n", i, ph_entry[i].p_memsz);
		printf("  [%d] p_align  = 0x%08lx\n", i, ph_entry[i].p_align);
		printf("\n");

		if ((ph_entry[i].p_paddr <= sh_entry[fini_id].sh_addr) &&
			(ph_entry[i].p_paddr + ph_entry[i].p_filesz >
			         sh_entry[fini_id].sh_addr)) {
			/* .fini is located in this segment */
			ph_entry[i].p_filesz += sizeof (glob_instr);
			ph_entry[i].p_memsz += sizeof (glob_instr);
		}
	}
	printf("\n");

	i = 0;
	while (dyn_entry[i].d_tag != DT_NULL) {
		if (dyn_entry[i].d_tag == DT_FINI) {
			dyn_entry[i].d_un.d_ptr = sh_entry[fini_id].sh_addr;

			break;
		}
		i++;
	}
}

static int prepare_elf(const char *fname)
{
	int ret = 0;
	std::streamsize size;
	std::string in_name(fname);
	std::string filename = in_name.substr(in_name.find_last_of("/") + 1);
	std::ifstream in(fname, std::ios::binary);
	std::ofstream out(filename + std::string(".out"),
		std::ios::binary);

	if (!in.is_open() || !out.is_open()) {
		return -1;
	}

	in.seekg(0, std::ios::end);
	size = in.tellg();
	in.seekg(0, std::ios::beg);

	std::vector<char> buffer(size);
	std::vector<char> out_buffer;

	if (!in.read(buffer.data(), size)) {
		in.close();
		out.close();

		ret = -1;
		goto out;
	}

	insert_profiler_code(buffer, out_buffer);

	modify_elf_header((unsigned char *)out_buffer.data());

	out.write(out_buffer.data(), out_buffer.size());

out:
	in.close();
	out.close();

	return ret;
}

int main(int argc, char **argv)
{
	pid_t pid;
	int waitres;

	if (argc < 2) {
		fprintf(stderr, "Error: ELF missed\n");

		return -1;
	}

	printf("Profiling ELF: %s\n", argv[1]);

	prepare_elf(argv[1]);

	pid = fork();

	if (pid == -1) {
		perror("fork error");
	} else if (pid == 0) {
		execv(argv[1], argv + 1);

		printf("Unknown command\n");
		exit(-1);
	} else {
		waitpid(pid, &waitres, 0);

		printf("END\n");
	}

	return 0;
}
