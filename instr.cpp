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

#include <disasm/disasm.h>
#include <disasm/capstone_disasm.h>

static uint64_t text_end;
static bool use_file = false;

static std::string glob_func_name;
static uint64_t glob_instr_addr;
static std::vector<unsigned char> glob_instr;

static Elf64_Shdr *elf_get_section(unsigned char *v, const char *sh_name);
static Elf64_Phdr *elf_get_region(unsigned char *v, uint64_t addr);
static int elf_get_func_addr(unsigned char *v, const char *sym_name,
                            uint64_t *sym_addr);

#if 1
static void modify_ins(b_instr *ins)
{
	int i;
	int64_t shift;
	uint64_t dst_addr;
	b_op *op;

	for (i = 0; i < ins->ops.size(); i++) {
		op = ins->ops[i];

		if (!op->is_relative()) {
			continue;
		}

		op->extract_val(&shift);

		dst_addr = ins->address() + ins->size() + shift;

		if (dst_addr < text_end) {
			if ((ins->address() < glob_instr_addr) &&
					(dst_addr > glob_instr_addr)) {
				shift += glob_instr.size();
			} else if ((ins->address() > glob_instr_addr) &&
			           (dst_addr < glob_instr_addr)) {
				shift -= glob_instr.size();
			}
		} else if (ins->address() + ins->size() > glob_instr_addr) {
			shift -= glob_instr.size();
		}

		op->deposit_val(shift);
	}
}
#endif

static int insert_profiler_code(std::vector<char> &v, std::vector<char> &outv)
{
	Elf64_Shdr *code_shdr;
	Elf64_Phdr *code_region;
	unsigned char *vd = (unsigned char *) v.data();
	int i, j, k;
	uint64_t addr = 0;
	const char *sections[2] = { ".text", ".fini" };

	code_shdr = elf_get_section((unsigned char *)v.data(), ".text");
	code_region = elf_get_region((unsigned char *)v.data(), code_shdr->sh_addr);

	text_end = code_region->p_offset + code_region->p_filesz;

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

		b_capstone_dis cdis = b_capstone_dis(
		                       &vd[code_shdr->sh_offset],
		                       code_shdr->sh_offset, code_shdr->sh_size);
		b_dis *dis = &cdis;
		uint8_t *bytes;

		for (i = 0; i < dis->insn.size(); i++) {
			/* push new instr */
			if (addr == glob_instr_addr) {
				for (j = 0; j < glob_instr.size(); j++) {
					outv.push_back(glob_instr[j]);
				}
			}

			modify_ins(dis->insn[i]);

			bytes = dis->insn[i]->bytes();

			for (j = 0; j < dis->insn[i]->size(); j++) {
				outv.push_back(bytes[j]);
			}
			addr += dis->insn[i]->size();
		}
	}

	addr += glob_instr.size();

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

static Elf64_Phdr *elf_get_region(unsigned char *v, uint64_t addr)
{
	Elf64_Ehdr *elf_hdr;
	Elf64_Phdr *ph_entry;
	int i;

	elf_hdr = (Elf64_Ehdr *) &v[0];
	ph_entry = (Elf64_Phdr *) (v + elf_hdr->e_phoff);

	for (i = 0; i < elf_hdr->e_phnum; i++) {
		if ((ph_entry[i].p_paddr <= addr) &&
				(ph_entry[i].p_paddr + ph_entry[i].p_filesz > addr)) {
			return &ph_entry[i];
		}
	}

	return nullptr;
}

static int elf_get_func_addr(unsigned char *v, const char *sym_name,
                            uint64_t *sym_addr)
{
	Elf64_Ehdr *elf_hdr;
	Elf64_Shdr *sh_entry;
	Elf64_Shdr *symtab = nullptr;
	Elf64_Shdr *strtab = nullptr;
	Elf64_Sym *sym;
	const char *str;
	const char *sh_str;
	int i;

	if (!sym_addr) {
		return -1;
	}

	elf_hdr = (Elf64_Ehdr *) &v[0];
	sh_entry = (Elf64_Shdr *) (v + elf_hdr->e_shoff);
	sh_str = (const char *) (v + sh_entry[elf_hdr->e_shstrndx].sh_offset);

	for (i = 0; i < elf_hdr->e_shnum; i++) {
		if (symtab && strtab) {
			break;
		} else if (!strcmp(sh_str + sh_entry[i].sh_name, ".symtab")) {
			symtab = &sh_entry[i];
		} else if (!strcmp(sh_str + sh_entry[i].sh_name, ".strtab")) {
			strtab = &sh_entry[i];
		}
	}

	sym = (Elf64_Sym *) (v + symtab->sh_offset);
	str = (const char *) (v + strtab->sh_offset);

	for (i = 0; i < symtab->sh_size / symtab->sh_entsize; i++) {
		if (ELF64_ST_TYPE(sym[i].st_info) != STT_FUNC) {
			continue;
		}

		if (!strcmp(str + sym[i].st_name, sym_name)) {
			*sym_addr = sym[i].st_value;

			return 0;
		}
	}

	return -1;
}

static int elf_get_instr_addr(unsigned char *v, const char *func_name)
{
	int ret;
	uint64_t func_addr;

	ret = elf_get_func_addr(v, func_name, &func_addr);
	if (ret < 0) {
		return -1;
	}
	b_capstone_dis cdis = b_capstone_dis(&v[func_addr], func_addr, 4);
	b_dis *dis = &cdis;

	glob_instr_addr = func_addr;

	if (dis->insn[0]->is_endbr64()) {
		glob_instr_addr += dis->insn[0]->size();
	}

	printf("\n glob_instr_addr = 0x%08lx\n", glob_instr_addr);

	return 0;
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
			sh_entry[i].sh_addr += glob_instr.size();
			sh_entry[i].sh_offset += glob_instr.size();
			sh_entry[i].sh_addralign = 0;
			fini_id = i;
#if 0
			printf(".fini sh_addr      = 0x%08lx\n", sh_entry[i].sh_addr);
			printf(".fini sh_offset    = 0x%08lx\n", sh_entry[i].sh_offset);
			printf(".fini sh_addralign = 0x%08lx\n", sh_entry[i].sh_addralign);
#endif
		}

		if (!strcmp(".dynamic", sh_str + sh_entry[i].sh_name)) {
			dyn_entry = (Elf64_Dyn *) (v + sh_entry[i].sh_offset);
		}
	}

	//printf("\nPhdr:\n");
	for (i = 0; i < elf_hdr->e_phnum; i++) {
#if 0
		printf("  [%d] p_offset = 0x%08lx\n", i, ph_entry[i].p_offset);
		printf("  [%d] p_vaddr  = 0x%08lx\n", i, ph_entry[i].p_vaddr);
		printf("  [%d] p_paddr  = 0x%08lx\n", i, ph_entry[i].p_paddr);
		printf("  [%d] p_filesz = 0x%08lx\n", i, ph_entry[i].p_filesz);
		printf("  [%d] p_memsz  = 0x%08lx\n", i, ph_entry[i].p_memsz);
		printf("  [%d] p_align  = 0x%08lx\n", i, ph_entry[i].p_align);
		printf("\n");
#endif

		if ((ph_entry[i].p_paddr <= sh_entry[fini_id].sh_addr) &&
			(ph_entry[i].p_paddr + ph_entry[i].p_filesz >
			         sh_entry[fini_id].sh_addr)) {
			/* .fini is located in this segment */
			ph_entry[i].p_filesz += glob_instr.size();
			ph_entry[i].p_memsz += glob_instr.size();
		}
	}
	//printf("\n");

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

	ret = elf_get_instr_addr((unsigned char *) buffer.data(), glob_func_name.data());
	if (ret < 0) {
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

static void get_instr_from_file(const char *file)
{
	std::string line;
	std::ifstream in(file);
	int i, j;

	while (std::getline(in, line)) {
		switch (i) {
		case 0:
			glob_func_name = line.data();

			break;
		case 1:
			/* enter, exit */
			break;
		case 2:
			j = 0;

			while (j < line.size()) {
				if (line[j] == ' ') {
					j++;

					continue;
				}

				glob_instr.push_back(std::stoul(line.substr(j, 2), 0, 16));

				j += 2;
			}

			printf("instr: ");
			for (j = 0; j < glob_instr.size(); j++) {
				printf("%02x ", glob_instr[j]);
			}
			printf("\n");

			break;
		}

		if (++i == 3) {
			break;
		}
	}
}

int main(int argc, char **argv)
{
	pid_t pid;
	int waitres;
	char *file;
	int c;

	if (argc < 2) {
		fprintf(stderr, "Error: ELF missed\n");

		return -1;
	}

	while ((c = getopt(argc, argv, "hf:")) != -1) {
		switch (c) {
		case 'f':
			use_file = true;
			file = optarg;

			break;
		case 'h':
			break;
		}
	}

	printf("Profiling ELF: %s\n", argv[argc - 1]);

	if (use_file) {
		get_instr_from_file(file);
	} else {
		fprintf(stderr, "Please, provide file with -f <file>");

		return 0;
	}

	prepare_elf(argv[argc - 1]);

	pid = fork();

	if (pid == -1) {
		perror("fork error");
	} else if (pid == 0) {
		execv(argv[argc - 1], argv + argc - 1);

		printf("Unknown command\n");
		exit(-1);
	} else {
		waitpid(pid, &waitres, 0);

		printf("END\n");
	}

	return 0;
}
