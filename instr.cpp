#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cxxabi.h>

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <regex>

#include <disasm/disasm.h>

#if defined(USE_ZYDIS)
#include <disasm/zydis_disasm.h>
#elif defined(USE_CAPSTONE)
#include <disasm/capstone_disasm.h>
#endif

struct instr_info {
	uint64_t addr;
	std::vector<unsigned char> bytes;
};

static std::vector<struct instr_info> ins_v;

static uint64_t text_end;
static bool use_file = false;
static char *instr_file;

static Elf64_Shdr *elf_get_section(unsigned char *v, const char *sh_name);
static Elf64_Phdr *elf_get_region(unsigned char *v, uint64_t addr);
static int elf_get_func_addr(unsigned char *v, const char *sym_name,
                            uint64_t *sym_addr);

static b_dis *create_dis(unsigned char *buffer, uint64_t address, size_t size)
{
#if defined(USE_ZYDIS)
	b_zydis_dis *cdis = new b_zydis_dis(buffer, address, size);
#elif defined(USE_CAPSTONE)
	b_capstone_dis *cdis = new b_capstone_dis(buffer, address, size);
#else
	#error "No disassembler selected (capstone, zydis)"
#endif
	b_dis *dis = cdis;

	return dis;
}

static void destroy_dis(b_dis *dis)
{
#if defined(USE_ZYDIS)
	delete (b_zydis_dis *) dis;
#elif defined(USE_CAPSTONE)
	delete (b_capstone_dis *) dis;
#else
	#error "No disassembler selected (capstone, zydis)"
#endif
}

static int64_t calc_new_shift(b_instr *ins, int64_t shift)
{
	uint64_t dst_addr;
	uint64_t start, stop;
	int64_t val = 0;
	int i;

	dst_addr = ins->address() + ins->size() + shift;

	if (ins->address() >= dst_addr) {
		start = dst_addr;
		stop = ins->address();
	} else {
		start = ins->address();
		stop = dst_addr;
	}

	if (dst_addr < text_end) {
		for (i = 0; i < ins_v.size(); i++) {
			if ((ins_v[i].addr >= start) && (ins_v[i].addr < stop)) {
				val += ins_v[i].bytes.size(); /* instr size */
			}
		}
		val *= ins->address() < dst_addr ? 1 : -1;
	} else {
		for (i = 0; i < ins_v.size(); i++) {
			if (ins_v[i].addr < start) {
				val -= ins_v[i].bytes.size(); /* instr size */
			}
		}
	}

	shift += val;

	return shift;
}

static void modify_ins(b_instr *ins)
{
	int i;
	int64_t shift;
	b_op *op;

	for (i = 0; i < ins->ops.size(); i++) {
		op = ins->ops[i];

		if (!op->is_relative()) {
			continue;
		}

		op->extract_val(&shift);

		shift = calc_new_shift(ins, shift);

		op->deposit_val(shift);
	}
}

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

		b_dis *dis = create_dis(&vd[code_shdr->sh_offset],
		                        code_shdr->sh_offset, code_shdr->sh_size);
		uint8_t *bytes;

		for (i = 0; i < dis->insn.size(); i++) {
			/* push new instr. TODO sort instrs before */
			for (j = 0; j < ins_v.size(); j++) {
				if (addr == ins_v[j].addr) {
					int n;

					for (n = 0; n < ins_v[j].bytes.size(); n++) {
						outv.push_back(ins_v[j].bytes[n]);
					}
				}
			}

			modify_ins(dis->insn[i]);

			bytes = dis->insn[i]->bytes();

			for (j = 0; j < dis->insn[i]->size(); j++) {
				outv.push_back(bytes[j]);
			}
			addr += dis->insn[i]->size();
		}

		destroy_dis(dis);
	}

	for (i = 0; i < ins_v.size(); i++) {
		addr += ins_v[i].bytes.size();
	}

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
	char *demangled_name;
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
		size_t len;
		int status;
		char *name;

		if ((ELF64_ST_TYPE(sym[i].st_info) != STT_FUNC) ||
				/* It means the symbol is not in any section, it's undefined. */
				(sym[i].st_shndx == SHN_UNDEF)) {
			continue;
		}

		demangled_name = abi::__cxa_demangle(str + sym[i].st_name,
		                                     0, &len, &status);
		if (demangled_name) {
			name = demangled_name;
		} else {
			if (status == -2) {
				/* -2: mangled_name is not a valid name under the C++ ABI mangling rules. */
				/* I interpret this as the symbol is C-function.  */
				name = const_cast<char *>(str + sym[i].st_name);
			} else {
				/* Symbol name invalid */
				fprintf(stderr, "Symbol name is invalid: %s\n",
				        str + sym[i].st_name);

				continue;
			}
		}

		if (!strcmp(name, sym_name)) {
			*sym_addr = sym[i].st_value;
			if (demangled_name) {
				std::free(demangled_name);
			}

			return 0;
		} else {
			if (demangled_name) {
				std::free(demangled_name);
			}
		}
	}

	return -1;
}

static int elf_get_instr_addr(unsigned char *v,
                              const char *func_name, uint64_t *instr_addr)
{
	int ret;
	uint64_t func_addr;
	uint64_t addr;

	if (!instr_addr) {
		return -1;
	}

	ret = elf_get_func_addr(v, func_name, &func_addr);
	if (ret < 0) {
		return -1;
	}
	b_dis *dis = create_dis(&v[func_addr], func_addr, 4);

	addr = func_addr;

	if (dis->insn[0]->is_endbr64()) {
		addr += dis->insn[0]->size();
	}

	destroy_dis(dis);

	*instr_addr = addr;

	return 0;
}

static void modify_elf_header(unsigned char *v)
{
	Elf64_Ehdr *elf_hdr;
	Elf64_Shdr *sh_entry;
	Elf64_Phdr *ph_entry;
	Elf64_Dyn *dyn_entry;
	int i, j;
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
		if (!strcmp(".text", sh_str + sh_entry[i].sh_name)) {
			for (j = 0; j < ins_v.size(); j++) {
				sh_entry[i].sh_size += ins_v[j].bytes.size();
			}
		}

		if (!strcmp(".fini", sh_str + sh_entry[i].sh_name)) {
			for (j = 0; j < ins_v.size(); j++) {
				sh_entry[i].sh_addr += ins_v[j].bytes.size();
				sh_entry[i].sh_offset += ins_v[j].bytes.size();
			}

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

	/* TODO Remove this check and adjust sections properly. */
	/* Here we check that there is no intersections of sections. */
	for (i = 0; i < elf_hdr->e_shnum; i++) {
		if (!(sh_entry[i].sh_flags & SHF_ALLOC)) {
			continue;
		}

		for (j = 0; j < elf_hdr->e_shnum; j++) {
			if (!(sh_entry[j].sh_flags & SHF_ALLOC)) {
				continue;
			}

			if ((sh_entry[i].sh_addr > sh_entry[j].sh_addr) &&
				(sh_entry[i].sh_addr < (sh_entry[j].sh_addr + sh_entry[j].sh_size))) {
				fprintf(stderr, "Error: pheaders overflow!\n");
				printf("addr[%d] = 0x%lx, addr[%d]=0x%lx, sz[%d]=0x%lx\n",
					i, sh_entry[i].sh_addr, j, sh_entry[j].sh_addr,
					j, sh_entry[j].sh_size);
				exit(1);
			}
		}
	}

	//printf("\nPhdr:\n");
	for (i = 0; i < elf_hdr->e_phnum; i++) {
#if 0
		printf("  [%d] p_offset = 0x%08lx\n", i, ph_entry[i].p_type);
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
			for (j = 0; j < ins_v.size(); j++) {
				ph_entry[i].p_filesz += ins_v[j].bytes.size();
				ph_entry[i].p_memsz += ins_v[j].bytes.size();
			}
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

static int get_instr_from_file(unsigned char *buffer)
{
	std::string line;
	std::ifstream in(instr_file);
	int i, j;
	int ret;
	struct instr_info ins_info;

	while (std::getline(in, line)) {
		if (!line.size()) {
			continue;
		}

		switch (i) {
		case 0:
			ret = elf_get_instr_addr(buffer, line.data(), &ins_info.addr);
			if (ret < 0) {
				//fprintf(stderr, "Cannot resolve function's name: %s\n",
				//	line.data());

				/* Skip next lines to go to the next instruction */
				std::getline(in, line);
				std::getline(in, line);

				continue;
			}

			ins_info.bytes.clear();

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

				ins_info.bytes.push_back(std::stoul(line.substr(j, 2), 0, 16));

				j += 2;
			}

			printf("instr (addr=0x%08lx): ", ins_info.addr);
			for (j = 0; j < ins_info.bytes.size(); j++) {
				printf("%02x ", ins_info.bytes[j]);
			}
			printf("\n");

			ins_v.push_back(ins_info);

			break;
		}

		if (++i == 3) {
			/* Process next instruction */
			i = 0;
		}
	}

	in.close();

	return 0;
}

static int prepare_file(const char *fname)
{
	int ret = 0;
	std::streamsize size;
	std::string in_name(fname);
	std::string filename = in_name.substr(in_name.find_last_of("/") + 1);
	std::ifstream in(fname, std::ios::binary);
	std::ofstream out(std::string("out/") + filename,
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

	ret = get_instr_from_file((unsigned char *) buffer.data());
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

static int prepare_elf(const char *path)
{
	std::string in_name = std::string(path);
	std::string filename = in_name.substr(in_name.find_last_of("/") + 1);
	std::ifstream in(filename + std::string(".libs"));
	std::string line;
	int ret;

	printf("Handle file: %s\n", path);
	ret = prepare_file(path);
	if (ret < 0) {
		goto out;
	}
	ins_v.clear();

	while (std::getline(in, line)) {
		printf("Handle file: %s\n", line.data());
		ret = prepare_file(line.data());
		if (ret < 0) {
			goto out;
		}
		ins_v.clear();
	}

out:
	return ret;
}

int main(int argc, char **argv)
{
	pid_t pid;
	int waitres;
	int c;

	if (argc < 2) {
		fprintf(stderr, "Error: ELF missed\n");

		return -1;
	}

	while ((c = getopt(argc, argv, "hf:")) != -1) {
		switch (c) {
		case 'f':
			use_file = true;
			instr_file = optarg;

			break;
		case 'h':
			break;
		}
	}

	printf("Profiling ELF: %s\n", argv[argc - 1]);

	if (!use_file) {
		fprintf(stderr, "Please, provide file with -f <file>");

		return 0;
	}

	if (prepare_elf(argv[argc - 1]) < 0) {
		return -1;
	}

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
