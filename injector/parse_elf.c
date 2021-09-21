#include "parse_elf.h"
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <fcntl.h>
#include <elf.h>
#include <unistd.h>

unsigned long get_symbol_address(unsigned long base, char *elf_path,
				 const char *symbol)
{
	unsigned long symbol_addr = (unsigned long)-1;
	int fd;
	Elf32_Ehdr ehdr;
	Elf32_Off shstrtab_off = 0;
	Elf32_Shdr shstrtab;
	Elf32_Off symtab_off = 0;
	Elf32_Half symtab_entsize = 0;
	Elf32_Half symtab_num = 0;
	Elf32_Off dynsym_off = 0;
	Elf32_Half dynsym_entsize = 0;
	Elf32_Half dynsym_num = 0;
	Elf32_Off strtab_off = 0;
	Elf32_Off dynstr_off = 0;
	Elf32_Half i;

	fd = open(elf_path, O_RDONLY);
	if (fd == -1)
		return symbol_addr;

	read(fd, &ehdr, sizeof(ehdr));

	shstrtab_off = ehdr.e_shoff + (ehdr.e_shstrndx * ehdr.e_shentsize);

	lseek(fd, shstrtab_off, SEEK_SET);
	read(fd, &shstrtab, ehdr.e_shentsize);
	shstrtab_off = shstrtab.sh_offset;

	lseek(fd, ehdr.e_shoff, SEEK_SET);
	for (i = 0; i < ehdr.e_shnum; ++i) {
		Elf32_Shdr shdr;
		char shstr[16] = { 0 };

		read(fd, &shdr, ehdr.e_shentsize);
		pread(fd, shstr, sizeof(shstr),
			shstrtab_off + shdr.sh_name);
		
		if (!strcmp(shstr, ".strtab")) {
			strtab_off = shdr.sh_offset;
		} else if (!strcmp(shstr, ".dynstr")) {
			dynstr_off = shdr.sh_offset;
		} else if (!strcmp(shstr, ".symtab")) {
			symtab_off = shdr.sh_offset;
			symtab_entsize = shdr.sh_entsize;
			symtab_num = shdr.sh_size;
		} else if (!strcmp(shstr, ".dynsym")) {
			dynsym_off = shdr.sh_offset;
			dynsym_entsize = shdr.sh_entsize;
			dynsym_num = shdr.sh_size;
		}
	}

	lseek(fd, symtab_off, SEEK_SET);
	for (i = 0; i < symtab_num; ++i) {
		Elf32_Sym sym;
		char c;
		size_t j = 0;
		char *symstr = (char *)NULL;

		read(fd, &sym, symtab_entsize);

		do {
			char *old_symstr = symstr;
			
			symstr = (char *)calloc(j + 1, sizeof(char));

			if (old_symstr) {
				if (symstr) {
					strncpy(symstr, old_symstr, j);
				}

				free(old_symstr);
			}

			if (!symstr)
				goto _CLEAN_RET;
			
			pread(fd, &c, sizeof(c),
				strtab_off + sym.st_name + j);
			
			symstr[j] = c;

			++j;
		} while (c != '\x00');

		if (!strcmp(symstr, symbol)) {
			if (ehdr.e_type != ET_EXEC) {
				symbol_addr = (unsigned long)(
					&((char *)base)[sym.st_value]
				);
			} else {
				symbol_addr = (unsigned long)sym.st_value;
			}
		}
		
		free(symstr);

		if (symbol_addr != (unsigned long)-1)
			goto _CLEAN_RET;
	}

	lseek(fd, dynsym_off, SEEK_SET);
	for (i = 0; i < dynsym_num; ++i) {
		Elf32_Sym sym;
		char c;
		size_t j = 0;
		char *symstr = (char *)NULL;

		read(fd, &sym, dynsym_entsize);

		do {
			char *old_symstr = symstr;
			
			symstr = (char *)calloc(j + 1, sizeof(char));

			if (old_symstr) {
				if (symstr) {
					strncpy(symstr, old_symstr, j);
				}

				free(old_symstr);
			}

			if (!symstr)
				goto _CLEAN_RET;
			
			pread(fd, &c, sizeof(c),
				dynstr_off + sym.st_name + j);
			
			symstr[j] = c;

			++j;
		} while (c != '\x00');

		if (!strcmp(symstr, symbol)) {
			if (ehdr.e_type != ET_EXEC) {
				symbol_addr = (unsigned long)(
					&((char *)base)[sym.st_value]
				);
			} else {
				symbol_addr = (unsigned long)sym.st_value;
			}
		}
		
		free(symstr);

		if (symbol_addr != (unsigned long)-1)
			goto _CLEAN_RET;
	}

	_CLEAN_RET:
	close(fd);
	return symbol_addr;
}
