#ifndef PARSE_ELF_H
#define PARSE_ELF_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

unsigned long get_symbol_address(unsigned long base, char *elf_path,
				 const char *symbol);

#endif
