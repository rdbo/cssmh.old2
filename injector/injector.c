#include "procfs.h"
#include "parse_elf.h"
#include "ptrace_utils.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <malloc.h>
#include <sys/mman.h>
#include <dlfcn.h>

#define ARRLEN(arr) (sizeof(arr) / sizeof(arr[0]))

int find_dlopen_callback(struct maps_line *maps_line, void *arg)
{
	struct {
		const char *libname;
		const char *symname;
	} options[] = {
		{ "libdl.", "dlopen" },
		{ "libdl-", "dlopen" },
		{ "libc.", "__libc_dlopen_mode" },
		{ "libc-", "__libc_dlopen_mode" }
	};
	size_t i;

	for (i = 0; i < ARRLEN(options); ++i) {
		size_t liblen;
		char *libname;
		char *tmp;

		liblen = strlen(options[i].libname);
		libname = maps_line->filename;
		
		while ((tmp = strchr(libname, '/')))
			libname = &tmp[1];

		if (strlen(libname) < liblen)
			continue;
		
		if (!strncmp(libname, options[i].libname, liblen)) {
			unsigned long dlopen_addr;
			
			dlopen_addr = get_symbol_address(maps_line->base,
							 maps_line->filename,
							 options[i].symname);
			
			if (dlopen_addr == (unsigned long)-1)
				continue;
			
			printf("[*] Library with dlopen: %s\n",
			       maps_line->filename);
			printf("[*] Symbol: %s\n", options[i].symname);
			
			*(unsigned long *)arg = dlopen_addr;
			return 1;
		}
	}

	return 0;
}

unsigned long find_dlopen(pid_t pid)
{
	unsigned long dlopen_addr = (unsigned long)-1;

	iterate_maps(pid, find_dlopen_callback, (void *)&dlopen_addr);
	if (dlopen_addr == (unsigned long)-1)
		printf("[!] Unable to find dlopen\n");

	return dlopen_addr;
}

int inject_lib(pid_t pid, char *libpath)
{
	int ret = -1;
	unsigned long dlopen_addr;
	unsigned long alloc;
	unsigned char payload[] = {
		0x51, /* push %ecx */
		0x53, /* push %ebx */
		0xFF, 0xD0, /* call *%eax */
		0xCC /* int3 */
	};
	size_t pathlen;
	size_t alloc_size;
	struct user_regs_struct regs, old_regs;

	dlopen_addr = find_dlopen(pid);
	printf("[*] Address of dlopen: %lx\n", dlopen_addr);

	printf("[*] Injecting...\n");

	if (ptrace_attach(pid))
		return -1;
	
	pathlen = strlen(libpath) + 1;
	alloc_size = sizeof(payload) + pathlen;

	alloc = ptrace_vmalloc(pid, alloc_size, PROT_EXEC | PROT_READ | PROT_WRITE);
	if (alloc == (unsigned long)-1) {
		printf("[!] Unable to allocate memory\n");
		goto DETACH_EXIT;
	}
	printf("[*] Allocation: %lx\n", alloc);

	if (ptrace_write(pid, (char *)alloc, (char *)payload, sizeof(payload)))
		goto FREE_EXIT;
	if (ptrace_write(pid, &((char *)alloc)[sizeof(payload)], libpath, pathlen))
		goto FREE_EXIT;

	if (ptrace_getregs(pid, &old_regs))
		goto FREE_EXIT;
	
	regs = old_regs;
	regs.eax = dlopen_addr;
	regs.ebx = (unsigned long)(&((char *)alloc)[sizeof(payload)]); /* file */
	regs.ecx = RTLD_LAZY; /* mode */
	regs.eip = alloc;

	if (ptrace_setregs(pid, &regs))
		goto FREE_EXIT;
	
	if (ptrace_cont(pid))
		goto RESTORE_EXIT;
	
	if (!ptrace_getregs(pid, &regs) && regs.eax) {
		printf("[*] Library handle: %lx\n", regs.eax);
		ret = 0;
	}

RESTORE_EXIT:
	ptrace_setregs(pid, &old_regs);
FREE_EXIT:
	ptrace_vmfree(pid, alloc, alloc_size);
DETACH_EXIT:
	ptrace_detach(pid);

	return ret;
}

int main()
{
	pid_t pid;
	char *cwd;
	size_t cwd_len;
	char *libpath;
	size_t libpath_len;
	char libname[] = LIBNAME;

	printf("[CSSMH Injector]\n");

	cwd = getcwd(NULL, 0);
	if (!cwd) {
		printf("[!] Unable to get current directory\n");
		return -1;
	}

	cwd_len = strlen(cwd);
	libpath_len = cwd_len + 1 + sizeof(libname);
	libpath = calloc(libpath_len + 1, sizeof(char));
	if (libpath) {
		snprintf(libpath, libpath_len + 1, "%s/%s", cwd, libname);
		libpath[libpath_len] = '\x00';
	}
	
	free(cwd);

	if (!libpath) {
		printf("[!] Unable to get CSSMH library\n");
		return -1;
	}

	printf("[*] CSSMH library: %s\n", libpath);

	printf("[*] Searching for target process...\n");
	for (;;) {
		pid = find_process(TARGET_PROCESS);
		if (pid != -1)
			break;
		
		if (errno) {
			printf("[!] Error: %d\n", errno);
		}

		sleep(1);
	}
	printf("[*] Target process found: %d\n", pid);

	if (!inject_lib(pid, libpath)) {
		printf("[*] Injection successful\n");
	} else {
		printf("[!] Injection failed\n");
	}

	free(libpath);

	return 0;
}
