#include "ptrace_utils.h"
#include <stdio.h>
#include <errno.h>
#include <wait.h>
#include <syscall.h>
#include <malloc.h>
#include <memory.h>
#include <sys/mman.h>

int ptrace_attach(pid_t pid)
{
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
		return -1;
	
	wait(NULL);

	return 0;
}

int ptrace_detach(pid_t pid)
{
	return ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

int ptrace_getregs(pid_t pid, struct user_regs_struct *regs)
{
	return ptrace(PTRACE_GETREGS, pid, NULL, regs);
}

int ptrace_setregs(pid_t pid, struct user_regs_struct *regs)
{
	return ptrace(PTRACE_SETREGS, pid, NULL, regs);
}

int ptrace_read(pid_t pid, char *src, char *dst, size_t size)
{
	size_t i;

	for (i = 0; i < size; ++i) {
		long data;

		data = ptrace(PTRACE_PEEKDATA, pid, &src[i], NULL);
		if (data == -1 && errno)
			return -1;
		dst[i] = (char)data;
	}

	return 0;
}

int ptrace_write(pid_t pid, char *dst, char *src, size_t size)
{
	int ret = -1;
	char *buf;
	size_t bufsize;
	size_t i;

	if (size > sizeof(long))
		bufsize = size + (size % sizeof(long));
	else
		bufsize = sizeof(long);

	buf = malloc(bufsize);
	if (ptrace_read(pid, dst, buf, bufsize))
		goto FREE_EXIT;
	
	memcpy(buf, src, size);

	for (i = 0; i < bufsize; i += sizeof(long)) {
		long data = *(long *)&buf[i];
		if (ptrace(PTRACE_POKEDATA, pid, &dst[i], data) == -1)
			goto FREE_EXIT;
	}

	ret = 0;
FREE_EXIT:
	free(buf);
	return ret;
}

int ptrace_cont(pid_t pid)
{
	if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
		return -1;
	
	waitpid(pid, NULL, WSTOPPED);
	return 0;
}

int ptrace_singlestep(pid_t pid)
{
	if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1)
		return -1;
	
	waitpid(pid, NULL, WSTOPPED);
	return 0;
}

unsigned long ptrace_vmalloc(pid_t pid, size_t size, int prot)
{
	unsigned long alloc = (unsigned long)-1;
	struct user_regs_struct regs, old_regs;
	unsigned char payload[] = {
		0xCD, 0x80
	};
	unsigned char old_code[sizeof(payload)];

	if (ptrace_getregs(pid, &old_regs))
		return alloc;
	
	regs = old_regs;

	regs.eax = __NR_mmap2;
	regs.ebx = 0; /* address */
	regs.ecx = size; /* length */
	regs.edx = prot; /* prot */
	regs.esi = MAP_PRIVATE | MAP_ANON; /* flags */
	regs.edi = -1; /* fd */
	regs.ebp = 0; /* offset */

	if (ptrace_read(pid, (char *)regs.eip, (char *)old_code, sizeof(old_code)))
		return alloc;
	
	if (ptrace_setregs(pid, &regs))
		return alloc;

	if (ptrace_write(pid, (char *)regs.eip, (char *)payload, sizeof(payload)))
		goto RESTORE_REGS_EXIT;
	
	if (ptrace_singlestep(pid))
		goto RESTORE_EXIT;
	
	if (!ptrace_getregs(pid, &regs))
		alloc = regs.eax;

RESTORE_EXIT:
	ptrace_write(pid, (char *)old_regs.eip, (char *)old_code, sizeof(old_code));
RESTORE_REGS_EXIT:
	ptrace_setregs(pid, &old_regs);
	return alloc;
}

int ptrace_vmfree(pid_t pid, unsigned long addr, size_t size)
{
	int ret = -1;
	struct user_regs_struct regs, old_regs;
	unsigned char payload[] = {
		0xCD, 0x80
	};
	unsigned char old_code[sizeof(payload)];

	if (ptrace_getregs(pid, &old_regs))
		return ret;
	
	regs = old_regs;

	regs.eax = __NR_munmap;
	regs.ebx = addr; /* address */
	regs.ecx = size; /* length */

	if (ptrace_read(pid, (char *)regs.eip, (char *)old_code, sizeof(old_code)))
		return ret;
	
	if (ptrace_setregs(pid, &regs))
		return ret;

	if (ptrace_write(pid, (char *)regs.eip, (char *)payload, sizeof(payload)))
		goto RESTORE_REGS_EXIT;
	
	if (ptrace_singlestep(pid))
		goto RESTORE_EXIT;
	
	if (!ptrace_getregs(pid, &regs) && !regs.eax)
		ret = 0;

RESTORE_EXIT:
	ptrace_write(pid, (char *)old_regs.eip, (char *)old_code, sizeof(old_code));
RESTORE_REGS_EXIT:
	ptrace_setregs(pid, &old_regs);
	return ret;
}
