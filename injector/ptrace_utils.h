#ifndef PTRACE_UTILS_H
#define PTRACE_UTILS_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <sys/ptrace.h>
#include <sys/user.h>
#include <unistd.h>

int ptrace_attach(pid_t pid);
int ptrace_detach(pid_t pid);
int ptrace_getregs(pid_t pid, struct user_regs_struct *regs);
int ptrace_setregs(pid_t pid, struct user_regs_struct *regs);
int ptrace_read(pid_t pid, char *src, char *dst, size_t size);
int ptrace_write(pid_t pid, char *dst, char *src, size_t size);
int ptrace_cont(pid_t pid);
int ptrace_singlestep(pid_t pid);
unsigned long ptrace_vmalloc(pid_t pid, size_t size, int prot);
int ptrace_vmfree(pid_t pid, unsigned long addr, size_t size);

#endif
