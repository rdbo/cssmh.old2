#ifndef PROCFS_H
#define PROCFS_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <unistd.h>

struct maps_line {
	unsigned long base;
	unsigned long end;
	int prot;
	int alloc;
	unsigned long offset;
	unsigned int dev_major;
	unsigned int dev_minor;
	int inode;
	char *filename;
};

pid_t find_process(const char *name);

int iterate_maps(pid_t pid,
		 int(*callback)(struct maps_line *maps_line, void *arg),
		 void *arg);

#endif
