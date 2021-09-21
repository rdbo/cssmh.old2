#include "procfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <malloc.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

pid_t find_process(const char *name)
{
	pid_t pid = -1;
	pid_t curpid;
	DIR *procfs_dir;
	struct dirent *pdirent;
	char status_path[64];
	char scan_fmt[64];
	char *curname;
	FILE *status_file;

	procfs_dir = opendir("/proc");
	if (!procfs_dir)
		return pid;
	
	curname = calloc(PATH_MAX, sizeof(curname));
	if (!curname) {
		/* errno = ENOMEM; */
		goto CLOSE_RET;
	}
	
	snprintf(scan_fmt, sizeof(scan_fmt), "Name:\t%%%lu[^\n]", PATH_MAX - 1UL);
	
	while ((pdirent = readdir(procfs_dir))) {
		curpid = (pid_t)atoi(pdirent->d_name);

		if (!curpid)
			continue;

		snprintf(status_path, sizeof(status_path),
			 "/proc/%d/status", curpid);
		
		status_file = fopen(status_path, "r");
		if (!status_file)
			continue;

		fscanf(status_file, scan_fmt, curname);
		fclose(status_file);

		if (!strcmp(curname, name)) {
			pid = curpid;
			break;
		}
	}

	free(curname);
CLOSE_RET:
	closedir(procfs_dir);
	return pid;
}

int iterate_maps(pid_t pid,
		 int(*callback)(struct maps_line *maps_line, void *arg),
		 void *arg)
{
	char maps_path[64];
	FILE *maps_file;
	char flags[4];
	char scan_fmt[64];
	struct maps_line maps_line;
	char *line = (char *)NULL;
	size_t linelen = 0;

	maps_line.filename = calloc(PATH_MAX, sizeof(char));
	if (!maps_line.filename)
		return -1;

	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
	maps_file = fopen(maps_path, "r");
	if (!maps_file) {
		/* errno = ENOENT; */
		return -1;
	}

	snprintf(scan_fmt, sizeof(scan_fmt),
		 "%%lx-%%lx %%4s %%lx %%x:%%x %%u %%%lu[^\n]", PATH_MAX - 1UL);

	while (getline(&line, &linelen, maps_file)) {
		size_t i;

		maps_line.filename[0] = '\x00';

		sscanf(line, scan_fmt,
		       &maps_line.base, &maps_line.end, flags,
		       &maps_line.offset, &maps_line.dev_major,
		       &maps_line.dev_minor, &maps_line.inode,
		       maps_line.filename);
		
		maps_line.prot = 0;
		maps_line.alloc = 0;

		for (i = 0; i < sizeof(flags); ++i) {
			switch (flags[i]) {
			case 'r':
				maps_line.prot |= PROT_READ;
				break;
			case 'w':
				maps_line.prot |= PROT_WRITE;
				break;
			case 'x':
				maps_line.prot |= PROT_EXEC;
				break;
			case 's':
				maps_line.alloc = MAP_SHARED;
				break;
			case 'p':
				maps_line.alloc = MAP_PRIVATE;
				break;
			}
		}

		if (callback(&maps_line, arg))
			break;
		
		maps_line.filename[0] = '\x00';

		free(line);
		line = (char *)NULL;
	}

	free(maps_line.filename);
	
	return 0;
}
