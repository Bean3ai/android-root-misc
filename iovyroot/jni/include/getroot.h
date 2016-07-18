#ifndef GETROOT_H
#define GETROOT_H

#include "threadinfo.h"

#define MAX_CONTEXT 64

#ifdef __cplusplus

extern "C" {

    int read_at_address_pipe(void* address, void* buf, ssize_t len);
    int write_at_address_pipe(void* address, void* buf, ssize_t len);
    inline int writel_at_address_pipe(void* address, unsigned long val);
    int modify_task_cred_uc(struct thread_info* info, int sid, unsigned long *cred_addr);
//32bit
    int change_context(const char *context);
    int set_enforce(int value);
    int get_enforce();
    int get_context(char *buf);
};
#else

int read_at_address_pipe(void* address, void* buf, ssize_t len);
int write_at_address_pipe(void* address, void* buf, ssize_t len);
inline int writel_at_address_pipe(void* address, unsigned long val);
int modify_task_cred_uc(struct thread_info* info, int sid, unsigned long *cred_addr);
//32bit
int change_context(const char *context);
int set_enforce(int value);
int get_enforce();
int get_context(char *buf);

#endif
//64bit
void preparejop(void** addr, void* jopret);

#endif /* GETROOT_H */
