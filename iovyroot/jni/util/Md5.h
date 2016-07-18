
#ifndef TK_MD5_H
#define TK_MD5_H
#include "stdint.h"

struct TKMD5Context {
	uint32_t buf[4];
	uint32_t bits[2];
	unsigned char in[64];
};

void TKMD5Init(struct TKMD5Context *ctx);
void TKMD5Update(struct TKMD5Context *ctx, unsigned char *buf, unsigned len);
void TKMD5Final(unsigned char digest[16], struct TKMD5Context *ctx);
void TKMD5Transform(uint32_t buf[4], uint32_t in[16]);
/*
 * This is needed to make RSAREF happy on some MS-DOS compilers.
 */
typedef struct TKMD5Context MD5_CTX;

char* tk_str_md5(char* content, int32_t len);
char* tk_file_md5(char* path);

#endif /* !TK_MD5_H */
