#ifndef __TKUtil_h__
#define __TKUtil_h__

#include<stdio.h>

unsigned char  tk_read_uint8(const unsigned char** pp, unsigned int* plen);

unsigned short tk_read_uint16(const unsigned char** pp, unsigned int* plen);

unsigned int  tk_read_uint32(const unsigned char** pp, unsigned int* plen);

unsigned char* tk_read_data(const unsigned char** pp, int* plen, unsigned int length);

char* tk_read_str(const unsigned char** pp, unsigned int* plen);

char* tk_convert_hexchars_to_hex(const unsigned char* content, unsigned int content_len);

char* convertHexToHexchars(const unsigned char* content, unsigned int content_len);

#endif
