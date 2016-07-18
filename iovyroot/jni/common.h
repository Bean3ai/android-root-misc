/*
 * common.h
 *
 *  Created on: Jul 9, 2014
 *      Author: wangzhiheng
 */

#ifndef COMMON_H_
#define COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include "DArray.h"

typedef struct {
	char symbol[NAME_MAX];
	uint32_t offset;
} SymbolAddressPair;

typedef enum {
	trace, debug, info, warn, error, fatal, off = 0xFF
} LogLevel;

extern LogLevel gLogLevel;
extern char gLogPath[];

#if defined(__cplusplus) || defined(c_plusplus) //跨平台定义方法
extern "C"{
#endif

void outputMessage(LogLevel loglevel, const char* format, ...);
void outputMessageDebug(LogLevel loglevel, const char* filename, int32_t line, const char * function,
		const char* format, ...);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#define TRACE(format,args...) do { \
		outputMessageDebug(trace, __FILE__, __LINE__, __FUNCTION__, format, ##args); \
} while (0)

#define INFO(format,args...) do { \
		outputMessage(info, format, ##args); \
} while (0)

#define ERROR(format,args...) do { \
		outputMessage(error, format, ##args); \
} while (0)



#endif /* COMMON_H_ */
