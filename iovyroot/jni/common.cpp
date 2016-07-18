/*
 * common.cpp
 *
 *  Created on: Jul 9, 2014
 *      Author: wangzhiheng
 */

#include "common.h"
#include <stdarg.h>
#include <time.h>
LogLevel gLogLevel = info;

char gLogPath[NAME_MAX] = "\0";

#ifdef LOGFILE
#ifndef OUTPUT_FILE
#define OUTPUT_FILE
#endif
#endif

#define KEY 0xFE

void encode(char * const pStartAddress, uint32_t uiSize) {
#ifdef DONT_ENCODE
	return;
#else
	char *pCurrent = pStartAddress;
	for (int i = 0; i < uiSize; i++, pCurrent++) {
		*pCurrent ^= KEY;
	}
#endif
}

static void encodeFvprintf(FILE* file, const char* format, ...) {
	char szText[4096];
	memset(szText, 0, 4096);
	va_list args;
	va_start(args, format); //一定要“...”之前的那个参数
	vsprintf(szText, format, args);
	va_end(args);
	int32_t iCount = strlen(szText);
	encode(szText, iCount);
	fwrite(szText, sizeof(char), iCount, file);
}

static void encodeFvprintfArgs(FILE* file, const char* format, va_list args) {
	char szText[4096];
	memset(szText, 0, 4096);
	vsprintf(szText, format, args);
	int32_t iCount = strlen(szText);
	encode(szText, iCount);
	fwrite(szText, sizeof(char), iCount, file);
}

static uint32_t getTimespan() {
	return time(NULL);
}

void outputMessage(LogLevel loglevel, const char* format, ...) {
	if (gLogLevel == off) {
		return;
	}
	char level_name[NAME_MAX] = "\0";
	switch (loglevel) {
	case trace:
		strcpy(level_name, "trace");
		break;
	case debug:
		strcpy(level_name, "debug");
		break;
	case info:
		strcpy(level_name, "info");
		break;
	case warn:
		strcpy(level_name, "warn");
		break;
	case error:
		strcpy(level_name, "error");
		break;
	case fatal:
		strcpy(level_name, "fatal");
		break;
	case off:
	default:
		return;
	}
	if (loglevel >= gLogLevel) {
#ifdef LOGTOFILEANDIO
		{
			FILE* pf = fopen(gLogPath, "a+");
			if (pf != NULL) {
				va_list args;
				va_start(args, format); //一定要“...”之前的那个参数
				encodeFvprintf(pf, "%d:%s:\t", getTimespan(), level_name);
				encodeFvprintfArgs(pf, format, args);
				va_end(args);
				fflush(pf);
				fclose(pf);
			}
		}
		{
			va_list args;
			va_start(args, format); //一定要“...”之前的那个参数
			printf("%d:%s:\t", getTimespan(), level_name);
			vprintf(format, args);
			va_end(args);
		}
#else
#ifdef OUTPUT_FILE
		{
			FILE* pf = fopen(gLogPath, "a+");
			if (pf != NULL) {
				va_list args;
				va_start(args, format); //一定要“...”之前的那个参数
				encodeFvprintf(pf, "%d:%s:\t", getTimespan(), level_name);
				encodeFvprintfArgs(pf, format, args);
				va_end(args);
				fflush(pf);
				fclose(pf);
			}
		}
#else
		{
			va_list args;
			va_start(args, format); //一定要“...”之前的那个参数
			printf("%d:%s:\t", getTimespan(), level_name);
			vprintf(format, args);
			va_end(args);
		}
#endif
#endif
	}
}

void outputMessageDebug(LogLevel loglevel, const char* filename, int32_t line, const char * function,
		const char* format, ...) {
	if (gLogLevel == off) {
		return;
	}
	char level_name[NAME_MAX] = "\0";
	switch (loglevel) {
	case trace:
		strcpy(level_name, "trace");
		break;
	case debug:
		strcpy(level_name, "debug");
		break;
	case info:
		strcpy(level_name, "info");
		break;
	case warn:
		strcpy(level_name, "warn");
		break;
	case error:
		strcpy(level_name, "error");
		break;
	case fatal:
		strcpy(level_name, "fatal");
		break;
	case off:
	default:
		return;
	}

	if (loglevel >= gLogLevel) {
#ifdef LOGTOFILEANDIO
		{
			FILE* pf = fopen(gLogPath, "a+");
			if (pf != NULL) {

				va_list args;
				va_start(args, format); //一定要“...”之前的那个参数
				if (loglevel <= debug) {
					encodeFvprintf(pf, "%d:%s:%s:%d:%s()\t", getTimespan(), level_name, filename, line, function);
					encodeFvprintfArgs(pf, format, args);
				} else {
					encodeFvprintfArgs(pf, format, args);
				}
				va_end(args);
				fflush(pf);
				fclose(pf);
			}
		}
		{
			va_list args;
			va_start(args, format); //一定要“...”之前的那个参数
			if (loglevel <= debug) {
				printf("%d:%s:%s:%d:%s()\t", getTimespan(), level_name, filename, line, function);
				vprintf(format, args);
			} else {
				vprintf(format, args);
			}
			va_end(args);
		}
#else
#ifdef OUTPUT_FILE
		{
			FILE* pf = fopen(gLogPath, "a+");
			if (pf != NULL) {

				va_list args;
				va_start(args, format); //一定要“...”之前的那个参数
				if (loglevel <= debug) {
					encodeFvprintf(pf, "%d:%s:%s:%d:%s()\t", getTimespan(), level_name, filename, line, function);
					encodeFvprintfArgs(pf, format, args);
				} else {
					encodeFvprintfArgs(pf, format, args);
				}
				va_end(args);
				fflush(pf);
				fclose(pf);
			}
		}
#else
		{
			va_list args;
			va_start(args, format); //一定要“...”之前的那个参数
			if (loglevel <= debug) {
				printf("%d:%s:%s:%d:%s()\t", getTimespan(), level_name, filename, line, function);
				vprintf(format, args);
			} else {
				vprintf(format, args);
			}
			va_end(args);
		}
#endif
#endif
	}
}

#ifdef OUTPUT_FILE
#undef OUTPUT_FILE
#endif
