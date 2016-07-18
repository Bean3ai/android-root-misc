#include "CheckFile.h"
#include "util/Md5.h"
#include "util/RsaCrypt.h"
#include "util/Util.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include "common.h"

static uint32_t fileSize(const char* filePath) {
	struct stat buf = { 0 };
	if (filePath && !stat(filePath, &buf)) {
		return (uint32_t) buf.st_size;
	}
	return 0;
}

#define CHECK_LEN 128

static char* calculateFileMd5(const char* filePath) {
	struct TKMD5Context md5c = { 0 };
	unsigned char ss[16] = { 0 };
	FILE* fp;
	uint32_t size = fileSize(filePath);
	uint32_t len = 0;
	unsigned char buff[1024];
	if (size == 0) {
		return 0;
	}
	fp = fopen(filePath, "r");
	if (fp == 0) {
		return 0;
	}
	TKMD5Init(&md5c);
	size -= CHECK_LEN;
	while (size > 0) {
		uint32_t readLen = (size > sizeof(buff)) ? (sizeof(buff)) : size;
		uint32_t currentLen = fread(buff, 1, readLen, fp);
		if (currentLen != readLen) {
			return 0;
		}
		TKMD5Update(&md5c, buff, currentLen);
		size -= currentLen;
	}
	fclose(fp);
	TKMD5Final(ss, &md5c);

	return convertHexToHexchars(ss, 16);
}

static bool fillCheckBuffer(const char* filePath, char* checkBuffer) {
	FILE* fp = fopen(filePath, "r");
	uint32_t size = fileSize(filePath);
	if (size == 0) {
		return false;
	}
	if (fp == 0) {
		return false;
	}
	fseek(fp, size - CHECK_LEN, 0);
	fread(checkBuffer, 1, CHECK_LEN, fp);
	fclose(fp);
	return true;
}

bool checkFile(const char* filePath) {
#ifdef NOCHECKFILE
	return true;
#else
	bool ret = false;
	char* fileMd5 = 0;
	char checkBuffer[CHECK_LEN] = { 0 };
	char decodeMd5[17] = { 0 };
	int len[1] = { 16 };
	unsigned char* checkBufferHexChars = 0;
	fileMd5 = calculateFileMd5(filePath);
	if (fileMd5 == 0) {
		INFO("不能计算出文件 %s 的hash.\n", filePath);
		goto EXIT;
	}
	INFO("验证文件路径是 %s(%s)\n", filePath, fileMd5);
	if (fillCheckBuffer(filePath, checkBuffer) == false) {
		INFO("不能读出文件 %s 的hash.\n", filePath);
		goto EXIT;
	}
	checkBufferHexChars = (unsigned char*) convertHexToHexchars((unsigned char const*) checkBuffer, CHECK_LEN);
	if (checkBufferHexChars == 0) {
		INFO("转化16进制为字符串失败.\n");
		goto EXIT;
	}
	rsaDecrpytedContent((const unsigned char *) checkBufferHexChars, (unsigned char *) decodeMd5, len);
	if (strcmp((const char*) fileMd5, (const char*) decodeMd5) != 0) {
		INFO("不匹配, 通过文件本身计算出来的hash: %s\n通过计算出来hash: %s\n", fileMd5, decodeMd5);
	} else {
		ret = true;
	}
	EXIT: if (fileMd5) {
		free(fileMd5);
	}
	if (checkBufferHexChars) {
		free(checkBufferHexChars);
	}
	INFO("验证文件 %s 的结果 %d.\n", filePath, ret);
	return ret;
#endif
}
