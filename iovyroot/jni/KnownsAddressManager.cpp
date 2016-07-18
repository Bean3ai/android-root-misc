/*
 * KnowsAddressManager.cpp
 *
 *  Created on: Mar 10, 2015
 *      Author: mbp
 */

#include <KnownsAddressManager.h>
#include <linux/limits.h>
#include "ReportManager.h"
#include "strings.h"

KnownsAddressManager::KnownsAddressManager() {
	array = darray_init();
	this->shellCode = -1;
	this->initialized = false;

	memset(this->reader, 0, NAME_MAX);
	memset(this->writer, 0, NAME_MAX);
}

KnownsAddressManager::~KnownsAddressManager() {
	darray_free(array);
}

KnownsAddressManager* KnownsAddressManager::manager = NULL;
KnownsAddressManager* const KnownsAddressManager::instance() {
	if (KnownsAddressManager::manager != NULL) {
		return KnownsAddressManager::manager;
	}
	KnownsAddressManager::manager = new KnownsAddressManager();
	return KnownsAddressManager::manager;
}

void KnownsAddressManager::destory() {
	INFO("销毁已知地址管理器 .\n");
	if (KnownsAddressManager::manager != NULL) {
		delete KnownsAddressManager::manager;
	}
	KnownsAddressManager::manager = NULL;
}

uint32_t KnownsAddressManager::getAddress(const char *name) {

	if (!this->initialized) {
		return 0;
	}

	int length = this->array->last;
	for (int i = 0; i <= length; i++) {
		SymbolAddressPair* pair = (SymbolAddressPair*) darray_get(this->array, i);
		if (strcasecmp(name, pair->symbol) == 0) {
			// TRACE("找到符号 %s, 地址: %08x\n", name, pair->offset);
			return pair->offset;
		}
	}

	// TRACE("未找到符号 %s\n", name);

	return 0;
}

static int32_t findstr(const char* input, char c) {

	int32_t result;
	char * current = index(input, (int) c);
	if (current == NULL) {
		return -1;
	}

	result = (long) current - (long) input;

	return result;
}

static int32_t getShellCodeByString(const char *input) {

	if (strstr(input, "\"sc\":") != NULL) {
		int32_t index = findstr(input, ':');
		int32_t begin = index + 2;
		int32_t length = strlen(input);
		int32_t end = length - 1;
		length = end - begin;
		char buffer[NAME_MAX] = { 0 };
		strncpy(buffer, input + begin, length);
		int32_t number = strtol(buffer, NULL, 16);
		return number;
	}
	return -1;
}

bool KnownsAddressManager::getReaderAndWriterByString(const char *input) {

	int32_t index = findstr(input, ':');
	int32_t begin = index + 2;
	int32_t length = strlen(input);
	int32_t end = length - 1;
	length = end - begin;
	char buffer[NAME_MAX] = { 0 };
	strncpy(buffer, input + begin, length);

	if (strstr(input, "\"reader\":") != NULL) {
		strcpy(this->reader, buffer);
	} else if (strstr(input, "\"writer\":") != NULL) {
		strcpy(this->writer, buffer);
	} else {
		return false;
	}

	return true;
}

static SymbolAddressPair* getAddressByString(const char *input) {
	char symbol[NAME_MAX] = { 0 };
	char number[NAME_MAX] = { 0 };
	uint32_t address = 0;

	int32_t middle = findstr(input, ':');
	if (middle <= 0) {
		return NULL;
	}

	int32_t begin = 1;
	int32_t end = middle - 1;
	int32_t length = end - begin;

	strncpy(symbol, input + begin, length);

	begin = middle + 2;
	end = strlen(input) - 1;
	length = end - begin;

	strncpy(number, input + begin, length);

	address = strtoul(number, NULL, 16);

	SymbolAddressPair *pair = (SymbolAddressPair*) malloc(sizeof(SymbolAddressPair));
	pair->offset = address;
	strcpy(pair->symbol, symbol);

	return pair;
}

void paramTrim(char *commandParam, char *commandParamTrim) {
	if (*commandParam == '{') {
		int32_t begin = 1;
		int32_t length = strlen(commandParam) - 1;
		strncpy(commandParamTrim, commandParam + begin, length);
	}
}

void KnownsAddressManager::initialize(char *commandParam) {

	uint32_t length;
	char *current;
	char commandParamTrim[NAME_MAX] = {0};

	INFO("开始初始化已知地址管理器 .\n");

	if (this->initialized) {
		return;
	}

	if (commandParam == NULL || strlen(commandParam) == 0) {
		return;
	}

	paramTrim(commandParam, commandParamTrim);

	current = strtok(commandParamTrim, ",");

	while (current != NULL) {
		int result = getShellCodeByString(current);
		if (result < 0) {
			if (!this->getReaderAndWriterByString(current)) {
				SymbolAddressPair *pair = getAddressByString(current);
				if (pair != NULL) {
					darray_push(this->array, (void*) pair);
				}
			}
		} else {
			this->shellCode = result;
		}
		current = strtok(NULL, ",");
	}

	this->initialized = true;

	ReportManager *rManager = ReportManager::instance();
	rManager->setEnable(true);

	INFO("结束初始化已知地址管理器, 成功 .\n");

	TRACE("地址个数 : %d .\n", this->array->last);
}
