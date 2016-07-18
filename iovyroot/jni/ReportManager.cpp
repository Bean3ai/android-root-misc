/*
 * ReportManager.cpp
 *
 *  Created on: Mar 13, 2015
 *      Author: joncey
 */

#include <ReportManager.h>
#include "common.h"

ReportManager::ReportManager() {
	this->shellCode = -1;
	this->enable = true;
	memset(reader, 0, NAME_MAX);
	memset(writer, 0, NAME_MAX);
	this->array = darray_init();
}

ReportManager::~ReportManager() {
	darray_free(array);
}


ReportManager* ReportManager::manager = NULL;
ReportManager* const ReportManager::instance() {
	if (ReportManager::manager != NULL) {
		return ReportManager::manager;
	}
	ReportManager::manager = new ReportManager();
	return ReportManager::manager;
}

void ReportManager::destory() {
	INFO("销毁结果管理器 .\n");
	if (ReportManager::manager != NULL) {
		delete ReportManager::manager;
	}
	ReportManager::manager = NULL;
}


void ReportManager::setAddress(char* name, uint32_t address) {

	if(name == NULL || strlen(name) == 0 || address == 0) {
		return;
	}

	SymbolAddressPair *pair = (SymbolAddressPair*)malloc(sizeof(SymbolAddressPair));
	memset(pair, 0, sizeof(SymbolAddressPair));
	pair->offset = address;
	strcpy(pair->symbol, name);

	darray_push(this->array, (void*) pair);
}

void ReportManager::getResult(char *result) {
	char text[256] = {0};

	strcat(result, "RAS#");

	if(this->shellCode != -1) {
		sprintf(text, "\"sc\":\"%d\"|", this->shellCode);
		strcat(result, text);
	}

	if(strlen(this->reader) != 0) {
		sprintf(text, "\"reader\":\"%s\"|", this->reader);
		strcat(result, text);
	}

	if(strlen(this->writer) != 0) {
		sprintf(text, "\"writer\":\"%s\"|", this->writer);
		strcat(result, text);
	}

	int length = this->array->last;
	for (int i = 0; i <= length; i++) {
		SymbolAddressPair* pair = (SymbolAddressPair*) darray_get(this->array, i);
		sprintf(text, "\"%s\":\"%08x\"|", pair->symbol, pair->offset);
		strcat(result, text);
	}

	strcat(result, "#");
}
