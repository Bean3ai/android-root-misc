/*
 * MemoryBlock.cpp
 *
 *  Created on: Jul 23, 2014
 *      Author: wangzhiheng
 */

#include <helpers/MemoryBlock.h>

MemoryBlock::MemoryBlock(uint32_t size) {
	this->pStartAddress = malloc(size);
	memset(this->pStartAddress, 0, size);
	this->size = size;
}

MemoryBlock::~MemoryBlock() {
	if (this->pStartAddress != NULL) {
		free(this->pStartAddress);
		this->pStartAddress = NULL;
		this->size = 0;
	}
}

