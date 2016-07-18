/*
 * MemoryBlock.h
 *
 *  Created on: Jul 23, 2014
 *      Author: wangzhiheng
 */

#ifndef MEMORYBLOCK_H_
#define MEMORYBLOCK_H_

#include "common.h"

class MemoryBlock {
public:
	MemoryBlock(uint32_t size);
	virtual ~MemoryBlock();

	void* startAddress() const {
		return this->pStartAddress;
	}

	uint32_t length() const {
		return this->size;
	}

private:
	void* pStartAddress;
	uint32_t size;

};

#endif /* MEMORYBLOCK_H_ */
