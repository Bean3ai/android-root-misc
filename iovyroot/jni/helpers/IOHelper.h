/*
 * IOHelper.h
 *
 *  Created on: Jul 24, 2014
 *      Author: wangzhiheng
 */

#ifndef IOHELPER_H_
#define IOHELPER_H_

#include <sys/stat.h>
#include "common.h"
#include "helpers/MemoryBlock.h"

class IOHelper {
public:
	IOHelper();
	virtual ~IOHelper();

	static bool isFile(const char* path);
	static bool isFolder(const char* path);
	static bool createFolder(const char* path, mode_t mode);
	static uint32_t getDeviceCount(const char* path);
	static MemoryBlock* getDevices(const char* path, uint32_t count);

};

#endif /* IOHELPER_H_ */
