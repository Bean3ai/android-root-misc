/*
 * IOHelper.cpp
 *
 *  Created on: Jul 24, 2014
 *      Author: wangzhiheng
 */

#include <helpers/IOHelper.h>

#include <dirent.h>
#include <sys/stat.h>
#include <linux/limits.h>

IOHelper::IOHelper() {
	// TODO Auto-generated constructor stub

}

IOHelper::~IOHelper() {
	// TODO Auto-generated destructor stub
}

bool IOHelper::isFile(const char* path) {
	struct stat st;
	int error = lstat(path, &st);
	return error >= 0 && S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode);
}

bool IOHelper::isFolder(const char* path) {
	struct stat st;
	int error = lstat(path, &st);
	return error >= 0 && S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode);
}

uint32_t IOHelper::getDeviceCount(const char* path) {
	DIR * pDir;
	struct dirent *pDirent;
	uint32_t count = 0;

	if ((pDir = opendir(path)) != NULL) {
		while ((pDirent = readdir(pDir)) != NULL) {
			if (strcmp(".", pDirent->d_name) == 0 || strcmp("..", pDirent->d_name) == 0) {
				continue;
			}
			char text[PATH_MAX] = "\0";
			strcpy(text, path);
			strcat(text, "/");
			strcat(text, pDirent->d_name);
			if (isFolder(text)) {
				count += getDeviceCount(text);
			} else if (!isFile(text)) {
				count++;
			}
		}
		closedir(pDir);
	}
	return count;
}

static void getSubDevices(const char* path, char* devices, uint32_t deviceCount, uint32_t& index) {
	DIR * pDir;
	struct dirent *pDirent;

	if ((pDir = opendir(path)) != NULL) {
		while ((pDirent = readdir(pDir)) != NULL) {
			if (strcmp(".", pDirent->d_name) == 0 || strcmp("..", pDirent->d_name) == 0) {
				continue;
			}
			char text[PATH_MAX] = "\0";
			strcpy(text, path);
			strcat(text, "/");
			strcat(text, pDirent->d_name);
			if (IOHelper::isFolder(text)) {
				getSubDevices(text, devices, deviceCount, index);
			} else if (!IOHelper::isFile(text)) {
				if (index < deviceCount) {
					char* current = (char*) ((unsigned long) devices + index * NAME_MAX);
					strncpy(current, text, NAME_MAX);
					index++;
				}
			}
		}
		closedir(pDir);
	}
}

MemoryBlock* IOHelper::getDevices(const char* path, uint32_t count) {
	uint32_t index = 0;
	if (count == 0) {
		return NULL;
	}
	MemoryBlock *pMemoryBlock = new MemoryBlock(count * NAME_MAX);
	char* devices = (char*) pMemoryBlock->startAddress();
	getSubDevices(path, devices, count, index);
	return pMemoryBlock;
}

bool IOHelper::createFolder(const char* path, mode_t mode) {
	int errorCode = mkdir(path, mode);
	return errorCode == 0;
}
