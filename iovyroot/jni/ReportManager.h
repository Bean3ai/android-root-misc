/*
 * ReportManager.h
 *
 *  Created on: Mar 13, 2015
 *      Author: joncey
 */

#ifndef REPORTMANAGER_H_
#define REPORTMANAGER_H_

#include <linux/limits.h>
#include "DArray.h"
#include "common.h"

class ReportManager {
public:

	virtual ~ReportManager();

	void setShellCode(int32_t index) {
		this->shellCode = index;
	}

	void setReader(char *reader) {
		if(reader == NULL || strlen(reader) == 0) {
			return;
		}

		strcpy(this->reader, reader);
	}

	void setWriter(char *writer) {
		if(writer == NULL || strlen(writer) == 0) {
			return;
		}

		strcpy(this->writer, writer);
	}

	void setAddress(char *name, uint32_t address);

	void getResult(char *result);

	void setEnable(bool enable) {
		this->enable = enable;
	}

	bool getEnable() {
		return this->enable;
	}

	static void destory();

	static ReportManager* const instance();
private:
	ReportManager();
	int32_t shellCode;
	char reader[NAME_MAX];
	char writer[NAME_MAX];
	DArray *array;
	static ReportManager* manager;
	bool enable;
};

#endif /* REPORTMANAGER_H_ */
