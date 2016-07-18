/*
 * KnowsAddressManager.h
 *
 *  Created on: Mar 10, 2015
 *      Author: mbp
 */

#ifndef KNOWNSADDRESSMANAGER_H_
#define KNOWNSADDRESSMANAGER_H_

#include <linux/limits.h>
#include "common.h"
#include "DArray.h"

/*
 * 已知地址管理器
 *
 * 单件模式实现.
 */
class KnownsAddressManager {
public:

    virtual ~KnownsAddressManager();

    /*
     * 获取已知名称对应的地址.
     * parameter
     * name : 地址名称
     * return
     * 如果地址存在返回地址, 否则返回0.
     */
    uint32_t getAddress(const char *name);

    /*
     * 获取已知的shellcode.
     * return
     * 如果shellcode存在返回, 否则返回-1.
     */
    int32_t getShellCode() {
        if (this->initialized) {
            return this->shellCode;
        }

        return -1;
    }

    char *getReader() {
        return this->reader;
    }

    char *getWriter() {
        return this->writer;
    }


    /*
     * 初始化并拆分r命令行参数字符串.
     * parameter
     * commandParam : r命令行参数字符串
     *
     * remark
     */
    void initialize(char *commandParam);

    static void destory();

    static KnownsAddressManager *const instance();

private:
    bool getReaderAndWriterByString(const char *input);


private:
    KnownsAddressManager();

    static KnownsAddressManager *manager;
    DArray *array;
    int32_t shellCode;
    bool initialized;
    char reader[NAME_MAX];
    char writer[NAME_MAX];
};

#endif /* KNOWNSADDRESSMANAGER_H_ */
