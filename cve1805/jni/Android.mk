LOCAL_PATH := $(call my-dir)
######################test##########################
include $(CLEAR_VARS)

LOCAL_SRC_FILES := test.c
LOCAL_MODULE := test

LOCAL_CFLAGS += -pie -fPIE
LOCAL_LDFLAGS += -pie -fPIE

include $(BUILD_EXECUTABLE)
######################关闭selinux##########################
include $(CLEAR_VARS)

LOCAL_SRC_FILES := test2.c
LOCAL_MODULE := test2

LOCAL_CFLAGS += -pie -fPIE
LOCAL_LDFLAGS += -pie -fPIE


include $(BUILD_EXECUTABLE)

######################root##########################
include $(CLEAR_VARS)

LOCAL_SRC_FILES := main.c poc.c exploit.c callbackfunc.c ksyms.c
LOCAL_MODULE := main

#LOCAL_LDFLAGS := -static
LOCAL_CFLAGS += -pie -fPIE
LOCAL_LDFLAGS += -pie -fPIE

include $(BUILD_EXECUTABLE)
