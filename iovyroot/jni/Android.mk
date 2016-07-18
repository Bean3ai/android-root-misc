LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := rsa  
LOCAL_SRC_FILES := lib/librsa.a   
include $(PREBUILT_STATIC_LIBRARY) 

include $(CLEAR_VARS)

#LOCAL_ARM_MODE := arm
LOCAL_CFLAGS := -DNDEBUG -Wall
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include/

LOCAL_MODULE    := iovyroot
LOCAL_SRC_FILES := getroot.c \
		   ksyms.c \
                   flex_array.c \
                   sid.c \
		   shellcode.cpp \
		   main.cpp \
		   common.cpp \
		   DArray.c \
		   ReportManager.cpp \
		   helpers/MemoryBlock.cpp \
		   helpers/IOHelper.cpp \
		   KnownsAddressManager.cpp \
		   util/CheckFile.cpp 

LOCAL_STATIC_LIBRARIES := rsa

#include $(BUILD_EXECUTABLE)

include $(BUILD_SHARED_LIBRARY)
