LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := main3_dazen
LOCAL_SRC_FILES :=  main.cpp becomeRoot.cpp redress.cpp

LOCAL_LDFLAGS += -static

include $(BUILD_EXECUTABLE)
