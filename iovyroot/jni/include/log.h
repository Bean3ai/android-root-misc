

#ifndef M_LOG_H
#define M_LOG_H

#include <android/log.h>

//#define DEBUG
#define M_LOG_TAG "vsnake-jni"


#ifdef DEBUG
	#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, M_LOG_TAG, __VA_ARGS__);printf(__VA_ARGS__); printf("\n"); fflush(stdout)
	#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, M_LOG_TAG, __VA_ARGS__);printf(__VA_ARGS__); printf("\n"); fflush(stdout)
	#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, M_LOG_TAG, __VA_ARGS__);printf(__VA_ARGS__); printf("\n"); fflush(stdout)
	#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, M_LOG_TAG, __VA_ARGS__);printf(__VA_ARGS__); printf("\n"); fflush(stdout)
#else
	#define LOGI(...) printf(__VA_ARGS__);printf("\n")
	#define LOGD(...) printf(__VA_ARGS__);printf("\n")
	#define LOGW(...) printf(__VA_ARGS__);printf("\n")
	#define LOGE(...) printf(__VA_ARGS__);printf("\n")

#endif /*--#ifdef DEBUG--*/

#endif /*--ifndef M_LOG_H--*/ 
