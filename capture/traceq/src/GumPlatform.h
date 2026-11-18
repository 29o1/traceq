#pragma once
#include "platform.h"
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>

#if defined(TRACEQ_HOST_LAB)
#include "frida-gum.h"
#include <Foundation/Foundation.h>
#define LOGE(fmt, ...) fprintf(stderr,"[traceq] " fmt "\n",##__VA_ARGS__)
#elif PLATFORM_IOS
#include "../libs/FridaGum-IOS-17.8.3.h"
#include <Foundation/Foundation.h>
#define LOGE(fmt, ...) NSLog(@"[traceq] " @fmt,##__VA_ARGS__)
#else
#include "frida-gum.h"
#include <android/log.h>
#define LOGE(fmt, ...) __android_log_print(ANDROID_LOG_ERROR,"traceq",fmt,##__VA_ARGS__)
#endif
