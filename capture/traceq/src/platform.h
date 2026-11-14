//
// Created by lidongyooo on 2026/2/5.
//

#ifndef TRACEQ_PLATFORM_H
#define TRACEQ_PLATFORM_H

#ifdef __APPLE__
    #define PLATFORM_IOS 1
    #define PLATFORM_ANDROID 0
    #define PLATFORM_NAME "iOS"
#else
    #define PLATFORM_IOS 0
    #define PLATFORM_ANDROID 1
    #define PLATFORM_NAME "Android"
#endif

#endif //TRACEQ_PLATFORM_H