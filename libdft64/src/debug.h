
#ifndef __DEBUG_H__
#define __DEBUG_H__

// Colored Logs
#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"


// #define DEBUG_INFO 1

#ifdef DEBUG_INFO
// #define DEBUG_PRINTF printf
#define LOGD(...)                                                              \
  do {                                                                         \
    printf(__VA_ARGS__);                                                       \
  } while (0)
#else
#define LOGD(...)
#endif

#define LOGE(...)                                                              \
  do {                                                                         \
    fprintf(stderr, __VA_ARGS__);                                              \
  } while (0)
#else

#endif