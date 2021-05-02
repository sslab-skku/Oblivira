#ifndef __OBLIVIRA_DEBUG_H__
#define __OBLIVIRA_DEBUG_H__

#define COLOR_GREEN "\x1B[32m"
#define COLOR_NORMAL "\x1B[0m"
#define COLOR_RED "\x1B[31m"

/* #define OBV_USER_DEBUG 1 */
/* #define OBV_USER_DEBUG_VERBOSE 1 */

#define obv_print(fmt, args...)                                                \
  do {                                                                         \
    printf("%s[App][%s] " fmt, COLOR_NORMAL, __func__, ##args);                \
  } while (0)

#ifdef OBV_USER_DEBUG
#define obv_debug(fmt, args...)                                                \
  do {                                                                         \
    printf("%s[App][%s] " fmt, COLOR_NORMAL, __func__, ##args);                \
  } while (0)
#else
#define obv_debug(fmt, args...) (void)0
#endif

#define obv_err(fmt, args...)                                                  \
  do {                                                                         \
    printf("%s[App][%s]*ERROR*%s: " fmt, COLOR_RED, __func__, COLOR_NORMAL, ##args); \
  } while (0)

#endif
