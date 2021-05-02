#ifndef __ENCLAVE_UTILS_HH__
#define __ENCLAVE_UTILS_HH__

#include <string>

#include "Enclave_t.h"
#include <sgx_thread.h>
#include <sgx_trts.h>

#include "global_config.h"

#ifdef OBLIVIRA_CACHE_ENABLED
#include "PathORAM/DID_Map.hpp"
#include "PathORAM/PathORAM.hpp"
#include "global_config.h"
#endif

#define GET_REQUEST "GET %s%s HTTP/1.0\r\n"
#define GET_REQUEST_END "\r\n"
#define HTTP_RESPONSE                                                          \
  "HTTP/1.0 200 OK\r\nContent-Type: application/json; Charset=utf-8\r\n\r\n"
#define MAX_MAP_SIZE 128

#if defined(__cplusplus)
extern "C" {
#endif


#define COLOR_GREEN "\x1B[32m"
#define COLOR_NORMAL "\x1B[0m"
#define COLOR_RED "\x1B[31m"


  
// #define OBV_USER_DEBUG 1

#ifdef OBV_USER_DEBUG
#define obvenc_debug(fmt, args...)                                                \
  do {                                                                         \
    printf("%s[App][%s] " fmt, COLOR_NORMAL, __func__, ##args);                \
  } while (0)
#else
#define obvenc_debug(fmt, args...) (void)0
#endif



#define obvenc_err(fmt, args...)                                                  \
  do {                                                                         \
    printf("%s[App][%s]*ERROR*%s: " fmt, COLOR_RED, __func__, COLOR_NORMAL,##args);	\
  } while (0)




  
void printf(const char *fmt, ...);
int sprintf(char *buf, const char *fmt, ...);
double current_time(void);
int puts(const char *str);
char *getenv(char *name);
int fflush(void *stream);

int LowResTimer(void);
size_t recv(int sockfd, void *buf, size_t len, int flags);
size_t send(int sockfd, const void *buf, size_t len, int flags);

std::string gen_eph_did( size_t);
#ifdef OBLIVIRA_CACHE_ENABLED
void initialize_cache(uint32_t max_blocks, uint32_t data_size,
                      uint32_t stash_size, uint32_t recursion_data_size,
                      int8_t recursion_levels, uint8_t Z);
int cache_access(const char *did, char *did_doc, char op_type);
#endif

struct did_map {
  char eph_did[MAX_DID_SIZE];
  char did[MAX_DID_SIZE];
  bool is_used;
  static sgx_thread_mutex_t m;
};

extern struct did_map map_did[MAX_MAP_SIZE];

int get_dids(const char *, char *);
int set_dids(const char *, const char *);
int rm_dids(const char *);

#if defined(__cplusplus)
}
#endif

#endif
