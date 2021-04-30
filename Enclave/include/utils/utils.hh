#ifndef __ENCLAVE_UTILS_HH__
#define __ENCLAVE_UTILS_HH__

#include <string>

#include <sgx_trts.h>
#include <sgx_thread.h>
#include "Enclave_t.h"

#include "global_config.h"

#ifdef OBLIVIRA_CACHE_ENABLED
#include "PathORAM/PathORAM.hpp"
#include "PathORAM/DID_Map.hpp"
#include "global_config.h"
#endif

#define GET_REQUEST "GET %s%s HTTP/1.0\r\n"
#define GET_REQUEST_END "\r\n"
#define HTTP_RESPONSE "HTTP/1.0 200 OK\r\nContent-Type: application/json; Charset=utf-8\r\n\r\n"
#define MAX_MAP_SIZE 128

std::string gen_eph_did(const size_t);
#ifdef OBLIVIRA_CACHE_ENABLED
void initialize_cache(uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t recursion_data_size, int8_t recursion_levels, uint8_t Z);
int cache_access(const char *did, char *did_doc, char op_type);
#endif

struct did_map
{
    char eph_did[MAX_DID_SIZE];
    char did[MAX_DID_SIZE];
    bool is_used;
    static sgx_thread_mutex_t m;
};

extern struct did_map map_did[MAX_MAP_SIZE];

int get_dids(const char *, char *);
int set_dids(const char *, const char *);
int rm_dids(const char *);

#endif