#ifndef __ENCLAVE_UTILS_HH__
#define __ENCLAVE_UTILS_HH__

#include <string>

#include "sgx_trts.h"
#include "Enclave_t.h"

#include "PathORAM/PathORAM.hpp"
#include "PathORAM/DID_Map.hpp"
#include "global_config.h"

#define GET_REQUEST "GET %s%s HTTP/1.0\r\n"
#define GET_REQUEST_END "\r\n"
#define HTTP_RESPONSE "HTTP/1.0 200 OK\r\nContent-Type: application/json; Charset=utf-8\r\n\r\n"

std::string gen_eph_did(const size_t);
void initialize_cache(uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t recursion_data_size, int8_t recursion_levels, uint8_t Z);
int cache_access(const char *did, char *did_doc, char op_type);

#endif