#include "Enclave_t.h"
#include "certs_test.h"
#include "global_config.h"
#include "ssl.h"
#include "utils.h"
#include "wolfssl/ssl.h"
#include <cstring>
#include <iostream>
#include <map>
#include <string>
#include <tuple>
#include <utility>
// typedef struct did_map_entry {
//   // char eph_did[MAX_DID_SIZE];
//   std::string eph_did;
//   std::string did;
//   // char did[MAX_DID_SIZE];
//   WOLFSSL *ssl;
// } DIDMapEntry;

// std::map<std::string, DIDMapEntry> did_map;
std::map<std::string, std::pair<std::string, WOLFSSL *>> did_map;

sgx_thread_mutex_t did_map::m;
struct did_map map_did[MAX_MAP_SIZE];

uint8_t ecall_createNewORAM(uint32_t max_blocks, uint32_t data_size,
                            uint32_t stash_size, uint32_t recursion_data_size,
                            int8_t recursion_levels, uint8_t Z) {

#ifdef OBLIVIRA_CACHE_ENABLED
  sgx_status_t ocall_status;

  initialize_cache(max_blocks, data_size, stash_size, recursion_data_size,
                   recursion_levels, Z);
#endif
  return 0;
}

int respond_did(WOLFSSL *ssl, std::string buf) {
  buf = HTTP_RESPONSE + buf;
  return wolfSSL_write(ssl, buf.c_str(), buf.length());
}

void ecall_handle_did_req(long sslID, char *eph_did, size_t did_sz) {
  int ret, cached;
  size_t len;
  char buf[DATA_SIZE];
  std::string input, new_did_method, did, new_eph_did;

  WOLFSSL *ssl = GetSSL(sslID);
  if (ssl == NULL) {
    printf("[ENCLAVE][handle_did_req] GetSSL failure\n");
    return;
  }

  if ((ret = wolfSSL_read(ssl, buf, DATA_SIZE)) < 0) {
    printf("[ENCLAVE][handle_did_req] wolfSSL_read failure\n");
    return;
  }
  input = buf;

  // GET /1.0/identifiers/did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w
  // HTTP/1.1

  // 1.Must extract 'did:ion' + DID
  //   a. erase up to GET /1.0/identifiers/
  input.erase(0, 21);
  //   b. erase  HTTP/1.1 in the end
  input.erase(input.find(" HTTP/1.1"), input.npos);
  //   c. Separate method and identifier
  size_t pos = input.find(":");
  pos = input.find(":", pos + 1);

  new_did_method = input;
  did = input;

  new_did_method.erase(pos, new_did_method.npos);
  did.erase(0, pos + 1);

  // 2. generate EPH_DID for DID
  new_eph_did = gen_eph_did(did.length());
  // 3. put 'did:ion' on DID and EPH_DID
  did = new_did_method + ':' + did;
  new_eph_did = new_did_method + ':' + new_eph_did;

  // 4. Save DID, EPH_DID, ssl

  printf("[Enclave][handle_did_req] DID Method:\'%s\'\nDID    :\'%s\'\nEph "
         "DID:\'%s\'\n",
         new_did_method.c_str(), did.c_str(), new_eph_did.c_str());

  // DIDMapEntry new_entry;

  // Save to map
  // new_entry.ssl = ssl;
  // new_entry.did = did;
  // new_entry.eph_did = new_eph_did;

  auto pair = std::make_pair(did, ssl);
  did_map[new_eph_did] = pair;
  // strncpy(new_entry.did, did.c_str(), did_sz);
  // strncpy(new_entry.eph_did, new_eph_did.c_str(), did_sz);

  // did_map[new_eph_did] = new_entry;
  // printf("[Enclave] ssl: %ld\n", did_map[did].ssl);

  // Return
  strncpy(eph_did, new_eph_did.c_str(), did_sz);

#if defined(OBLIVIRA_CACHE_ENABLED)
  /* cache check */
  do {
    cached = cache_access(did.c_str(), buf, 'r'); // for synchronization
  } while (cached == -1);

  if (cached == 1) {
    if (respond_did(ssl, buf) < 0) {
      printf(
          "[Enclave] [ENCLAVE][handle_did_req] Write to requester failed!\n");
    }
    return;
  }
#endif
  return;

#if defined(OBLIVIRA_PRINT_LOG)
  // printf("[Enclave] %s -> %s\n", did.c_str(), eph_did);
#endif
}

// Input ssl connection to blockchain net
#define MAX_BC_REQ_SIZE 2048
#define MAX_DID_DOC_SIZE 4096
int ecall_handle_doc_fetch(long sslID, char *base_addr, size_t ba_sz,
                           char *eph_did, size_t ed_sz) {
  // DIDMapEntry entry;
  char req2bc[MAX_BC_REQ_SIZE];
  char did_doc[MAX_DID_DOC_SIZE];
  int i, count;
  char c;
  int requester_sock;

  printf("[Enclave] [doc_fetch] req_eph_did %s\n", eph_did);
  // 1. Convert eph_did to did
  auto entry = did_map[eph_did];
  printf("[Enclave] [doc_fetch] %s->%s\n", eph_did, entry.first.c_str());

  // 2. Send request to BC
  // TODO: use base address
  snprintf(req2bc, sizeof(req2bc),
           "GET /1.0/identifiers/%s "
           "HTTP/1.1\r\nHost:beta.discover.did.microsoft.com\r\nUser-Agent: "
           "curl/7.68.0\r\nAccept: */*\r\n\r\n",
           entry.first.c_str());

  WOLFSSL *ssl = GetSSL(sslID);
  if (ssl == NULL) {
    printf("[Enclave] [doc_fetch] invalid SSL\n");
    return -1;
  }

  auto ret = wolfSSL_connect(ssl);
  if (ret != SSL_SUCCESS) {
    printf("[Enclave] [doc_fetch] Failed connecting to BC server\n");
    return -1;
  }

  printf("[Enclave] [doc_fetch] Sending to BC server:\n%s", req2bc);
  ret = wolfSSL_write(ssl, req2bc, strlen(req2bc));
  if (ret < 0) {
    printf("[Enclave] [doc_fetch] Failed sending request to BC server\n");
    return -1;
  }

  // Blocking
  ret = wolfSSL_read(ssl, did_doc, MAX_DID_DOC_SIZE);
  if (ret < 0) {
    printf("[Enclave] [doc_fetch] Failed sending request to BC server\n");
    return -1;
  }
  printf("[Enclave] [doc_fetch] Received from BC server:\n%s", did_doc);

  ret = wolfSSL_write(entry.second, did_doc, MAX_DID_DOC_SIZE);
  if (ret < 0) {

    printf("[Enclave] [doc_fetch] Failed returning document to requester\n");
    return -1;
  }

  requester_sock = wolfSSL_get_fd(entry.second);
  wolfSSL_free(entry.second);

  return requester_sock;
  // 1. Convert Eph DID to DID
  // entry = did_map[req_eph_did];
  // printf("[Enclave] found entry: %s\n", entry.eph_did.c_str());

  // 2. Fetch DID Doc

  // wolfSSL_write(ssl, in, sz);

  // 4. Return Result to original requester
}
// void ecall_request_to_blockchain(long ctxID, int client_fd, long sslID,
//                                  const char *addr, const char *eph_did,
//                                  const char *query) {
//   int ret, cached;
//   std::string base_addr = "beta.discover.did.microsoft.com", doc = "",
//               url = "/1.0/identifiers/";
//   char did[MAX_DID_SIZE] =
//       "did:ion:EiD3DIbDgBCajj2zCkE48x74FKTV9_Dcu1u_imzZddDKfg";
//   char buf[DATA_SIZE];
//   WOLFSSL_CTX *ctx;
//   WOLFSSL *ssl;

//   if (get_dids(eph_did, did) < 0) {
//     printf("[Enclave] [ENCLAVE][request_to_blockchain] get did failure\n");
//     RemoveSSL(sslID);
//     return;
//   }

//   /* connect to blockchain */
//   ctx = GetCTX(ctxID);
//   if (ctx == NULL) {
//     printf("[Enclave] [ENCLAVE][request_to_blockchain] GetCTX failure\n");
//     RemoveSSL(sslID);
//     return;
//   }
//   ssl = wolfSSL_new(ctx);
//   if (ssl == NULL) {
//     printf("[Enclave] [ENCLAVE][request_to_blockchain] Create ssl
//     failure\n"); RemoveSSL(sslID); return;
//   }

//   if (wolfSSL_set_fd(ssl, client_fd) != SSL_SUCCESS) {
//     printf("[Enclave] [ENCLAVE][request_to_blockchain] wolfSSL_set_fd
//     failure\n"); RemoveSSL(sslID); wolfSSL_free(ssl); return;
//   }

//   if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
//     printf("[Enclave] [ENCLAVE][request_to_blockchain] wolfSSL_connect
//     failure\n"); RemoveSSL(sslID); wolfSSL_free(ssl); return;
//   }

//   /* generate did rquest */

// #if defined(OBLIVIRA_PRINT_LOG)
//   printf("[Enclave] Address: %s\n", addr);
//   printf("[Enclave] eph_did: %s -> did: %s\n", eph_did, did);
// #endif

//   if (strlen(addr) != 0) {
//     base_addr = addr;
//     size_t pos = base_addr.find("/");
//     size_t start_pos = pos + 2;

//     pos = base_addr.find("/", pos + 2);
//     url = base_addr.substr(pos);
//     base_addr = base_addr.substr(start_pos, pos - start_pos);
//   }

//   if (strlen(query) != 0) {
//     doc = query;
//   }

//   snprintf(buf, sizeof buf, GET_REQUEST, url.c_str(), did);
//   strncat(buf, "Host: ", strlen("Host: ") + 1);
//   strncat(buf, base_addr.c_str(), base_addr.length() + 1);
//   strncat(buf, GET_REQUEST_END, strlen(GET_REQUEST_END) + 1);
//   strncat(buf, GET_REQUEST_END, strlen(GET_REQUEST_END) + 1);
//   strncat(buf, doc.c_str(), doc.length() + 1);

//   /* request to blockchain */
//   if (wolfSSL_write(ssl, buf, strlen(buf)) < 0) {
//     printf("[Enclave] [ENCLAVE][request_to_blockchain] wolfSSL_write
//     failure\n"); RemoveSSL(sslID); wolfSSL_free(ssl); return;
//   }

//   buf[0] = 0;

//   if ((ret = wolfSSL_read(ssl, buf, DATA_SIZE)) < 0) {
//     printf("[Enclave] [ENCLAVE][request_to_blockchain] wolfSSL_read
//     failure\n"); RemoveSSL(sslID); wolfSSL_free(ssl); return;
//   }

//   buf[ret] = '\0';

//   wolfSSL_free(ssl);
//   /* write to requester */
//   ssl = GetSSL(sslID);

// #if defined(OBLIVIRA_PRINT_LOG)
//   printf("[Enclave] sslID: %ld\n", sslID);
//   printf("[Enclave] buf: %s\nlenght: %d\n", buf, strlen(buf));
// #endif

//   if (wolfSSL_write(ssl, buf, strlen(buf) + 1) < 0) {
//     printf("[Enclave] [ENCLAVE][request_to_blockchain] wolfSSL_write to
//     requester "
//            "failure\n");
//   }
//   RemoveSSL(sslID);

//   /* write to cache */
// #if defined(OBLIVIRA_CACHE_ENABLED)
//   do {
//     cached = cache_access(did, std::strchr((const char *)buf, '{'), 'w');
//   } while (cached == -1);
// #endif
// }
