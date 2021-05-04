#include "Enclave_t.h"

#include "certs_test.h"
#include "global_config.h"
#include "ssl.h"
#include "utils.h"
#include "wolfssl/ssl.h"

#include <map>
#include <string>
#include <tuple>

// Input ssl connection to blockchain net
#define MAX_BC_REQ_SIZE 2048
#define MAX_DID_DOC_SIZE 4096

std::map<std::string, std::pair<std::string, long>> did_map;

uint8_t ecall_createNewORAM(uint32_t max_blocks, uint32_t data_size,
                            uint32_t stash_size, uint32_t recursion_data_size,
                            int8_t recursion_levels, uint8_t Z)
{

#ifdef OBLIVIRA_CACHE_ENABLED
  sgx_status_t ocall_status;

  initialize_cache(max_blocks, data_size, stash_size, recursion_data_size,
                   recursion_levels, Z);
#endif
  return 0;
}

void ecall_handle_did_req(long sslID, char *eph_did, size_t did_sz)
{
  int ret, cached = -1;
  size_t len;
  char buf[DATA_SIZE];
  std::string input, new_did_method, did, new_eph_did;

  WOLFSSL *ssl = GetSSL(sslID);
  if (ssl == NULL)
  {
    obvenc_err("[ENCLAVE][handle_did_req] GetSSL failure\n");
    return;
  }

  if ((ret = wolfSSL_read(ssl, buf, DATA_SIZE)) < 0)
  {
    obvenc_err("[ENCLAVE][handle_did_req] wolfSSL_read failure\n");
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

#if defined(OBLIVIRA_CACHE_ENABLED)
  /* cache check */
  obvenc_debug("[ENCLAVE][handle_did_req] checking cache...\n");
  do
  {
    cached = cache_access(did.c_str(), buf, 'r'); // for synchronization
  } while (cached == -1);

  if (cached == 1)
  {
    obvenc_debug("[ENCLAVE][handle_did_req] cache hit!\n");
    obvenc_debug("[ENCLAVE][handle_did_req] cached document:\n%s\n", buf);
    if (wolfSSL_write(ssl, buf, MAX_DID_DOC_SIZE) != 0)
    {
      obvenc_err("[Enclave] [ENCLAVE][handle_did_req] Write to requester failed!\n");
    }
    RemoveSSL(sslID);
    return;
  }
#endif

  new_did_method.erase(pos, new_did_method.npos);
  did.erase(0, pos + 1);

  // 2. generate EPH_DID for DID
  new_eph_did = gen_eph_did(did.length());
  // 3. put 'did:ion' on DID and EPH_DID
  did = new_did_method + ':' + did;
  new_eph_did = new_did_method + ':' + new_eph_did;

  // 4. Save DID, EPH_DID, ssl

  obvenc_debug("[Enclave][handle_did_req] DID Method:\'%s\'\nDID    :\'%s\'\nEph "
               "DID:\'%s\'\n",
               new_did_method.c_str(), did.c_str(), new_eph_did.c_str());

  // Save to map
  auto pair = std::make_pair(did, sslID);
  did_map[new_eph_did] = pair;

  // Return
  strncpy(eph_did, new_eph_did.c_str(), did_sz);
  return;
}

int ecall_handle_doc_fetch(long sslID, char *base_addr, size_t ba_sz,
                           char *eph_did, size_t ed_sz)
{
  // DIDMapEntry entry;
  char req2bc[MAX_BC_REQ_SIZE] = { '\0' };
  char did_doc[MAX_DID_DOC_SIZE];
  int i, count;
  char c;
  int requester_sock;

  obvenc_debug("[Enclave] [doc_fetch] req_eph_did %s\n", eph_did);
  // 1. Convert eph_did to did
  auto entry = did_map[eph_did];
  obvenc_debug("[Enclave] [doc_fetch] %s->%s\n", eph_did, entry.first.c_str());

  // 2. Send request to BC
  // TODO: use base address
  snprintf(req2bc, sizeof(req2bc),
           "GET /1.0/identifiers/%s "
           "HTTP/1.1\r\n"
           "Host:beta.discover.did.microsoft.com\r\n"
           "Connection: keep-alive\r\n"
           "\r\n",
           entry.first.c_str());

  WOLFSSL *ssl = GetSSL(sslID);
  if (ssl == NULL)
  {
    obvenc_debug("[Enclave] [doc_fetch] invalid SSL\n");
    return -1;
  }

  auto ret = wolfSSL_connect(ssl);
  if (ret != SSL_SUCCESS)
  {
    obvenc_err("[Enclave] [doc_fetch] Failed connecting to BC server\n");
    return -1;
  }

  obvenc_debug("[Enclave] [doc_fetch] Sending to BC server:\n%s", req2bc);
  ret = wolfSSL_write(ssl, req2bc, strlen(req2bc));
  if (ret == 0)
  {
    obvenc_err("[Enclave] [doc_fetch] Failed sending request to BC server\n");
    return -1;
  }

  // Blocking
  ret = wolfSSL_read(ssl, did_doc, MAX_DID_DOC_SIZE);
  if (ret == 0)
  {
    obvenc_err("[Enclave] [doc_fetch] Failed sending request to BC server\n");
    return -1;
  }
  did_doc[ret] = '\0';
  obvenc_debug("[Enclave] [doc_fetch] Received from BC server:\n%s", did_doc);
  ssl = GetSSL(entry.second);

#if defined(OBLIVIRA_CACHE_ENABLED)
  /* cache check */
  int cached;
  obvenc_debug("[ENCLAVE][doc_fetch] Writing to ORAM cache...\n");
  obvenc_debug("[ENCLAVE][doc_fetch] DID: %s\n", entry.first.c_str());
  obvenc_debug("[ENCLAVE][doc_fetch] document:\n%s\n", did_doc);
  do
  {
    cached = cache_access(entry.first.c_str(), did_doc, 'w'); // for synchronization
  } while (cached == -1);
#endif

  ret = wolfSSL_write(ssl, did_doc, MAX_DID_DOC_SIZE);
  if (ret == 0)
  {
    obvenc_err("[Enclave] [doc_fetch] Failed returning document to requester\n");
    return -1;
  }

  requester_sock = wolfSSL_get_fd(ssl);
  RemoveSSL(entry.second);

  did_map.erase(eph_did);

  return requester_sock;
}
