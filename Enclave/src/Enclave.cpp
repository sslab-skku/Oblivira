#include <string>
#include <cstring>
#include <map>

#include "utils/utils.hh"
#include "wolfssl-enc/wolfssl_utils.hh"
#include "wolfssl-enc/testenclave.hh"

#include "Enclave_t.h"

std::map<std::string, std::string> dids;

uint8_t ecall_createNewORAM(uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t recursion_data_size, int8_t recursion_levels, uint8_t Z)
{
    sgx_status_t ocall_status;

    initialize_cache(max_blocks, data_size, stash_size, recursion_data_size, recursion_levels, Z);
    return 0;
}

int respond_did(WOLFSSL *ssl, std::string buf)
{
    buf = HTTP_RESPONSE + buf;
    return wolfSSL_write(ssl, buf.c_str(), buf.length());
}

void ecall_handle_did_req(long sslID, char *eph_did, size_t sz)
{
    int ret, cached;
    size_t len;
    char buf[DATA_SIZE];
    std::string did;

    WOLFSSL *ssl = GetSSL(sslID);

    if (ssl == NULL)
    {
        printf("[ENCLAVE][handle_did_req] GetSSL failure\n");
        return;
    }

    if ((ret = wolfSSL_read(ssl, buf, DATA_SIZE)) < 0)
    {
        printf("[ENCLAVE][handle_did_req] wolfSSL_read failure\n");
        return;
    }

    buf[ret] = '\0';
#if defined(OBLIVIRA_PRINT_LOG)
    printf("%s\n", buf);
#endif
    did = buf;
    ret = did.find_first_of('/', 0) + 1;
    ret = did.find_first_of('/', ret) + 1;
    ret = did.find_first_of('/', ret) + 1;
    did = did.substr(ret, did.find_first_of(' ', ret) - ret);
    len = did.find(":");
    len = did.find(":", len + 1);

#if defined(OBLIVIRA_CACHE_ENABLED)
    /* cache check */
    do
    {
        cached = cache_access(did.c_str(), buf, 'r'); // for synchronization
    } while (cached == -1);

    if (cached == 1)
    {
        if (respond_did(ssl, buf) < 0)
        {
            printf("[ENCLAVE][handle_did_req] Write to requester failed!\n");
        }
        return;
    }
#endif

    /* return */
    std::strncpy(eph_did, did.substr(0, len + 1).c_str(), len + 1);
    std::strncat(eph_did, gen_eph_did(did.length() - len).c_str(), did.length() - len);

    std::string tmp = eph_did;
    dids[tmp] = did;

#if defined(OBLIVIRA_PRINT_LOG)
    printf("%s -> %s\n", dids[tmp].c_str(), eph_did);
#endif
}

void ecall_request_to_blockchain(long ctxID, int client_fd, long sslID,
                                 const char *addr, const char *eph_did, const char *query)
{
    int ret;
    std::string did = "did:ion:EiD3DIbDgBCajj2zCkE48x74FKTV9_Dcu1u_imzZddDKfg";
    std::string base_addr = "beta.discover.did.microsoft.com", doc = "", url = "/1.0/identifiers/";
    std::string tmp = eph_did;
    char buf[DATA_SIZE];
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;

    /* connect to blockchain */
    ctx = GetCTX(ctxID);
    if (ctx == NULL)
    {
        printf("[ENCLAVE][request_to_blockchain] GetCTX failure\n");
        RemoveSSL(sslID);
        return;
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL)
    {
        printf("[ENCLAVE][request_to_blockchain] Create ssl failure\n");
        RemoveSSL(sslID);
        return;
    }

    if (wolfSSL_set_fd(ssl, client_fd) != SSL_SUCCESS)
    {
        printf("[ENCLAVE][request_to_blockchain] wolfSSL_set_fd failure\n");
        RemoveSSL(sslID);
        wolfSSL_free(ssl);
        return;
    }

    if (wolfSSL_connect(ssl) != SSL_SUCCESS)
    {
        printf("[ENCLAVE][request_to_blockchain] wolfSSL_connect failure\n");
        RemoveSSL(sslID);
        wolfSSL_free(ssl);
        return;
    }

    /* generate did rquest */
    did = dids[tmp];

#if defined(OBLIVIRA_PRINT_LOG)
    printf("Address: %s\n", addr);
    printf("%s -> %s\n", eph_did, dids[tmp].c_str());
#endif

    if (strlen(addr) != 0)
    {
        base_addr = addr;
        size_t pos = base_addr.find("/");
        size_t start_pos = pos + 2;

        pos = base_addr.find("/", pos + 2);
        url = base_addr.substr(pos);
        base_addr = base_addr.substr(start_pos, pos - start_pos);
    }

    if (strlen(query) != 0)
    {
        doc = query;
    }

    snprintf(buf, sizeof buf, GET_REQUEST, url.c_str(), did.c_str());
    strncat(buf, "Host: ", strlen("Host: ") + 1);
    strncat(buf, base_addr.c_str(), base_addr.length() + 1);
    strncat(buf, GET_REQUEST_END, strlen(GET_REQUEST_END) + 1);
    strncat(buf, GET_REQUEST_END, strlen(GET_REQUEST_END) + 1);
    strncat(buf, doc.c_str(), doc.length() + 1);

#if defined(OBLIVIRA_PRINT_LOG)
    printf("%s", buf);
#endif

    /* request to blockchain */
    if (wolfSSL_write(ssl, buf, strlen(buf)) < 0)
    {
        printf("[ENCLAVE][request_to_blockchain] wolfSSL_write failure\n");
        RemoveSSL(sslID);
        wolfSSL_free(ssl);
        return;
    }

    buf[0] = 0;

    if ((ret = wolfSSL_read(ssl, buf, DATA_SIZE)) < 0)
    {
        printf("[ENCLAVE][request_to_blockchain] wolfSSL_read failure\n");
        RemoveSSL(sslID);
        wolfSSL_free(ssl);
        return;
    }

    buf[ret] = '\0';

#if defined(OBLIVIRA_PRINT_LOG)
    printf("%s", buf);
#endif

    wolfSSL_free(ssl);

    /* write to requester */
    ssl = GetSSL(sslID);
    if (respond_did(ssl, std::strchr((const char *)buf, '{')) < 0)
    {
        printf("[ENCLAVE][request_to_blockchain] respond to did failure!\n");
    }

    RemoveSSL(sslID);

    /* write to cache */
#if defined(OBLIVIRA_CACHE_ENABLED)
    do
    {
        cached = cache_access(dids[tmp], std::strchr((const char *)buf, '{'), 'w');
    } while (cached == -1);
#endif
}