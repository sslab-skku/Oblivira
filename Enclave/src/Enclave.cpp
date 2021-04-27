#include <string>
#include <cstring>

#include "utils/utils.hh"
#include "wolfssl-enc/wolfssl_utils.hh"
#include "wolfssl-enc/testenclave.hh"

#include "Enclave_t.h"

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

    ret = wolfSSL_read(ssl, buf, DATA_SIZE);
    if (ret < 0)
    {
        printf("[ENCLAVE][handle_did_req] wolfSSL_read failure\n");
        return;
    }

    did = buf;
    ret = did.find_first_of(' ', 0) + 1;
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
        if (respond_did(ssl, buf) != SSL_SUCCESS)
        {
            printf("[ENCLAVE][handle_did_req] Write to requester failed!\n");
        }
        return;
    }
#endif

    /* return */
    std::strncpy(eph_did, did.substr(0, len + 1).c_str(), len + 1);
    std::strncat(eph_did, gen_eph_did(did.length() - len).c_str(), did.length() - len);
}

int respond_did(WOLFSSL *ssl, std::string buf)
{
    return wolfSSL_write(ssl, buf.c_str(), buf.length());
}

uint8_t ecall_createNewORAM(uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t recursion_data_size, int8_t recursion_levels, uint8_t Z)
{
    sgx_status_t ocall_status;

    initialize_cache(max_blocks, data_size, stash_size, recursion_data_size, recursion_levels, Z);
    return 0;
}