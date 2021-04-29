#include "wolfssl-enc/wolfssl_utils.hh"

WOLFSSL_CTX *CTX_TABLE[MAX_WOLFSSL_CTX];
WOLFSSL *SSL_TABLE[MAX_WOLFSSL];

sgx_thread_mutex_t ctx_table_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t ssl_table_mutex = SGX_THREAD_MUTEX_INITIALIZER;

long AddCTX(WOLFSSL_CTX *ctx)
{
    long i;

    sgx_thread_mutex_lock(&ctx_table_mutex);
    for (i = 0; i < MAX_WOLFSSL_CTX; i++)
    {
        if (CTX_TABLE[i] == NULL)
        {
            CTX_TABLE[i] = ctx;
            sgx_thread_mutex_unlock(&ctx_table_mutex);
            return i;
        }
    }
    sgx_thread_mutex_unlock(&ctx_table_mutex);
    return -1;
}

long AddSSL(WOLFSSL *ssl)
{
    long i;
    sgx_thread_mutex_lock(&ssl_table_mutex);
    for (i = 0; i < MAX_WOLFSSL; i++)
    {
        if (SSL_TABLE[i] == NULL)
        {
            SSL_TABLE[i] = ssl;
            sgx_thread_mutex_unlock(&ssl_table_mutex);
            return i;
        }
    }
    sgx_thread_mutex_unlock(&ssl_table_mutex);
    return -1;
}

WOLFSSL_CTX *GetCTX(long id)
{
    if (id >= MAX_WOLFSSL_CTX || id < 0)
        return NULL;
    return CTX_TABLE[id];
}

WOLFSSL *GetSSL(long id)
{
    if (id >= MAX_WOLFSSL || id < 0)
        return NULL;
    return SSL_TABLE[id];
}

void RemoveCTX(long id)
{
    if (id >= MAX_WOLFSSL_CTX || id < 0)
        return;
    wolfSSL_CTX_free(CTX_TABLE[id]);
    CTX_TABLE[id] = NULL;
}

void RemoveSSL(long id)
{
    if (id >= MAX_WOLFSSL || id < 0)
        return;
    sgx_thread_mutex_lock(&ssl_table_mutex);
    wolfSSL_free(SSL_TABLE[id]);
    SSL_TABLE[id] = NULL;
    sgx_thread_mutex_unlock(&ssl_table_mutex);
}