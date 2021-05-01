#include "ssl.h"

#include "Enclave_t.h"

#include <sgx_thread.h>
#include <wolfssl/ssl.h>
#include "utils.h"

#if defined(XMALLOC_USER) || defined(XMALLOC_OVERRIDE)
#warning verfication of heap hint pointers needed when overriding default malloc/free
#endif

#if defined(WOLFSSL_STATIC_MEMORY)
/* check on heap hint when used, aborts if pointer is not in Enclave.
 * In the default case where wolfSSL_Malloc is used the heap hint pointer is not
 * used.*/

static void checkHeapHint(WOLFSSL_CTX *ctx, WOLFSSL *ssl) {
  WOLFSSL_HEAP_HINT *heap;
  if ((heap = (WOLFSSL_HEAP_HINT *)wolfSSL_CTX_GetHeap(ctx, ssl)) != NULL) {
    if (sgx_is_within_enclave(heap, sizeof(WOLFSSL_HEAP_HINT)) != 1)
      abort();
    if (sgx_is_within_enclave(heap->memory, sizeof(WOLFSSL_HEAP)) != 1)
      abort();
  }
}
#endif /* WOLFSSL_STATIC_MEMORY */

WOLFSSL_CTX *CTX_TABLE[MAX_WOLFSSL_CTX];
WOLFSSL *SSL_TABLE[MAX_WOLFSSL];

sgx_thread_mutex_t ctx_table_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t ssl_table_mutex = SGX_THREAD_MUTEX_INITIALIZER;

void enc_wolfSSL_Debugging_ON(void) { wolfSSL_Debugging_ON(); }

void enc_wolfSSL_Debugging_OFF(void) { wolfSSL_Debugging_OFF(); }

long AddCTX(WOLFSSL_CTX *ctx) {
  long i;

  sgx_thread_mutex_lock(&ctx_table_mutex);
  for (i = 0; i < MAX_WOLFSSL_CTX; i++) {
    if (CTX_TABLE[i] == NULL) {
      CTX_TABLE[i] = ctx;
      sgx_thread_mutex_unlock(&ctx_table_mutex);
      return i;
    }
  }
  sgx_thread_mutex_unlock(&ctx_table_mutex);
  return -1;
}

long AddSSL(WOLFSSL *ssl) {
  long i;
  sgx_thread_mutex_lock(&ssl_table_mutex);
  for (i = 0; i < MAX_WOLFSSL; i++) {
    if (SSL_TABLE[i] == NULL) {
      SSL_TABLE[i] = ssl;
      sgx_thread_mutex_unlock(&ssl_table_mutex);
      return i;
    }
  }
  sgx_thread_mutex_unlock(&ssl_table_mutex);
  return -1;
}

WOLFSSL_CTX *GetCTX(long id) {
  if (id >= MAX_WOLFSSL_CTX || id < 0)
    return NULL;
  return CTX_TABLE[id];
}

WOLFSSL *GetSSL(long id) {
  if (id >= MAX_WOLFSSL || id < 0)
    return NULL;
  return SSL_TABLE[id];
}

void RemoveCTX(long id) {
  if (id >= MAX_WOLFSSL_CTX || id < 0)
    return;
  wolfSSL_CTX_free(CTX_TABLE[id]);
  CTX_TABLE[id] = NULL;
}

void RemoveSSL(long id) {
  if (id >= MAX_WOLFSSL || id < 0)
    return;
  sgx_thread_mutex_lock(&ssl_table_mutex);
  wolfSSL_free(SSL_TABLE[id]);
  SSL_TABLE[id] = NULL;
  sgx_thread_mutex_unlock(&ssl_table_mutex);
}
int enc_wolfSSL_Init(void) { return wolfSSL_Init(); }

long enc_wolfSSL_new(long id) {
  WOLFSSL_CTX *ctx;
  WOLFSSL *ssl;
  long ret = -1;

  ctx = GetCTX(id);
  if (ctx == NULL) {
    return -1;
  }
  ssl = wolfSSL_new(ctx);
  if (ssl != NULL) {
    ret = AddSSL(ssl);
  }
  return ret;
}

int enc_wolfSSL_set_fd(long sslId, int fd) {
  WOLFSSL *ssl = GetSSL(sslId);
  if (ssl == NULL) {
    return -1;
  }
  return wolfSSL_set_fd(ssl, fd);
}

int enc_wolfSSL_connect(long sslId) {

  WOLFSSL *ssl = GetSSL(sslId);
  if (ssl == NULL) {
    return -1;
  }
  // const char *cipherList = "ECDHE-RSA-AES128-GCM-SHA256";
  // wolfSSL_set_cipher_list(ssl, cipherList);
  // wolfSSL_SetTmpDH(ssl, p, sizeof(p), g, sizeof(g));
  // printf("Calling wolfssl_connect\n");
  return wolfSSL_connect(ssl);
}

int enc_wolfSSL_write(long sslId, const void *in, int sz) {
  WOLFSSL *ssl = GetSSL(sslId);
  if (ssl == NULL) {
    return -1;
  }
  return wolfSSL_write(ssl, in, sz);
}

int enc_wolfSSL_get_error(long sslId, int ret) {
  WOLFSSL *ssl = GetSSL(sslId);
  if (ssl == NULL) {
    return -1;
  }
  return wolfSSL_get_error(ssl, ret);
}

int enc_wolfSSL_read(long sslId, void *data, int sz) {
  WOLFSSL *ssl = GetSSL(sslId);
  if (ssl == NULL) {
    return -1;
  }
  return wolfSSL_read(ssl, data, sz);
}

void enc_wolfSSL_free(long sslId) { RemoveSSL(sslId); }

void enc_wolfSSL_CTX_free(long id) { RemoveCTX(id); }

int enc_wolfSSL_Cleanup(void) {
  long id;

  /* free up all WOLFSSL's */
  for (id = 0; id < MAX_WOLFSSL; id++)
    RemoveSSL(id);

  /* free up all WOLFSSL_CTX's */
  for (id = 0; id < MAX_WOLFSSL_CTX; id++)
    RemoveCTX(id);
  return wolfSSL_Cleanup();
}

/* custom function */
long ecall_init_ctx_server(void) {
  long ret;
  WOLFSSL_CTX *ctx;

  ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
  if (ctx == NULL) {
    printf("[ENCLAVE][init_ctx_server] Failed to create new context!\n");
    return -1;
  }

  /* Load server certificates into WOLFSSL_CTX */
  ret = wolfSSL_CTX_use_certificate_buffer(ctx, server_cert_der_2048,
                                           sizeof_server_cert_der_2048,
                                           SSL_FILETYPE_ASN1);
  if (ret != SSL_SUCCESS) {
    printf("[ENCLAVE][init_ctx_server] wolfSSL_CTX_use_certificate_buffer "
           "failure\n");
    return -1;
  }

  /* Load server key into WOLFSSL_CTX */
  ret = wolfSSL_CTX_use_PrivateKey_buffer(
      ctx, server_key_der_2048, sizeof_server_key_der_2048, SSL_FILETYPE_ASN1);

  if (ret != SSL_SUCCESS) {
    printf("[ENCLAVE][init_ctx_server] wolfSSL_CTX_use_PrivateKey_buffer "
           "failure\n");
    return -1;
  }

  ret = AddCTX(ctx);
  return ret;
}

long ecall_init_ctx_client(void) {
  long ret;
  WOLFSSL_CTX *ctx;

  const char *cipherList = "ECDHE-RSA-AES128-GCM-SHA256";

  ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
  if (ctx == NULL) {
    printf("[ENCLAVE][init_ctx_client] Failed to create new context!\n");
    return -1;
  }

  ret = wolfSSL_CTX_set_cipher_list(ctx, cipherList);
  if (ret != SSL_SUCCESS) {
    printf("[ENCLAVE][init_ctx_client] wolfSSL_CTX_set_cipher_list failure\n");
    return -1;
  }

  wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

  ret = wolfSSL_CTX_use_certificate_chain_buffer_format(
      ctx, client_cert_der_2048, sizeof_client_cert_der_2048,
      SSL_FILETYPE_ASN1);
  if (ret != SSL_SUCCESS) {
    printf("[ENCLAVE][init_ctx_client] "
           "wolfSSL_CTX_use_certificate_chain_buffer_format failure\n");
    return -1;
  }

  ret = wolfSSL_CTX_use_PrivateKey_buffer(
      ctx, client_key_der_2048, sizeof_client_key_der_2048, SSL_FILETYPE_ASN1);
  if (ret != SSL_SUCCESS) {
    printf("[ENCLAVE][init_ctx_client] wolfSSL_CTX_use_PrivateKey_buffer "
           "failure\n");
    return -1;
  }

  ret = wolfSSL_CTX_load_verify_buffer(
      ctx, ca_cert_der_2048, sizeof_ca_cert_der_2048, SSL_FILETYPE_ASN1);
  if (ret != SSL_SUCCESS) {
    printf("[ENCLAVE][init_ctx_client] Error loading cert\n");
    return -1;
  }

  ret = AddCTX(ctx);
  return ret;
}
