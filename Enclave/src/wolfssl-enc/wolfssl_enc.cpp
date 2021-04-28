#include "wolfssl-enc/certs_test.h"
#include "wolfssl-enc/wolfssl_utils.hh"
#include "wolfssl-enc/testenclave.hh"

#include "Enclave_t.h"

#if defined(XMALLOC_USER) || defined(XMALLOC_OVERRIDE)
#warning verfication of heap hint pointers needed when overriding default malloc/free
#endif


#if defined(WOLFSSL_STATIC_MEMORY)
/* check on heap hint when used, aborts if pointer is not in Enclave.
 * In the default case where wolfSSL_Malloc is used the heap hint pointer is not
 * used.*/
static void checkHeapHint(WOLFSSL_CTX *ctx, WOLFSSL *ssl)
{
  WOLFSSL_HEAP_HINT *heap;
  if ((heap = (WOLFSSL_HEAP_HINT *)wolfSSL_CTX_GetHeap(ctx, ssl)) != NULL)
  {
    if (sgx_is_within_enclave(heap, sizeof(WOLFSSL_HEAP_HINT)) != 1)
      abort();
    if (sgx_is_within_enclave(heap->memory, sizeof(WOLFSSL_HEAP)) != 1)
      abort();
  }
}
#endif /* WOLFSSL_STATIC_MEMORY */

/* int wc_test(void* args) */
/* { */
/* #ifdef HAVE_WOLFSSL_TEST */
/* 	return wolfcrypt_test(args); */
/* #else */
/*     /\* wolfSSL test not compiled in! *\/ */
/*     return -1; */
/* #endif /\* HAVE_WOLFSSL_TEST *\/ */
/* } */

/* int wc_benchmark_test(void* args) */
/* { */

/* #ifdef HAVE_WOLFSSL_BENCHMARK */
/*     return benchmark_test(args); */
/* #else */
/*     /\* wolfSSL benchmark not compiled in! *\/ */
/*     return -1; */
/* #endif /\* HAVE_WOLFSSL_BENCHMARK *\/ */
/* } */

void enc_wolfSSL_Debugging_ON(void) { wolfSSL_Debugging_ON(); }

void enc_wolfSSL_Debugging_OFF(void) { wolfSSL_Debugging_OFF(); }

int enc_wolfSSL_Init(void) { return wolfSSL_Init(); }

// #define WOLFTLSv12_CLIENT 1
// #define WOLFTLSv12_SERVER 2

// long enc_wolfTLSv1_2_client_method(void)
// {
//   return WOLFTLSv12_CLIENT;
// }

// long enc_wolfTLSv1_2_server_method(void) { return WOLFTLSv12_SERVER; }

/* returns method releated to id */
// static WOLFSSL_METHOD *GetMethod(long id)
// {
//   switch (id)
//   {
//   case WOLFTLSv12_CLIENT:
//     return wolfTLSv1_2_client_method();
//   case WOLFTLSv12_SERVER:
//     return wolfTLSv1_2_server_method();
//   default:
//     return NULL;
//   }
// }

// long enc_wolfSSL_CTX_new(long method)
// {
//   WOLFSSL_CTX *ctx;
//   long id = -1;

//   ctx = wolfSSL_CTX_new(GetMethod(method));
//   if (ctx != NULL)
//   {
//     id = AddCTX(ctx);
//   }

//   return id;
// }

// int enc_wolfSSL_CTX_use_certificate_chain_buffer_format(
//     long id, const unsigned char *buf, long sz, int type) {
//   WOLFSSL_CTX *ctx = GetCTX(id);
//   if (ctx == NULL) {
//     return -1;
//   }
//   return wolfSSL_CTX_use_certificate_chain_buffer_format(ctx, buf, sz, type);
// }

// int enc_wolfSSL_CTX_use_certificate_buffer(long id, const unsigned char *buf,
//                                            long sz, int type) {
//   WOLFSSL_CTX *ctx = GetCTX(id);
//   if (ctx == NULL) {
//     return -1;
//   }
//   return wolfSSL_CTX_use_certificate_buffer(ctx, buf, sz, type);
// }

// int enc_wolfSSL_CTX_use_PrivateKey_buffer(long id, const unsigned char *buf,
//                                           long sz, int type) {
//   int ret;
//   WOLFSSL_CTX *ctx = GetCTX(id);
//   if (ctx == NULL) {
//     return -1;
//   }
//   return wolfSSL_CTX_use_PrivateKey_buffer(ctx, buf, sz, type);
// }

// int enc_wolfSSL_CTX_load_verify_buffer(long id, const unsigned char *in,
//                                        long sz, int format) {
//   WOLFSSL_CTX *ctx = GetCTX(id);
//   if (ctx == NULL) {
//     return -1;
//   }
//   wolfSSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL);
//   return wolfSSL_CTX_load_verify_buffer(ctx, in, sz, format);
// }

// int enc_wolfSSL_CTX_set_cipher_list(long id, const char *list) {
//   WOLFSSL_CTX *ctx = GetCTX(id);
//   if (ctx == NULL) {
//     return -1;
//   }
//   return wolfSSL_CTX_set_cipher_list(ctx, list);
// }

long enc_wolfSSL_new(long id)
{
  WOLFSSL_CTX *ctx;
  WOLFSSL *ssl;
  long ret = -1;

  ctx = GetCTX(id);
  if (ctx == NULL)
  {
    return -1;
  }
  ssl = wolfSSL_new(ctx);
  if (ssl != NULL)
  {
    ret = AddSSL(ssl);
  }
  return ret;
}

int enc_wolfSSL_set_fd(long sslId, int fd)
{
  WOLFSSL *ssl = GetSSL(sslId);
  if (ssl == NULL)
  {
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

int enc_wolfSSL_get_error(long sslId, int ret)
{
  WOLFSSL *ssl = GetSSL(sslId);
  if (ssl == NULL)
  {
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

int enc_wolfSSL_Cleanup(void)
{
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
long ecall_init_ctx_server(void)
{
  long ret;
  WOLFSSL_CTX *ctx;

  ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
  if (ctx == NULL)
  {
    printf("[ENCLAVE][init_ctx_server] Failed to create new context!\n");
    return -1;
  }

  /* Load server certificates into WOLFSSL_CTX */
  ret = wolfSSL_CTX_use_certificate_buffer(ctx, server_cert_der_2048,
                                           sizeof_server_cert_der_2048, SSL_FILETYPE_ASN1);
  if (ret != SSL_SUCCESS)
  {
    printf("[ENCLAVE][init_ctx_server] wolfSSL_CTX_use_certificate_buffer failure\n");
    return -1;
  }

  /* Load server key into WOLFSSL_CTX */
  ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, server_key_der_2048,
                                          sizeof_server_key_der_2048, SSL_FILETYPE_ASN1);

  if (ret != SSL_SUCCESS)
  {
    printf("[ENCLAVE][init_ctx_server] wolfSSL_CTX_use_PrivateKey_buffer failure\n");
    return -1;
  }

  ret = AddCTX(ctx);
  return ret;
}

long ecall_init_ctx_client(void)
{
  long ret;
  WOLFSSL_CTX *ctx;

  const char *cipherList = "ECDHE-RSA-AES128-GCM-SHA256";

  ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
  if (ctx == NULL)
  {
    printf("[ENCLAVE][init_ctx_client] Failed to create new context!\n");
    return -1;
  }

  ret = wolfSSL_CTX_set_cipher_list(ctx, cipherList);
  if (ret != SSL_SUCCESS)
  {
    printf("[ENCLAVE][init_ctx_client] wolfSSL_CTX_set_cipher_list failure\n");
    return -1;
  }

  wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

  ret = wolfSSL_CTX_use_certificate_chain_buffer_format(ctx, client_cert_der_2048,
                                                        sizeof_client_cert_der_2048, SSL_FILETYPE_ASN1);
  if (ret != SSL_SUCCESS)
  {
    printf("[ENCLAVE][init_ctx_client] wolfSSL_CTX_use_certificate_chain_buffer_format failure\n");
    return -1;
  }

  ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, client_key_der_2048,
                                          sizeof_client_key_der_2048, SSL_FILETYPE_ASN1);
  if (ret != SSL_SUCCESS)
  {
    printf("[ENCLAVE][init_ctx_client] wolfSSL_CTX_use_PrivateKey_buffer failure\n");
    return -1;
  }

  ret = wolfSSL_CTX_load_verify_buffer(ctx, ca_cert_der_2048,
                                       sizeof_ca_cert_der_2048, SSL_FILETYPE_ASN1);
  if (ret != SSL_SUCCESS)
  {
    printf("[ENCLAVE][init_ctx_client] Error loading cert\n");
    return -1;
  }

  ret = AddCTX(ctx);
  return ret;
}
