#ifndef __WOLFSSL_UTILS_HH__
#define __WOLFSSL_UTILS_HH__

#include <wolfssl/ssl.h>
#include "certs_test.h"
#include <sgx_thread.h>

/* Max number of WOLFSSL_CTX's */
#ifndef MAX_WOLFSSL_CTX
#define MAX_WOLFSSL_CTX 2
#endif

/* Max number of WOLFSSL's */
#ifndef MAX_WOLFSSL
#define MAX_WOLFSSL 1024
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* returns ID assigned on success and -1 on failure
 * @TODO mutex for threaded use cases */
long AddCTX(WOLFSSL_CTX *);

/* returns ID assigned on success and -1 on failure
 * @TODO mutex for threaded use cases */
long AddSSL(WOLFSSL *);

/* returns the WOLFSSL_CTX pointer on success and NULL on failure */
WOLFSSL_CTX *GetCTX(long);

/* returns the WOLFSSL pointer on success and NULL on failure */
WOLFSSL *GetSSL(long);

/* Free's and removes the WOLFSSL_CTX associated with 'id' */
void RemoveCTX(long);

/* Free's and removes the WOLFSSL associated with 'id' */
void RemoveSSL(long);

int enc_wolfSSL_write(long sslId, const void *in, int sz);

int enc_wolfSSL_get_error(long sslId, int ret);

int enc_wolfSSL_read(long sslId, void *data, int sz);

void enc_wolfSSL_free(long sslId);

void enc_wolfSSL_CTX_free(long id);

int enc_wolfSSL_Cleanup(void);

long ecall_init_ctx_server(void);

long ecall_init_ctx_client(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
