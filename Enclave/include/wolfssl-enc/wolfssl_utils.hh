#ifndef __WOLFSSL_UTILS_HH__
#define __WOLFSSL_UTILS_HH__

#include <wolfssl/ssl.h>

#include <sgx_thread.h>

/* Max number of WOLFSSL_CTX's */
#ifndef MAX_WOLFSSL_CTX
#define MAX_WOLFSSL_CTX 2
#endif

/* Max number of WOLFSSL's */
#ifndef MAX_WOLFSSL
#define MAX_WOLFSSL 128
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

#endif
