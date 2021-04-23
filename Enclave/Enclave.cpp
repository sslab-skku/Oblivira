/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdarg.h>
#include <stdio.h> /* vsnprintf */



#include "Enclave.h"
#include "Enclave_t.h" /* print_string */

#define ADD_ENTROPY_SIZE 32

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...) {
  char buf[BUFSIZ] = {'\0'};
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, BUFSIZ, fmt, ap);
  va_end(ap);
  uprint(buf);
}

void hello() {
  
  
}
// typedef void CRYPTO_RWLOCK;

// struct evp_pkey_st {
//     int type;
//     int save_type;
//     int references;
//     const EVP_PKEY_ASN1_METHOD *ameth;
//     ENGINE *engine;
//     union {
//         char *ptr;
// # ifndef OPENSSL_NO_RSA
//         struct rsa_st *rsa;     /* RSA */
// # endif
// # ifndef OPENSSL_NO_DSA
//         struct dsa_st *dsa;     /* DSA */
// # endif
// # ifndef OPENSSL_NO_DH
//         struct dh_st *dh;       /* DH */
// # endif
// # ifndef OPENSSL_NO_EC
//         struct ec_key_st *ec;   /* ECC */
// # endif
//     } pkey;
//     int save_parameters;
//     STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
//     CRYPTO_RWLOCK *lock;
// } /* EVP_PKEY */ ;

// void rsa_key_gen()
// {
// 	BIGNUM *bn = BN_new();
// 	if (bn == NULL) {
// 		printf("BN_new failure: %ld\n", ERR_get_error());
// 	    return;
// 	}
// 	int ret = BN_set_word(bn, RSA_F4);
//     if (!ret) {
//        	printf("BN_set_word failure\n");
// 	    return;
// 	}

// 	RSA *keypair = RSA_new();
// 	if (keypair == NULL) {
// 		printf("RSA_new failure: %ld\n", ERR_get_error());
// 	    return;
// 	}
// 	ret = RSA_generate_key_ex(keypair, 4096, bn, NULL);
// 	if (!ret) {
//         printf("RSA_generate_key_ex failure: %ld\n", ERR_get_error());
// 	    return;
// 	}

// 	EVP_PKEY *evp_pkey = EVP_PKEY_new();
// 	if (evp_pkey == NULL) {
// 		printf("EVP_PKEY_new failure: %ld\n", ERR_get_error());
// 		return;
// 	}
// 	EVP_PKEY_assign_RSA(evp_pkey, keypair);

// 	// public key - string
// 	int len = i2d_PublicKey(evp_pkey, NULL);
// 	unsigned char *buf = (unsigned char *) malloc (len + 1);
// 	unsigned char *tbuf = buf;
// 	i2d_PublicKey(evp_pkey, &tbuf);

// 	// print public key
// 	printf ("{\"public\":\"");
// 	int i;
// 	for (i = 0; i < len; i++) {
// 	    printf("%02x", (unsigned char) buf[i]);
// 	}
// 	printf("\"}\n");

// 	free(buf);

// 	// private key - string
// 	len = i2d_PrivateKey(evp_pkey, NULL);
// 	buf = (unsigned char *) malloc (len + 1);
// 	tbuf = buf;
// 	i2d_PrivateKey(evp_pkey, &tbuf);

// 	// print private key
// 	printf ("{\"private\":\"");
// 	for (i = 0; i < len; i++) {
// 	    printf("%02x", (unsigned char) buf[i]);
// 	}
// 	printf("\"}\n");

// 	free(buf);

// 	BN_free(bn);

// 	EVP_PKEY_free(evp_pkey);

// 	if (evp_pkey->pkey.ptr != NULL) {
// 	  RSA_free(keypair);
// 	}
// }

// void ec_key_gen()
// {
// 	unsigned char entropy_buf[ADD_ENTROPY_SIZE] = {0};

// 	RAND_add(entropy_buf, sizeof(entropy_buf), ADD_ENTROPY_SIZE);
// 	RAND_seed(entropy_buf, sizeof(entropy_buf));

// 	EC_KEY * ec = NULL;
//     int eccgroup;
//     eccgroup = OBJ_txt2nid("secp384r1");
//     ec = EC_KEY_new_by_curve_name(eccgroup);
//     if (ec == NULL) {
//     	printf("EC_KEY_new_by_curve_name failure: %ld\n", ERR_get_error());
// 	    return;
//     }

// 	EC_KEY_set_asn1_flag(ec, OPENSSL_EC_NAMED_CURVE);

// 	int ret = EC_KEY_generate_key(ec);
// 	if (!ret) {
//         printf("EC_KEY_generate_key failure\n");
// 	    return;
// 	}

// 	EVP_PKEY *ec_pkey = EVP_PKEY_new();
// 	if (ec_pkey == NULL) {
// 		printf("EVP_PKEY_new failure: %ld\n", ERR_get_error());
// 		return;
// 	}
// 	EVP_PKEY_assign_EC_KEY(ec_pkey, ec);

// 	// public key - string
// 	int len = i2d_PublicKey(ec_pkey, NULL);
// 	unsigned char *buf = (unsigned char *) malloc (len + 1);
// 	unsigned char *tbuf = buf;
// 	i2d_PublicKey(ec_pkey, &tbuf);

// 	// print public key
// 	printf ("{\"public\":\"");
// 	int i;
// 	for (i = 0; i < len; i++) {
// 	    printf("%02x", (unsigned char) buf[i]);
// 	}
// 	printf("\"}\n");

// 	free(buf);

// 	// private key - string
// 	len = i2d_PrivateKey(ec_pkey, NULL);
// 	buf = (unsigned char *) malloc (len + 1);
// 	tbuf = buf;
// 	i2d_PrivateKey(ec_pkey, &tbuf);

// 	// print private key
// 	printf ("{\"private\":\"");
// 	for (i = 0; i < len; i++) {
// 	    printf("%02x", (unsigned char) buf[i]);
// 	}
// 	printf("\"}\n");

// 	free(buf);

// 	EVP_PKEY_free(ec_pkey);
// 	if (ec_pkey->pkey.ptr != NULL) {
// 	  EC_KEY_free(ec);
// 	}
// }

// int vprintf_cb(Stream_t stream, const char * fmt, va_list arg)
// {
// 	char buf[BUFSIZ] = {'\0'};

// 	int res = vsnprintf(buf, BUFSIZ, fmt, arg);
// 	if (res >=0) {
// 		sgx_status_t sgx_ret = uprint((const char *) buf);
// 		TEST_CHECK(sgx_ret);
// 	}
// 	return res;
// }

// extern "C" int CRYPTO_set_mem_functions(
//         void *(*m)(size_t, const char *, int),
//         void *(*r)(void *, size_t, const char *, int),
//         void (*f)(void *, const char *, int));
// void* priv_malloc(size_t size, const char *file, int line)
// {
// 	void* addr = malloc(size);

// 	printf("[malloc:%s:%d] size: %d, addr: %p\n", file, line, size, addr);

// 	return addr;
// }
// void* priv_realloc(void* old_addr, size_t new_size, const char *file, int
// line)
// {
// 	void* new_addr = realloc(old_addr, new_size);

// 	printf("[realloc:%s:%d] old_addr: %p, new_size: %d, new_addr: %p\n",
// file, line, old_addr, new_size, new_addr);

// 	return new_addr;
// }
// void priv_free(void* addr, const char *file, int line)
// {
// 	printf("[free:%s:%d] addr: %p\n", file, line, addr);

// 	free(addr);
// }

// void t_sgxssl_call_apis()
// {
//     int ret = 0;

//     printf("Start tests\n");

//     SGXSSLSetPrintToStdoutStderrCB(vprintf_cb);

//     //CRYPTO_set_mem_functions(priv_malloc, priv_realloc, priv_free);

//     // Initialize SGXSSL crypto
//     OPENSSL_init_crypto(0, NULL);

//     rsa_key_gen();
//     printf("test rsa_key_gen completed\n");

//     ec_key_gen();
// 	printf("test ec_key_gen completed\n");

//     ret = rsa_test();
//     if (ret != 0)
//     {
//     	printf("test rsa_test returned error %d\n", ret);
//     	exit(ret);
//     }
// 	printf("test rsa_test completed\n");

// 	ret = ec_test();
// 	if (ret != 0)
//     {
//     	printf("test ec_test returned error %d\n", ret);
//     	exit(ret);
//     }
// 	printf("test ec_test completed\n");

// 	ret = ecdh_test();
// 	if (ret != 0)
//     {
//     	printf("test ecdh_test returned error %d\n", ret);
//     	exit(ret);
//     }
// 	printf("test ecdh_test completed\n");

// 	ret = ecdsa_test();
// 	if (ret != 0)
//     {
//     	printf("test ecdsar_test returned error %d\n", ret);
//     	exit(ret);
//     }
// 	printf("test ecdsa_test completed\n");

// 	ret = bn_test();
// 	if (ret != 0)
//     {
//     	printf("test bn_test returned error %d\n", ret);
//     	exit(ret);
//     }
// 	printf("test bn_test completed\n");

// 	ret = dh_test();
// 	if (ret != 0)
//     {
//     	printf("test dh_test returned error %d\n", ret);
//     	exit(ret);
//     }
// 	printf("test dh_test completed\n");

// 	ret = sha256_test();
// 	if (ret != 0)
//     {
//     	printf("test sha256_test returned error %d\n", ret);
//     	exit(ret);
//     }
// 	printf("test sha256_test completed\n");

// 	ret = sha1_test();
// 	if (ret != 0)
//     {
//     	printf("test sha1_test returned error %d\n", ret);
//     	exit(ret);
//     }
// 	printf("test sha1_test completed\n");

// 	ret = threads_test();
// 	if (ret != 0)
//     {
//     	printf("test threads_test returned error %d\n", ret);
//     	exit(ret);
//     }
// 	printf("test threads_test completed\n");

// 	ret = threads_test();
// 	if (ret != 0)
//     {
//     	printf("test threads_test returned error %d\n", ret);
//     	exit(ret);
//     }
// 	printf("test threads_test completed\n");

// }


// static SSL_CTX *create_context() {
//   const SSL_METHOD *method;
//   SSL_CTX *ctx;

//   method = TLSv1_2_method();

//   ctx = SSL_CTX_new(method);
//   if (!ctx) {
//     printf("Unable to create SSL context");
//     exit(EXIT_FAILURE);
//   }
//   return ctx;
// }

// static EVP_PKEY *generatePrivateKey() {
//   EVP_PKEY *pkey = NULL;
//   EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
//   EVP_PKEY_keygen_init(pctx);
//   EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
//   EVP_PKEY_keygen(pctx, &pkey);
//   return pkey;
// }

// static X509 *generateCertificate(EVP_PKEY *pkey) {
//   X509 *x509 = X509_new();
//   X509_set_version(x509, 2);
//   ASN1_INTEGER_set(X509_get_serialNumber(x509), 0);
//   X509_gmtime_adj(X509_get_notBefore(x509), 0);
//   X509_gmtime_adj(X509_get_notAfter(x509), (long)60 * 60 * 24 * 365);
//   X509_set_pubkey(x509, pkey);

//   X509_NAME *name = X509_get_subject_name(x509);
//   X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
//                              (const unsigned char *)"US", -1, -1, 0);
//   X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
//                              (const unsigned char *)"YourCN", -1, -1, 0);
//   X509_set_issuer_name(x509, name);
//   X509_sign(x509, pkey, EVP_md5());
//   return x509;
// }

// static void configure_context(SSL_CTX *ctx)
// {
//     EVP_PKEY *pkey = generatePrivateKey();
// 	X509 *x509 = generateCertificate(pkey);

// 	SSL_CTX_use_certificate(ctx, x509);
// 	SSL_CTX_set_default_passwd_cb(ctx, password_cb);
// 	SSL_CTX_use_PrivateKey(ctx, pkey);

// 	RSA *rsa=RSA_generate_key(512, RSA_F4, NULL, NULL);
// 	SSL_CTX_set_tmp_rsa(ctx, rsa);
// 	RSA_free(rsa);

// 	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
// }

// static int create_socket_server(int port)
// {
//     int s, optval = 1;
//     struct sockaddr_in addr;

//     addr.sin_family = AF_INET;
//     addr.sin_port = htons(port);
//     addr.sin_addr.s_addr = htonl(INADDR_ANY);

//     s = socket(AF_INET, SOCK_STREAM, 0);
//     if (s < 0) {
//     	printf("sgx_socket");
// 		exit(EXIT_FAILURE);
//     }
//     if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
//     sizeof(int)) < 0) {
// 		printf("sgx_setsockopt");
// 		exit(EXIT_FAILURE);
//     }
//     if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
//     	printf("sgx_bind");
// 		exit(EXIT_FAILURE);
//     }
//     if (listen(s, 128) < 0) {
//     	printf("sgx_listen");
// 		exit(EXIT_FAILURE);
//     }
//     return s;
// }

void ecall_init_tls() {
  // OpenSSL_add_ssl_algorithms();
  // OpenSSL_add_all_ciphers();
  // SSL_load_error_strings();
}

void ecall_prepare_tls_context() {}

void new_thread_func() {

  
}
void ecall_start_tls_server(void) {
  int sock;
  // SSL_CTX *ctx;
  // init_openssl();
  // BIO_new_ssl_connect(NULL);

  // printf("OPENSSL Version = %s", SSLeay_version(SSLEAY_VERSION));
  // init_openssl();
  // ctx = create_context();
  // configure_context(ctx);

  // sock = create_socket_server(4433);
  // if (sock < 0) {
  //   printe("create_socket_client");
  //   exit(EXIT_FAILURE);
  // }

  // /* Handle SSL/TLS connections */
  // while (1) {
  //   struct sockaddr_in addr;
  //   int len = sizeof(addr);
  //   SSL *cli;
  //   unsigned char read_buf[1024];
  //   int r = 0;
  //   printf("Wait for new connection...");
  //   int client = accept(sock, (struct sockaddr *)&addr, &len);
  //   if (client < 0) {
  //     printe("Unable to accept");
  //     exit(EXIT_FAILURE);
  //   }

  //   cli = SSL_new(ctx);
  //   SSL_set_fd(cli, client);
  //   if (SSL_accept(cli) <= 0) {
  //     printe("SSL_accept");
  //     exit(EXIT_FAILURE);
  //   }

  //   printf("ciphersuit: %s", SSL_get_current_cipher(cli)->name);
  //   /* Receive buffer from TLS server */
  //   r = SSL_read(cli, read_buf, sizeof(read_buf));
  //   printf("read_buf: length = %d : %s", r, read_buf);
  //   memset(read_buf, 0, sizeof(read_buf));

  //   printf("Close SSL/TLS client");
  //   SSL_free(cli);
  //   sgx_close(client);
  // }

  // sgx_close(sock);
  // SSL_CTX_free(ctx);
  // cleanup_openssl();
}
