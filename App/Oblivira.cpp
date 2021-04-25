#include <assert.h>
#include <cstdlib>
#include <stdio.h>
#include <string.h>

#include <inttypes.h>
#include <libgen.h>
#include <pthread.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <wolfssl/certs_test.h>
#include <wolfssl/ssl.h>

#define CIPHER_LIST "ECDHE-ECDSA-AES128-GCM-SHA256"

#define SERVERBACKLOG 10
#define NUM_DID_REQ_THR 4
#define NUM_DRF_RECV_THR 4

#define MAX_PATH FILENAME_MAX
#define MAX_EVENTS 2000

#include "Enclave_u.h"
#include "Oblivira.h"
#include <sgx_urts.h>

#include "ThreadPool.h"
#define DID_REQ_PORT 8080
#define DID_REQ_PORT 8888
#define EVENTS_BUFF_SZ 256

#define WITH_TLS 1
#define WITHOUT_TLS 0

/* Global EID shared by multiple threads */
sgx_enclave_id_t enclave_id = 0;

// EPOLL fd
static int did_req_epoll_fd, drf_recv_epoll_fd;
// For DID requests, and DRF receiving
// int did_req_sock, drf_recv_sock;

typedef struct _sgx_errlist_t {
  sgx_status_t err;
  const char *msg;
  const char *sug; /* Suggestion */
} sgx_errlist_t;

struct service_port {
  int server_fd;
  int epoll_fd;
  int is_tls;
  long ctx;
  long ssl;
  void *(*handler)(void *arg);
  // struct epoll_event events[256];
};

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {SGX_ERROR_UNEXPECTED, "Unexpected error occurred.", NULL},
    {SGX_ERROR_INVALID_PARAMETER, "Invalid parameter.", NULL},
    {SGX_ERROR_OUT_OF_MEMORY, "Out of memory.", NULL},
    {SGX_ERROR_ENCLAVE_LOST, "Power transition occurred.",
     "Please refer to the sample \"PowerTransition\" for details."},
    {SGX_ERROR_INVALID_ENCLAVE, "Invalid enclave image.", NULL},
    {SGX_ERROR_INVALID_ENCLAVE_ID, "Invalid enclave identification.", NULL},
    {SGX_ERROR_INVALID_SIGNATURE, "Invalid enclave signature.", NULL},
    {SGX_ERROR_OUT_OF_EPC, "Out of EPC memory.", NULL},
    {SGX_ERROR_NO_DEVICE, "Invalid Intel® Software Guard Extensions device.",
     "Please make sure Intel® Software Guard Extensions module is enabled in "
     "the BIOS, and install Intel® Software Guard Extensions driver "
     "afterwards."},
    {SGX_ERROR_MEMORY_MAP_CONFLICT, "Memory map conflicted.", NULL},
    {SGX_ERROR_INVALID_METADATA, "Invalid enclave metadata.", NULL},
    {SGX_ERROR_DEVICE_BUSY, "Intel® Software Guard Extensions device was busy.",
     NULL},
    {SGX_ERROR_INVALID_VERSION, "Enclave version was invalid.", NULL},
    {SGX_ERROR_INVALID_ATTRIBUTE, "Enclave was not authorized.", NULL},
    {SGX_ERROR_ENCLAVE_FILE_ACCESS, "Can't open enclave file.", NULL},
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret) {
  size_t idx = 0;
  size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

  for (idx = 0; idx < ttl; idx++) {
    if (ret == sgx_errlist[idx].err) {
      if (NULL != sgx_errlist[idx].sug)
        printf("Info: %s\n", sgx_errlist[idx].sug);
      printf("Error: %s\n", sgx_errlist[idx].msg);
      break;
    }
  }

  if (idx == ttl)
    printf("Error: Unexpected error occurred [0x%x].\n", ret);
}

/* Initialize the enclave:
 *   Step 1: retrive the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void) {
  char token_path[MAX_PATH] = {'\0'};
  sgx_launch_token_t token = {0};
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  int updated = 0;
  /* Step 1: retrive the launch token saved by last transaction */

  /* try to get the token saved in $HOME */
  const char *home_dir = getpwuid(getuid())->pw_dir;
  if (home_dir != NULL && (strlen(home_dir) + strlen("/") +
                           sizeof(TOKEN_FILENAME) + 1) <= MAX_PATH) {
    /* compose the token path */
    strncpy(token_path, home_dir, strlen(home_dir));
    strncat(token_path, "/", strlen("/"));
    strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 1);
  } else {
    /* if token path is too long or $HOME is NULL */
    strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
  }

  FILE *fp = fopen(token_path, "rb");
  if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
    printf("Warning: Failed to create/open the launch token file \"%s\".\n",
           token_path);
  }
  printf("token_path: %s\n", token_path);
  if (fp != NULL) {
    /* read the token from saved file */
    size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
    if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
      /* if token is invalid, clear the buffer */
      memset(&token, 0x0, sizeof(sgx_launch_token_t));
      printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
    }
  }

  /* Step 2: call sgx_create_enclave to initialize an enclave instance */
  /* Debug Support: set 2nd parameter to 1 */

  ret = sgx_create_enclave(TESTENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token,
                           &updated, &enclave_id, NULL);

  if (ret != SGX_SUCCESS) {
    print_error_message(ret);
    if (fp != NULL)
      fclose(fp);

    return -1;
  }

  /* Step 3: save the launch token if it is updated */

  if (updated == FALSE || fp == NULL) {
    /* if the token is not updated, or file handler is invalid, do not perform
     * saving */
    if (fp != NULL)
      fclose(fp);
    return 0;
  }

  /* reopen the file with write capablity */
  fp = freopen(token_path, "wb", fp);
  if (fp == NULL)
    return 0;
  size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
  if (write_num != sizeof(sgx_launch_token_t))
    printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
  fclose(fp);

  return 0;
}

/* OCall functions */
void uprint(const char *str) {
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  printf("%s", str);
  fflush(stdout);
}

void usgx_exit(int reason) {
  printf("usgx_exit: %d\n", reason);
  exit(reason);
}

static double current_time() {
  struct timeval tv;
  gettimeofday(&tv, NULL);

  return (double)(1000000 * tv.tv_sec + tv.tv_usec) / 1000000.0;
}

void ocall_print_string(const char *str) {
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  printf("%s", str);
}

void ocall_current_time(double *time) {
  if (!time)
    return;
  *time = current_time();
  return;
}

void ocall_low_res_time(int *time) {
  struct timeval tv;
  if (!time)
    return;
  *time = tv.tv_sec;
  return;
}

size_t ocall_recv(int sockfd, void *buf, size_t len, int flags) {
  return recv(sockfd, buf, len, flags);
}

size_t ocall_send(int sockfd, const void *buf, size_t len, int flags) {
  return send(sockfd, buf, len, flags);
}

int prepare_socket(int port) {

  int sockfd;
  struct sockaddr_in serveraddr;

  serveraddr.sin_family = AF_INET;
  serveraddr.sin_port = htons(port);
  serveraddr.sin_addr.s_addr = INADDR_ANY;

  if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
    perror("socket(2) failed");
    exit(EXIT_FAILURE);
  }

  if (bind(sockfd, (const struct sockaddr *)&serveraddr, sizeof(serveraddr)) <
      0) {
    perror("bind(2) failed");
    exit(EXIT_FAILURE);
  }

  if (listen(sockfd, SERVERBACKLOG) < 0) {
    perror("listen(2) failed");
    exit(EXIT_FAILURE);
  }
  return sockfd;
}

int prepare_epoll(int sock) {
  int epoll_fd;
  struct epoll_event epevent;
  epevent.events = EPOLLIN | EPOLLET;
  epevent.data.fd = sock;
  if ((epoll_fd = epoll_create(1)) < 0) {
    perror("epoll_create(2) failed");
    exit(EXIT_FAILURE);
  }
  // Epoll
  epevent.events = EPOLLIN | EPOLLET;
  epevent.data.fd = sock;

  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &epevent) < 0) {
    perror("epoll_ctl(2) failed on main server socket");
    exit(EXIT_FAILURE);
  }

  return epoll_fd;
}

// Initialize SSL Context
long init_ssl_ctx(void) {
  int sgxStatus;
  int ret;
  long ctx;
  // long ssl;
  long method;

  sgxStatus = enc_wolfTLSv1_2_server_method(enclave_id, &method);
  if (sgxStatus != SGX_SUCCESS) {
    printf("wolfTLSv1_2_server_method failure\n");
    return EXIT_FAILURE;
  }

  sgxStatus = enc_wolfSSL_CTX_new(enclave_id, &ctx, method);
  if (sgxStatus != SGX_SUCCESS || ctx < 0) {
    printf("wolfSSL_CTX_new failure\n");
    return EXIT_FAILURE;
  }

  /* Load server certificates into WOLFSSL_CTX */
  sgxStatus = enc_wolfSSL_CTX_use_certificate_buffer(
      enclave_id, &ret, ctx, server_cert_der_2048, sizeof_server_cert_der_2048,
      SSL_FILETYPE_ASN1);
  if (sgxStatus != SGX_SUCCESS || ret != SSL_SUCCESS) {
    printf("enc_wolfSSL_CTX_use_certificate_chain_buffer_format failure\n");
    return EXIT_FAILURE;
  }

  /* Load server key into WOLFSSL_CTX */
  sgxStatus = enc_wolfSSL_CTX_use_PrivateKey_buffer(
      enclave_id, &ret, ctx, server_key_der_2048, sizeof_server_key_der_2048,
      SSL_FILETYPE_ASN1);

  if (sgxStatus != SGX_SUCCESS || ret != SSL_SUCCESS) {
    printf("wolfSSL_CTX_use_PrivateKey_buffer failure \n");
    return EXIT_FAILURE;
  }
  return ctx;
}

void *hello(void *a) {
  printf("%d\n", a);
  return NULL;
}

int handle_request(int clientfd) {
  char readbuff[512];
  struct sockaddr_in addr;
  socklen_t addrlen = sizeof(addr);
  ssize_t n;

  if ((n = recv(clientfd, readbuff, sizeof(readbuff) - 1, 0)) < 0) {
    return -1;
  }

  if (n == 0) {
    return 0;
  }

  readbuff[n] = '\0';

  if (getpeername(clientfd, (struct sockaddr *)&addr, &addrlen) < 0) {
    return -1;
  }

  char ip_buff[INET_ADDRSTRLEN + 1];
  if (inet_ntop(AF_INET, &addr.sin_addr, ip_buff, sizeof(ip_buff)) == NULL) {
    return -1;
  }

  printf("*** [%p] [%s:%" PRIu16 "] -> server: %s", (void *)pthread_self(),
         ip_buff, ntohs(addr.sin_port), readbuff);

  ssize_t sent;
  if ((sent = send(clientfd, readbuff, n, 0)) < 0) {
    return -1;
  }

  readbuff[sent] = '\0';

  printf("*** [%p] server -> [%s:%" PRIu16 "]: %s", (void *)pthread_self(),
         ip_buff, ntohs(addr.sin_port), readbuff);

  return 0;
}
static int __accept_tls_client(struct service_port *service, int conn_fd) {
  int sgxStatus, ret;

  sgxStatus = enc_wolfSSL_new(enclave_id, &service->ssl, service->ctx);
  if (sgxStatus != SGX_SUCCESS || service->ssl < 0) {
    printf("wolfSSL_new failure\n");
    return EXIT_FAILURE;
  }
  printf("[TLS] context creation successful\n");
  sgxStatus = enc_wolfSSL_set_fd(enclave_id, &ret, service->ssl, conn_fd);
  if (sgxStatus != SGX_SUCCESS || ret != SSL_SUCCESS) {
    printf("wolfSSL_set_fd failure\n");
    return EXIT_FAILURE;
  }
  printf("[TLS] setting socket fd successful\n");

  printf("[TLS] Client connected successfully\n");
  return EXIT_SUCCESS;
}

// Input: server_fd, epoll_fd
void *worker_thread(struct service_port *service) {

  int i;
  int ret;

  // Connection per thread
  int conn_fd;
  struct sockaddr_in conn_addr;
  socklen_t addrlen = sizeof(struct sockaddr_in);
  struct epoll_event event;
  int events_cnt;

  // 256 event buffer per thread
  struct epoll_event events[EVENTS_BUFF_SZ];

  printf("[%p]Entering event looop\n", pthread_self());
  // Worker thread loop
  while (1) {
    // Fetch events
    events_cnt = epoll_wait(service->epoll_fd, events, EVENTS_BUFF_SZ, 0);
    // printf("[Event Loop] events_cnt:%d\n", events_cnt);

    // handle error
    if (events_cnt < 0)
      printf("[EventLoop] epoll_wait() error\n");

    // iterate through events
    for (i = 0; i < events_cnt; i++) {
      // Event at server fd, new connection
      if (events[i].data.fd == service->server_fd) {
        printf("[EventLoop] Accepting client\n");
        // accept
        conn_fd =
            accept(service->server_fd, (struct sockaddr *)&conn_addr, &addrlen);

        // If accept fails, then skip
        if (conn_fd < 0)
          continue;

        // Create TLS channel if 'is_tls'
        if (service->is_tls == TRUE) {
          ret = __accept_tls_client(service, conn_fd);
          if (ret == EXIT_FAILURE)
            continue;

          printf("[EventLoop][TLS][%p] Accept Succeeded\n", pthread_self());
          char buff[128];
          int sgxStatus;
          memset(buff, 0, sizeof(buff));
          sgxStatus = enc_wolfSSL_read(enclave_id, &ret, service->ssl, buff,
                                       sizeof(buff) - 1);

          printf("%s\n", buff);
          sgxStatus = enc_wolfSSL_write(enclave_id, &ret, service->ssl,
                                       (void *)httpOKResponse,
                                       strlen(httpOKResponse) - 1);

          sgxStatus = enc_wolfSSL_free(enclave_id, service->ssl);
	  close(conn_fd);
          continue;
        }

        // int flags = fcntl(conn_fd, F_GETFL);
        // flags |= O_NONBLOCK;
        // if (fcntl(conn_fd, F_SETFL, flags) < 0) {
        //   printf("client_fd[%d] fcntl() error\n", conn_fd);
        //   return 0;
        // }

        // Handle request
        printf("Handle request here\n");
        // service->handler(events[i].data.fd);

      } else {
        // Existing connection
        // Read or close
        event.events = EPOLLIN | EPOLLET;
        event.data.fd = conn_fd;
      }
    }
  }
}

int main(int argc, char *argv[]) {
  int ret;
  int sgxStatus;
  ThreadPool didQueryPool(NUM_DID_REQ_THR);
  ThreadPool didDocFetchPool(NUM_DRF_RECV_THR);
  /* Changing dir to where the executable is.*/
  // char absolutePath[MAX_PATH];
  // struct epoll_event epevent;

  /* Initialize the enclave */
  if (initialize_enclave() < 0)
    return 1;

  // Initialize WolfSSL
  enc_wolfSSL_Init(enclave_id, &sgxStatus);

  // Initialize thread pools
  didQueryPool.init();
  didDocFetchPool.init();

  struct service_port did_req_service;
  did_req_service.server_fd = prepare_socket(DID_REQ_PORT);
  if (did_req_service.server_fd == -1)
    return 1;
  did_req_service.epoll_fd = prepare_epoll(did_req_service.server_fd);
  if (did_req_service.epoll_fd == -1)
    return 1;
  did_req_service.is_tls = TRUE;
  did_req_service.ctx = init_ssl_ctx();
  did_req_service.handler = hello;

  // Create, bind, listen
  // did_req_sock = prepare_socket(DID_REQ_PORT);
  // if (did_req_sock == -1)
  //   return 0;

  // did_req_epoll_fd = prepare_epoll(did_req_sock);
  // if (did_req_epoll_fd == -1)
  //   return 0;

  printf("Starting worker threads\n");

  auto wt1 = didQueryPool.submit(worker_thread, &did_req_service);
  auto wt2 = didQueryPool.submit(worker_thread, &did_req_service);
  auto wt3 = didQueryPool.submit(worker_thread, &did_req_service);
  auto wt4 = didQueryPool.submit(worker_thread, &did_req_service);
  auto wt5 = didQueryPool.submit(worker_thread, &did_req_service);

  didQueryPool.shutdown();
  didDocFetchPool.shutdown();
  sgx_destroy_enclave(enclave_id);

  return 0;
}
