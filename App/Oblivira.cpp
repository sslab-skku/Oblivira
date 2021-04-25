#include <assert.h>
#include <cstdlib>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include <inttypes.h>
#include <libgen.h>
#include <pthread.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

#include <sgx_urts.h>

#include <wolfssl/certs_test.h>
#include <wolfssl/ssl.h>

#include "Enclave_u.h"
#include "Oblivira.h"
#include "ServiceServer.h"
#include "ThreadPool.h"

#define CIPHER_LIST "ECDHE-ECDSA-AES128-GCM-SHA256"

#define NUM_DID_REQ_THR 4
#define NUM_DRF_RECV_THR 4

#define MAX_PATH FILENAME_MAX
#define MAX_EVENTS 2000

#define DID_REQ_PORT 8080
#define DID_REQ_PORT 8888

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

// Input: server_fd, epoll_fd

void *did_req_handler(void *arg) {
  int ret;
  struct thread_data *thread_data = (struct thread_data *)arg;
  char buff[128];
  int sgxStatus;

  printf("Handling Request\n");
  memset(buff, 0, sizeof(buff));
  sgxStatus = enc_wolfSSL_read(enclave_id, &ret, thread_data->ssl, buff,
                               sizeof(buff) - 1);

  printf("%s\n", buff);
  sgxStatus =
      enc_wolfSSL_write(enclave_id, &ret, thread_data->ssl,
                        (void *)httpOKResponse, strlen(httpOKResponse) - 1);
  printf("Sent response\n");
  sgxStatus = enc_wolfSSL_free(enclave_id, thread_data->ssl);
  printf("Freed ssl context\n");
  close(thread_data->conn_fd);
  printf("closed socket\n");
  return NULL;
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
  init_service_server();

  // Initialize thread pools
  didQueryPool.init();
  didDocFetchPool.init();

  struct service did_req_service;
  ret = init_service(&did_req_service, DID_REQ_PORT, TLS_ENABLED, did_req_handler);

  struct thread_data thread_data;

  // Create, bind, listen
  // did_req_sock = prepare_socket(DID_REQ_PORT);
  // if (did_req_sock == -1)
  //   return 0;

  // did_req_epoll_fd = prepare_epoll(did_req_sock);
  // if (did_req_epoll_fd == -1)
  //   return 0;

  printf("Starting worker threads\n");

  auto wt1 = didQueryPool.submit(worker_thread, &did_req_service, &thread_data);
  auto wt2 = didQueryPool.submit(worker_thread, &did_req_service, &thread_data);
  auto wt3 = didQueryPool.submit(worker_thread, &did_req_service, &thread_data);
  auto wt4 = didQueryPool.submit(worker_thread, &did_req_service, &thread_data);
  auto wt5 = didQueryPool.submit(worker_thread, &did_req_service, &thread_data);

  didQueryPool.shutdown();
  didDocFetchPool.shutdown();
  sgx_destroy_enclave(enclave_id);

  return 0;
}
