#include "ServiceServer.h"

#include <cstdlib>
#include <iostream>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <wolfssl/ssl.h>

#include "Enclave_u.h"

#include "debug.h"

#define SERVERBACKLOG 10

extern sgx_enclave_id_t enclave_id;

static std::vector<struct service *> services;

static int kill_switch = 0;

int prepare_server_socket(int port) {

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
    obv_err("Creating socket for %d failed\n", ntohs(serveraddr.sin_port));
    perror("bind(2) failed");
    exit(EXIT_FAILURE);
  }

  if (listen(sockfd, SERVERBACKLOG) < 0) {
    perror("listen(2) failed");
    exit(EXIT_FAILURE);
  }
  return sockfd;
}

int prepare_client_socket(char *addr, int port) {
  int ret;
  int sockfd;
  struct sockaddr_in clientaddr;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  clientaddr.sin_family = AF_INET;
  clientaddr.sin_port = htons(port);
  inet_pton(AF_INET, addr, &clientaddr.sin_addr);

  if (connect(sockfd, (struct sockaddr *)&clientaddr, sizeof(clientaddr)) < 0) {
    perror("Error connecting to client ");
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
  // // Epoll
  // epevent.events = EPOLLIN | EPOLLET;
  // epevent.data.fd = sock;

  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &epevent) < 0) {
    perror("epoll_ctl(2) failed on main server socket");
    exit(EXIT_FAILURE);
  }

  return epoll_fd;
}

// Returns ssl
long create_ssl_conn(long ctx, int conn_fd) {
  int sgxStatus, ret;
  long ssl;
  sgxStatus = enc_wolfSSL_new(enclave_id, &ssl, ctx);
  if (sgxStatus != SGX_SUCCESS || ssl < 0) {
    obv_err("wolfSSL_new failure\n");
    return -1;
  }
#if defined(OBLIVIRA_PRINT_LOG)
  obv_err("[TLS] context creation successful\n");
#endif
  sgxStatus = enc_wolfSSL_set_fd(enclave_id, &ret, ssl, conn_fd);
  if (sgxStatus != SGX_SUCCESS || ret != SSL_SUCCESS) {
    obv_err("wolfSSL_set_fd failure\n");
    return -1;
  }
#if defined(OBLIVIRA_PRINT_LOG)
  obv_debug("[TLS] setting socket fd successful\n");
#endif
  return ssl;
}


// Initialize SSL Context
long init_ssl_server_ctx(void) {
  int sgxStatus;
  long ctx;

  if (ecall_init_ctx_server(enclave_id, &ctx) != SGX_SUCCESS && ctx < 0) {
    std::cout
        << "[OBLIVIRA][init_ssl_server_ctx] Initializing server context failed!"
        << std::endl;
  }

  return ctx;
}

long init_ssl_client_ctx(void) {
  int sgxStatus;
  long ctx;

  if (ecall_init_ctx_client(enclave_id, &ctx) != SGX_SUCCESS && ctx < 0) {
    std::cout
        << "[OBLIVIRA][init_ssl_client_ctx] Initializing client context failed!"
        << std::endl;
  }

  return ctx;
}

void init_service_server() {
  int sgxStatus;
  enc_wolfSSL_Init(enclave_id, &sgxStatus);
}

