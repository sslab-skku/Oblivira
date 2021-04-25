#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "ServiceServer.h"

static int prepare_socket(int port) {

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

static int prepare_epoll(int sock) {
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

static int __create_tls_channel(struct service *service, int conn_fd) {
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

void *worker_thread(struct service *service, struct thread_data* data) {

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

        service->handler((void*)service);
        // Create TLS channel if 'is_tls'
        if (service->is_tls == TRUE) {
          ret = __create_tls_channel(service, conn_fd);
          if (ret == EXIT_FAILURE)
            continue;
          printf("[EventLoop][TLS][%p] Accept Succeeded\n", pthread_self());
        }
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
    }
    else {
      // Existing connection
      // Read or close
      event.events = EPOLLIN | EPOLLET;
      event.data.fd = conn_fd;
    }
  }
}
}

// Initialize SSL Context
static long init_ssl_ctx(void) {
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

void init_service_server() {
  int sgxStatus;
  enc_wolfSSL_Init(enclave_id, &sgxStatus);
}

int init_service(struct service *service, int port, int is_tls,
                 void *(*handler)(void *)) {
  service->server_fd = prepare_socket(port);
  if (service->server_fd == -1)
    return 1;
  service->epoll_fd = prepare_epoll(service->server_fd);
  if (service->epoll_fd == -1)
    return 1;
  service->is_tls = TRUE;
  service->ctx = init_ssl_ctx();
  service->handler = handler;

  return 0;
}
