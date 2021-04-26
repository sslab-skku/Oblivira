#ifndef __SERVICESERVER_H__
#define __SERVICESERVER_H__
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sgx_urts.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "Enclave_u.h"
/* #include "certs_test.h" */
#include <wolfssl/ssl.h>

#define EVENTS_BUFF_SZ 256
#define TLS_ENABLED 1
#define TLS_DISABLED 0

extern sgx_enclave_id_t enclave_id;

#define SERVERBACKLOG 10
struct service {
  int server_fd;
  int epoll_fd;
  int is_server_tls;
  int is_client_tls;
  long server_ctx;
  long client_ctx;
  /* long ssl; */
  void *(*handler)(void *arg);
  
  // struct epoll_event events[256];
};

struct thread_data {
  struct service *service;
  int conn_fd;
  long ssl;
};
void *worker_thread(struct service *service);
void init_service_server(void);

int init_service(struct service *service, int port, int is_server_tls,
                 int is_client_tls, void *(*handler)(void *));

void stop_worker_threads();
void destroy_service(struct service *service);
void destroy_services(void);
static const char httpOKResponse[100000] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html; charset=UTF-8\r\n\r\n"
    "<!DOCTYPE html>\r\n"
    "<html><head><title></title></head>\r\n"
    "<body><p></p></body><html>\r\n";

#endif /* __SERVICESERVER_H__ */
