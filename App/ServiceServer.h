#ifndef __SERVICESERVER_H__
#define __SERVICESERVER_H__

#include <sgx_urts.h>
#include <pthread.h>

#define TLS_ENABLED 1
#define TLS_DISABLED 0


struct connection {
  int socket_fd;
  int epoll_fd;
  long ctx;
  long ssl;
  pthread_mutex_t send_lock;
  pthread_mutex_t recv_lock;
  void *(*handler)(void *arg);
};

struct service {
  struct connection server;
  struct connection client;
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

int prepare_server_socket(int port);
int prepare_client_socket(char *addr, int port);
int prepare_epoll(int sock);
long init_ssl_server_ctx(void);
long init_ssl_client_ctx(void);

int create_tls_channel(struct service *service,
		       struct thread_data *thread_data, int conn_fd);
long create_ssl_conn(long ctx, int conn_fd);

void stop_worker_threads();
void destroy_service(struct service *service);

#endif /* __SERVICESERVER_H__ */
