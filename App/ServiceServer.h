#ifndef __SERVICESERVER_H__
#define __SERVICESERVER_H__

#include <sgx_urts.h>

#define TLS_ENABLED 1
#define TLS_DISABLED 0

struct service
{
    int server_fd;
    int epoll_fd;
    int is_server_tls;
    int is_client_tls;
    long server_ctx;
    long client_ctx;
    /* long ssl; */
    void *(*handler)(void *arg);
};

struct thread_data
{
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

#endif /* __SERVICESERVER_H__ */
