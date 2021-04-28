#include "ServiceServer/ServiceServer.h"

#include <iostream>
#include <cstdlib>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <wolfssl/ssl.h>

#include "Enclave_u.h"

#define EVENTS_BUFF_SZ 256
#define SERVERBACKLOG 10

extern sgx_enclave_id_t enclave_id;

static std::vector<struct service *> services;

static int kill_switch = 0;

static int prepare_socket(int port)
{

    int sockfd;
    struct sockaddr_in serveraddr;

    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(port);
    serveraddr.sin_addr.s_addr = INADDR_ANY;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
        perror("socket(2) failed");
        exit(EXIT_FAILURE);
    }

    if (bind(sockfd, (const struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
    {
        printf("Creating socket for %d failed\n", ntohs(serveraddr.sin_port));
        perror("bind(2) failed");
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, SERVERBACKLOG) < 0)
    {
        perror("listen(2) failed");
        exit(EXIT_FAILURE);
    }
    return sockfd;
}

static int prepare_epoll(int sock)
{
    int epoll_fd;
    struct epoll_event epevent;
    epevent.events = EPOLLIN | EPOLLET;
    epevent.data.fd = sock;
    if ((epoll_fd = epoll_create(1)) < 0)
    {
        perror("epoll_create(2) failed");
        exit(EXIT_FAILURE);
    }
    // Epoll
    epevent.events = EPOLLIN | EPOLLET;
    epevent.data.fd = sock;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &epevent) < 0)
    {
        perror("epoll_ctl(2) failed on main server socket");
        exit(EXIT_FAILURE);
    }

    return epoll_fd;
}

static int __create_tls_channel(struct service *service,
                                struct thread_data *thread_data, int conn_fd)
{
    int sgxStatus, ret;

    sgxStatus =
        enc_wolfSSL_new(enclave_id, &thread_data->ssl, service->server_ctx);
    if (sgxStatus != SGX_SUCCESS || thread_data->ssl < 0)
    {
        printf("wolfSSL_new failure\n");
        return EXIT_FAILURE;
    }
#if defined(OBLIVIRA_PRINT_LOG)
    printf("[TLS] context creation successful\n");
#endif
    sgxStatus = enc_wolfSSL_set_fd(enclave_id, &ret, thread_data->ssl, conn_fd);
    if (sgxStatus != SGX_SUCCESS || ret != SSL_SUCCESS)
    {
        printf("wolfSSL_set_fd failure\n");
        return EXIT_FAILURE;
    }
#if defined(OBLIVIRA_PRINT_LOG)
    printf("[TLS] setting socket fd successful\n");
#endif
    return EXIT_SUCCESS;
}

void *worker_thread(struct service *service)
{
    int i;
    int ret;
    struct thread_data thread_data;
    // Connection per thread
    struct sockaddr_in conn_addr;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    struct epoll_event event;
    int events_cnt;

    // For later use
    thread_data.service = service;

    // 256 event buffer per thread
    struct epoll_event events[EVENTS_BUFF_SZ];

    printf("[%lx]Entering event looop\n", pthread_self());
    // Worker thread loop
    while (kill_switch == 0)
    {
        // Fetch events
        events_cnt = epoll_wait(service->epoll_fd, events, EVENTS_BUFF_SZ, 0);
        // printf("[Event Loop] events_cnt:%d\n", events_cnt);

        // handle error
        if (events_cnt < 0)
            printf("[EventLoop] epoll_wait() error\n");

        // iterate through events
        for (i = 0; i < events_cnt; i++)
        {
            // Event at server fd, new connection
            if (events[i].data.fd == service->server_fd)
            {
#if defined(OBLIVIRA_PRINT_LOG)
                printf("[EventLoop] Accepting client\n");
#endif
                // accept
                thread_data.conn_fd =
                    accept(service->server_fd, (struct sockaddr *)&conn_addr, &addrlen);

                // If accept fails, then skip
                if (thread_data.conn_fd < 0)
                    continue;

                // Create TLS channel if 'is_tls'
                if (service->is_server_tls == TRUE)
                {
                    ret =
                        __create_tls_channel(service, &thread_data, thread_data.conn_fd);
                    if (ret == EXIT_FAILURE)
                        continue;
#if defined(OBLIVIRA_PRINT_LOG)
                    printf("[EventLoop][TLS][%lx] Accept Succeeded\n", pthread_self());
#endif
                }
#if defined(OBLIVIRA_PRINT_LOG)
                printf("Handle request here\n");
#endif
                service->handler(&thread_data);
#if defined(OBLIVIRA_PRINT_LOG)
                printf("Finished Handling request\n");
#endif
                close(thread_data.conn_fd);
                // int flags = fcntl(thread_data.conn_fd, F_GETFL);
                // flags |= O_NONBLOCK;
                // if (fcntl(thread_data.conn_fd, F_SETFL, flags) < 0) {
                //   printf("client_fd[%d] fcntl() error\n", thread_data.conn_fd);
                //   return 0;
                // }

                // Handle request

                // service->handler(events[i].data.fd);
            }
            else
            {
                // Existing connection
                // Read or close
                event.events = EPOLLIN | EPOLLET;
                event.data.fd = thread_data.conn_fd;
            }
        }
    }
    printf("[%lx]Exiting event looop\n", pthread_self());
    pthread_exit(NULL);
}

// Initialize SSL Context
static long init_ssl_server_ctx(void)
{
    int sgxStatus;
    long ctx;

    if (ecall_init_ctx_server(enclave_id, &ctx) != SGX_SUCCESS && ctx < 0)
    {
        std::cout << "[OBLIVIRA][init_ssl_server_ctx] Initializing server context failed!" << std::endl;
    }

    return ctx;
}

static long init_ssl_client_ctx(void)
{
    int sgxStatus;
    long ctx;

    if (ecall_init_ctx_client(enclave_id, &ctx) != SGX_SUCCESS && ctx < 0)
    {
        std::cout << "[OBLIVIRA][init_ssl_client_ctx] Initializing client context failed!" << std::endl;
    }

    return ctx;
}

void init_service_server()
{
    int sgxStatus;
    enc_wolfSSL_Init(enclave_id, &sgxStatus);
}

int init_service(struct service *service, int port, int is_server_tls,
                 int is_client_tls, void *(*handler)(void *))
{
    service->server_fd = prepare_socket(port);
    if (service->server_fd == -1)
        return -1;
    service->epoll_fd = prepare_epoll(service->server_fd);
    if (service->epoll_fd == -1)
        return -1;
    service->is_server_tls = is_server_tls;
    if (is_server_tls == TLS_ENABLED)
    {
        service->server_ctx = init_ssl_server_ctx();
        if (service->server_ctx < 0)
            return -1;
    }
    service->is_client_tls = is_client_tls;
    if (is_client_tls == TLS_ENABLED)
    {
        service->client_ctx = init_ssl_client_ctx();
        if (service->client_ctx < 0)
            return -1;
    }

    service->handler = handler;
    services.push_back(service);
    return 0;
}

void stop_worker_threads() { kill_switch = 1; }

void destroy_service(struct service *service)
{
    int ret;
    epoll_ctl(service->epoll_fd, EPOLL_CTL_DEL, service->server_fd, NULL);
    close(service->server_fd);
    close(service->epoll_fd);
    enc_wolfSSL_CTX_free(enclave_id, service->server_ctx);
    enc_wolfSSL_CTX_free(enclave_id, service->client_ctx);
}
