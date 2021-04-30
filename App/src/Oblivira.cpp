/* standard library */
#include <string.h>
#include <iostream>
#include <string>
#include <csignal>
#include <mutex>

/* sgx */
#include "sgx/sgx_init.hh"
#include "Enclave_u.h"

/* epoll service */
#include "ServiceServer/ServiceServer.h"

/* ThreadPool */
#include "ThreadPool/ThreadPool.h"

#ifdef OBLIVIRA_CACHE_ENABLED
/* localstorage */
#include <math.h>
#include "localstorage/localstorage.hh"
#endif

/* json */
#include "json/json.h"

/* untrusted config */
#include "config.hh"
#include "global_config.h"

/* curl */
#include <wolfssl/ssl.h>

/* define */
#define UNIRESOLVER_URL "http://localhost:8080/1.0/identifiers/"

/* Global EID shared by multiple threads */
sgx_enclave_id_t enclave_id = 0;

/* service threadpool */
struct service did_req_service;
struct service did_doc_fetch_service;
ThreadPool didQueryPool(NUM_DID_REQ_THR);
ThreadPool didDocFetchPool(NUM_DOC_FETCH_THR);

// EPOLL fd
static int did_req_epoll_fd, drf_recv_epoll_fd;

#ifdef OBLIVIRA_CACHE_ENABLED
LocalStorage *ls = new LocalStorage();
#endif

#define UNIV_REQ "GET /1.0/identifiers/%s HTTP/1.1\r\nHost: localhost:8080\r\n\r\n"

#define MAX_MAP_SIZE 128
struct safe_map
{
    char eph_did[MAX_DID_SIZE];
    long ssl;
    bool is_empty;
    static std::mutex m;
};

std::mutex safe_map::m;
struct safe_map eph_ssl[MAX_MAP_SIZE];

long get_eph_ssl(const char *did)
{
    long ssl;
    for (int i = 0; i < MAX_MAP_SIZE; ++i)
    {
        if (!strncmp(eph_ssl[i].eph_did, did, strlen(eph_ssl[i].eph_did) + 1) && !eph_ssl[i].is_empty)
        {
            ssl = eph_ssl[i].ssl;
            return ssl;
        }
    }
    errno = EINVAL;
    return -1;
}

int set_eph_ssl(const char* did, long ssl)
{
    for (int i = 0; i < MAX_MAP_SIZE; ++i)
    {
        if (eph_ssl[i].is_empty)
        {
            int min = strlen(did) < sizeof(eph_ssl[i].eph_did) ? strlen(did) + 1 : sizeof(eph_ssl[i].eph_did);
            eph_ssl->m.lock();
            strncpy(eph_ssl[i].eph_did, did, min);
            eph_ssl[i].ssl = ssl;
            eph_ssl[i].is_empty = false;
            eph_ssl->m.unlock();
            return 0;
        }
    }
    errno = EBUSY;
    return -1;
}

int rm_eph_ssl(const char *did)
{
    for (int i = 0; i < MAX_MAP_SIZE; ++i)
    {
        if (!strncmp(eph_ssl[i].eph_did, did, strlen(eph_ssl[i].eph_did) + 1))
        {

            eph_ssl->m.lock();
            eph_ssl[i].is_empty = true;
            eph_ssl->m.unlock();
            return 0;
        }
    }
    errno = EINVAL;
    return -1;
}

void *did_req_handler(void *arg)
{
    int ret;
    struct thread_data *thread_data = (struct thread_data *)arg;
    char eph_did[MAX_DID_SIZE] = {0};
    char buf[DATA_SIZE];

    if (int sgxStatus = ecall_handle_did_req(enclave_id, thread_data->ssl, eph_did, MAX_DID_SIZE))
    {
        std::cerr << "[OBRIVIRA][did_req_handler] Failed to handle did request!" << std::endl;
        return NULL;
    }

    if (!eph_did[0])
    {
        close(thread_data->conn_fd);
        return NULL;
    }

#if defined(OBLIVIRA_PRINT_LOG)
    std::cout << "[UNTRUSTED][did_req_handler] eph_did -> " << eph_did << std::endl;
#endif

    snprintf(buf, sizeof buf, UNIV_REQ, eph_did);

#if defined(OBLIVIRA_PRINT_LOG)
    printf("thread_data->ssl = %ld\n", thread_data->ssl);
    printf("eph_did = %s, length = %ld\n", eph_did, strlen(eph_did));
#endif

    if (set_eph_ssl(eph_did, thread_data->ssl) < 0)
    {
        perror("[UNTRUSTED][did_req_handler][set_eph_ssl]: ");
        return NULL;
    }

    int universalfd;

    struct sockaddr_in clientaddr;

    universalfd = socket(AF_INET, SOCK_STREAM, 0);

    clientaddr.sin_family = AF_INET;
    clientaddr.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &clientaddr.sin_addr);

    if (connect(universalfd, (struct sockaddr *)&clientaddr, sizeof(clientaddr)) < 0)
    {
        perror("[UNTRUSTED][did_req_handler][connect]: ");
    }
    ret = send(universalfd, buf, strlen(buf) + 1, 0);

    if (ret < 0)
    {
        perror("[UNTRUSTED][did_req_handler][write]: ");
        return NULL;
    }

    ret = recv(universalfd, buf, DATA_SIZE, 0);

    close(universalfd);

#if defined(OBLIVIRA_PRINT_LOG)
    std::cout << "[UNTRUSTED][did_req_handler] request to universal resolver succeded!"<< std::endl;
#endif

    return NULL;
}

const char *extract_blockchain_url(const char *input) { return "beta.discover.did.microsoft.com"; }
const char *domain2ip(const char *domain) { return "52.153.152.19"; }
#define RESPONSE "HTTP/1.1 200 OK\r\n\r\n"

void *did_doc_fetch_handler(void *arg)
{
    int ret, n, sgxStatus;
    char input[DRF_MAX_LEN];
    struct thread_data *thread_data = (struct thread_data *)arg;

    // For connecting to blockchain
    int bc_server_fd;
    long ssl, serverssl;
    const char *ip;
    struct sockaddr_in servAddr;

    char buf[DATA_SIZE] = {0};
    char eph_did[MAX_DID_SIZE];

    // 1. receive DRF
    n = recv(thread_data->conn_fd, input, sizeof(input) - 1, 0);
    if (n < 0)
    {
        return NULL;
    }

    n = send(thread_data->conn_fd, RESPONSE, sizeof(RESPONSE), 0);
    if (n < 0)
    {
        return NULL;
    }

    // 2. Parse DRF to extract blockchain URL
    std::string data;

    Json::CharReaderBuilder builder;
    const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    Json::Value query_info;

    data = strstr(input, "{");

    // parse http request body to get eph did
    reader->parse(data.c_str(), data.c_str() + data.length(), &query_info, NULL);

    // 3. Fetch document
    bc_server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (bc_server_fd < 0)
    {
        printf("Failed to create socket. errno: %i\n", errno);
        return NULL;
    }

    memset(&servAddr, 0, sizeof(servAddr)); /* clears memory block for use */
    servAddr.sin_family = AF_INET;          /* sets addressfamily to internet*/
    servAddr.sin_port = htons(443);         /* sets port to defined port */

    // FIXME
    ip = domain2ip(extract_blockchain_url(""));
    if (ip == NULL)
    {
        close(bc_server_fd);
        return NULL;
    }

#if defined(OBLIVIRA_PRINT_LOG)
    std::cout << "Connecting to " << ip << ":" << ntohs(servAddr.sin_port) << std::endl;
#endif

    /* looks for the server at the entered address (ip in the command line) */
    if (inet_pton(AF_INET, ip, &servAddr.sin_addr) < 1)
    {
        /* checks validity of address */
        perror("[UNTRUSTED][did_doc_fetch_handler][inet_pton]: ");

        close(bc_server_fd);
        return NULL;
    }

    if (connect(bc_server_fd, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0)
    {
        ret = errno;
        perror("[UNTRUSTED][did_doc_fetch_handler][connect]: ");

        close(bc_server_fd);
        return NULL;
    }

    strncpy(eph_did, query_info["identifier"].asString().c_str(), MAX_DID_SIZE);

    if ((serverssl = get_eph_ssl(eph_did)) < 0)
    {
        perror("[UNTRUSTED][did_doc_fetch_handler][get_eph_ssl]: ");
        close(bc_server_fd);
        return NULL;
    }

    if (rm_eph_ssl(eph_did) < 0)
    {
        perror("[UNTRUSTED][did_doc_fetch_handler][get_eph_ssl]: ");
        close(bc_server_fd);
        return NULL;
    }

#if defined(OBLIVIRA_PRINT_LOG)
    std::cout << "FD: " << serverssl << std::endl;
    std::cout << "Addr: " << query_info["baseAddress"].asString().c_str() << std::endl;
    std::cout << "eph_did: " << eph_did << ", length: " << query_info["identifier"].asString().length() << std::endl;
    std::cout << "query: " << query_info["query"].asString().c_str() << std::endl;
#endif

    sgxStatus = ecall_request_to_blockchain(enclave_id, thread_data->service->client_ctx, bc_server_fd,
                                            serverssl,
                                            query_info["baseAddress"].asString().c_str(),
                                            eph_did,
                                            query_info["query"].asString().c_str());
    if (sgxStatus != SGX_SUCCESS)
    {
        std::cout << "[Untrusted][ecall_request_blockchain] Failed to request blockchain!" << std::endl;

        close(bc_server_fd);
        return NULL;
    }

    return NULL;
}

void destroy_oblivira(int status)
{
    std::cout << "Shutting down oblivira" << std::endl;
    stop_worker_threads();
    didQueryPool.shutdown();
    didDocFetchPool.shutdown();

    std::cout << "Thread pool shut down" << std::endl;
    destroy_service(&did_req_service);
    destroy_service(&did_doc_fetch_service);

    std::cout << "Services shut down" << std::endl;
    sgx_destroy_enclave(enclave_id);

    std::cout << "Bye" << std::endl;
    exit(status);
}

int main(int argc, char *argv[])
{
    int ret, i;
    int sgxStatus;

    signal(SIGINT, destroy_oblivira);

    /* Initialize the enclave */
    if (initialize_enclave(&enclave_id) < 0)
        return 1;

#ifdef OBLIVIRA_CACHE_ENABLED
    int recursion_levels = computeRecursionLevels(MAX_BLOCKS, RECURSION_DATA_SIZE, MEM_POSMAP_LIMIT);
    uint32_t D = (uint32_t)ceil(log((double)MAX_BLOCKS / SIZE_Z) / log((double)2));
    ls->setParams(MAX_BLOCKS, D, SIZE_Z, STASH_SIZE, DATA_SIZE + ADDITIONAL_METADATA_SIZE, RECURSION_DATA_SIZE + ADDITIONAL_METADATA_SIZE, recursion_levels);

    ecall_createNewORAM(enclave_id, (uint8_t *)&ret, MAX_BLOCKS, DATA_SIZE, STASH_SIZE, RECURSION_DATA_SIZE, recursion_levels, SIZE_Z);
#endif

    for(i = 0; i < MAX_MAP_SIZE; ++i){
        eph_ssl[i].is_empty = true;
    }

#if defined(OBLIVIRA_PRINT_LOG)
    // enc_wolfSSL_Debugging_ON(enclave_id);
#endif
    // Initialize WolfSSL
    init_service_server();

    // Initialize thread pools
    didQueryPool.init();
    didDocFetchPool.init();

    ret = init_service(&did_req_service, DID_REQ_PORT, TLS_ENABLED, TLS_DISABLED,
                       did_req_handler);
    if (ret < 0)
    {
        printf("Error Initializing service\n");
        exit(1);
    }

    ret = init_service(&did_doc_fetch_service, DOC_FETCH_PORT, TLS_DISABLED,
                       TLS_ENABLED, did_doc_fetch_handler);

    if (ret < 0)
    {
        printf("Error Initializing service\n");
        exit(1);
    }

    struct thread_data thread_data;

    printf("Starting worker threads\n");

    for (i = 0; i < NUM_DID_REQ_THR; i++)
    {
        didQueryPool.submit(worker_thread, &did_req_service);
    }

    for (i = 0; i < NUM_DOC_FETCH_THR; i++)
    {
        didDocFetchPool.submit(worker_thread, &did_doc_fetch_service);
    }
    while (1)
    {
        char c = '\0';
        c = getchar();
        if ((c == 'q') || (c == EOF)) // stop if EOF or 'q'.
            break;
    }

    destroy_oblivira(SIGTERM);

    return 0;
}
