/* standard library */
#include <iostream>
#include <string>
#include <csignal>
#include <map>

/* sgx */
#include "sgx/sgx_init.hh"
#include "Enclave_u.h"

/* epoll service */
#include "ServiceServer/ServiceServer.h"

/* ThreadPool */
#include "ThreadPool/ThreadPool.h"

/* localstorage */
#include "localstorage/localstorage.hh"

/* curl */
#include <curl/curl.h>

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

LocalStorage *ls = new LocalStorage();

std::map<std::string, long> edid_fd;


void *did_req_handler(void *arg)
{
    struct thread_data *thread_data = (struct thread_data *)arg;
    char eph_did[MAX_DID_SIZE] = {0};

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

    CURL *curl;
    CURLcode ret;
    std::string url = UNIRESOLVER_URL;

    // curl init
    curl = curl_easy_init();

#if defined(OBLIVIRA_PRINT_LOG)
    std::cout << "[UNTRUSTED][did_req_handler][curl] get request!" << std::endl;
#endif

    // set curl config
    url += eph_did;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    
    // send curl to universal resolver
    ret = curl_easy_perform(curl);
    if (ret != CURLE_OK)
    {
        std::cerr << "[UNTRUSTED][did_req_handler][curl] Failed with curl error code: " << ret << ", url: " << url << std::endl;
    }
#if defined(OBLIVIRA_PRINT_LOG)
    else
    {
        std::cout << "\n[UNTRUSTED][did_req_handler][curl] curl SUCCESS: " << url << std::endl;
    }
#endif

    // free curl
    curl_easy_cleanup(curl);

    edid_fd[eph_did] = thread_data->ssl;

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
    long ssl;
    const char *ip;
    struct sockaddr_in servAddr;

    char buf[DATA_SIZE] = {0};

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
#if defined(OBLIVIRA_PRINT_LOG)
    std::cout << input << std::endl;
#endif
    Json::CharReaderBuilder builder;
    const std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    Json::Value query_info;

    // parse http request body to get eph did
    reader->parse(input, input + strlen(input), &query_info, NULL);

    query_info["baseAddress"].asString().c_str();

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
    printf("Connecting to %s:%d\n", ip, ntohs(servAddr.sin_port));
#endif

    /* looks for the server at the entered address (ip in the command line) */
    if (inet_pton(AF_INET, ip, &servAddr.sin_addr) < 1)
    {
        /* checks validity of address */
        ret = errno;
        printf("Invalid Address. errno: %i\n", ret);

        close(bc_server_fd);
        return NULL;
    }

    if (connect(bc_server_fd, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0)
    {
        ret = errno;
        printf("Connect error. Error: %i\n", ret);

        close(bc_server_fd);
        return NULL;
    }

    sgxStatus = ecall_request_to_blockchain(enclave_id, thread_data->service->client_ctx, bc_server_fd,
                                            edid_fd[query_info["identifier"].asString()],
                                            query_info["baseAddress"].asString().c_str(),
                                            query_info["identifier"].asString().c_str(),
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

#if defined(OBLIVIRA_PRINT_LOG)
    enc_wolfSSL_Debugging_ON(enclave_id);
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

    // initialize curl global
    curl_global_init(CURL_GLOBAL_ALL);

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
