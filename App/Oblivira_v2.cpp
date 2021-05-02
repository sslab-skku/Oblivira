/* standard library */
#include <csignal>
#include <iostream>
#include <mutex>
#include <pthread.h>
#include <string.h>
#include <string>

#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <utility>
#include <wolfssl/ssl.h>

#include "Enclave_u.h"
#include "SafeQueue.h"
#include "ServiceServer.h"
#include "ThreadPool.h"
#include "json.h"
#include "sgx_init.h"
#ifdef OBLIVIRA_CACHE_ENABLED
#include "localstorage.h"
#include <math.h>
#endif

#define NUM_DID_REQ_THR 2
#define NUM_DRF_RECV_THR 2
#define NUM_DOC_FETCH_THR 2

#define MAX_PATH_LEN FILENAME_MAX
#define MAX_EVENTS 64

#define DID_REQ_PORT 4433
#define DRF_RECV_PORT 8081

#define BASE_ADDR_MAX_LEN 128

#define DRF_MAX_LEN 2048
#include "debug.h"
#include "global_config.h"

#define UNIRESOLVER_URL "http://localhost:8080/1.0/identifiers/"
#define UNIV_REQ                                                               \
  "GET /1.0/identifiers/%s HTTP/1.1\r\nHost: localhost:8080\r\n\r\n"
#define UNIV_REQ                                                               \
  "GET /1.0/identifiers/%s HTTP/1.1\r\nHost: localhost:8080\r\n\r\n"

#define EVENTS_BUFF_SZ 64
/* Global EID shared by multiple threads */
sgx_enclave_id_t enclave_id = 0;
int kill_services = 0;

/* service threadpool */
struct service did_req_service;
struct service drf_recv_service;
struct service did_doc_fetch_service;
ThreadPool ServicePool(NUM_DID_REQ_THR + NUM_DRF_RECV_THR);
ThreadPool DocFetchPool(NUM_DOC_FETCH_THR);

// typedef struct {
//   char eph_did[MAX_DID_SIZE];
// } DocFetchReq;

// class DocFetchReq {
// public:
//   std::string baseAddr;
//   std::string eph_did;
// };

SafeQueue<std::pair<std::string, std::string>> docFetchQueue;
// EPOLL fd
static int did_req_epoll_fd, drf_recv_epoll_fd;

#ifdef OBLIVIRA_CACHE_ENABLED
LocalStorage *ls = new LocalStorage();
#endif

// #define UNIV_REQ                                                               \
//   "GET /1.0/identifiers/%s HTTP/1.1\r\nHost: localhost:8080\r\n\r\n"

// #define MAX_MAP_SIZE 128
// struct safe_map {
//   char eph_did[MAX_DID_SIZE];
//   long ssl;
//   bool is_empty;
//   static std::mutex m;
// };

// std::mutex safe_map::m;
// struct safe_map eph_ssl[MAX_MAP_SIZE];

// long get_eph_ssl(const char *did) {
//   long ssl;
//   for (int i = 0; i < MAX_MAP_SIZE; ++i) {
//     if (!strncmp(eph_ssl[i].eph_did, did, strlen(eph_ssl[i].eph_did) + 1) &&
//         !eph_ssl[i].is_empty) {
//       ssl = eph_ssl[i].ssl;
//       return ssl;
//     }
//   }
//   errno = EINVAL;
//   return -1;
// }

// int set_eph_ssl(const char *did, long ssl) {
//   for (int i = 0; i < MAX_MAP_SIZE; ++i) {
//     if (eph_ssl[i].is_empty) {
//       int min = strlen(did) < sizeof(eph_ssl[i].eph_did)
//                     ? strlen(did) + 1
//                     : sizeof(eph_ssl[i].eph_did);
//       eph_ssl->m.lock();
//       strncpy(eph_ssl[i].eph_did, did, min);
//       eph_ssl[i].ssl = ssl;
//       eph_ssl[i].is_empty = false;
//       eph_ssl->m.unlock();
//       return 0;
//     }
//   }
//   errno = EBUSY;
//   return -1;
// }

// int rm_eph_ssl(const char *did) {
//   for (int i = 0; i < MAX_MAP_SIZE; ++i) {
//     if (!strncmp(eph_ssl[i].eph_did, did, strlen(eph_ssl[i].eph_did) + 1)) {

//       eph_ssl->m.lock();
//       eph_ssl[i].is_empty = true;
//       eph_ssl->m.unlock();
//       return 0;
//     }
//   }
//   errno = EINVAL;
//   return -1;
// }

const char *extract_blockchain_url(const char *input) {
  return "beta.discover.did.microsoft.com";
}
const char *domain2ip(const char *domain) { return "52.153.152.19"; }
#define RESPONSE "HTTP/1.1 200 OK\r\n\r\n"

void destroy_oblivira(int status) {

  close(did_req_service.server.socket_fd);
  close(drf_recv_service.server.socket_fd);
  std::cout << "Shutting down oblivira" << std::endl;
  // stop_worker_threads();
  ServicePool.shutdown();
  DocFetchPool.shutdown();

  std::cout << "Thread pool shut down" << std::endl;
  // destroy_service(&did_req_service);
  // destroy_service(&did_doc_fetch_service);

  std::cout << "Services shut down" << std::endl;
  sgx_destroy_enclave(enclave_id);

  std::cout << "Bye" << std::endl;
  exit(status);
}

void init_oram_cache() {
#ifdef OBLIVIRA_CACHE_ENABLED
  int recursion_levels =
      computeRecursionLevels(MAX_BLOCKS, RECURSION_DATA_SIZE, MEM_POSMAP_LIMIT);
  uint32_t D =
      (uint32_t)ceil(log((double)MAX_BLOCKS / SIZE_Z) / log((double)2));
  ls->setParams(
      MAX_BLOCKS, D, SIZE_Z, STASH_SIZE, DATA_SIZE + ADDITIONAL_METADATA_SIZE,
      RECURSION_DATA_SIZE + ADDITIONAL_METADATA_SIZE, recursion_levels);

  ecall_createNewORAM(enclave_id, (uint8_t *)&ret, MAX_BLOCKS, DATA_SIZE,
                      STASH_SIZE, RECURSION_DATA_SIZE, recursion_levels,
                      SIZE_Z);
#endif
  return;
}

int init_doc_fetch_service(struct service *s) {
  // DID Request server
  s->server.socket_fd = -1;
  s->server.epoll_fd = -1;
  s->server.ctx = -1;
  s->server.ssl = -1;
  // s->server->handler = did_req_handler;

  // Connection to ION
  s->client.socket_fd = prepare_client_socket("52.153.152.19", 443);
  if (s->client.socket_fd < 0) {
    obv_err("Error creating client socket for doc_fetch_service\n");
    return -1;
  }
  s->client.epoll_fd = -1;
  s->client.ctx = init_ssl_client_ctx();
  if (s->client.ctx < 0) {
    obv_err("Error creating client ctx\n");
    return -1;
  }
  s->client.ssl = -1;
  s->client.handler = NULL;

  pthread_mutex_init(&s->server.send_lock, NULL);
  pthread_mutex_init(&s->server.recv_lock, NULL);
  pthread_mutex_init(&s->client.send_lock, NULL);
  pthread_mutex_init(&s->client.recv_lock, NULL);

  return 0;
}

int init_did_req_service(struct service *s) {
  // DID Request server
  s->server.socket_fd = prepare_server_socket(DID_REQ_PORT);
  if (s->server.socket_fd == -1)
    return -1;
  s->server.epoll_fd = prepare_epoll(s->server.socket_fd);
  if (s->server.epoll_fd == -1)
    return -1;
  s->server.ctx = init_ssl_server_ctx();
  if (s->server.ctx < 0)
    return -1;
  s->server.ssl = -1;
  // s->server->handler = did_req_handler;

  // Connection to UR
  s->client.socket_fd = prepare_client_socket("115.145.154.183", 8080);
  if (s->client.socket_fd < 0) {
    obv_err("Error creating client socket for did_req_service\n");
    return -1;
  }

  int yes = 1;
  setsockopt(s->client.socket_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&yes,
             sizeof(int));

  s->client.epoll_fd = -1;
  s->client.ctx = -1;
  s->client.ssl = -1;
  s->client.handler = NULL;

  pthread_mutex_init(&s->server.send_lock, NULL);
  pthread_mutex_init(&s->server.recv_lock, NULL);
  pthread_mutex_init(&s->client.send_lock, NULL);
  pthread_mutex_init(&s->client.recv_lock, NULL);

  return 0;
}

int init_drf_recv_service(struct service *s) {
  // DRF Recv server, no TLS
  s->server.socket_fd = prepare_server_socket(DRF_RECV_PORT);
  if (s->server.socket_fd == -1) {
    obv_err("failed creating epoll fd\n");
    return -1;
  }
  s->server.epoll_fd = prepare_epoll(s->server.socket_fd);
  if (s->server.epoll_fd == -1) {
    obv_err("failed creating epoll fd\n");
    return -1;
  }
  s->server.ctx = -1;
  s->server.ssl = -1;
  s->server.handler = NULL;

  // Not used
  s->client.socket_fd = -1;
  s->client.epoll_fd = -1;
  s->client.ctx = -1;
  s->client.ssl = -1;
  s->client.handler = NULL;

  pthread_mutex_init(&s->server.send_lock, NULL);
  pthread_mutex_init(&s->server.recv_lock, NULL);
  pthread_mutex_init(&s->client.send_lock, NULL);
  pthread_mutex_init(&s->client.recv_lock, NULL);

  return 0;
}

void *doc_fetch_worker_thread(struct service *s) {
  int ret;
  int sgxStatus;
  long ctx = s->client.ctx;
  long ssl;
  // std::string eph_did;
  // DocFetchReq req;
  char eph_did[MAX_DID_SIZE];
  char base_addr[MAX_BASE_ADDR_SIZE];

  int requester_sock;
  obv_debug("[%lx]Entering Doc Fetch event looop\n", pthread_self());

  // Make TLS connection to BCNet before entering loop
  // socket connection to bc net was made during init
  sgxStatus = enc_wolfSSL_new(enclave_id, &s->client.ssl, s->client.ctx);
  if (sgxStatus != SGX_SUCCESS || s->client.ssl < 0) {
    obv_err("wolfSSL_new failure\n");
    return NULL;
  }

  sgxStatus =
      enc_wolfSSL_set_fd(enclave_id, &ret, s->client.ssl, s->client.socket_fd);
  if (sgxStatus != SGX_SUCCESS || ret != SSL_SUCCESS) {
    obv_err("wolfSSL_set_fd failure\n");
    return NULL;
  }

  // keep this connection
  // If this disconnects make socket keep-alive
  // sgxSntatus = enc_wolfSSL_connect(enclave_id, &ret, s->client.ssl);
  // if (sgxStatus != SGX_SUCCESS || ret != SSL_SUCCESS) {
  //   obv_err("wolfSSL_connect failure\n");
  //   return NULL;
  // }

  std::pair<std::string, std::string> req;
  while (1) {
    if (kill_services == 1)
      return NULL;
    if (docFetchQueue.dequeue(req) == true) {

      obv_debug("Dequeued %s/%s\n", req.first.c_str(), req.second.c_str());

      // Input: ssl handle to blockchain net
      // Enter sgx to fetch doc and return to requester

      strncpy(base_addr, req.first.c_str(), MAX_BASE_ADDR_SIZE);
      strncpy(eph_did, req.second.c_str(), MAX_DID_SIZE);

      sgxStatus =
	ecall_handle_doc_fetch(enclave_id, &requester_sock, s->client.ssl, base_addr,
                                 MAX_BASE_ADDR_SIZE, eph_did, MAX_DID_SIZE);
      
      if (sgxStatus != SGX_SUCCESS || requester_sock == -1) {
        obv_err("ecall_handle_doc_fetch failure\n");
        return NULL;
      }
      // Now disconnect requester
      obv_debug("Closing requester sock %d\n", requester_sock );
      close(requester_sock);
    }
    
  }

  return NULL;
}

#define RESPONSE "HTTP/1.1 200 OK\r\n\r\n"
void *drf_recv_worker_thread(struct service *s) {
  int i, ret, sgxStatus;
  int events_cnt;
  long ssl;
  // struct thread_data thread_data;
  int conn_fd;
  struct epoll_event events[EVENTS_BUFF_SZ];

  struct sockaddr_in conn_addr;
  socklen_t addrlen = sizeof(struct sockaddr_in);

  char buf[DRF_MAX_LEN];

  obv_debug("[%lx]Entering DRF Recv event looop\n", pthread_self());
  while (1) {
    if (kill_services == 1)
      return NULL;

    events_cnt = epoll_wait(s->server.epoll_fd, events, EVENTS_BUFF_SZ, 0);
    if (events_cnt < 0) {
      obv_err("[EventLoop] epoll_wait() error\n");
      return NULL;
    }
    for (i = 0; i < events_cnt; i++) {
      // Event at server fd, new connection
      if (events[i].data.fd == s->server.socket_fd) {
        obv_debug("[EventLoop] Accepting connect from Driver\n");
        conn_fd = accept(s->server.socket_fd,
                                     (struct sockaddr *)&conn_addr, &addrlen);
        if (conn_fd < 0) {
          obv_err("[DRF_RECV] Error accepting connection from driver\n");
          continue;
        }

        // Receive DRF
        ret = recv(conn_fd, buf, DRF_MAX_LEN, 0);
        if (ret < 0) {
          obv_err("[DRF_RECV] Error receiving from driver\n");
          continue;
        }
        // Send OK
        ret = send(conn_fd, RESPONSE, sizeof(RESPONSE), 0);
        if (ret < 0) {
          obv_err("[DRF_RECV] Error receiving from driver\n");
          continue;
        }
	close(conn_fd);
        obv_debug("[%lx] DRF Received:\n %s\n", pthread_self(), buf);

        // POST / HTTP/1.1
        //   Host: dockerhost:8081
        // 	  Connection: Keep-Alive
        // 	  Request-Id: |83715629-4b7b786857706367.1.
        // 	  Content-Type: application/json
        // 	  Content-Length: 144

        // 	  {"baseAddress":"https://beta.discover.did.microsoft.com/1.0/identifiers/","identifier":"did:ion:O4eKUHlbRSphlUsHiJMnBM63ZX8jkkyiApKA6uzOtz5Tne"}

        // Handle DRF Here and extract DRF
        std::string data = buf;
        data.erase(0, data.find("{"));

        Json::Reader reader;
        Json::Value root;

        reader.parse(data, root);

        const Json::Value &baseAddr = root["baseAddress"];
        const Json::Value &eph_did = root["identifier"];

        // std::cout << baseAddr.asString() << std::endl;
        // std::cout << eph_did.asString() << std::endl;

        // Place docfetch request in queuem
        // DocFetchReq* req = new DocFetchReq();

        obv_debug("Final URL:%s/%s\n", baseAddr.asCString(),
                  eph_did.asCString());

        auto req = std::make_pair(baseAddr.asString(), eph_did.asString());
        docFetchQueue.enqueue(req);
        // req.eph_did
        //     .erase(0, )
        //     // Queue eph_did request for docFetch Service
        //     docFetchQueue.enqueue(req);

        // Convert it to std::string
        // std::string req_eph_did = eph_did;

        // Put it in the queue
        // docFetchQueue.enqueue(req_eph_did);

        // Now enter SGX to

        // For performance testing
        // close(thread_data.conn_fd);
        // Send ephDID to UR
        // May check if connection is alive?
        // ret = send(s->client.socket_fd, eph_did, strlen(eph_did), 0);
        // if (ret < 0) {
        //   obv_debug("Error sending Eph_DID to UR\n");
        //   continue;
        // }

      }

      else {
        obv_debug("[%lx] Got event on existing connection\n", pthread_self());
        obv_debug("[%lx] We don't handle this case\n", pthread_self());
      }
    }
  }
}

void *did_req_worker_thread(struct service *s) {
  int i, ret, sgxStatus;
  int events_cnt;
  long ssl;
  struct thread_data thread_data;
  struct epoll_event events[EVENTS_BUFF_SZ];

  struct sockaddr_in conn_addr;
  socklen_t addrlen = sizeof(struct sockaddr_in);

  char did_method[MAX_DID_METHOD_SIZE];
  char eph_did[MAX_DID_SIZE];
  char req2ur[256];
  char dummy[2048];
  obv_debug("[%lx][DID_REQ] Entering DID Req event looop\n", pthread_self());

  // Individual connection to UR
  int sock_fd;
  struct sockaddr_in clientaddr;

  sock_fd = socket(AF_INET, SOCK_STREAM, 0);

  clientaddr.sin_family = AF_INET;
  clientaddr.sin_port = htons(8080);
  inet_pton(AF_INET, "115.145.154.183", &clientaddr.sin_addr);

  if (connect(sock_fd, (struct sockaddr *)&clientaddr, sizeof(clientaddr)) <
      0) {
    perror("Error connecting to client ");
  }

  while (1) {
    if (kill_services == 1)
      return NULL;

    events_cnt = epoll_wait(s->server.epoll_fd, events, EVENTS_BUFF_SZ, 0);
    if (events_cnt < 0) {
      obv_err("[DID_REQ] epoll_wait() error\n");
      return NULL;
    }
    for (i = 0; i < events_cnt; i++) {
      // Event at server fd, new connection
      if (events[i].data.fd == s->server.socket_fd) {
        obv_debug("[DID_REQ] Accepting client\n");
        thread_data.conn_fd = accept(s->server.socket_fd,
                                     (struct sockaddr *)&conn_addr, &addrlen);
        if (thread_data.conn_fd < 0)
          continue;

        // events[i].events = EPOLLIN | EPOLLET | EPOLLONESHOT;

        // SSL Handshake
        ssl = create_ssl_conn(s->server.ctx, thread_data.conn_fd);
        if (ret == -1) {
          obv_debug("Error creating ssl channel\n");
          continue;
        }

        // Don't read/write ssl in untrusted for thread safety
        // Receive DID, create EphDID in enclave
        // Enclave returns "did:{method}:{identifier}"
        sgxStatus =
            ecall_handle_did_req(enclave_id, ssl, eph_did, MAX_DID_SIZE);
        if (sgxStatus != SGX_SUCCESS)
          continue;

        obv_debug("[%lx][DID_REQ] Received DID Method: %s\n", pthread_self(),
                  did_method);
        obv_debug("[%lx][DID_REQ] Received EphDID: %s\n", pthread_self(),
                  eph_did);
        snprintf(
            req2ur, sizeof(req2ur),
            "GET /1.0/identifiers/%s "
            "HTTP/1.1\r\nHost:localhost:8080\r\nUser-Agent: "
            "curl/7.68.0\r\nAccept: */*\r\nCache-Control: no-cache\r\n\r\n",
            eph_did);

        ret = send(sock_fd, req2ur, strlen(req2ur), 0);
        if (ret < 0) {
          obv_err("Error sending Eph_DID to UR\n");
          continue;
        }
        obv_debug("[%ld]Sent : \n%s", pthread_self(), req2ur);

        ret = recv(sock_fd, dummy, 2048, 0);
        if (ret < 0) {
          obv_err("[DRF_RECV] Error receiving dummy response from UR\n");
          continue;
        }

        close(sock_fd);

	// Reconnect
        sock_fd = socket(AF_INET, SOCK_STREAM, 0);

        clientaddr.sin_family = AF_INET;
        clientaddr.sin_port = htons(8080);
        inet_pton(AF_INET, "115.145.154.183", &clientaddr.sin_addr);

        if (connect(sock_fd, (struct sockaddr *)&clientaddr,
                    sizeof(clientaddr)) < 0) {
          perror("Error connecting to client ");
        }

        // close(s->client.socket_fd);

        // s->client.socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        // struct sockaddr_in clientaddr;
        // clientaddr.sin_family = AF_INET;
        // clientaddr.sin_port = htons(8080);
        // inet_pton(AF_INET, "127.0.0.1", &clientaddr.sin_addr);

        // if (connect(s->client.socket_fd, (struct sockaddr *)&clientaddr,
        //             sizeof(clientaddr)) < 0) {
        //   obv_err("Error reconnecting to UR\n");
        //   perror("Error connecting to client ");
        // }

        // For performance testing
        // close(thread_data.conn_fd);
        // Send ephDID to UR
        // May check if connection is alive?

        // snprintf(req2ur, sizeof(req2ur), UNIV_REQ, eph_did);
        // snprintf(
        // 	 req2ur, sizeof(UNIV_REQ)+MAX_DID_SIZE,
        // 	 "GET /1.0/identifiers/did: HTTP/1.1\r\nHost:
        // localhost:8080\r\n",

        // snprintf(req2ur, sizeof(UNIV_REQ)+MAX_DID_SIZE, "%s%s"

        // char buf[256];
        // recv(s->client.socket_fd, buf, 256, 0);
        // printf("UR replied: %s\n", buf);

      }

      else {
        obv_err("[%lx] Got event on existing connection\n", pthread_self());
        obv_err("[%lx] We don't handle this case\n", pthread_self());
      }
    }
  }
}

int main(int argc, char *argv[]) {
  int ret, i;
  int sgxStatus;

  signal(SIGINT, destroy_oblivira);

  // Initialize WolfSSL
  init_service_server();

  // Initialize thread pools
  ServicePool.init();
  DocFetchPool.init();

  struct service did_req_service, drf_recv_service, doc_fetch_service;

  /* Initialize the enclave */
  if (initialize_enclave(&enclave_id) < 0)
    return 1;

  // for (i = 0; i < MAX_MAP_SIZE; ++i) {
  //   eph_ssl[i].is_empty = true;
  // }

  ret = init_did_req_service(&did_req_service);
  if (ret < 0) {
    obv_err("Error Initializing service\n");
    exit(1);
  }

  ret = init_drf_recv_service(&drf_recv_service);
  if (ret < 0) {
    obv_err("Error Initializing service\n");
    exit(1);
  }

  ret = init_doc_fetch_service(&doc_fetch_service);
  if (ret < 0) {
    obv_err("Error Initializing service\n");
    exit(1);
  }

  struct thread_data thread_data;

  obv_print("Starting worker threads\n");

  for (i = 0; i < NUM_DID_REQ_THR; i++) {
    ServicePool.submit(did_req_worker_thread, &did_req_service);
  }

  for (i = 0; i < NUM_DRF_RECV_THR; i++) {
    ServicePool.submit(drf_recv_worker_thread, &drf_recv_service);
  }

  for (i = 0; i < NUM_DOC_FETCH_THR; i++) {
    DocFetchPool.submit(doc_fetch_worker_thread, &doc_fetch_service);
  }

  // for (i = 0; i < NUM_DRF_RECV_THR; i++) {
  //   DocFetchPool.submit(worker_thread, &did_doc_fetch_service);
  // }
  while (1) {
    if (kill_services == 1)
      return NULL;
    char c = '\0';
    c = getchar();
    if ((c == 'q') || (c == EOF)) // stop if EOF or 'q'.
      break;
  }

  // destroy_oblivira(SIGTERM);

  return 0;
}
