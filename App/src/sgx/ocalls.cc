#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#include "localstorage/localstorage.hh"

#include "Enclave_u.h"

extern LocalStorage *ls;

/* OCall functions */
void uprint(const char *str)
{
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  printf("%s", str);
  fflush(stdout);
}

void usgx_exit(int reason)
{
  printf("usgx_exit: %d\n", reason);
  exit(reason);
}

static double current_time()
{
  struct timeval tv;
  gettimeofday(&tv, NULL);

  return (double)(1000000 * tv.tv_sec + tv.tv_usec) / 1000000.0;
}

void ocall_print_string(const char *str)
{
  /* Proxy/Bridge will check the length and null-terminate
   * the input string to prevent buffer overflow.
   */
  printf("%s", str);
}

void ocall_current_time(double *time)
{
  if (!time)
    return;
  *time = current_time();
  return;
}

void ocall_low_res_time(int *time)
{
  struct timeval tv;
  if (!time)
    return;
  *time = tv.tv_sec;
  return;
}

size_t ocall_recv(int sockfd, void *buf, size_t len, int flags)
{
  return recv(sockfd, buf, len, flags);
}

size_t ocall_send(int sockfd, const void *buf, size_t len, int flags)
{
  return send(sockfd, buf, len, flags);
}

uint8_t ocall_uploadBucket(unsigned char *serialized_bucket, uint32_t bucket_size, uint32_t label, unsigned char *hash, uint32_t hash_size, uint32_t size_for_level, uint8_t recursion_level)
{
  ls->uploadBucket(label, serialized_bucket, size_for_level, hash, hash_size, recursion_level);
  return 0;
}

uint8_t ocall_uploadPath(unsigned char *path_array, uint32_t path_size, uint32_t leaf_label, unsigned char *path_hash, uint32_t path_hash_size, uint8_t level, uint32_t D_level)
{
  ls->uploadPath(leaf_label, path_array, path_hash, level, D_level);
  return 0;
}

uint8_t ocall_downloadBucket(unsigned char *serialized_bucket, uint32_t bucket_size, uint32_t label, unsigned char *hash, uint32_t hash_size, uint32_t size_for_level, uint8_t recursion_level)
{
  ls->downloadBucket(label, serialized_bucket, size_for_level, hash, hash_size, recursion_level);
  return 0;
}

uint8_t ocall_downloadPath(unsigned char *path_array, uint32_t path_size, uint32_t leaf_label, unsigned char *path_hash, uint32_t path_hash_size, uint8_t level, uint32_t D_level)
{
  ls->downloadPath(leaf_label, path_array, path_hash, path_hash_size, level, D_level);
  return 0;
}

void ocall_buildFetchChildHash(uint32_t left, uint32_t right, unsigned char *lchild, unsigned char *rchild, uint32_t hash_size, uint32_t recursion_level)
{
  ls->fetchHash(left, lchild, hash_size, recursion_level);
  ls->fetchHash(right, rchild, hash_size, recursion_level);
}