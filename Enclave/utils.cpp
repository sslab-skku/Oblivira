#include "utils.h"

#ifdef OBLIVIRA_CACHE_ENABLED
PathORAM *pathoram;
DIDMap *DIDmap;

bool lock = false;
unsigned char dummy_buf[DATA_SIZE] = {'\0'};
#endif


void printf(const char *fmt, ...)
{

  char buf[BUFSIZ] = {'\0'};
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, BUFSIZ, fmt, ap);
  va_end(ap);
  ocall_print_string(buf);

}

int sprintf(char *buf, const char *fmt, ...)
{
  va_list ap;
  int ret;
  va_start(ap, fmt);
  ret = vsnprintf(buf, BUFSIZ, fmt, ap);
  va_end(ap);
  return ret;
}

double current_time(void)
{
  double curr;
  ocall_current_time(&curr);
  return curr;
}

int LowResTimer(void) /* low_res timer */
{
  int time;
  ocall_low_res_time(&time);
  return time;
}

size_t recv(int sockfd, void *buf, size_t len, int flags)
{
  size_t ret;
  int sgxStatus;
  sgxStatus = ocall_recv(&ret, sockfd, buf, len, flags);
  return ret;
}

size_t send(int sockfd, const void *buf, size_t len, int flags)
{
  size_t ret;
  int sgxStatus;
  sgxStatus = ocall_send(&ret, sockfd, buf, len, flags);
  return ret;
}


std::string gen_eph_did(size_t len)
{
    int i;
    unsigned char rand;
    std::string eph_did = "";
    static const char alphanum[] = "0123456789"
                                   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "abcdefghijklmnopqrstuvwxyz";

    for (i = 0; i < len; i++)
    {
        sgx_read_rand(&rand, 1);
        rand = rand % 62;
        eph_did += alphanum[rand];
    }
    return eph_did;
}

#ifdef OBLIVIRA_CACHE_ENABLED
void initialize_cache(uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t recursion_data_size, int8_t recursion_levels, uint8_t Z)
{
    pathoram = new PathORAM();
    DIDmap = new DIDMap();

    pathoram->Create(Z, max_blocks, data_size, stash_size, recursion_data_size, recursion_levels);
    DIDmap->initialize();

    return;
}

int cache_access(const char *did, char *did_doc, char op_type)
{
    int id;

    if (lock)
        return -1;

    lock = true;

    id = DIDmap->convertDIDToBlockID((unsigned char *)did, op_type);

    if (id == -1)
    {
        lock = false;
        return 0;
    }

    unsigned char *data_in, *data_out;
    if (op_type == 'r')
    {
        data_in = dummy_buf;
        data_out = (unsigned char *)did_doc;
    }
    else
    {
        data_in = (unsigned char *)did_doc;
        data_out = dummy_buf;
    }
    pathoram->Access(id, op_type, data_in, data_out);

    lock = false;

    return 1;
}
#endif

int get_dids(const char *eph_did, char *ret)
{
    for (int i = 0; i < MAX_MAP_SIZE; ++i)
    {
        if (!strncmp(map_did[i].eph_did, eph_did, strlen(map_did[i].eph_did) + 1) && map_did[i].is_used)
        {
            strncpy(ret, map_did[i].did, MAX_DID_SIZE);
            return 0;
        }
    }
    return -1;
}

int set_dids(const char *eph_did, const char *did)
{
    for (int i = 0; i < MAX_MAP_SIZE; ++i)
    {
        if (!map_did[i].is_used)
        {
            strncpy(map_did[i].eph_did, eph_did, MAX_DID_SIZE);
            strncpy(map_did[i].did, did, MAX_DID_SIZE);
            map_did[i].is_used = true;
            return 0;
        }
    }
    return -1;
}

int rm_dids(const char *eph_did)
{
    for (int i = 0; i < MAX_MAP_SIZE; ++i)
    {
        if (!strncmp(map_did[i].eph_did, eph_did, strlen(map_did[i].eph_did) + 1))
        {
            sgx_thread_mutex_lock(&map_did->m);
            map_did[i].is_used = false;
            sgx_thread_mutex_unlock(&map_did->m);
            return 0;
        }
    }
    return -1;
}
