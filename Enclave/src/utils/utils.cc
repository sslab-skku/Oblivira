#include "utils/utils.hh"


#ifdef OBLIVIRA_CACHE_ENABLED
PathORAM *pathoram;
DIDMap *DIDmap;

bool lock = false;
unsigned char dummy_buf[DATA_SIZE] = {'\0'};
#endif

std::string gen_eph_did(const size_t len)
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