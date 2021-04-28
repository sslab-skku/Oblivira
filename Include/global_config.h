#ifndef __OBLIVIRA_GLOBAL_CONFIG_H__
#define __OBLIVIRA_GLOBAL_CONFIG_H__

#include <stdint.h>
#include <string.h>

#define MAX_BASE_ADDR_SIZE          64
#define MAX_QUERY_SIZE              512

#define ADDITIONAL_METADATA_SIZE    24
#define AES_GCM_BLOCK_SIZE_IN_BYTES 16
#define HASH_LENGTH                 32
#define ID_SIZE_IN_BYTES            4
#define IV_LENGTH                   12
#define MEM_POSMAP_LIMIT            1024 * 1024
#define NONCE_LENGTH                16
#define KEY_LENGTH                  16
#define TAG_SIZE                    16

#define MAX_DID_SIZE                64 // did
#define DATA_SIZE                   4096 // temporal did_docs size
#define MAX_BLOCKS                  128 // maximum capacity of PathORAM tree
#define STASH_SIZE                  32 // It is typically sufficient to use 150 for PathORAM
#define RECURSION_DATA_SIZE         64 // recursion_data_size can be used to tailor the data size of the recursive ORAM trees, since currently OC uses ids of 4 bytes, recursion sie of 64, gives us a compression factor 16 with each level of recrusion.
#define SIZE_Z                      4 // Z is the number of blocks in a bucket of the ORAMTree, typically PathORAM uses Z=4

//#define OBLIVIRA_CACHE_ENABLED
#define OBLIVIRA_PRINT_LOG

// Inline functions
inline bool isBlockDummy(unsigned char *serialized_block, uint64_t gN){
    bool dummy_flag = *((uint32_t*)(serialized_block+16))==gN;
    return dummy_flag;
}

inline uint32_t getId(unsigned char *serialized_block){
    uint32_t id = *((uint32_t*)(serialized_block+16));
    return id;
}

inline uint32_t* getIdPtr(unsigned char *serialized_block){
    uint32_t *id = ((uint32_t*)(serialized_block+16));
    return id;
}

inline void setId(unsigned char *serialized_block, uint32_t new_id){
    *((uint32_t*)(serialized_block+16)) = new_id;
}

inline uint32_t getTreeLabel(unsigned char *serialized_block){
    uint32_t treeLabel = *((uint32_t*)(serialized_block+20));
    return treeLabel;
}

inline uint32_t* getTreeLabelPtr(unsigned char *serialized_block){
    uint32_t *labelptr = ((uint32_t*)(serialized_block+20));
    return labelptr;
}

inline uint32_t ShiftBy(uint32_t n, uint32_t w) {
    return(n>>w);
}

inline unsigned char* getDataPtr(unsigned char* decrypted_path_ptr){
    return (unsigned char*) (decrypted_path_ptr+24);
}

#endif