#ifndef __LOCALSTORAGE_HPP__
#define __LOCALSTORAGE_HPP__

#include <cstdint>

class LocalStorage
{
public:
    uint32_t Z;
    uint32_t D;
    uint8_t recursion_levels;
    uint64_t gN;

    unsigned char **inmem_tree_l;
    unsigned char **inmem_hash_l;

    uint64_t *blocks_in_level;
    uint64_t *buckets_in_level;
    uint64_t *real_max_blocks_level;
    uint32_t *D_level;

    uint32_t bucket_size;

    uint32_t data_block_size;
    uint32_t recursion_block_size;

    LocalStorage();
    void setParams(uint32_t max_blocks, uint32_t D, uint32_t Z, uint32_t stash_size, uint32_t data_size, uint32_t recursion_block_size, uint8_t recursion_levels);

    uint8_t uploadBucket(uint32_t bucket_id, unsigned char *serialized_bucket, uint32_t bucket_size, unsigned char *hash, uint32_t hash_size, uint8_t level);
    uint8_t uploadPath(uint32_t leaf_label, unsigned char *path, unsigned char *path_hash, uint8_t level, uint32_t p_D);
    uint8_t downloadBucket(uint32_t bucket_id, unsigned char *bucket, uint32_t bucket_size, unsigned char *hash, uint32_t hash_size, uint8_t level);
    unsigned char *downloadPath(uint32_t leaf_label, unsigned char *path, unsigned char *path_hash, uint32_t path_hash_size, uint8_t level, uint32_t p_D);

    void fetchHash(uint32_t bucket_id, unsigned char *hash, uint32_t hash_size, uint8_t recursion_level);

    void showPath_reverse(unsigned char *decrypted_path, uint8_t Z, uint32_t d, uint32_t data_size);
};

uint8_t computeRecursionLevels(uint32_t max_blocks, uint32_t recursion_data_size, uint64_t onchip_posmap_memory_limit);

#endif