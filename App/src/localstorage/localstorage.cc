#include "localstorage/localstorage.hh"
#include "global_config.h"

#if defined(OBLIVIRA_PRINT_LOG)
#include <stdio.h>
#endif

#include <stdlib.h>
#include <math.h>

LocalStorage::LocalStorage()
{
}

void LocalStorage::setParams(uint32_t max_blocks, uint32_t p_D, uint32_t p_Z, uint32_t stash_size, uint32_t data_size, uint32_t p_recursion_block_size, uint8_t p_recursion_levels)
{
    data_block_size = data_size;
    D = p_D;
    Z = p_Z;
    recursion_block_size = p_recursion_block_size;
    recursion_levels = p_recursion_levels;
    bucket_size = data_size * Z;

    uint64_t datatree_size = (pow(2, D + 1) - 1) * (bucket_size);
    uint64_t hashtree_size = ((pow(2, D + 1) - 1) * (HASH_LENGTH));

    if (recursion_levels == 1)
    {
        inmem_tree_l = (unsigned char **)malloc(sizeof(unsigned char *));
        inmem_hash_l = (unsigned char **)malloc(sizeof(unsigned char *));
        inmem_tree_l[0] = (unsigned char *)malloc(datatree_size);
        inmem_hash_l[0] = (unsigned char *)malloc(hashtree_size);
        blocks_in_level = (uint64_t *)malloc((recursion_levels) * sizeof(uint64_t *));
        buckets_in_level = (uint64_t *)malloc((recursion_levels) * sizeof(uint64_t *));
        blocks_in_level[0] = max_blocks;
    }
    else
    {
        uint32_t x = (recursion_block_size - ADDITIONAL_METADATA_SIZE) / sizeof(uint32_t);

        uint64_t size_pmap0 = max_blocks * sizeof(uint32_t);
        uint64_t cur_pmap0_blocks = max_blocks;
        while (size_pmap0 > MEM_POSMAP_LIMIT)
        {
            cur_pmap0_blocks = (uint64_t)ceil((double)cur_pmap0_blocks / (double)x);
            size_pmap0 = cur_pmap0_blocks * sizeof(uint32_t);
        }

        blocks_in_level = (uint64_t *)malloc((recursion_levels) * sizeof(uint64_t *));
        buckets_in_level = (uint64_t *)malloc((recursion_levels) * sizeof(uint64_t *));
        real_max_blocks_level = (uint64_t *)malloc((recursion_levels) * sizeof(uint64_t));

        uint8_t max_recursion_level_index = recursion_levels - 1;
        real_max_blocks_level[max_recursion_level_index] = max_blocks;
        int32_t lev = max_recursion_level_index - 1;
        while (lev >= 0)
        {
            real_max_blocks_level[lev] = ceil((double)real_max_blocks_level[lev + 1] / (double)x);
            lev--;
        }

        blocks_in_level[0] = cur_pmap0_blocks;
        for (uint32_t i = 1; i <= max_recursion_level_index; i++)
        {
            blocks_in_level[i] = blocks_in_level[i - 1] * x;
        }

        gN = blocks_in_level[max_recursion_level_index];

        inmem_tree_l = (unsigned char **)malloc((recursion_levels) * sizeof(unsigned char *));
        inmem_hash_l = (unsigned char **)malloc((recursion_levels) * sizeof(unsigned char *));

        for (uint32_t i = 0; i < recursion_levels; i++)
        {
            uint64_t level_size;
            uint32_t pD_temp = ceil((double)blocks_in_level[i] / (double)Z);
            uint32_t pD = (uint32_t)ceil(log((double)pD_temp) / log((double)2));
            uint64_t pN = (int)pow((double)2, (double)pD);
            uint64_t tree_size = 2 * pN - 1;
            buckets_in_level[i] = tree_size;

            if (i == recursion_levels - 1)
                level_size = tree_size * ((uint64_t)(Z * (data_size + ADDITIONAL_METADATA_SIZE)));
            else
                level_size = tree_size * ((uint64_t)(Z * (recursion_block_size + ADDITIONAL_METADATA_SIZE)));

            uint64_t hashtree_size = (uint64_t)(tree_size * (uint64_t)(HASH_LENGTH));

            //Setup Memory locations for hashtree and recursion block
            inmem_tree_l[i] = (unsigned char *)malloc(level_size);
            inmem_hash_l[i] = (unsigned char *)malloc(hashtree_size);
        }
    }
}

uint8_t LocalStorage::uploadBucket(uint32_t bucket_id, unsigned char *bucket, uint32_t bucket_size, unsigned char *hash, uint32_t hash_size, uint8_t recursion_level)
{
    uint64_t pos = ((uint64_t)(Z * bucket_size)) * ((uint64_t)(bucket_id - 1));

    memcpy(inmem_tree_l[recursion_level] + (pos), bucket, (bucket_size * Z));
    memcpy(inmem_hash_l[recursion_level] + (HASH_LENGTH * (bucket_id - 1)), hash, HASH_LENGTH);

    return 0;
}

uint8_t LocalStorage::uploadPath(uint32_t leaf_label, unsigned char *path, unsigned char *path_hash, uint8_t level, uint32_t D_level)
{
    uint32_t size_for_level;

    if (level == recursion_levels - 1)
        size_for_level = data_block_size;
    else
        size_for_level = recursion_block_size;

    uint32_t temp = leaf_label;
    unsigned char *path_iter = path;
    unsigned char *path_hash_iter = path_hash;

    for (uint8_t i = 0; i < D_level; i++)
    {
        memcpy(inmem_tree_l[level] + ((Z * size_for_level) * (temp - 1)), path_iter, (Z * size_for_level));
        memcpy(inmem_hash_l[level] + (HASH_LENGTH * (temp - 1)), path_hash_iter, HASH_LENGTH);
        path_hash_iter += HASH_LENGTH;
        path_iter += (Z * size_for_level);
        temp = temp >> 1;
    }

    return 0;
}

uint8_t LocalStorage::downloadBucket(uint32_t bucket_id, unsigned char *bucket, uint32_t bucket_size, unsigned char *hash, uint32_t hash_size, uint8_t level)
{
    uint64_t pos;
    uint32_t size_for_level;

    if (level == recursion_levels - 1)
        size_for_level = data_block_size;
    else
        size_for_level = recursion_block_size;

    memcpy(bucket, inmem_tree_l[level] + ((Z * size_for_level) * (bucket_id - 1)), (Z * size_for_level));
    memcpy(hash, inmem_hash_l[level] + (HASH_LENGTH * (bucket_id - 1)), HASH_LENGTH);

    return 0;
}

unsigned char *LocalStorage::downloadPath(uint32_t leaf_label, unsigned char *path, unsigned char *path_hash, uint32_t path_hash_size, uint8_t level, uint32_t p_D)
{
    uint32_t size_for_level;

    if (level == recursion_levels - 1)
        size_for_level = data_block_size;
    else
        size_for_level = recursion_block_size;

    uint32_t temp = leaf_label;
    unsigned char *path_iter = path;
    unsigned char *path_hash_iter = path_hash;

    for (uint8_t i = 0; i < p_D; i++)
    {
        memcpy(path_iter, inmem_tree_l[level] + ((Z * size_for_level) * (temp - 1)), (Z * size_for_level));
        if (i != p_D - 1)
        {
            if (temp % 2 == 0)
            {
                memcpy(path_hash_iter, inmem_hash_l[level] + (HASH_LENGTH * (temp - 1)), HASH_LENGTH);
                path_hash_iter += HASH_LENGTH;
                memcpy(path_hash_iter, inmem_hash_l[level] + (HASH_LENGTH * (temp)), HASH_LENGTH);
                path_hash_iter += HASH_LENGTH;
            }
            else
            {
                memcpy(path_hash_iter, inmem_hash_l[level] + (HASH_LENGTH * (temp - 2)), HASH_LENGTH);
                path_hash_iter += HASH_LENGTH;
                memcpy(path_hash_iter, inmem_hash_l[level] + (HASH_LENGTH * (temp - 1)), HASH_LENGTH);
                path_hash_iter += HASH_LENGTH;
            }
        }
        else
        {
            memcpy(path_hash_iter, inmem_hash_l[level] + (HASH_LENGTH * (temp - 1)), HASH_LENGTH);
            path_hash_iter += (HASH_LENGTH);
        }

        path_iter += (Z * size_for_level);
        temp = temp >> 1;
    }

    return path;
}

void LocalStorage::fetchHash(uint32_t bucket_id, unsigned char *hash, uint32_t hash_size, uint8_t recursion_level)
{
    memcpy(hash, inmem_hash_l[recursion_level] + ((bucket_id - 1) * HASH_LENGTH), HASH_LENGTH);
}

void LocalStorage::showPath_reverse(unsigned char *decrypted_path, uint8_t Z, uint32_t d, uint32_t data_size)
{
    //TODO: gN is hardcoded here for quick debugging
    uint32_t gN = 100;
#if defined(OBLIVIRA_PRINT_LOG)
    printf("\n\nIN LS: showPath_reverse (Root to leaf): \n");
#endif
    uint32_t block_size = data_size + ADDITIONAL_METADATA_SIZE;
    unsigned char *decrypted_path_iter = decrypted_path + ((uint64_t)((Z * (d - 1))) * uint64_t(block_size));

    if (data_size == recursion_block_size - 24)
    {
        for (uint32_t i = 0; i < d; i++)
        {
            unsigned char *bucket_iter = decrypted_path_iter;

            for (uint32_t j = 0; j < Z; j++)
            {
#if defined(OBLIVIRA_PRINT_LOG)
                printf("(%d,%d) :", getId(bucket_iter), getTreeLabel(bucket_iter));
#endif
                uint32_t no = (data_size) / sizeof(uint32_t);
                uint32_t *data_iter = (uint32_t *)(bucket_iter + ADDITIONAL_METADATA_SIZE);
                unsigned char *data_ptr = (unsigned char *)(bucket_iter + ADDITIONAL_METADATA_SIZE);
#if defined(OBLIVIRA_PRINT_LOG)
                if (getId(bucket_iter) == gN)
                {
                    for (uint8_t q = 0; q < data_size; q++)
                        printf("%c", data_ptr[q]);
                }
                else
                {
                    for (uint8_t q = 0; q < no; q++)
                        printf("%d,", data_iter[q]);
                }

                printf("\n");
#endif
                bucket_iter += block_size;
            }
#if defined(OBLIVIRA_PRINT_LOG)
            printf("\n");
#endif
            decrypted_path_iter -= (Z * block_size);
        }
    }
    else
    {
        for (uint32_t i = 0; i < d; i++)
        {
            unsigned char *bucket_iter = decrypted_path_iter;

            for (uint32_t j = 0; j < Z; j++)
            {
#if defined(OBLIVIRA_PRINT_LOG)
                printf("(%d,%d) :", getId(bucket_iter), getTreeLabel(bucket_iter));
#endif
                unsigned char *data_ptr = (unsigned char *)(bucket_iter + ADDITIONAL_METADATA_SIZE);
#if defined(OBLIVIRA_PRINT_LOG)
                for (uint8_t q = 0; q < data_size; q++)
                    printf("%c", data_ptr[q]);

                printf("\n");
#endif
                bucket_iter += (block_size);
            }
#if defined(OBLIVIRA_PRINT_LOG)
            printf("\n");
#endif
            decrypted_path_iter -= (Z * block_size);
        }
    }
}

uint8_t computeRecursionLevels(uint32_t max_blocks, uint32_t recursion_data_size, uint64_t onchip_posmap_memory_limit) {
    uint8_t recursion_levels = 1;
    uint8_t x;

    if(recursion_data_size!=0) {		
        recursion_levels = 1;
        x = recursion_data_size / sizeof(uint32_t);
        uint64_t size_pmap0 = max_blocks * sizeof(uint32_t);
        uint64_t cur_pmap0_blocks = max_blocks;

        while(size_pmap0 > onchip_posmap_memory_limit) {
            cur_pmap0_blocks = (uint64_t) ceil((double)cur_pmap0_blocks/(double)x);
            recursion_levels++;
            size_pmap0 = cur_pmap0_blocks * sizeof(uint32_t);
        }
    }

    return recursion_levels;
}
