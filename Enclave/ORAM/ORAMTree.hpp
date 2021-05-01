#ifndef __ORAMTREE_HPP__
#define __ORAMTREE_HPP__

#include <math.h>

#include "Bucket.hpp"
#include "Stash.hpp"
#include "oram_utils.hpp"

#include <sgx_trts.h>
#include "Enclave_t.h"

class ORAMTree {
    public:
        // Basic params
        uint8_t Z;
        uint32_t data_size;
        uint32_t stash_size;
        uint8_t recursion_levels;
        uint32_t recursion_data_size;
        
        // Buffers
        unsigned char *encrypted_path;
        unsigned char *decrypted_path;
        unsigned char *fetched_path_array;
        unsigned char *path_hash;
        unsigned char *new_path_hash;
        unsigned char *serialized_result_block;

        // Computed params
        uint32_t x;
        uint64_t gN;
        uint32_t tree_size;

        // Position map
        uint32_t *posmap;

        //Stash compenents
        Stash *recursive_stash;

        // Key components
        unsigned char *aes_key;

        // Parameters for recursive ORAMs
        uint64_t *max_blocks_level; // The total capacity of blocks in a lvevl
        uint64_t *real_max_blocks_level; // The real blocks used out of that toal capacity
        uint64_t *N_level; // For non-recursive, N = N_level[0]
        uint32_t *D_level; // For non-recursive, D = D_level[0]
        sgx_sha256_hash_t *merkle_root_hash_level;

        ORAMTree();
        ~ORAMTree();

        // Initialize/build funtions
        void setParams(uint8_t p_Z, uint32_t p_max_blocks, uint32_t p_data_size, uint32_t p_stash_size, uint32_t p_recursion_data_size, uint8_t p_recursion_levels);
        void initialize();
        // For non-recursive, simple invoke BuildTreeRecursive(0, NULL)
        void buildTreeRecursive(uint8_t level, uint32_t *prev_pmap);
        uint32_t *buildTreeLevel(uint8_t level, uint32_t *prev_pmap);
        void sampleKey();

        // Path functions
        void verifyPath(unsigned char *path_array, unsigned char *path_hash, uint32_t leaf, uint32_t D, uint32_t block_size, uint8_t level);
        void decryptPath(unsigned char* path_array, unsigned char *decrypted_path_array, uint32_t num_of_blocks_on_path, uint32_t data_size);
        void encryptPath(unsigned char* path_array, unsigned char *encrypted_path_array, uint32_t num_of_blocks_on_path, uint32_t data_size);

        unsigned char* downloadPath(uint32_t leaf, unsigned char *path_hash, uint8_t level);
        void uploadPath(uint32_t leaf, unsigned char *path, uint64_t path_size, unsigned char* path_hash, uint64_t path_hash_size, uint8_t level);

        // Access functions
        void createNewPathHash(unsigned char *path_ptr, unsigned char *old_path_hash, unsigned char *new_path_hash, uint32_t leaf, uint32_t block_size, uint8_t level);  
        void pushBlocksFromPathIntoStash(unsigned char* decrypted_path_ptr, uint8_t level, uint32_t data_size, uint32_t block_size, uint32_t id, uint32_t position_in_id, uint32_t leaf, uint32_t *next_leaf, uint32_t newleaf, uint32_t sampled_leaf, int32_t newleaf_nextlevel);
        void OAssignNewLabelToBlock(uint32_t id, uint32_t position_in_id, uint8_t level, uint32_t newleaf, uint32_t newleaf_nextlevel, uint32_t * next_leaf);

        // crypto functions
        void aes_dec_serialized(unsigned char* encrypted_block, uint32_t data_size, unsigned char *decrypted_block, unsigned char* aes_key);
        void aes_enc_serialized(unsigned char* decrypted_block, uint32_t data_size, unsigned char *encrypted_block, unsigned char* aes_key);
};

#endif
