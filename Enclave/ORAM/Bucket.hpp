#ifndef __BUCKET_HPP__
#define __BUCKET_HPP__

#include "oram_utils.hpp"
#include "Block.hpp"

class Bucket {
    public:
        Block *blocks;
        uint8_t Z;

        Bucket(uint8_t Z);
        
        void initialize(uint32_t data_size, uint32_t gN);
        void reset_blocks(uint32_t data_size, uint32_t gN);

        unsigned char *serialize(uint32_t data_size);

        void aes_encryptBlocks(uint32_t data_size, unsigned char *aes_key);
};

#endif
