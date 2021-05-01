#ifndef __PATHORAM_BLOCKS_HPP__
#define __PATHORAM_BLOCKS_HPP__

#include "global_config.h"
#include "oram_utils.hpp"

#include "sgx_trts.h"
#include "Enclave_t.h"

class Block {
    public:
        unsigned char *data; // data = did_docs
        uint32_t id; // block id
        uint32_t tree_label;
        uint8_t *r;
        
        Block(uint32_t data_size, uint32_t gN);
        void generate_data(uint32_t data_size);
        void generate_r();
        
        void initialize(uint32_t data_size, uint32_t gN);

        void reset(uint32_t data_size, uint32_t gN);

        void fill_recursion_data(uint32_t *pmap, uint32_t recursion_data_size);

        unsigned char *serialize(uint32_t data_size);
        void aes_enc(uint32_t data_size, unsigned char *aes_key);
        void serializeForAes(unsigned char *buffer, uint32_t bData_size);
};

#endif
