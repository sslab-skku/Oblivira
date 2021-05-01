#include "Bucket.hpp"

Bucket::Bucket(uint8_t p_Z){
  Z = p_Z;	
}

void Bucket::initialize(uint32_t data_size, uint32_t gN) {
    blocks = (Block*)malloc(Z * sizeof(Block));
    for(uint8_t i = 0; i < Z; i++)
        blocks[i].initialize(data_size, gN);	
}

void Bucket::reset_blocks(uint32_t data_size, uint32_t gN) {
    for(uint8_t i = 0; i < Z; i++)
        blocks[i].reset(data_size, gN);		
}

unsigned char * Bucket::serialize(uint32_t data_size) {
    uint32_t size_of_bucket = Z * (data_size+ADDITIONAL_METADATA_SIZE);
    uint32_t tdata_size = (data_size+ADDITIONAL_METADATA_SIZE);	
    unsigned char* serialized_bucket = (unsigned char*)malloc(size_of_bucket);
    unsigned char* ptr = serialized_bucket;

    for(int i = 0; i < Z;i++) {
        unsigned char* serial_block = blocks[i].serialize(data_size);
        memcpy(ptr, serial_block,tdata_size);
        free(serial_block);
        ptr += tdata_size;
    }

    return serialized_bucket;
}

void Bucket::aes_encryptBlocks(uint32_t data_size, unsigned char *aes_key) {
    for(uint8_t i = 0; i < Z; i++)
        blocks[i].aes_enc(data_size, aes_key);
}
