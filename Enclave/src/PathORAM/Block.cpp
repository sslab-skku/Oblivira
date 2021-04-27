#include "PathORAM/Block.hpp"

Block::Block(uint32_t data_size, uint32_t gN) {
    data = NULL;
    r = NULL;
    generate_data(data_size);
    generate_r();
    tree_label = 0;
    id = gN;
}

void Block::generate_data(uint32_t data_size) {
    if(data == NULL)
        data = (uint8_t *)malloc(data_size);
    
    for(uint32_t i = 0; i < data_size; i++) 
        data[i] = (i % 26) + 65; // ASCII 'A'

    data[data_size - 1] = '\0';
}

void Block::generate_r() {
    if(r == NULL)
        r = (uint8_t *)malloc(NONCE_LENGTH);
    
    for(uint8_t i = 0; i < NONCE_LENGTH; i++)
        r[i] = 'A';
}

void Block::initialize(uint32_t data_size, uint32_t gN) {
    data = NULL;
    r = NULL;
    generate_data(data_size);
    generate_r();
    tree_label = 0;
    id = gN;
}

void Block::reset(uint32_t data_size, uint32_t gN) {
    id = gN;
    tree_label = 0;

    if(data==NULL)
        data=(uint8_t*)malloc(data_size);
  
	for(uint32_t i=0; i<data_size; i++) {
	    data[i] = (i % 26) + 65; // ASCII 'A'
	}
    
    data[data_size-1]='\0';
}

void Block::fill_recursion_data(uint32_t *pmap, uint32_t recursion_data_size) {
    memcpy(data, pmap, recursion_data_size);
}

unsigned char *Block::serialize(uint32_t data_size) {
    uint32_t tdata_size = data_size + ADDITIONAL_METADATA_SIZE;
	unsigned char* serialized_block = (unsigned char*) malloc(tdata_size);
	unsigned char *ptr = serialized_block;

	memcpy(ptr,(void *) r,NONCE_LENGTH);
	ptr+=NONCE_LENGTH;
	memcpy(ptr,(void *) &id, sizeof(id));
	ptr+=sizeof(id);
	memcpy(ptr,(void *) &tree_label, sizeof(tree_label));
	ptr+=sizeof(tree_label);
	memcpy(ptr,data,data_size);
	ptr+=data_size;

	return serialized_block;
}

void Block::aes_enc(uint32_t data_size, unsigned char *aes_key) {
    
    generate_r();

    uint32_t input_size = data_size + 2 * ID_SIZE_IN_BYTES;		
	unsigned char *ctr = (unsigned char*)malloc(NONCE_LENGTH);
	unsigned char *ciphertext = (unsigned char*)malloc(input_size);
	unsigned char *input_buffer = (unsigned char*)malloc(input_size);

	serializeForAes(input_buffer, data_size);

    memcpy(ctr, r, NONCE_LENGTH);
    sgx_status_t ret = SGX_SUCCESS;

    uint32_t ctr_inc_bits = 16;

    /*
	ret = sgx_aes_ctr_encrypt((const sgx_aes_ctr_128bit_key_t *) aes_key,
				                input_buffer,
			                    input_size,
			                    ctr,
			                    ctr_inc_bits, 
			                    ciphertext);
                                */
    memcpy(ciphertext, input_buffer, input_size);

	memcpy((void *) &id, ciphertext, ID_SIZE_IN_BYTES);
	memcpy((void *) &tree_label, ciphertext + ID_SIZE_IN_BYTES, ID_SIZE_IN_BYTES);
	memcpy(data, ciphertext + ID_SIZE_IN_BYTES*2, data_size);	    

	free(input_buffer);
	free(ciphertext);
	free(ctr);

}

void Block::serializeForAes(unsigned char *buffer, uint32_t bData_size) {
    memcpy(buffer, (void *) &id, sizeof(id));
	memcpy(buffer+ID_SIZE_IN_BYTES, (void *) &tree_label, sizeof(tree_label));
	memcpy(buffer+ID_SIZE_IN_BYTES*2, data, bData_size);
}