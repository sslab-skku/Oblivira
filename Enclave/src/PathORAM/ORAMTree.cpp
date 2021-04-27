#include "PathORAM/ORAMTree.hpp"

ORAMTree::ORAMTree() {

}

ORAMTree::~ORAMTree() {
    
}

void ORAMTree::setParams(uint8_t p_Z, uint32_t p_max_blocks, uint32_t p_data_size, uint32_t p_stash_size, uint32_t p_recursion_data_size, uint8_t p_recursion_levels) {
    data_size = p_data_size;
    stash_size = p_stash_size;
    recursion_data_size = p_recursion_data_size;
    recursion_levels = p_recursion_levels;
    x = recursion_data_size / sizeof(uint32_t);
    Z = p_Z;

    uint64_t size_pmap0 = p_max_blocks * sizeof(uint32_t);
    uint64_t cur_pmap0_blocks = p_max_blocks;

    while(size_pmap0 > MEM_POSMAP_LIMIT) {
        cur_pmap0_blocks = (uint64_t)ceil((double)cur_pmap0_blocks / (double)x);
        size_pmap0 = cur_pmap0_blocks * sizeof(uint32_t);
    }

    max_blocks_level = (uint64_t*) malloc((recursion_levels) * sizeof(uint64_t));
    real_max_blocks_level = (uint64_t*) malloc((recursion_levels) * sizeof(uint64_t));

    uint8_t max_recursion_level_index = recursion_levels - 1;
    real_max_blocks_level[max_recursion_level_index] = p_max_blocks;

    int32_t lev = max_recursion_level_index - 1;
    while(lev >= 0) {
        real_max_blocks_level[lev] = ceil((double)real_max_blocks_level[lev+1]/(double) x);
        lev--;
    }

    max_blocks_level[0] = cur_pmap0_blocks;
    for(uint32_t i = 1; i <= max_recursion_level_index; i++) {			
        max_blocks_level[i] = max_blocks_level[i-1] * x;
    }

    gN = max_blocks_level[max_recursion_level_index];
    merkle_root_hash_level = (sgx_sha256_hash_t*) malloc((max_recursion_level_index+1) * sizeof(sgx_sha256_hash_t));
}

void ORAMTree::initialize() {
    uint32_t i;
    N_level = (uint64_t*) malloc ((recursion_levels) * sizeof(uint64_t));
    D_level = (uint32_t*) malloc ((recursion_levels) * sizeof(uint64_t));
    recursive_stash = (Stash *) malloc((recursion_levels) * sizeof(Stash));

    for(i = 0; i < recursion_levels; i++){
        if(i!=recursion_levels-1 && recursion_levels!=1)
            recursive_stash[i].setup(stash_size, recursion_data_size, gN);
        else
            recursive_stash[i].setup(stash_size, data_size, gN);
    }

    buildTreeRecursive(recursion_levels-1, NULL);

    uint32_t d_largest;
    if(recursion_levels==0)
        d_largest = D_level[0];
    else
        d_largest = D_level[recursion_levels-1];

    uint64_t largest_path_size = Z*(data_size+ADDITIONAL_METADATA_SIZE)*(d_largest);
    encrypted_path = (unsigned char*) malloc (largest_path_size);
    decrypted_path = (unsigned char*) malloc (largest_path_size);
    fetched_path_array = (unsigned char*) malloc (largest_path_size);
    path_hash = (unsigned char*) malloc (HASH_LENGTH*2*(d_largest));
    new_path_hash = (unsigned char*) malloc (HASH_LENGTH*2*(d_largest));
    serialized_result_block = (unsigned char*) malloc (data_size+ADDITIONAL_METADATA_SIZE);
}

void ORAMTree::buildTreeRecursive(uint8_t level, uint32_t *prev_pmap) {
    if(level == 0) {
        uint32_t *posmap_l;

        if(recursion_levels == 1) {
            posmap_l = buildTreeLevel(level, NULL);
        }
        else {
            posmap_l = (uint32_t *) malloc( real_max_blocks_level[level] * sizeof(uint32_t) );
            memcpy(posmap_l, prev_pmap, real_max_blocks_level[level] * sizeof(uint32_t));
            D_level[level] = 0;
            N_level[level] = max_blocks_level[level];
        }
        posmap = posmap_l;
    }
    else {
        uint32_t *posmap_level = buildTreeLevel(level, prev_pmap);
        buildTreeRecursive(level-1, posmap_level);
        free(posmap_level);
    }
}

uint32_t *ORAMTree::buildTreeLevel(uint8_t level, uint32_t *prev_pmap) {
    uint32_t tdata_size;
    uint32_t block_size;
    sgx_sha256_hash_t current_bucket_hash; 
  
    uint32_t util_divisor = Z;
    uint32_t pD_temp = ceil((double)max_blocks_level[level]/(double)util_divisor);
    uint32_t pD = (uint32_t) ceil(log((double)pD_temp)/log((double)2));
    uint32_t pN = (int) pow((double)2, (double) pD);
    uint32_t ptreeSize = 2*pN-1;
    
    //+1 to depth pD, since ptreeSize = 2 *pN	
    D_level[level] = pD+1;
    N_level[level] = pN;    

    if(level==(recursion_levels-1) || level==0) {
        tdata_size = data_size;	
        block_size = (data_size+ADDITIONAL_METADATA_SIZE);		
    }
    else {	
        tdata_size = recursion_data_size;
        block_size = recursion_data_size + ADDITIONAL_METADATA_SIZE;
    }						   

    uint32_t *posmap_l = (uint32_t *) malloc(max_blocks_level[level] * sizeof(uint32_t));
    if(posmap_l==NULL) {
        ;//ocall_printf("Failed to allocate\n");
    }

    uint32_t hashsize = HASH_LENGTH;
    unsigned char* hash_lchild = (unsigned char*) malloc(HASH_LENGTH);	
    unsigned char* hash_rchild = (unsigned char*) malloc(HASH_LENGTH);
    uint32_t blocks_per_bucket_in_ll = real_max_blocks_level[level]/pN;

    uint32_t c = real_max_blocks_level[level] - (blocks_per_bucket_in_ll * pN);
    uint32_t cnt = 0;

    Bucket temp(Z);
    temp.initialize(tdata_size, gN);

    // Build Last Level of Tree
    uint32_t label = 0;
    for(uint32_t i = pN; i <= ptreeSize; i++) {    
        temp.reset_blocks(tdata_size, gN);

        uint32_t blocks_in_this_bucket = blocks_per_bucket_in_ll;
        if(cnt < c) {
            blocks_in_this_bucket += 1;
            cnt += 1;
        }        

        for(uint8_t q = 0; q < blocks_in_this_bucket; q++) {	
            temp.blocks[q].id = label;
            // treeLabel will be the bucket_id of that leaf = nlevel[level] + leaf
            temp.blocks[q].tree_label = (pN) + (i - pN);

            if(level < recursion_levels-1 && level>0) { 	
                temp.blocks[q].fill_recursion_data(&(prev_pmap[(label)*x]), recursion_data_size);
            }
            posmap_l[temp.blocks[q].id] = temp.blocks[q].tree_label;
            label++;	
        }

        temp.aes_encryptBlocks(tdata_size, aes_key);
        
        unsigned char *serialized_bucket = temp.serialize(tdata_size);
        uint8_t ret;        
        
        //Hash / Integrity Tree
        sgx_sha256_msg(serialized_bucket, block_size * Z, (sgx_sha256_hash_t*) &(current_bucket_hash));

        //Upload Bucket
        ocall_uploadBucket(&ret, serialized_bucket, Z*block_size ,i, (unsigned char*) &(current_bucket_hash), HASH_LENGTH, block_size, level);

        free(serialized_bucket);
    }

    //Build Upper Levels of Tree
    for(uint32_t i = pN - 1; i>=1; i--){
        temp.reset_blocks(tdata_size, gN);
        temp.aes_encryptBlocks(tdata_size, aes_key);

        unsigned char *serialized_bucket = temp.serialize(tdata_size);
        uint8_t ret;

        //Hash 	
        ocall_buildFetchChildHash(i*2, i*2 +1, hash_lchild, hash_rchild, HASH_LENGTH, level);		
        sgx_sha_state_handle_t p_sha_handle;
        sgx_sha256_init(&p_sha_handle);
        sgx_sha256_update(serialized_bucket, block_size * Z, p_sha_handle);					
        sgx_sha256_update(hash_lchild, SGX_SHA256_HASH_SIZE, p_sha_handle);
        sgx_sha256_update(hash_rchild, SGX_SHA256_HASH_SIZE, p_sha_handle);
        sgx_sha256_get_hash(p_sha_handle, (sgx_sha256_hash_t*) merkle_root_hash_level[level]);
        sgx_sha256_close(p_sha_handle);	

        //Upload Bucket 
        ocall_uploadBucket(&ret, serialized_bucket, Z*block_size ,i, (unsigned char*) &(merkle_root_hash_level[level]), HASH_LENGTH, block_size, level);

        free(serialized_bucket);
    }
    free(hash_lchild);
    free(hash_rchild);

    return(posmap_l);
}

void ORAMTree::verifyPath(unsigned char *path_array, unsigned char *path_hash, uint32_t leaf, uint32_t D, uint32_t block_size, uint8_t level) {
    unsigned char *path_array_iter = path_array;
    unsigned char *path_hash_iter = path_hash;
    sgx_sha256_hash_t parent_hash;
    sgx_sha256_hash_t child;
    sgx_sha256_hash_t lchild;
    sgx_sha256_hash_t rchild;
    sgx_sha256_hash_t lchild_retrieved;
    sgx_sha256_hash_t rchild_retrieved;
    sgx_sha256_hash_t parent_hash_retrieved;
    uint32_t temp = leaf;
    uint32_t cmp1, cmp2, cmp;
    int32_t i;	

    for(i=D-1;i>=0;i--) {
        if(i == (D - 1)) {
            //No child hashes to compute			
            sgx_sha256_msg(path_array_iter, (block_size*Z), (sgx_sha256_hash_t*)child);
            path_array_iter+=(block_size*Z);		
            memcpy((uint8_t*)lchild_retrieved, path_hash_iter, HASH_LENGTH);
            path_hash_iter+=HASH_LENGTH;
            memcpy((uint8_t*)rchild_retrieved, path_hash_iter, HASH_LENGTH);
            path_hash_iter+=HASH_LENGTH;

            if(temp%2==0)
                cmp1 = memcmp((uint8_t*)child,(uint8_t*)lchild_retrieved,HASH_LENGTH);			
            else
                cmp1 = memcmp((uint8_t*)child,(uint8_t*)rchild_retrieved,HASH_LENGTH);
        }
        else if(i==0){
            //No sibling child	
            sgx_sha_state_handle_t p_sha_handle;
            sgx_sha256_init(&p_sha_handle);
            sgx_sha256_update(path_array_iter, (block_size*Z), p_sha_handle);
            path_array_iter+=(block_size*Z);
            sgx_sha256_update((uint8_t*)lchild_retrieved, SGX_SHA256_HASH_SIZE, p_sha_handle);
            sgx_sha256_update((uint8_t*)rchild_retrieved, SGX_SHA256_HASH_SIZE, p_sha_handle);
            sgx_sha256_get_hash(p_sha_handle, (sgx_sha256_hash_t*)parent_hash);
            sgx_sha256_close(p_sha_handle);

            //Fetch retreived root hash :
            memcpy((uint8_t*)parent_hash_retrieved, path_hash_iter, HASH_LENGTH);
            path_hash_iter+=HASH_LENGTH;
            // Test if retrieved merkle_root_hash of tree matches internally stored merkle_root_hash 
            // If retrieved matches internal, then computed merkle_root_hash should match as well for free.
      
            cmp = memcmp((uint8_t*)parent_hash_retrieved, (uint8_t*)merkle_root_hash_level[level],HASH_LENGTH); 
        }
        else {			
            sgx_sha_state_handle_t p_sha_handle;
            sgx_sha256_init(&p_sha_handle);
            sgx_sha256_update(path_array_iter, (block_size*Z), p_sha_handle);
            path_array_iter+=(block_size*Z);
            sgx_sha256_update((uint8_t*)lchild_retrieved, SGX_SHA256_HASH_SIZE, p_sha_handle);
            sgx_sha256_update((uint8_t*)rchild_retrieved, SGX_SHA256_HASH_SIZE, p_sha_handle);
            sgx_sha256_get_hash(p_sha_handle, (sgx_sha256_hash_t*) parent_hash);
            sgx_sha256_close(p_sha_handle);			

            //Children hashes for next round	
            memcpy((uint8_t*)lchild_retrieved, path_hash_iter, HASH_LENGTH);
            path_hash_iter+=HASH_LENGTH;
            memcpy((uint8_t*)rchild_retrieved, path_hash_iter, HASH_LENGTH);
            path_hash_iter+=HASH_LENGTH;

            if(temp%2==0)
                cmp = memcmp((uint8_t*)lchild_retrieved, (uint8_t*)parent_hash, HASH_LENGTH);
            else
                cmp = memcmp((uint8_t*)rchild_retrieved, (uint8_t*)parent_hash, HASH_LENGTH);	
        }
        temp = temp >> 1;
    }
}

void ORAMTree::decryptPath(unsigned char* path_array, unsigned char *decrypted_path_array, uint32_t num_of_blocks_on_path, uint32_t data_size) {
    unsigned char *path_iter = path_array;
    unsigned char *decrypted_path_iter = decrypted_path_array;

    for(uint32_t i = 0; i < num_of_blocks_on_path; i++) {
        aes_dec_serialized(path_iter, data_size, decrypted_path_iter, aes_key);
        path_iter += (data_size + ADDITIONAL_METADATA_SIZE);
        decrypted_path_iter += (data_size + ADDITIONAL_METADATA_SIZE);
    }
}

void ORAMTree::encryptPath(unsigned char* path_array, unsigned char *encrypted_path_array, uint32_t num_of_blocks_on_path, uint32_t data_size) {
    unsigned char *path_iter = path_array;
    unsigned char *encrypted_path_iter = encrypted_path_array;

    for(uint32_t i =0;i<num_of_blocks_on_path;i++)
        aes_enc_serialized(path_iter, data_size, encrypted_path_iter, aes_key);
    
    path_iter +=(data_size + ADDITIONAL_METADATA_SIZE);
    encrypted_path_iter +=(data_size + ADDITIONAL_METADATA_SIZE);
}

unsigned char *ORAMTree::downloadPath(uint32_t leaf, unsigned char *path_hash, uint8_t level) {
    sgx_status_t ocall_status;

    uint32_t temp = leaf;
    uint8_t rt;
    uint32_t tdata_size;
    uint32_t path_size, path_hash_size;
    uint32_t d = D_level[level];

    if(level == recursion_levels - 1 || recursion_levels == 1)
        tdata_size = data_size;
    else 
        tdata_size = recursion_data_size;

    path_size = Z * (tdata_size + ADDITIONAL_METADATA_SIZE) * d;
    path_hash_size = HASH_LENGTH * 2 * d;

    ocall_downloadPath(&rt, fetched_path_array, path_size, leaf, path_hash, path_hash_size, level, d);
    verifyPath(fetched_path_array, path_hash, leaf, d, tdata_size + ADDITIONAL_METADATA_SIZE, level);
    decryptPath(fetched_path_array, decrypted_path, (Z * d), tdata_size);

    return decrypted_path;
}

void ORAMTree::uploadPath(uint32_t leaf, unsigned char *path, uint64_t path_size, unsigned char* path_hash, uint64_t path_hash_size, uint8_t level) {
    uint32_t d = D_level[level];
    uint8_t ret;
    ocall_uploadPath(&ret, path, path_size, leaf, path_hash, path_hash_size, level, d);
}

void ORAMTree::createNewPathHash(unsigned char *path_ptr, unsigned char *old_path_hash, unsigned char *new_path_hash, uint32_t leaf, uint32_t block_size, uint8_t level) {
    uint32_t d = D_level[level];
    uint32_t leaf_temp = leaf;
    uint32_t leaf_temp_prev = leaf;
    unsigned char *new_path_hash_trail = new_path_hash;

    for(uint8_t i = 0; i<d+1; i++){
        if(i==0){
            sgx_sha256_msg(path_ptr, (block_size*Z), (sgx_sha256_hash_t*) new_path_hash);
            path_ptr+=(block_size*Z);
            new_path_hash_trail = new_path_hash;
            new_path_hash+=HASH_LENGTH;
        }
        else{
            sgx_sha_state_handle_t sha_handle;
            sgx_sha256_init(&sha_handle);
            sgx_sha256_update(path_ptr, (block_size*Z), sha_handle);
            path_ptr+=(block_size*Z);
            if(leaf_temp_prev%2==0) {
                sgx_sha256_update(new_path_hash_trail, HASH_LENGTH, sha_handle);
                old_path_hash+=HASH_LENGTH;
                sgx_sha256_update(old_path_hash, HASH_LENGTH, sha_handle);
                old_path_hash+=HASH_LENGTH;
            }
            else{
                sgx_sha256_update(old_path_hash, HASH_LENGTH, sha_handle);
                old_path_hash+=(2*HASH_LENGTH);
                sgx_sha256_update(new_path_hash_trail, HASH_LENGTH, sha_handle);
            }
            sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t*) new_path_hash);
            if(i==d){
                memcpy(merkle_root_hash_level[level], new_path_hash_trail, HASH_LENGTH);
            }
            new_path_hash_trail+=HASH_LENGTH;
            new_path_hash+=HASH_LENGTH;
            sgx_sha256_close(sha_handle);
        }
        leaf_temp_prev = leaf_temp;
        leaf_temp = leaf_temp >> 1;
    }
}

void ORAMTree::pushBlocksFromPathIntoStash(unsigned char* decrypted_path_ptr, uint8_t level, uint32_t data_size, uint32_t block_size, uint32_t id, uint32_t position_in_id, uint32_t leaf, uint32_t *next_leaf, uint32_t newleaf, uint32_t sampled_leaf, int32_t newleaf_nextlevel) {
    uint32_t d = D_level[level];
    uint32_t i;

    // FetchBlock Module:
    for(i = 0; i < (Z*(d)); i++) {
        recursive_stash[level].passInsert(decrypted_path_ptr, isBlockDummy(decrypted_path_ptr, gN));
        setId(decrypted_path_ptr, gN);
        decrypted_path_ptr+=block_size;	
    }    
    
}

void ORAMTree::OAssignNewLabelToBlock(uint32_t id, uint32_t position_in_id, uint8_t level, uint32_t newleaf, uint32_t newleaf_nextlevel, uint32_t * next_leaf) {
    uint32_t k;
    nodev2 *listptr_t;
    listptr_t = recursive_stash[level].getStart();		
  
    for(k=0; k < stash_size; k++) {
        bool flag1,flag2 = false;
        flag1 = ( (getId(listptr_t->serialized_block) == id) && (!isBlockDummy(listptr_t->serialized_block,gN)) );
        oassign_newlabel(getTreeLabelPtr(listptr_t->serialized_block),newleaf, flag1);

        if(level!=recursion_levels && recursion_levels!=-1) {
            for(uint8_t p = 0;p < x;p++) {
                flag2 = (flag1 && (position_in_id == p));
                ofix_recursion( &(listptr_t->serialized_block[24+p*4]), flag2, newleaf_nextlevel, next_leaf);
            }   
        }
        listptr_t = listptr_t->next;
    }
}


void ORAMTree::aes_dec_serialized(unsigned char* encrypted_block, uint32_t data_size, unsigned char *decrypted_block, unsigned char* aes_key) {
    unsigned char *ctr = (unsigned char*) malloc (NONCE_LENGTH);
    unsigned char *encrypted_block_ptr = encrypted_block + NONCE_LENGTH;
    unsigned char *decrypted_block_ptr = decrypted_block + NONCE_LENGTH;
    memcpy(ctr, encrypted_block, NONCE_LENGTH);

    // 8 from 4 bytes for id and 4 bytes for treelabel
    uint32_t ciphertext_size = data_size + 8;
    sgx_status_t ret = SGX_SUCCESS;
    uint32_t ctr_inc_bits = 16;
    /*
    ret = sgx_aes_ctr_decrypt((const sgx_aes_ctr_128bit_key_t *) aes_key,
            encrypted_block_ptr,
            ciphertext_size,
            ctr,
            ctr_inc_bits, 
            decrypted_block_ptr);
    */
    //memcpy(decrypted_block_ptr, encrypted_block_ptr, data_size + 8);
    memcpy(decrypted_block_ptr, encrypted_block_ptr, data_size + ADDITIONAL_METADATA_SIZE);

    free(ctr);
}

void ORAMTree::aes_enc_serialized(unsigned char* decrypted_block, uint32_t data_size, unsigned char *encrypted_block, unsigned char* aes_key) {
  //Add generate_randomness() for nonce.
  unsigned char *ctr =  (unsigned char*) malloc (NONCE_LENGTH);
  memcpy(encrypted_block, ctr, NONCE_LENGTH);
    
  unsigned char *decrypted_block_ptr = decrypted_block + NONCE_LENGTH;
  unsigned char *encrypted_block_ptr = encrypted_block + NONCE_LENGTH;

  sgx_status_t ret = SGX_SUCCESS;
  uint32_t ctr_inc_bits = 16;
    
    // 8 from 4 bytes for id and 4 bytes for treelabel
  uint32_t input_size = data_size + 8;
  /*
  ret = sgx_aes_ctr_encrypt((const sgx_aes_ctr_128bit_key_t *) aes_key,
                decrypted_block_ptr,
                input_size,
                ctr,
                ctr_inc_bits, 
                encrypted_block_ptr);
    */
   //memcpy(encrypted_block_ptr, decrypted_block_ptr, data_size+8);
   memcpy(encrypted_block_ptr, decrypted_block_ptr, data_size + ADDITIONAL_METADATA_SIZE);

  free(ctr);
}