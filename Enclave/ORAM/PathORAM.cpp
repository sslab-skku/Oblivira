#include "PathORAM.hpp"

void PathORAM::Create(uint8_t Z, uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t recursion_data_size, uint8_t recursion_levels){
  initialize(Z, max_blocks, data_size, stash_size, recursion_data_size, recursion_levels);
}

void PathORAM::initialize(uint8_t Z, uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t recursion_data_size, uint8_t recursion_levels) {
    ORAMTree::setParams(Z, max_blocks, data_size, stash_size, recursion_data_size, recursion_levels);
    ORAMTree::initialize();
}

void PathORAM::Access(uint32_t id, char op_type, unsigned char *data_in, unsigned char *data_out) {
    uint32_t prev_sampled_leaf = -1;
    if(id <= MAX_BLOCKS)
        access(id, -1, op_type, recursion_levels - 1, data_in, data_out, &prev_sampled_leaf);
}

uint32_t PathORAM::access(uint32_t id, uint32_t position_in_id, char op_type, uint8_t level, unsigned char *data_in, unsigned char *data_out, uint32_t *prev_sampled_leaf) {
    uint32_t leaf = 0;
    uint32_t next_leaf;
    uint32_t id_adj;				
    uint32_t newleaf;
    uint32_t newleaf_nextlevel = -1;
    uint32_t random_value;

    if(recursion_levels == 1) {
        level = 0;
        sgx_status_t rt = SGX_SUCCESS;
            
        rt = sgx_read_rand((unsigned char*)&random_value, ID_SIZE_IN_BYTES);
        
        uint32_t newleaf = N_level[0] + random_value % N_level[0];        
        oarraySearch(posmap, id, &leaf, newleaf, max_blocks_level[0]); // extract leaf and chane to new leaf

        decrypted_path = downloadPath(leaf, path_hash, 0);

        PathORAM_Access(op_type, id, -1, leaf, newleaf, -1, decrypted_path, path_hash, 0, data_in, data_out);
        
        return 0;
    } else {
        if(level == 0) {
            sgx_read_rand((unsigned char *)random_value, ID_SIZE_IN_BYTES);
            newleaf = N_level[1] + (*((uint32_t *)random_value) % (N_level[level + 1]));
            oarraySearch(posmap, id, &leaf, newleaf, real_max_blocks_level[level]);

            *prev_sampled_leaf = newleaf;
            return leaf;
        }
        else if(level == recursion_levels - 1) {
            id_adj = id/x;
            position_in_id = id%x;
            leaf = access(id_adj, position_in_id, op_type, level-1, data_in, data_out, prev_sampled_leaf);

            access_oram_level(op_type, leaf, id, -1, level, *prev_sampled_leaf, -1, data_in, data_out);

            return 0;
        }
        else {
            id_adj = id/x;
            int32_t pos_in_id = (level==1)? -1: id%x; 
            leaf = access(id_adj, pos_in_id, op_type, level-1, data_in, data_out, prev_sampled_leaf);
      
            //sampling leafs for a level ahead		
            sgx_read_rand((unsigned char *)random_value, ID_SIZE_IN_BYTES);
            newleaf_nextlevel = N_level[level+1] + (*((uint32_t *)random_value) % N_level[level+1]);
            next_leaf = access_oram_level(op_type, leaf, id, position_in_id, level, *prev_sampled_leaf, newleaf_nextlevel, data_in, data_out);

            *prev_sampled_leaf = newleaf_nextlevel;
            return next_leaf;
        }
    }
}

uint32_t PathORAM::access_oram_level(char op_type, uint32_t leaf, uint32_t id, uint32_t position_in_id, uint32_t level, uint32_t newleaf, uint32_t newleaf_nextlevel, unsigned char *data_in, unsigned char *data_out) {
    uint32_t return_value = -1;

    decrypted_path = downloadPath(leaf, path_hash, level);
    return_value = PathORAM_Access(op_type, id, position_in_id, leaf, newleaf, newleaf_nextlevel, decrypted_path, path_hash,level, data_in, data_out); 
    return return_value;
}

uint32_t PathORAM::PathORAM_Access(char op_type, uint32_t id, uint32_t position_in_id, uint32_t leaf, uint32_t newleaf, uint32_t newleaf_nextlevel, unsigned char *decrypted_path, unsigned char *path_hash, uint32_t level, unsigned char *data_in, unsigned char *data_out) {
    sgx_status_t ocall_status = SGX_SUCCESS;

    uint32_t i, next_leaf = 0;
    uint32_t d = D_level[level];
    uint32_t n = N_level[level];
    uint32_t sampled_leaf;
    bool flag = false;
    bool ad_flag = false;
    unsigned char *decrypted_path_ptr = decrypted_path;
    uint8_t rt;
    unsigned char random_value[ID_SIZE_IN_BYTES];

    sgx_read_rand((unsigned char*) random_value, sizeof(uint32_t));

    if(recursion_levels!=1 && level!=recursion_levels-1){
        sampled_leaf= N_level[level+1] + (*((uint32_t *)random_value) % (N_level[level+1]));
    }			
    else{
        sampled_leaf= n + (*((uint32_t *)random_value) % (n));
    }

    uint32_t tblock_size, tdata_size;
    if(recursion_levels==1||level==recursion_levels-1) {
        tblock_size = data_size + ADDITIONAL_METADATA_SIZE;
        tdata_size = data_size;	
    } 
    else {
        tblock_size = recursion_data_size + ADDITIONAL_METADATA_SIZE;				
        tdata_size = recursion_data_size;			
    }
    
    uint32_t path_size = Z*tblock_size*(d);
    uint32_t new_path_hash_size = ((d+1)*HASH_LENGTH);

    unsigned char *new_path_hash_trail = new_path_hash;
    unsigned char *new_path_hash_iter = new_path_hash;
    unsigned char *old_path_hash_iter = path_hash;
    
    pushBlocksFromPathIntoStash(decrypted_path_ptr, level, tdata_size, tblock_size, id, position_in_id, leaf, &next_leaf, newleaf, sampled_leaf, newleaf_nextlevel);
    
    if(level == recursion_levels - 1) {
        recursive_stash[level].performAccessOperation(op_type, id, newleaf, data_in, data_out);
    } else {
        OAssignNewLabelToBlock(id, position_in_id, level, newleaf, newleaf_nextlevel, &next_leaf);
    }  

    decrypted_path_ptr = decrypted_path;
    PathORAM_RebuildPath(decrypted_path_ptr, tdata_size, tblock_size, leaf, level);

    encryptPath(decrypted_path, encrypted_path, Z * d, tdata_size);

    unsigned char *path_ptr;
    new_path_hash_iter = new_path_hash;
    new_path_hash_trail = new_path_hash;
    old_path_hash_iter = path_hash;		
    unsigned char *new_path_hash_ptr = new_path_hash;

    path_ptr = encrypted_path;
    createNewPathHash(path_ptr, path_hash, new_path_hash, leaf, data_size + ADDITIONAL_METADATA_SIZE, level);
    uploadPath(leaf, decrypted_path, path_size, new_path_hash, new_path_hash_size, level);

    return next_leaf;
}

void PathORAM::PathORAM_RebuildPath(unsigned char *decrypted_path_ptr, uint32_t data_size, uint32_t block_size, uint32_t leaf, uint32_t level) {
    uint32_t prefix;
    uint32_t i,k;
    uint32_t d = D_level[level];
    uint64_t n = N_level[level];
    unsigned char *decrypted_path_bucket_iterator = decrypted_path_ptr;
    unsigned char *decrypted_path_temp_iterator;

    for(i = 0; i < d; i++){
        prefix = ShiftBy(leaf+n,i);
    
        bool flag = false;
        nodev2 *listptr = NULL;
        listptr = recursive_stash[level].getStart();

        uint32_t posk = 0;	

        for(k=0; k < stash_size; k++)
        {				
            decrypted_path_temp_iterator = decrypted_path_bucket_iterator;			
            uint32_t jprefix = ShiftBy(getTreeLabel(listptr->serialized_block)+n,i);
            uint32_t sblock_written = false;      
            bool flag = (posk<Z)&&(prefix==jprefix)&&(!sblock_written)&&(!isBlockDummy(listptr->serialized_block, gN));

            for(uint8_t l=0;l<Z;l++){
                flag = (l==posk) && (posk<Z) && (prefix==jprefix) && (!sblock_written) && (!isBlockDummy(listptr->serialized_block,gN));
                omove_serialized_block(decrypted_path_temp_iterator, listptr->serialized_block, data_size, flag);
                oset_value(&sblock_written, 1, flag);
                oset_value(getIdPtr(listptr->serialized_block), gN, flag);
                oincrement_value(&posk, flag);
                decrypted_path_temp_iterator+= block_size;
            }

            listptr=listptr->next;
        }						
        decrypted_path_bucket_iterator+=(Z*block_size);
    }
}
