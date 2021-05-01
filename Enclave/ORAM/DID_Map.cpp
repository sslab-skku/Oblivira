#include "DID_Map.hpp"

void DIDMap::initialize() {
    map_cnt = 0;
    DID_map = (DID_Map *)malloc(sizeof(DID_Map) * MAX_BLOCKS);
}

// this function should be oblivious?
int DIDMap::convertDIDToBlockID(unsigned char *did, unsigned char op_type) {
    
    int ret = -1;

    for(int i = 0; i < MAX_BLOCKS; i++) { // should be oblivious linear scans
        if(DID_map[i].did != NULL) {
            if(strncmp((const char *)(DID_map[i].did), (const char *)did, MAX_DID_SIZE) == 0)
                ret = (int)(DID_map[i].block_id);
        }
    }

    if(ret == -1 && op_type == 'w') {
        DID_map[map_cnt].block_id = map_cnt; // should be randomly selected in the pool, sizeof max_blocks
        DID_map[map_cnt].did = (unsigned char *)malloc(MAX_DID_SIZE);
        memcpy(DID_map[map_cnt].did, did, MAX_DID_SIZE);
        ret = map_cnt;
        map_cnt++;
    }
    
    return ret;
}

