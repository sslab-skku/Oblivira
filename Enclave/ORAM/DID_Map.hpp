#ifndef __DID_MAP_HPP__
#define __DID_MAP_HPP__

#include <stdlib.h>
#include <stdint.h>

#include "global_config.h"

typedef struct _DID_Map {
    unsigned char *did;
    uint32_t block_id;
} DID_Map;

class DIDMap {
    public:
        uint32_t map_cnt;
        DID_Map *DID_map;

        DIDMap(){};
        void initialize();
        int convertDIDToBlockID(unsigned char *did, unsigned char op_type);
};

#endif