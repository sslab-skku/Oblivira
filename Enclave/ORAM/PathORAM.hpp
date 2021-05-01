#ifndef __PATHORAM_ENCLAVE_HPP__
#define __PATHORAM_ENCLAVE_HPP__

#include "Block.hpp"
#include "oram_utils.hpp"

#include "ORAMTree.hpp"
#include "ORAM_Interface.hpp"

class PathORAM: public ORAMTree, public ORAM_Interface {
    public:
        PathORAM(){};

        void initialize(uint8_t Z, uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t recursion_data_size, uint8_t recursion_levels);

        // Access Functions
        uint32_t access(uint32_t id, uint32_t position_in_id, char opType, uint8_t level, unsigned char *data_in, unsigned char *data_out, uint32_t *prev_sampled_leaf);
        uint32_t access_oram_level(char op_type, uint32_t leaf, uint32_t id, uint32_t position_in_id, uint32_t level, uint32_t newleaf, uint32_t newleaf_nextlevel, unsigned char *data_in, unsigned char *data_out);
        uint32_t PathORAM_Access(char op_type, uint32_t id, uint32_t position_in_id, uint32_t leaf, uint32_t newleaf, uint32_t newleaf_nextlevel, unsigned char *decrypted_path, unsigned char *path_hash, uint32_t level, unsigned char *data_in, unsigned char *data_out);
        
        void PathORAM_RebuildPath(unsigned char *decrypted_path_ptr, uint32_t data_size, uint32_t block_size, uint32_t leaf, uint32_t level);

        // Virtual Fucntions, inherited from ORAMTree Class
        void Access(uint32_t id, char op_type, unsigned char *data_in, unsigned char *data_out);
        void Create(uint8_t Z, uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t recursion_data_size, uint8_t recursion_levels);
};

#endif
