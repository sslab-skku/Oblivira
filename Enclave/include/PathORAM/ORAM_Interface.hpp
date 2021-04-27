#ifndef __ORAM_INTERFACE_HPP__
#define __ORAM_INTERFACE_HPP__

#include <stdint.h>

class ORAM_Interface {
    public:
        virtual void Create(uint8_t pZ, uint32_t max_blocks, uint32_t data_size, uint32_t stash_size, uint32_t recursion_data_size, uint8_t recursion_levels) = 0;
        virtual void Access(uint32_t id, char op_type, unsigned char *data_in, unsigned char *data_out) = 0;
};

#endif