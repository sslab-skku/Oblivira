#ifndef __STASH_HPP__
#define __STASH_HPP__

#include "PathORAM/oram_utils.hpp"

struct nodev2 {
    unsigned char *serialized_block;
    struct nodev2 *next;
};

class Stash {
    private:
        struct nodev2 *start;
        uint32_t current_size;
        uint32_t stash_data_size;
        uint32_t stash_size; // maximum stash size!
        uint64_t gN;
    public:
        Stash();

        void setup(uint32_t stash_size, uint32_t data_size, uint32_t gN);
        void insertNewBlock();
        struct nodev2 *getStart();
        void setStart(struct nodev2 *new_start);

        void performAccessOperation(char op_type, uint32_t id, uint32_t newleaf, unsigned char *data_in, unsigned char *data_out);

        void passInsert(unsigned char *serialized_block, bool is_dummy);
};

#endif