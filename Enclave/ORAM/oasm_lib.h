#ifndef __OASM_LIB_H__
#define __OASM_LIB_H__

#include <stdint.h>
#include "Block.hpp"

extern "C" void oassign_newlabel(uint32_t *ptr_to_label, uint32_t new_label, bool flag);
extern "C" void ofix_recursion(unsigned char *ptr_to_data_in_block, bool flag, uint32_t new_label, uint32_t* next_leaf);
extern "C" void omove(uint32_t i, uint32_t *item, uint32_t loc, uint32_t *leaf, uint32_t new_label);
extern "C" void omove_buffer(unsigned char *dest, unsigned char *source, uint32_t buffersize, uint32_t flag);

extern "C" void oset_value(uint32_t *dest, uint32_t value, uint32_t flag);
extern "C" void oincrement_value(uint32_t *dest, uint32_t flag);
extern "C" void omove_serialized_block(unsigned char *dest_block, unsigned char *source_block, uint32_t data_size, uint32_t flag);

extern "C" void stash_serialized_insert(unsigned char* iter_block, unsigned char *block, uint32_t extdata_size, bool flag, bool *block_written);

#endif
