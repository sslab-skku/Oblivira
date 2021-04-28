#include "PathORAM/Stash.hpp"

#if defined(OBLIVIRA_PRINT_LOG)
#include <cstdio>
#endif

Stash::Stash()
{
}

void Stash::setup(uint32_t p_stash_size, uint32_t p_data_size, uint32_t p_gN)
{
    gN = p_gN;
    stash_size = p_stash_size;
    stash_data_size = p_data_size;
    current_size = 0;
    for (uint32_t i = 0; i < stash_size; i++)
    {
        insertNewBlock();
    }
}

void Stash::insertNewBlock()
{
    Block block(stash_data_size, gN);
    struct nodev2 *new_node = (struct nodev2 *)malloc(sizeof(struct nodev2));

    if (current_size == stash_size)
    {
        return;
    }
    else
    {
        unsigned char *serialized_block = block.serialize(stash_data_size);
        new_node->serialized_block = serialized_block;
        new_node->next = getStart();
        setStart(new_node);
        current_size++;
    }
}

struct nodev2 *Stash::getStart()
{
    return start;
}

void Stash::setStart(struct nodev2 *new_start)
{
    start = new_start;
}

void Stash::performAccessOperation(char op_type, uint32_t id, uint32_t newleaf, unsigned char *data_in, unsigned char *data_out)
{
    struct nodev2 *iter = getStart();
    uint8_t cnt = 1;
    uint32_t flag_id = 0, flag_w = 0, flag_r = 0;
    unsigned char *data_ptr;
    uint32_t *leaflabel_ptr;

    while (iter && cnt <= stash_size)
    {
        data_ptr = (unsigned char *)getDataPtr(iter->serialized_block);
        leaflabel_ptr = getTreeLabelPtr(iter->serialized_block);
        flag_id = (getId(iter->serialized_block) == id);

        //Replace leaflabel in block with newleaf
        oassign_newlabel(leaflabel_ptr, newleaf, flag_id);
        flag_w = (flag_id && op_type == 'w');
        omove_buffer((unsigned char *)data_ptr, data_in, stash_data_size, flag_w);
        flag_r = (flag_id && op_type == 'r');
        omove_buffer(data_out, (unsigned char *)data_ptr, stash_data_size, flag_r);

        iter = iter->next;
        cnt++;
    }
}

void Stash::passInsert(unsigned char *serialized_block, bool is_dummy)
{
    struct nodev2 *iter = start;
    bool block_written = false;
    uint8_t cnt = 1;

    while (iter && cnt <= stash_size)
    {
        bool flag = (!is_dummy && (isBlockDummy(iter->serialized_block, gN)) && !block_written);
        stash_serialized_insert(iter->serialized_block, serialized_block, stash_data_size, flag, &block_written);
        iter = iter->next;
        cnt++;
    }
}