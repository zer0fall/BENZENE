#ifndef __VAL_BINARY_OP_H__
#define __VAL_BINARY_OP_H__
#include "pin.H"
#include "vfg_nodes.h"


void PIN_FAST_ANALYSIS_CALL val_r2r_binary_opb_ul(THREADID tid, uint32_t dst,
                                                     uint32_t src);

void PIN_FAST_ANALYSIS_CALL val_r2r_binary_opb_lu(THREADID tid, uint32_t dst,
                                                     uint32_t src);

void PIN_FAST_ANALYSIS_CALL val_r2r_binary_opb_u(THREADID tid, uint32_t dst,
                                                    uint32_t src);

void PIN_FAST_ANALYSIS_CALL val_r2r_binary_opb_l(THREADID tid, uint32_t dst,
                                                    uint32_t src);

void PIN_FAST_ANALYSIS_CALL val_r2r_binary_opw(THREADID tid, uint32_t dst,
                                                  uint32_t src);

void PIN_FAST_ANALYSIS_CALL val_r2r_binary_opl(THREADID tid, uint32_t dst,
                                                  uint32_t src);

void PIN_FAST_ANALYSIS_CALL val_r2r_binary_opq(THREADID tid, uint32_t dst,
                                                  uint32_t src);

void val_binary_op(INS ins, InsNode* node);
void val_binary_clean(INS ins, InsNode* node);

#endif