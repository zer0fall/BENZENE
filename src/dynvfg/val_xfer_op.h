#ifndef __VAL_XFER_OP_H__
#define __VAL_XFER_OP_H__
#include "pin.H"
#include "vfg_nodes.h"

void PIN_FAST_ANALYSIS_CALL val_r2r_xfer_opb_ul(THREADID tid, uint32_t dst,
                                            uint32_t src);
void PIN_FAST_ANALYSIS_CALL val_r2r_xfer_opb_lu(THREADID tid, uint32_t dst,
                                            uint32_t src);
void PIN_FAST_ANALYSIS_CALL val_r2r_xfer_opb_u(THREADID tid, uint32_t dst,
                                           uint32_t src);
void PIN_FAST_ANALYSIS_CALL val_r2r_xfer_opb_l(THREADID tid, uint32_t dst,
                                           uint32_t src);
void PIN_FAST_ANALYSIS_CALL val_r2r_xfer_opw(THREADID tid, uint32_t dst,
                                         uint32_t src);
void PIN_FAST_ANALYSIS_CALL val_r2r_xfer_opl(THREADID tid, uint32_t dst,
                                         uint32_t src);
void PIN_FAST_ANALYSIS_CALL val_r2r_xfer_opq(THREADID tid, uint32_t dst,
                                         uint32_t src);
void PIN_FAST_ANALYSIS_CALL val_r2r_xfer_opx(THREADID tid, uint32_t dst,
                                         uint32_t src);
void PIN_FAST_ANALYSIS_CALL val_r2r_xfer_opy(THREADID tid, uint32_t dst,
                                         uint32_t src);

void PIN_FAST_ANALYSIS_CALL val_m2r_xfer_opb_u(THREADID tid, uint32_t dst,
                                           ADDRINT src);
void PIN_FAST_ANALYSIS_CALL val_m2r_xfer_opb_l(THREADID tid, uint32_t dst,
                                           ADDRINT src);
void PIN_FAST_ANALYSIS_CALL val_m2r_xfer_opw(THREADID tid, uint32_t dst,
                                         ADDRINT src);
void PIN_FAST_ANALYSIS_CALL val_m2r_xfer_opl(THREADID tid, uint32_t dst,
                                         ADDRINT src);
void PIN_FAST_ANALYSIS_CALL val_m2r_xfer_opq(THREADID tid, uint32_t dst,
                                         ADDRINT src);
void PIN_FAST_ANALYSIS_CALL val_m2r_xfer_opx(THREADID tid, uint32_t dst,
                                         ADDRINT src);
void PIN_FAST_ANALYSIS_CALL val_m2r_xfer_opy(THREADID tid, uint32_t dst,
                                         ADDRINT src);

void PIN_FAST_ANALYSIS_CALL val_r2m_xfer_opb_u(THREADID tid, ADDRINT dst,
                                           uint32_t src);
void PIN_FAST_ANALYSIS_CALL val_r2m_xfer_opb_l(THREADID tid, ADDRINT dst,
                                           uint32_t src);
void PIN_FAST_ANALYSIS_CALL val_r2m_xfer_opw(THREADID tid, ADDRINT dst,
                                         uint32_t src);
void PIN_FAST_ANALYSIS_CALL val_r2m_xfer_opl(THREADID tid, ADDRINT dst,
                                         uint32_t src);
void PIN_FAST_ANALYSIS_CALL val_r2m_xfer_opq(THREADID tid, ADDRINT dst,
                                         uint32_t src);
void PIN_FAST_ANALYSIS_CALL val_r2m_xfer_opx(THREADID tid, ADDRINT dst,
                                         uint32_t src);
void PIN_FAST_ANALYSIS_CALL val_r2m_xfer_opy(THREADID tid, ADDRINT dst,
                                         uint32_t src);

void PIN_FAST_ANALYSIS_CALL val_m2m_xfer_opb(ADDRINT dst, ADDRINT src);
void PIN_FAST_ANALYSIS_CALL val_m2m_xfer_opw(ADDRINT dst, ADDRINT src);
void PIN_FAST_ANALYSIS_CALL val_m2m_xfer_opl(ADDRINT dst, ADDRINT src);
void PIN_FAST_ANALYSIS_CALL val_m2m_xfer_opq(ADDRINT dst, ADDRINT src);

void val_xfer_op(INS ins, InsNode* node);
void val_xfer_op_predicated(INS ins, InsNode* node);

void val_stosb(INS ins, InsNode* node);
void val_stosw(INS ins, InsNode* node);
void val_stosd(INS ins, InsNode* node);
void val_stosq(INS ins, InsNode* node);

void val_movlp(INS ins, InsNode* node);
void val_movhp(INS ins, InsNode* node);

// void val_lea(INS ins, InsNode * node);
void val_movbe_op(INS ins, InsNode* node);
void val_push_op(INS ins, InsNode* node);
void val_pop_op(INS ins, InsNode* node);

#endif
