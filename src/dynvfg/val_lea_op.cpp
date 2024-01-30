#include "val_lea_op.h"
#include "val_xfer_op.h"
#include "val_binary_op.h"
#include "val_helper.h"
#include "value_core.h"

#include <iostream>

extern thread_ctx_t *threads_ctx;
extern tag_t c_tag;
extern VFGCore *vfg_core;

extern bool val_enable;

/*
 *
 * LEA Instruction Callbacks
 * LEA is similar to binary operation
 * 
 */ 
static void PIN_FAST_ANALYSIS_CALL _lea_opw(THREADID tid, uint32_t dst,
                                            uint32_t base, uint32_t index) {
    if (val_enable == false) return;

    tag_t *dst_tags = RTAG[dst];

    for (size_t i = 0; i < 2; i++) {
        if (!tag_is_empty(RTAG[base][i])) {
            vfg_core->addInTag(RTAG[base][i], 0);
        }
        if (!tag_is_empty(RTAG[index][i])) {
            vfg_core->addInTag(RTAG[index][i], 1);
        }
        dst_tags[i] = c_tag;
    }        
}

static void PIN_FAST_ANALYSIS_CALL _lea_opl(THREADID tid, uint32_t dst,
                                            uint32_t base, uint32_t index) {
    if (val_enable == false) return;
    for (size_t i = 0; i < 4; i++)
        RTAG[dst][i] = c_tag;

    tag_t *dst_tags = RTAG[dst];

    for (size_t i = 0; i < 4; i++) {
        if (!tag_is_empty(RTAG[base][i])) {
            vfg_core->addInTag(RTAG[base][i], 0);
        }
        if (!tag_is_empty(RTAG[index][i])) {
            vfg_core->addInTag(RTAG[index][i], 1);
        } 
        dst_tags[i] = c_tag;
    }        
}

static void PIN_FAST_ANALYSIS_CALL _lea_opq(THREADID tid, uint32_t dst,
                                            uint32_t base, uint32_t index) {
    if (val_enable == false) return;
    
    tag_t *dst_tags = RTAG[dst];
    
    for (size_t i = 0; i < 8; i++) {
        if (!tag_is_empty(RTAG[base][i])) {
            vfg_core->addInTag(RTAG[base][i], 0);
        }
        if (!tag_is_empty(RTAG[index][i])) {
            vfg_core->addInTag(RTAG[index][i], 1);
        } 
        dst_tags[i] = c_tag;
    }     
}


static void PIN_FAST_ANALYSIS_CALL val_lea_binary_opw(THREADID tid, uint32_t dst, 
                                                    uint32_t base) {
    if (val_enable == false) return;

    tag_t *dst_tags = RTAG[dst];
    
    for (size_t i = 0; i < 2; i++) {
        if (!tag_is_empty(RTAG[base][i])) {
            vfg_core->addInTag(RTAG[base][i], 0);
        }
        dst_tags[i] = c_tag;
    }         
}

static void PIN_FAST_ANALYSIS_CALL val_lea_binary_opl(THREADID tid, uint32_t dst, 
                                                    uint32_t base) {
    if (val_enable == false) return;

    tag_t *dst_tags = RTAG[dst];
    
    for (size_t i = 0; i < 4; i++) {
        if (!tag_is_empty(RTAG[base][i])) {
            vfg_core->addInTag(RTAG[base][i], 0);
        }
        dst_tags[i] = c_tag;
    }    
}

static void PIN_FAST_ANALYSIS_CALL val_lea_binary_opq(THREADID tid, uint32_t dst, 
                                                    uint32_t base) {
    if (val_enable == false) return;
    
    tag_t *dst_tags = RTAG[dst];
    
    for (size_t i = 0; i < 8; i++) {
        if (!tag_is_empty(RTAG[base][i])) {
            vfg_core->addInTag(RTAG[base][i], 0);
        }
        dst_tags[i] = c_tag;
    }   
}


void val_lea_op(INS ins, InsNode* node) {
    REG reg_base = INS_MemoryBaseReg(ins);
    REG reg_indx = INS_MemoryIndexReg(ins);

    REG reg_dst = INS_OperandReg(ins, OP_0);

    //   if (reg_base == REG_INVALID() && reg_indx == REG_INVALID()) {
    //     ins_clear_op(ins);
    //   }
    if (reg_base != REG_INVALID() && reg_indx == REG_INVALID()) {
        node->addDataFlowEdge(reg_base, 0);        
        
        if (INS_OperandMemoryDisplacement(ins, OP_1)) { 
            // ex) lea eax, ptr [rdx+0x1234]
            if (REG_is_gr64(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)val_lea_binary_opq,
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_THREAD_ID,
                    IARG_UINT32, REG_INDX(reg_dst),
                    IARG_UINT32, REG_INDX(reg_base),
                    IARG_END
                );
            } else if (REG_is_gr32(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)val_lea_binary_opl,
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_THREAD_ID,
                    IARG_UINT32, REG_INDX(reg_dst),
                    IARG_UINT32, REG_INDX(reg_base),
                    IARG_END
                );
            } else if (REG_is_gr16(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)val_lea_binary_opw,
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_THREAD_ID,
                    IARG_UINT32, REG_INDX(reg_dst),
                    IARG_UINT32, REG_INDX(reg_base),
                    IARG_END
                );            
            }
        }
        else { // ex) lea rax, [rdx]
            if (REG_is_gr64(reg_dst)) {
                R2R_CALL(val_r2r_xfer_opq, reg_dst, reg_base);
            } else if (REG_is_gr32(reg_dst)) { // lea    eax,[rdx+0x1234]
                R2R_CALL(val_r2r_xfer_opl, reg_dst, reg_base);
            } else if (REG_is_gr16(reg_dst)) {
                R2R_CALL(val_r2r_xfer_opw, reg_dst, reg_base);
            }
        }
    }
    else if (reg_base == REG_INVALID() && reg_indx != REG_INVALID()) {
        node->addDataFlowEdge(reg_indx, 0);        

        // std::cerr << INS_Disassemble(ins) << std::endl;
        if (REG_is_gr64(reg_dst)) {
            R2R_CALL(val_r2r_xfer_opq, reg_dst, reg_indx);
        } else if (REG_is_gr32(reg_dst)) {
            R2R_CALL(val_r2r_xfer_opl, reg_dst, reg_indx);
        } else if (REG_is_gr16(reg_dst)) {
            R2R_CALL(val_r2r_xfer_opw, reg_dst, reg_indx);
        }
    }
    else if (reg_base != REG_INVALID() && reg_indx != REG_INVALID()) {
        node->addDataFlowEdge(reg_base, 0);
        node->addDataFlowEdge(reg_indx, 1);
        
        if (REG_is_gr64(reg_dst)) {
            // std::cerr << INS_Disassemble(ins) << std::endl;
            RR2R_CALL(_lea_opq, reg_dst, reg_base, reg_indx);
        } else if (REG_is_gr32(reg_dst)) {
            RR2R_CALL(_lea_opl, reg_dst, reg_base, reg_indx);
        } else if (REG_is_gr16(reg_dst)) {
            RR2R_CALL(_lea_opw, reg_dst, reg_base, reg_indx);
        }
    }
}
