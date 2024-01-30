#include "value_core.h"
#include "val_xfer_op.h"
#include "val_helper.h"

#include <iostream>

/* threads context */
extern thread_ctx_t *threads_ctx;
extern tag_t c_tag;
extern VFGCore *vfg_core;


extern bool val_enable;


void PIN_FAST_ANALYSIS_CALL val_r2r_xfer_opb_ul(THREADID tid, uint32_t dst,
                                            uint32_t src) {
    if (val_enable == false) return;

    tag_t src_tag = RTAG[src][0];
    if (!tag_is_empty(src_tag))
        vfg_core->addInTag(src_tag, 0);
    RTAG[dst][1] = c_tag;
}

void PIN_FAST_ANALYSIS_CALL val_r2r_xfer_opb_lu(THREADID tid, uint32_t dst,
                                            uint32_t src) {
    if (val_enable == false) return;

    tag_t src_tag = RTAG[src][1];
    if (!tag_is_empty(src_tag))
        vfg_core->addInTag(src_tag, 0);
    RTAG[dst][0] = c_tag;
}

void PIN_FAST_ANALYSIS_CALL val_r2r_xfer_opb_u(THREADID tid, uint32_t dst,
                                           uint32_t src) {
    if (val_enable == false) return;

    tag_t src_tag = RTAG[src][1];
    if (!tag_is_empty(src_tag))
        vfg_core->addInTag(src_tag, 0);
    RTAG[dst][1] = c_tag;
}

void PIN_FAST_ANALYSIS_CALL val_r2r_xfer_opb_l(THREADID tid, uint32_t dst,
                                           uint32_t src) {
    if (val_enable == false) return;

    tag_t src_tag = RTAG[src][0];
    if (!tag_is_empty(src_tag))
        vfg_core->addInTag(src_tag, 0);
    RTAG[dst][0] = c_tag;    
}

void PIN_FAST_ANALYSIS_CALL val_r2r_xfer_opw(THREADID tid, uint32_t dst,
                                         uint32_t src) {
    if (val_enable == false) return;

    for (size_t i = 0; i < 2; i++) {
        if (!tag_is_empty(RTAG[src][i]))
            vfg_core->addInTag(RTAG[src][i], 0);
        RTAG[dst][i] = c_tag;
    }  
}

void PIN_FAST_ANALYSIS_CALL val_r2r_xfer_opl(THREADID tid, uint32_t dst,
                                         uint32_t src) {
    if (val_enable == false) return;

    for (size_t i = 0; i < 4; i++) { 
        if (!tag_is_empty(RTAG[src][i]))
            vfg_core->addInTag(RTAG[src][i], 0);
        RTAG[dst][i] = c_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL val_r2r_xfer_opq(THREADID tid, uint32_t dst,
                                         uint32_t src) {
    if (val_enable == false) return;     

    for (size_t i = 0; i < 8; i++) {
        if (!tag_is_empty(RTAG[src][i]))
            vfg_core->addInTag(RTAG[src][i], 0);
        RTAG[dst][i] = c_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL val_r2r_xfer_opx(THREADID tid, uint32_t dst,
                                         uint32_t src) {
    if (val_enable == false) return;
    for (size_t i = 0; i < 16; i++) {
        if (!tag_is_empty(RTAG[src][i]))
            vfg_core->addInTag(RTAG[src][i], 0);
        RTAG[dst][i] = c_tag;              
    }
}

void PIN_FAST_ANALYSIS_CALL val_r2r_xfer_opy(THREADID tid, uint32_t dst,
                                         uint32_t src) {
    if (val_enable == false) return;
    for (size_t i = 0; i < 32; i++) {
        if (!tag_is_empty(RTAG[src][i]))
            vfg_core->addInTag(RTAG[src][i], 0);
        RTAG[dst][i] = c_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL val_m2r_xfer_opb_u(THREADID tid, uint32_t dst,
                                           ADDRINT src) {
    if (val_enable == false) return;
    
    tag_t src_tag = MTAG(src);
    if (!tag_is_empty(src_tag))
        vfg_core->addInTag(src_tag, 0);
    
    RTAG[dst][1] = c_tag;
}

void PIN_FAST_ANALYSIS_CALL val_m2r_xfer_opb_l(THREADID tid, uint32_t dst,
                                           ADDRINT src) {
    if (val_enable == false) return;

    tag_t src_tag = tagmap_getb(src);
    if (!tag_is_empty(src_tag))
        vfg_core->addInTag(src_tag, 0);
    
    RTAG[dst][0] = c_tag;     
}

void PIN_FAST_ANALYSIS_CALL val_m2r_xfer_opw(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
    if (val_enable == false) return;

    for (size_t i = 0; i < 2; i++) {
        tag_t src_tag = tagmap_getb(src + i);
        if (!tag_is_empty(src_tag))
            vfg_core->addInTag(src_tag, 0);
        
        RTAG[dst][i] = c_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL val_m2r_xfer_opl(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
    if (val_enable == false) return;

    for (size_t i = 0; i < 4; i++) {
        tag_t src_tag = tagmap_getb(src + i);
        if (!tag_is_empty(src_tag))
            vfg_core->addInTag(src_tag, 0);
        
        RTAG[dst][i] = c_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL val_m2r_xfer_opq(THREADID tid, uint32_t dst,
                                            ADDRINT src) {
    if (val_enable == false) return;

    for (size_t i = 0; i < 8; i++) {
        tag_t src_tag = tagmap_getb(src + i);
        if (!tag_is_empty(src_tag))
            vfg_core->addInTag(src_tag, 0);
        
        RTAG[dst][i] = c_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL val_m2r_xfer_opx(THREADID tid, uint32_t dst,
                                            ADDRINT src) {
    if (val_enable == false) return;
    for (size_t i = 0; i < 16; i++) {
        tag_t src_tag = tagmap_getb(src + i);
        if (!tag_is_empty(src_tag))
            vfg_core->addInTag(src_tag, 0);
        
        RTAG[dst][i] = c_tag;    
    }
}

void PIN_FAST_ANALYSIS_CALL val_m2r_xfer_opy(THREADID tid, uint32_t dst,
                                            ADDRINT src) {
    if (val_enable == false) return;
    for (size_t i = 0; i < 32; i++) {
        tag_t src_tag = tagmap_getb(src + i);
        if (!tag_is_empty(src_tag))
            vfg_core->addInTag(src_tag, 0);
        
        RTAG[dst][i] = c_tag;     
    }
}

void PIN_FAST_ANALYSIS_CALL val_r2m_xfer_opb_u(THREADID tid, ADDRINT dst,
                                           uint32_t src) {
    if (val_enable == false) return;

    tag_t src_tag = RTAG[src][1];
    if (!tag_is_empty(src_tag))
        vfg_core->addInTag(src_tag, 0);
    tagmap_setb(dst, c_tag);
}

void PIN_FAST_ANALYSIS_CALL val_r2m_xfer_opb_l(THREADID tid, ADDRINT dst,
                                           uint32_t src) {
    if (val_enable == false) return;
    
    tag_t src_tag = RTAG[src][0];
    if (!tag_is_empty(src_tag))
        vfg_core->addInTag(src_tag, 0);
    tagmap_setb(dst, c_tag);
}

void PIN_FAST_ANALYSIS_CALL val_r2m_xfer_opw(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
    if (val_enable == false) return;
    
    tag_t *src_tags = RTAG[src];

    if (!tag_is_empty(src_tags[0]))
        vfg_core->addInTag(src_tags[0], 0);
    tagmap_setb(dst, c_tag);        

    if (!tag_is_empty(src_tags[1]))
        vfg_core->addInTag(src_tags[1], 0);
    tagmap_setb(dst + 1, c_tag);                
}

void PIN_FAST_ANALYSIS_CALL val_r2m_xfer_opl(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
    if (val_enable == false) return;

    tag_t *src_tags = RTAG[src];

    for (size_t i = 0; i < 4; i++) {
        if (!tag_is_empty(src_tags[i]))
            vfg_core->addInTag(src_tags[i], 0);            
        tagmap_setb(dst + i, c_tag); 
    }    
}

void PIN_FAST_ANALYSIS_CALL val_r2m_xfer_opq(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
    if (val_enable == false) return;

    tag_t *src_tags = RTAG[src];
    for (size_t i = 0; i < 8; i++) {
        if (!tag_is_empty(src_tags[i]))
            vfg_core->addInTag(src_tags[i], 0);            
        tagmap_setb(dst + i, c_tag);                 
    }
}

void PIN_FAST_ANALYSIS_CALL val_r2m_xfer_opx(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
    if (val_enable == false) return;

    tag_t *src_tags = RTAG[src];
    for (size_t i = 0; i < 16; i++) {
        if (!tag_is_empty(src_tags[i]))
            vfg_core->addInTag(src_tags[i], 0);            
        tagmap_setb(dst + i, c_tag);              
    }
}

void PIN_FAST_ANALYSIS_CALL val_r2m_xfer_opy(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
    if (val_enable == false) return;

    tag_t *src_tags = RTAG[src];
    for (size_t i = 0; i < 32; i++) {
        if (!tag_is_empty(src_tags[i]))
            vfg_core->addInTag(src_tags[i], 0);            
        tagmap_setb(dst + i, c_tag);               
    }
}

void PIN_FAST_ANALYSIS_CALL val_m2m_xfer_opb(ADDRINT dst, ADDRINT src) {
    if (val_enable == false) return;

    tag_t src_tag = MTAG(src);
    if (!tag_is_empty(src_tag))
        vfg_core->addInTag(src_tag, 0);
    tagmap_setb(dst, c_tag);
}

void PIN_FAST_ANALYSIS_CALL val_m2m_xfer_opw(ADDRINT dst, ADDRINT src) {
    if (val_enable == false) return;
    
    tag_t src_tag = MTAG(src);
    for (size_t i = 0; i < 2; i++) {
        if (!tag_is_empty(src_tag))
            vfg_core->addInTag(src_tag, 0);
        tagmap_setb(dst + i, c_tag);
    }
}

void PIN_FAST_ANALYSIS_CALL val_m2m_xfer_opl(ADDRINT dst, ADDRINT src) {
    if (val_enable == false) return;

    for (size_t i = 0; i < 4; i++) {
        tag_t src_tag = MTAG(src + i);
        if (!tag_is_empty(src_tag))
            vfg_core->addInTag(src_tag, 0);
        tagmap_setb(dst + i, c_tag);
    }
}

void PIN_FAST_ANALYSIS_CALL val_m2m_xfer_opq(ADDRINT dst, ADDRINT src) {
    if (val_enable == false) return;
    
    for (size_t i = 0; i < 8; i++) {
        tag_t src_tag = MTAG(src + i);
        if (!tag_is_empty(src_tag))
            vfg_core->addInTag(src_tag, 0);
        tagmap_setb(dst + i, c_tag);
    }
}

void PIN_FAST_ANALYSIS_CALL val_m2r_xfer_opq_h(THREADID tid, uint32_t dst,
                                           ADDRINT src) {
    if (val_enable == false) return;

    for (size_t i = 0; i < 8; i++) {
        tag_t src_tag = MTAG(src + i);
        
        if (!tag_is_empty(src_tag))
            vfg_core->addInTag(src_tag, 0);
        RTAG[dst][i + 8] = c_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL val_r2m_xfer_opq_h(THREADID tid, ADDRINT dst,
                                           uint32_t src) {
    if (val_enable == false) return;
    
    tag_t *src_tags = RTAG[src];

    for (size_t i = 0; i < 8; i++) {
        if (!tag_is_empty(src_tags[i + 8]))
            vfg_core->addInTag(src_tags[i + 8], 0);
        tagmap_setb(dst + i, c_tag);
    }
}

static void PIN_FAST_ANALYSIS_CALL val_r2m_xfer_opbn(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags) {
    if (val_enable == false) return;

    tag_t src_tag = RTAG[DFT_REG_RAX][0];

    if (!tag_is_empty(src_tag)) {
        vfg_core->addInTag(src_tag, 0);
        return;
    }

    if (likely(EFLAGS_DF(eflags) == 0)) {
        /* EFLAGS.DF = 0 */
        for (size_t i = 0; i < count; i++) {
            tagmap_setb(dst + i, c_tag);
        }
    } else {
        /* EFLAGS.DF = 1 */
        for (size_t i = 0; i < count; i++) {
            size_t dst_addr = dst - count + 1 + i;
            tagmap_setb(dst_addr, c_tag);
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL val_r2m_xfer_opwn(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags) {
    if (val_enable == false) return;

    tag_t src_tag[] = R16TAG(DFT_REG_RAX);

    if (likely(EFLAGS_DF(eflags) == 0)) {
        /* EFLAGS.DF = 0 */
        for (size_t i = 0; i < (count << 1); i++) {
            if (tag_is_empty(src_tag[i % 2]))
                tagmap_setb(dst + i, c_tag);
            else {
                vfg_core->addInTag(src_tag[i % 2], 0);        
            }
        }
    } else {
        /* EFLAGS.DF = 1 */
        for (size_t i = 0; i < (count << 1); i++) {
            if (tag_is_empty(src_tag[i % 2])) {
                size_t dst_addr = dst - (count << 1) + 1 + i;
                tagmap_setb(dst_addr, c_tag);
            }
            else {
                vfg_core->addInTag(src_tag[i % 2], 0);        
            }
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL val_r2m_xfer_opln(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags) {
    if (val_enable == false) return;

    tag_t src_tag[] = R32TAG(DFT_REG_RAX);
    if (likely(EFLAGS_DF(eflags) == 0)) {
        /* EFLAGS.DF = 0 */
        for (size_t i = 0; i < (count << 2); i++) {
            if (tag_is_empty(src_tag[i % 4]))
                tagmap_setb(dst + i, c_tag);
            else {
                vfg_core->addInTag(src_tag[i % 4], 0);        
            }
        }
    } else {
        /* EFLAGS.DF = 1 */
        for (size_t i = 0; i < (count << 2); i++) {
            if (tag_is_empty(src_tag[i % 4])) {
                size_t dst_addr = dst - (count << 2) + 1 + i;
                tagmap_setb(dst_addr, c_tag);
            }
            else {
                vfg_core->addInTag(src_tag[i % 4], 0);        
            }
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL val_r2m_xfer_opqn(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags) {
    if (val_enable == false) return;

    tag_t src_tag[] = R64TAG(DFT_REG_RAX);
    if (likely(EFLAGS_DF(eflags) == 0)) {
        /* EFLAGS.DF = 0 */
        for (size_t i = 0; i < (count << 2); i++) {
            if (tag_is_empty(src_tag[i % 8])) {
                tagmap_setb(dst + i, c_tag);
            }
            else {
                vfg_core->addInTag(src_tag[i % 8], 0);        
            }
        }
    } else {
        /* EFLAGS.DF = 1 */
        for (size_t i = 0; i < (count << 2); i++) {
            if (tag_is_empty(src_tag[i % 8])) {
                size_t dst_addr = dst - (count << 2) + 1 + i;
                tagmap_setb(dst_addr, c_tag);
            }
            else {
                vfg_core->addInTag(src_tag[i % 8], 0);        
            }            
        }
    }
}

static ADDRINT PIN_FAST_ANALYSIS_CALL rep_predicate(BOOL first_iteration) {
  /* return the flag; typically this is true only once */
    return first_iteration;
}

// Immediate xfer operations
static void PIN_FAST_ANALYSIS_CALL r_xfer_imm_opq(THREADID tid, uint32_t reg) {
    if (val_enable == false) return;
    for (size_t i = 0; i < 8; i++) {
        RTAG[reg][i] = c_tag;
    }
}

static void PIN_FAST_ANALYSIS_CALL r_xfer_imm_opl(THREADID tid, uint32_t reg) {
    if (val_enable == false) return;
    for (size_t i = 0; i < 4; i++) {
        RTAG[reg][i] = c_tag;
    }    
}

static void PIN_FAST_ANALYSIS_CALL r_xfer_imm_opw(THREADID tid, uint32_t reg) {
    if (val_enable == false) return;
    for (size_t i = 0; i < 2; i++) {
        RTAG[reg][i] = c_tag;
    }
}

static void PIN_FAST_ANALYSIS_CALL r_xfer_imm_opb_l(THREADID tid, uint32_t reg) {
    if (val_enable == false) return;
    RTAG[reg][0] = c_tag;
}

static void PIN_FAST_ANALYSIS_CALL r_xfer_imm_opb_u(THREADID tid, uint32_t reg) {
    if (val_enable == false) return;
    RTAG[reg][1] = c_tag;
}

static void PIN_FAST_ANALYSIS_CALL m_xfer_imm_op(THREADID tid, ADDRINT dst, uint32_t size) {
    if (val_enable == false) return;    
    for (uint32_t i = 0; i < size; i++)
        tagmap_setb(dst+i, c_tag);
}

void val_xfer_op(INS ins, InsNode* node) {
    REG reg_dst, reg_src;
    if (INS_OperandIsImmediate(ins, OP_1)) {
        if (INS_IsMemoryWrite(ins)) { // mov dword ptr [rsp+0xc], 0x1            
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_xfer_imm_op,
                IARG_FAST_ANALYSIS_CALL,
                IARG_THREAD_ID,
                IARG_MEMORYWRITE_EA,
                IARG_MEMORYWRITE_SIZE,
                IARG_END);
        }
        else { // mov eax, 0x1
            reg_dst = INS_OperandReg(ins, OP_0);

            if (REG_is_gr64(reg_dst)) {
                R_CALL(r_xfer_imm_opq, reg_dst);
            } else if (REG_is_gr32(reg_dst)) {
                R_CALL(r_xfer_imm_opl, reg_dst);
            } else if (REG_is_gr16(reg_dst)) {
                R_CALL(r_xfer_imm_opw, reg_dst);
            } else if (REG_is_xmm(reg_dst)) {
                assert(false);
            } else if (REG_is_ymm(reg_dst)) {
                assert(false);
            } else if (REG_is_mm(reg_dst)) {
                assert(false);
            } else {
                if (REG_is_Lower8(reg_dst)) {
                    R_CALL(r_xfer_imm_opb_l, reg_dst);
                } else if (REG_is_Upper8(reg_dst)) {
                    R_CALL(r_xfer_imm_opb_u, reg_dst);
                }
                else {
                    assert(false);
                }
            }
        }

        return;
    }

    if (INS_MemoryOperandCount(ins) == 0) {
        reg_dst = INS_OperandReg(ins, OP_0);
        reg_src = INS_OperandReg(ins, OP_1);

        node->addDataFlowEdge(reg_src, 0);

        if (REG_is_gr64(reg_dst)) {
            R2R_CALL(val_r2r_xfer_opq, reg_dst, reg_src);
        } else if (REG_is_gr32(reg_dst)) {
            R2R_CALL(val_r2r_xfer_opl, reg_dst, reg_src);
        } else if (REG_is_gr16(reg_dst)) {
            R2R_CALL(val_r2r_xfer_opw, reg_dst, reg_src);
        } else if (REG_is_xmm(reg_dst)) {
            R2R_CALL(val_r2r_xfer_opx, reg_dst, reg_src);
        } else if (REG_is_ymm(reg_dst)) {
            R2R_CALL(val_r2r_xfer_opy, reg_dst, reg_src);
        } else if (REG_is_mm(reg_dst)) {
            R2R_CALL(val_r2r_xfer_opq, reg_dst, reg_src);
        } else {
            if (REG_is_Lower8(reg_dst) && REG_is_Lower8(reg_src)) {
                R2R_CALL(val_r2r_xfer_opb_l, reg_dst, reg_src);
            } else if (REG_is_Upper8(reg_dst) && REG_is_Upper8(reg_src)) {
                R2R_CALL(val_r2r_xfer_opb_u, reg_dst, reg_src);
            } else if (REG_is_Lower8(reg_dst)) {
                R2R_CALL(val_r2r_xfer_opb_lu, reg_dst, reg_src);
            } else {
                R2R_CALL(val_r2r_xfer_opb_ul, reg_dst, reg_src);
            }
        }
    } 
    else if (INS_OperandIsMemory(ins, OP_1)) {
        reg_dst = INS_OperandReg(ins, OP_0);

        node->addDataFlowEdge(REG_MEM, 0);

        if (REG_is_gr64(reg_dst)) {
            M2R_CALL(val_m2r_xfer_opq, reg_dst);
        } else if (REG_is_gr32(reg_dst)) {
            M2R_CALL(val_m2r_xfer_opl, reg_dst);
        } else if (REG_is_gr16(reg_dst)) {
            M2R_CALL(val_m2r_xfer_opw, reg_dst);
        } else if (REG_is_xmm(reg_dst)) {
            M2R_CALL(val_m2r_xfer_opx, reg_dst);
        } else if (REG_is_ymm(reg_dst)) {
            M2R_CALL(val_m2r_xfer_opy, reg_dst);
        } else if (REG_is_mm(reg_dst)) {
            M2R_CALL(val_m2r_xfer_opq, reg_dst);
        } else if (REG_is_Upper8(reg_dst)) {
            M2R_CALL(val_m2r_xfer_opb_u, reg_dst);
        } else {
            M2R_CALL(val_m2r_xfer_opb_l, reg_dst);
        }
    } else {
        reg_src = INS_OperandReg(ins, OP_1);

        node->addDataFlowEdge(reg_src, 0);

        if (REG_is_gr64(reg_src)) {
            R2M_CALL(val_r2m_xfer_opq, reg_src);
        } else if (REG_is_gr32(reg_src)) {
            R2M_CALL(val_r2m_xfer_opl, reg_src);
        } else if (REG_is_gr16(reg_src)) {
            R2M_CALL(val_r2m_xfer_opw, reg_src);
        } else if (REG_is_xmm(reg_src)) {
            R2M_CALL(val_r2m_xfer_opx, reg_src);
        } else if (REG_is_ymm(reg_src)) {
            R2M_CALL(val_r2m_xfer_opy, reg_src);
        } else if (REG_is_mm(reg_src)) {
            R2M_CALL(val_r2m_xfer_opq, reg_src);
        } else if (REG_is_Upper8(reg_src)) {
            R2M_CALL(val_r2m_xfer_opb_u, reg_src);
        } else {
            R2M_CALL(val_r2m_xfer_opb_l, reg_src);
        }
    }
}

void val_xfer_op_predicated(INS ins, InsNode * node) {
    REG reg_dst, reg_src;
    if (INS_MemoryOperandCount(ins) == 0) {
        reg_dst = INS_OperandReg(ins, OP_0);
        reg_src = INS_OperandReg(ins, OP_1);

        node->addDataFlowEdge(reg_src, 0);

        if (REG_is_gr64(reg_dst)) {
            R2R_CALL_P(val_r2r_xfer_opq, reg_dst, reg_src);
        } else if (REG_is_gr32(reg_dst)) {
            R2R_CALL_P(val_r2r_xfer_opl, reg_dst, reg_src);
        } else {
            R2R_CALL_P(val_r2r_xfer_opw, reg_dst, reg_src);
        }
    } else {
        reg_dst = INS_OperandReg(ins, OP_0);

        node->addDataFlowEdge(REG_MEM, 0);

        if (REG_is_gr64(reg_dst)) {
            M2R_CALL_P(val_m2r_xfer_opq, reg_dst);
        } else if (REG_is_gr32(reg_dst)) {
            M2R_CALL_P(val_m2r_xfer_opl, reg_dst);
        } else {
            M2R_CALL_P(val_m2r_xfer_opw, reg_dst);
        }
    }
}

// @TODO: handle stos series
void val_stos_ins(INS ins, AFUNPTR fn) {
  INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)rep_predicate,
                             IARG_FAST_ANALYSIS_CALL, IARG_FIRST_REP_ITERATION,
                             IARG_END);
  INS_InsertThenPredicatedCall(
      ins, IPOINT_BEFORE, fn, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
      IARG_MEMORYWRITE_EA, IARG_REG_VALUE, INS_RepCountRegister(ins),
      IARG_REG_VALUE, INS_OperandReg(ins, OP_4), IARG_END);
}

void val_stosb(INS ins, InsNode * node) {
    node->addDataFlowEdge(REG_AL, 0);
    if (INS_RepPrefix(ins)) {
        val_stos_ins(ins, (AFUNPTR)val_r2m_xfer_opbn);
    } else {
        R2M_CALL(val_r2m_xfer_opb_l, REG_AL);
    }
}

void val_stosw(INS ins, InsNode * node) {
    node->addDataFlowEdge(REG_AX, 0);
    if (INS_RepPrefix(ins)) {
        val_stos_ins(ins, (AFUNPTR)val_r2m_xfer_opwn);
    } else {
        R2M_CALL(val_r2m_xfer_opw, REG_AX);
    }
}

void val_stosd(INS ins, InsNode * node) {
    node->addDataFlowEdge(REG_EAX, 0);
    if (INS_RepPrefix(ins)) {
        val_stos_ins(ins, (AFUNPTR)val_r2m_xfer_opln);
    } else {
        R2M_CALL(val_r2m_xfer_opw, REG_EAX);
    }
}

void val_stosq(INS ins, InsNode * node) {
    node->addDataFlowEdge(REG_RAX, 0);
    if (INS_RepPrefix(ins)) {
        val_stos_ins(ins, (AFUNPTR)val_r2m_xfer_opqn);
    } else {
        R2M_CALL(val_r2m_xfer_opw, REG_RAX);
    }
}

void val_movlp(INS ins, InsNode * node) {
  if (INS_OperandIsMemory(ins, OP_0)) {
    REG reg_src = INS_OperandReg(ins, OP_1);

    node->addDataFlowEdge(reg_src, 0);

    R2M_CALL(val_r2m_xfer_opq, reg_src);
  } else {
    REG reg_dst = INS_OperandReg(ins, OP_0);

    node->addDataFlowEdge(REG_MEM, 0);

    M2R_CALL(val_m2r_xfer_opq, reg_dst);
  }
}

void val_movhp(INS ins, InsNode * node) {
  if (INS_OperandIsMemory(ins, OP_0)) {
    REG reg_src = INS_OperandReg(ins, OP_1);

    node->addDataFlowEdge(reg_src, 0);

    R2M_CALL(val_r2m_xfer_opq_h, reg_src);
  } else {
    REG reg_dst = INS_OperandReg(ins, OP_0);

    node->addDataFlowEdge(REG_MEM, 0);

    M2R_CALL(val_m2r_xfer_opq_h, reg_dst);
  }
}

void PIN_FAST_ANALYSIS_CALL val_m2r_xfer_opw_rev(THREADID tid, uint32_t dst,
                                             ADDRINT src) {
    if (val_enable == false) return;
    
    for (size_t i = 0; i < 2; i++) {
        tag_t src_tag = MTAG(src + (1 - i));
        
        if (tag_is_empty(src_tag)) {
            RTAG[dst][i] = c_tag;
        } 
        else {
            vfg_core->addInTag(src_tag, 0);                    
        }
    }
}

void PIN_FAST_ANALYSIS_CALL val_m2r_xfer_opl_rev(THREADID tid, uint32_t dst,
                                             ADDRINT src) {
    if (val_enable == false) return;

    for (size_t i = 0; i < 4; i++) {
        tag_t src_tag = MTAG(src + (3 - i));
    
        if (tag_is_empty(src_tag)) {
            RTAG[dst][i] = c_tag;
        } 
        else {
            vfg_core->addInTag(src_tag, 0);                    
        }        
    }
}

void PIN_FAST_ANALYSIS_CALL val_m2r_xfer_opq_rev(THREADID tid, uint32_t dst,
                                             ADDRINT src) {
    if (val_enable == false) return;

    for (size_t i = 0; i < 8; i++) {
        tag_t src_tag = MTAG(src + (7 - i));
    
        if (tag_is_empty(src_tag)) {
            RTAG[dst][i] = c_tag;
        } 
        else {
            vfg_core->addInTag(src_tag, 0);                    
        }    
    }
}

void PIN_FAST_ANALYSIS_CALL val_r2m_xfer_opw_rev(THREADID tid, ADDRINT dst,
                                             uint32_t src) {
    if (val_enable == false) return;

    tag_t *src_tags = RTAG[src];

    if (tag_is_empty(src_tags[1])) {
        tagmap_setb(dst, c_tag);        
    }
    else {
        vfg_core->addInTag(src_tags[1], 0);                    
    }

    if (tag_is_empty(src_tags[0])) {
        tagmap_setb(dst + 1, c_tag);        
    }
    else {
        vfg_core->addInTag(src_tags[0], 0);                    
    }    
}

void PIN_FAST_ANALYSIS_CALL val_r2m_xfer_opl_rev(THREADID tid, ADDRINT dst,
                                             uint32_t src) {

    if (val_enable == false) return;

    tag_t *src_tags = RTAG[src];

    for (size_t i = 0; i < 4; i++) {
        if (tag_is_empty(src_tags[i])) {
            tagmap_setb(dst + (3 - i), c_tag);
        }
        else {
            vfg_core->addInTag(src_tags[i], 0);                    
        }
    }
}

void PIN_FAST_ANALYSIS_CALL val_r2m_xfer_opq_rev(THREADID tid, ADDRINT dst,
                                             uint32_t src) {
    if (val_enable == false) return;
    
    tag_t *src_tags = RTAG[src];

    for (size_t i = 0; i < 8; i++) {
        if (tag_is_empty(src_tags[i])) {
            tagmap_setb(dst + (7 - i), c_tag);
        }
        else {
            vfg_core->addInTag(src_tags[i], 0);                    
        }    
    }
}

void val_movbe_op(INS ins, InsNode * node) {
    if (INS_OperandIsMemory(ins, OP_1)) {
        REG reg_dst = INS_OperandReg(ins, OP_0);

        node->addDataFlowEdge(REG_MEM, 0);

        if (REG_is_gr64(reg_dst)) {
            M2R_CALL(val_m2r_xfer_opq_rev, reg_dst);
        } else if (REG_is_gr32(reg_dst)) {
            M2R_CALL(val_m2r_xfer_opl_rev, reg_dst);
        } else if (REG_is_gr16(reg_dst)) {
            M2R_CALL(val_m2r_xfer_opw_rev, reg_dst);
        }
    } else {
        REG reg_src = INS_OperandReg(ins, OP_1);

        node->addDataFlowEdge(reg_src, 0);

        if (REG_is_gr64(reg_src)) {
            R2M_CALL(val_r2m_xfer_opq_rev, reg_src);
        } else if (REG_is_gr32(reg_src)) {
            R2M_CALL(val_r2m_xfer_opl_rev, reg_src);
        } else if (REG_is_gr16(reg_src)) {
            R2M_CALL(val_r2m_xfer_opw_rev, reg_src);
        }
    }
}

void val_push_op(INS ins, InsNode* node) {
    REG reg_src;
    if (INS_OperandIsReg(ins, OP_0)) {
        reg_src = INS_OperandReg(ins, OP_0);

        node->addDataFlowEdge(reg_src, 0);

        if (REG_is_gr64(reg_src)) {
            R2M_CALL(val_r2m_xfer_opq, reg_src);
        } else if (REG_is_gr32(reg_src)) {
            R2M_CALL(val_r2m_xfer_opl, reg_src);
        } else {
            R2M_CALL(val_r2m_xfer_opw, reg_src);
        }
    } else if (INS_OperandIsMemory(ins, OP_0)) {
        node->addDataFlowEdge(REG_MEM, 0);

        if (INS_MemoryOperandSize(ins, OP_0) == BIT2BYTE(MEM_64BIT_LEN)) {
            M2M_CALL(val_m2m_xfer_opq);
        } else if (INS_MemoryOperandSize(ins, OP_0) == BIT2BYTE(MEM_LONG_LEN)) {
            M2M_CALL(val_m2m_xfer_opl);
        } else {
            M2M_CALL(val_m2m_xfer_opw);
        }
    } else {
        INT32 n = INS_OperandWidth(ins, OP_0) / 8;
        M_CLEAR_N(n);
    }
}


void val_pop_op(INS ins, InsNode* node) {
    REG reg_dst;

    node->addDataFlowEdge(REG_MEM, 0);

    if (INS_OperandIsReg(ins, OP_0)) {
        reg_dst = INS_OperandReg(ins, OP_0);
        if (REG_is_gr64(reg_dst)) {
            M2R_CALL(val_m2r_xfer_opq, reg_dst);
        } else if (REG_is_gr32(reg_dst)) {
            M2R_CALL(val_m2r_xfer_opl, reg_dst);
        } else {
            M2R_CALL(val_m2r_xfer_opw, reg_dst);
        }
    } else if (INS_OperandIsMemory(ins, OP_0)) {
        if (INS_MemoryOperandSize(ins, OP_0) == BIT2BYTE(MEM_64BIT_LEN)) {
            M2M_CALL(val_m2m_xfer_opq);
        } else if (INS_MemoryOperandSize(ins, OP_0) == BIT2BYTE(MEM_LONG_LEN)) {
            M2M_CALL(val_m2m_xfer_opl);
        } else {
            M2M_CALL(val_m2m_xfer_opw);
        }
    }
}