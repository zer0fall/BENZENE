#include "val_binary_op.h"
#include "val_helper.h"

#include "value_core.h"

/* threads context */
extern thread_ctx_t *threads_ctx;
extern tag_t c_tag;

extern VFGCore *vfg_core;

extern bool val_enable;

void PIN_FAST_ANALYSIS_CALL val_r2r_binary_opb_ul(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
    if (val_enable == false) return;
    
    tag_t src_tag = RTAG[src][0];
    tag_t dst_tag = RTAG[dst][1];

    if (!tag_is_empty(src_tag)) {
        vfg_core->addInTag(src_tag, 0);
    }
    if (!tag_is_empty(dst_tag)) {
        vfg_core->addInTag(dst_tag, 1);
    }

    RTAG[dst][1] = c_tag;
}

void PIN_FAST_ANALYSIS_CALL val_r2r_binary_opb_lu(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
    if (val_enable == false) return;

    tag_t src_tag = RTAG[src][1];
    tag_t dst_tag = RTAG[dst][0];

    if (!tag_is_empty(src_tag)) {
        vfg_core->addInTag(src_tag, 0);
    }
    if (!tag_is_empty(dst_tag)) {
        vfg_core->addInTag(dst_tag, 1);
    }

    RTAG[dst][0] = c_tag;
}

void PIN_FAST_ANALYSIS_CALL val_r2r_binary_opb_u(THREADID tid, uint32_t dst,
                                                    uint32_t src) {
    if (val_enable == false) return;
    
    tag_t src_tag = RTAG[src][1];
    tag_t dst_tag = RTAG[dst][1];

    if (!tag_is_empty(src_tag)) {
        vfg_core->addInTag(src_tag, 0);
    }
    if (!tag_is_empty(dst_tag)) {
        vfg_core->addInTag(dst_tag, 1);
    }

    RTAG[dst][1] = c_tag;
}

void PIN_FAST_ANALYSIS_CALL val_r2r_binary_opb_l(THREADID tid, uint32_t dst,
                                                    uint32_t src) {
    if (val_enable == false) return;
    
    tag_t src_tag = RTAG[src][0];
    tag_t dst_tag = RTAG[dst][0];

    if (!tag_is_empty(src_tag)) {
        vfg_core->addInTag(src_tag, 0);
    }    
    if (!tag_is_empty(dst_tag)) {
        vfg_core->addInTag(dst_tag, 1);
    }

    RTAG[dst][0] = c_tag;
}

void PIN_FAST_ANALYSIS_CALL val_r2r_binary_opw(THREADID tid, uint32_t dst,
                                                  uint32_t src) {
    if (val_enable == false) return;

    tag_t *dst_tags = RTAG[dst];
    tag_t *src_tags = RTAG[src];

    for (size_t i = 0; i < 2; i++) {
        if (!tag_is_empty(src_tags[i])) {
            vfg_core->addInTag(src_tags[i], 0);
        }
        if (!tag_is_empty(dst_tags[i])) {
            vfg_core->addInTag(dst_tags[i], 1);
        }
        dst_tags[i] = c_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL val_r2r_binary_opl(THREADID tid, uint32_t dst,
                                                  uint32_t src) {

    if (val_enable == false) return;

    tag_t *dst_tags = RTAG[dst];
    tag_t *src_tags = RTAG[src];

    for (size_t i = 0; i < 4; i++) {
        if (!tag_is_empty(src_tags[i])) {
            vfg_core->addInTag(src_tags[i], 0);
        }    
        if (!tag_is_empty(dst_tags[i])) {
            vfg_core->addInTag(dst_tags[i], 1);
        }
        dst_tags[i] = c_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL val_r2r_binary_opq(THREADID tid, uint32_t dst,
                                                  uint32_t src) {
    if (val_enable == false) return;

    tag_t *dst_tags = RTAG[dst];
    tag_t *src_tags = RTAG[src];

    for (size_t i = 0; i < 8; i++) {
        if (!tag_is_empty(src_tags[i])) {
            vfg_core->addInTag(src_tags[i], 0);
        }    
        if (!tag_is_empty(dst_tags[i])) {
            vfg_core->addInTag(dst_tags[i], 1);
        }
        dst_tags[i] = c_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL val_r2r_binary_opx(THREADID tid, uint32_t dst,
                                                  uint32_t src) {
    if (val_enable == false) return;

    tag_t *dst_tags = RTAG[dst];
    tag_t *src_tags = RTAG[src];

    for (size_t i = 0; i < 16; i++) {
        if (!tag_is_empty(src_tags[i])) {
            vfg_core->addInTag(src_tags[i], 0);
        }    
        if (!tag_is_empty(dst_tags[i])) {
            vfg_core->addInTag(dst_tags[i], 1);
        }
        dst_tags[i] = c_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL val_r2r_binary_opy(THREADID tid, uint32_t dst,
                                                  uint32_t src) {
    if (val_enable == false) return;

    tag_t *dst_tags = RTAG[dst];
    tag_t *src_tags = RTAG[src];

    for (size_t i = 0; i < 32; i++) {
        if (!tag_is_empty(src_tags[i])) {
            vfg_core->addInTag(src_tags[i], 0);
        }    
        if (!tag_is_empty(dst_tags[i])) {
            vfg_core->addInTag(dst_tags[i], 1);
        }
        dst_tags[i] = c_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL val_m2r_binary_opb_u(THREADID tid, uint32_t dst,
                                                    ADDRINT src) {
    if (val_enable == false) return;

    tag_t src_tag = MTAG(src);
    tag_t dst_tag = RTAG[dst][1];

    if (!tag_is_empty(src_tag)) {
        vfg_core->addInTag(src_tag, 0);
    }        
    if (!tag_is_empty(dst_tag)) {
        vfg_core->addInTag(dst_tag, 1);
    }    

    RTAG[dst][1] = c_tag;
}

void PIN_FAST_ANALYSIS_CALL val_m2r_binary_opb_l(THREADID tid, uint32_t dst,
                                                    ADDRINT src) {
    if (val_enable == false) return;
    
    tag_t src_tag = MTAG(src);
    tag_t dst_tag = RTAG[dst][0];

    if (!tag_is_empty(src_tag)) {
        vfg_core->addInTag(src_tag, 0);
    }    
    if (!tag_is_empty(dst_tag)) {
        vfg_core->addInTag(dst_tag, 1);
    }    

    RTAG[dst][0] = c_tag;
}

void PIN_FAST_ANALYSIS_CALL val_m2r_binary_opw(THREADID tid, uint32_t dst,
                                                  ADDRINT src) {
    if (val_enable == false) return;

    tag_t *dst_tags = RTAG[dst];

    for (size_t i = 0; i < 2; i++) {
        tag_t src_tag = MTAG(src + i);

        if (!tag_is_empty(src_tag)) {
            vfg_core->addInTag(src_tag, 0);
        }
        
        if (!tag_is_empty(dst_tags[i])) {
            vfg_core->addInTag(dst_tags[i], 1);
        }   
    
        dst_tags[i] = c_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL val_m2r_binary_opl(THREADID tid, uint32_t dst,
                                                  ADDRINT src) {
    if (val_enable == false) return;

    tag_t *dst_tags = RTAG[dst];

    for (size_t i = 0; i < 4; i++) {
        tag_t src_tag = MTAG(src + i);

        if (!tag_is_empty(src_tag)) {
            vfg_core->addInTag(src_tag, 0);
        }     
        if (!tag_is_empty(dst_tags[i])) {
            vfg_core->addInTag(dst_tags[i], 1);
        }

        dst_tags[i] = c_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL val_m2r_binary_opq(THREADID tid, uint32_t dst,
                                                  ADDRINT src) {
    if (val_enable == false) return;

    tag_t *dst_tags = RTAG[dst];

    for (size_t i = 0; i < 8; i++) {
        tag_t src_tag = MTAG(src + i);

        if (!tag_is_empty(src_tag)) {
            vfg_core->addInTag(src_tag, 0);
        }     
        if (!tag_is_empty(dst_tags[i])) {
            vfg_core->addInTag(dst_tags[i], 1);
        }

        dst_tags[i] = c_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL val_m2r_binary_opx(THREADID tid, uint32_t dst,
                                                  ADDRINT src) {
    if (val_enable == false) return;

    tag_t *dst_tags = RTAG[dst];

    for (size_t i = 0; i < 16; i++) {
        tag_t src_tag = MTAG(src + i);

        if (!tag_is_empty(src_tag)) {
            vfg_core->addInTag(src_tag, 0);
        }     
        if (!tag_is_empty(dst_tags[i])) {
            vfg_core->addInTag(dst_tags[i], 1);
        }
            
        dst_tags[i] = c_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL val_m2r_binary_opy(THREADID tid, uint32_t dst,
                                                  ADDRINT src) {
    if (val_enable == false) return;

    tag_t *dst_tags = RTAG[dst];

    for (size_t i = 0; i < 32; i++) {
        tag_t src_tag = MTAG(src + i);

        if (!tag_is_empty(src_tag)) {
            vfg_core->addInTag(src_tag, 0);
        }     
        if (!tag_is_empty(dst_tags[i])) {
            vfg_core->addInTag(dst_tags[i], 1);
        }

        dst_tags[i] = c_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL val_r2m_binary_opb_u(THREADID tid, ADDRINT dst,
                                                    uint32_t src) {

    if (val_enable == false) return;

    tag_t src_tag = RTAG[src][1];
    tag_t dst_tag = MTAG(dst);

    if (!tag_is_empty(src_tag)) {
        vfg_core->addInTag(src_tag, 0);
    }      
    
    if (!tag_is_empty(dst_tag)) {
        vfg_core->addInTag(dst_tag, 1);
    }

    tagmap_setb(dst, c_tag);
}

void PIN_FAST_ANALYSIS_CALL val_r2m_binary_opb_l(THREADID tid, ADDRINT dst,
                                                    uint32_t src) {
    if (val_enable == false) return;
    
    tag_t src_tag = RTAG[src][0];
    tag_t dst_tag = MTAG(dst);

    if (!tag_is_empty(src_tag)) {
        vfg_core->addInTag(src_tag, 0);
    }     

    if (!tag_is_empty(dst_tag)) {
        vfg_core->addInTag(dst_tag, 1);
    }

    tagmap_setb(dst, c_tag);
}

void PIN_FAST_ANALYSIS_CALL val_r2m_binary_opw(THREADID tid, ADDRINT dst,
                                                  uint32_t src) {
    if (val_enable == false) return;
    
    tag_t *src_tags = RTAG[src];

    for (size_t i = 0; i < 2; i++) {
        tag_t dst_tag = MTAG(dst + i);

        if (!tag_is_empty(src_tags[i])) {
            vfg_core->addInTag(src_tags[i], 0);
        }   
        if (!tag_is_empty(dst_tag)) {
            vfg_core->addInTag(dst_tag, 1);
        }

        tagmap_setb(dst + i, c_tag);
    }
}

void PIN_FAST_ANALYSIS_CALL val_r2m_binary_opl(THREADID tid, ADDRINT dst,
                                                  uint32_t src) {
    if (val_enable == false) return;

    tag_t *src_tags = RTAG[src];

    for (size_t i = 0; i < 4; i++) {
        tag_t dst_tag = MTAG(dst + i);

        if (!tag_is_empty(src_tags[i])) {
            vfg_core->addInTag(src_tags[i], 0);
        }   
        if (!tag_is_empty(dst_tag)) {
            vfg_core->addInTag(dst_tag, 1);
        }

        tagmap_setb(dst + i, c_tag);
    }
}

void PIN_FAST_ANALYSIS_CALL val_r2m_binary_opq(THREADID tid, ADDRINT dst,
                                                  uint32_t src) {
    if (val_enable == false) return;

    tag_t *src_tags = RTAG[src];

    for (size_t i = 0; i < 8; i++) {
        tag_t dst_tag = MTAG(dst + i);

        if (!tag_is_empty(src_tags[i])) {
            vfg_core->addInTag(src_tags[i], 0);
        }   
        if (!tag_is_empty(dst_tag)) {
            vfg_core->addInTag(dst_tag, 1);
        }

        tagmap_setb(dst + i, c_tag);
    }
}

void PIN_FAST_ANALYSIS_CALL val_r2m_binary_opx(THREADID tid, ADDRINT dst,
                                                  uint32_t src) {
    if (val_enable == false) return;
    
    tag_t *src_tags = RTAG[src];
    
    for (size_t i = 0; i < 16; i++) {
        tag_t dst_tag = MTAG(dst + i);

        if (!tag_is_empty(src_tags[i])) {
            vfg_core->addInTag(src_tags[i], 0);
        }   
        if (!tag_is_empty(dst_tag)) {
            vfg_core->addInTag(dst_tag, 1);
        }

        tagmap_setb(dst + i, c_tag);
    }
}

void PIN_FAST_ANALYSIS_CALL val_r2m_binary_opy(THREADID tid, ADDRINT dst,
                                                  uint32_t src) {
    if (val_enable == false) return;
    
    tag_t *src_tags = RTAG[src];

    for (size_t i = 0; i < 32; i++) {
        tag_t dst_tag = MTAG(dst + i);

        if (!tag_is_empty(src_tags[i])) {
            vfg_core->addInTag(src_tags[i], 0);
        }   
        if (!tag_is_empty(dst_tag)) {
            vfg_core->addInTag(dst_tag, 1);
        }

        tagmap_setb(dst + i, c_tag);
    }
}

void PIN_FAST_ANALYSIS_CALL val_i2m_binary_opb(THREADID tid, ADDRINT dst) {
    if (val_enable == false) return;

    tag_t t = MTAG(dst);

    if (!tag_is_empty(t))
        vfg_core->addInTag(t, 0);    

    tagmap_setb(dst, c_tag);
}

void PIN_FAST_ANALYSIS_CALL val_i2m_binary_opw(THREADID tid, ADDRINT dst) {
    if (val_enable == false) return;

    for (size_t i = 0; i < 2; i++) {
        tag_t t = MTAG(dst + i);

        if (!tag_is_empty(t))
            vfg_core->addInTag(t, 0);    

        tagmap_setb(dst + i, c_tag);
    }
}

void PIN_FAST_ANALYSIS_CALL val_i2m_binary_opl(THREADID tid, ADDRINT dst) {
    if (val_enable == false) return;

    for (size_t i = 0; i < 4; i++) {
        tag_t t = MTAG(dst + i);

        if (!tag_is_empty(t))
            vfg_core->addInTag(t, 0);    

        tagmap_setb(dst + i, c_tag);
    }
}

void PIN_FAST_ANALYSIS_CALL val_i2m_binary_opq(THREADID tid, ADDRINT dst) {
    if (val_enable == false) return;

    for (size_t i = 0; i < 8; i++) {
        tag_t t = MTAG(dst + i);

        if (!tag_is_empty(t))
            vfg_core->addInTag(t, 0);    

        tagmap_setb(dst + i, c_tag);
    }
}

void PIN_FAST_ANALYSIS_CALL val_i2r_binary_opb_l(THREADID tid, uint32_t reg_idx) {
    if (val_enable == false) return;

    tag_t reg_tag = RTAG[reg_idx][0];

    if (!tag_is_empty(reg_tag))
        vfg_core->addInTag(reg_tag, 0);    

    RTAG[reg_idx][0] = c_tag;
}

void PIN_FAST_ANALYSIS_CALL val_i2r_binary_opb_u(THREADID tid, uint32_t reg_idx) {
    if (val_enable == false) return;

    tag_t reg_tag = RTAG[reg_idx][1];

    if (!tag_is_empty(reg_tag))
        vfg_core->addInTag(reg_tag, 0);    

    RTAG[reg_idx][1] = c_tag;
}

void PIN_FAST_ANALYSIS_CALL val_i2r_binary_opw(THREADID tid, uint32_t reg_idx) {
    if (val_enable == false) return;

    tag_t *reg_tags = RTAG[reg_idx];
    
    for (size_t i = 0; i < 2; i++) {
        
        if (!tag_is_empty(reg_tags[i]))
            vfg_core->addInTag(reg_tags[i], 0);    

        reg_tags[i] = c_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL val_i2r_binary_opl(THREADID tid, uint32_t reg_idx) {
    if (val_enable == false) return;

    tag_t *reg_tags = RTAG[reg_idx];
    
    for (size_t i = 0; i < 4; i++) {
        
        if (!tag_is_empty(reg_tags[i]))
            vfg_core->addInTag(reg_tags[i], 0);    

        reg_tags[i] = c_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL val_i2r_binary_opq(THREADID tid, uint32_t reg_idx) {
    if (val_enable == false) return;

    tag_t *reg_tags = RTAG[reg_idx];
    
    for (size_t i = 0; i < 8; i++) {
        
        if (!tag_is_empty(reg_tags[i]))
            vfg_core->addInTag(reg_tags[i], 0);    

        reg_tags[i] = c_tag;
    }
}


// Immediate xfer operations
static void PIN_FAST_ANALYSIS_CALL r_binary_clean_opy(THREADID tid, uint32_t reg) {
    if (val_enable == false) return;
    for (size_t i = 0; i < 32; i++) {
        RTAG[reg][i] = c_tag;
    }
}

static void PIN_FAST_ANALYSIS_CALL r_binary_clean_opx(THREADID tid, uint32_t reg) {
    if (val_enable == false) return;
    for (size_t i = 0; i < 16; i++) {
        RTAG[reg][i] = c_tag;
    }
}

static void PIN_FAST_ANALYSIS_CALL r_binary_clean_opq(THREADID tid, uint32_t reg) {
    if (val_enable == false) return;
    for (size_t i = 0; i < 8; i++) {
        RTAG[reg][i] = c_tag;
    }
}

static void PIN_FAST_ANALYSIS_CALL r_binary_clean_opl(THREADID tid, uint32_t reg) {
    if (val_enable == false) return;
    // Q) why 8 instead of 4?
    //    reference : https://stackoverflow.com/questions/11177137/why-do-x86-64-instructions-on-32-bit-registers-zero-the-upper-part-of-the-full-6
    for (size_t i = 0; i < 8; i++) {
        RTAG[reg][i] = c_tag;
    }    
}

static void PIN_FAST_ANALYSIS_CALL r_binary_clean_opw(THREADID tid, uint32_t reg) {
    if (val_enable == false) return;
    for (size_t i = 0; i < 2; i++) {
        RTAG[reg][i] = c_tag;
    }
}

static void PIN_FAST_ANALYSIS_CALL r_binary_clean_opb_l(THREADID tid, uint32_t reg) {
    if (val_enable == false) return;
    RTAG[reg][0] = c_tag;
}

static void PIN_FAST_ANALYSIS_CALL r_binary_clean_opb_u(THREADID tid, uint32_t reg) {
    if (val_enable == false) return;
    RTAG[reg][1] = c_tag;
}


void val_binary_op(INS ins, InsNode* node) { // need refactoring
    REG reg_dst, reg_src;

    if (INS_OperandIsImmediate(ins, OP_1)) { // Value modification also takes place
        if (INS_IsMemoryWrite(ins)) {
            node->addDataFlowEdge(REG_MEM, 0);

            switch(INS_MemoryOperandSize(ins, OP_0)) {
            case 1:
                I2M_CALL(val_i2m_binary_opb);
                break;
            case 2:
                I2M_CALL(val_i2m_binary_opw);
                break;
            case 4:
                I2M_CALL(val_i2m_binary_opl);
                break;
            case 8:
                I2M_CALL(val_i2m_binary_opq);
                break;
            default:
                fprintf(stderr, "Unhandled Case %s\n", INS_Disassemble(ins).c_str());
            }

            return;
        }
        else { // add    r12,0x10
            REG src_reg = INS_RegR(ins, 0);

            node->addDataFlowEdge(src_reg, 0);

            switch(REG_Size(src_reg)) {
            case 1:
                if (REG_is_Upper8(src_reg))
                    R_CALL(val_i2r_binary_opb_u, src_reg);
                else
                    R_CALL(val_i2r_binary_opb_l, src_reg);
                break;
            case 2:
                R_CALL(val_i2r_binary_opw, src_reg);
                break;
            case 4:                
                R_CALL(val_i2r_binary_opl, src_reg);
                break;
            case 8:
                R_CALL(val_i2r_binary_opq, src_reg);
                break;
            default:
                fprintf(stderr, "Unhandled Case %s\n", INS_Disassemble(ins).c_str());
            }

            return;
        }
    }
    else if (INS_MemoryOperandCount(ins) == 0) {
        reg_dst = INS_OperandReg(ins, OP_0);
        reg_src = INS_OperandReg(ins, OP_1);

        node->addDataFlowEdge(reg_src, 0);
        node->addDataFlowEdge(reg_dst, 1);
    }
    else
        goto __memory_operand_exists;
    
    if (REG_is_gr64(reg_dst)) {
        R2R_CALL(val_r2r_binary_opq, reg_dst, reg_src);
    } else if (REG_is_gr32(reg_dst)) {
        R2R_CALL(val_r2r_binary_opl, reg_dst, reg_src);
    } else if (REG_is_gr16(reg_dst)) {
        R2R_CALL(val_r2r_binary_opw, reg_dst, reg_src);
    } else if (REG_is_xmm(reg_dst)) {
        R2R_CALL(val_r2r_binary_opx, reg_dst, reg_src);
    } else if (REG_is_ymm(reg_dst)) {
        R2R_CALL(val_r2r_binary_opy, reg_dst, reg_src);
    } else if (REG_is_mm(reg_dst)) {
        R2R_CALL(val_r2r_binary_opq, reg_dst, reg_src);
    } 
    else {
        if (REG_is_Lower8(reg_dst) && REG_is_Lower8(reg_src))
            R2R_CALL(val_r2r_binary_opb_l, reg_dst, reg_src);
        else if (REG_is_Upper8(reg_dst) && REG_is_Upper8(reg_src))
            R2R_CALL(val_r2r_binary_opb_u, reg_dst, reg_src);
        else if (REG_is_Lower8(reg_dst))
            R2R_CALL(val_r2r_binary_opb_lu, reg_dst, reg_src);
        else
            R2R_CALL(val_r2r_binary_opb_ul, reg_dst, reg_src);     
    } 
    
    return;

__memory_operand_exists:
    if (INS_OperandIsMemory(ins, OP_1)) {
        reg_dst = INS_OperandReg(ins, OP_0);

        node->addDataFlowEdge(REG_MEM, 0);
        node->addDataFlowEdge(reg_dst, 1);

        if (REG_is_gr64(reg_dst)) {
            M2R_CALL(val_m2r_binary_opq, reg_dst);
        } else if (REG_is_gr32(reg_dst)) {
            M2R_CALL(val_m2r_binary_opl, reg_dst);
        } else if (REG_is_gr16(reg_dst)) {
            M2R_CALL(val_m2r_binary_opw, reg_dst);
        } else if (REG_is_xmm(reg_dst)) {
            M2R_CALL(val_m2r_binary_opx, reg_dst);
        } else if (REG_is_ymm(reg_dst)) {
            M2R_CALL(val_m2r_binary_opy, reg_dst);
        } else if (REG_is_mm(reg_dst)) {
            M2R_CALL(val_m2r_binary_opq, reg_dst);
        } else if (REG_is_Upper8(reg_dst)) {
            M2R_CALL(val_m2r_binary_opb_u, reg_dst);
        } else {
            M2R_CALL(val_m2r_binary_opb_l, reg_dst);
        }
    } else {
        reg_src = INS_OperandReg(ins, OP_1);
    
        node->addDataFlowEdge(reg_src, 0);
        node->addDataFlowEdge(REG_MEM, 1);

        if (REG_is_gr64(reg_src)) {
            R2M_CALL(val_r2m_binary_opq, reg_src);
        } else if (REG_is_gr32(reg_src)) {
            R2M_CALL(val_r2m_binary_opl, reg_src);
        } else if (REG_is_gr16(reg_src)) {
            R2M_CALL(val_r2m_binary_opw, reg_src);
        } else if (REG_is_xmm(reg_src)) {
            R2M_CALL(val_r2m_binary_opx, reg_src);
        } else if (REG_is_ymm(reg_src)) {
            R2M_CALL(val_r2m_binary_opy, reg_src);
        } else if (REG_is_mm(reg_src)) {
            R2M_CALL(val_r2m_binary_opq, reg_src);
        } else if (REG_is_Upper8(reg_src)) {
            R2M_CALL(val_r2m_binary_opb_u, reg_src);
        } else {
            R2M_CALL(val_r2m_binary_opb_l, reg_src);
        }
    }
}

void val_binary_clean(INS ins, InsNode* node) {
    REG reg_dst = INS_OperandReg(ins, OP_0);

    if (REG_is_gr64(reg_dst)) {
        R_CALL(r_binary_clean_opq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
        R_CALL(r_binary_clean_opl, reg_dst);
    } else if (REG_is_gr16(reg_dst)) {
        R_CALL(r_binary_clean_opw, reg_dst);
    } else if (REG_is_xmm(reg_dst)) {
        R_CALL(r_binary_clean_opx, reg_dst);
    } else if (REG_is_ymm(reg_dst)) {
        R_CALL(r_binary_clean_opy, reg_dst);
    } else if (REG_is_mm(reg_dst)) {
        R_CALL(r_binary_clean_opq, reg_dst);
    } else {
        if (REG_is_Lower8(reg_dst)) {
            R_CALL(r_binary_clean_opb_l, reg_dst);
        } else if (REG_is_Upper8(reg_dst)) {
            R_CALL(r_binary_clean_opb_u, reg_dst);
        }
        else {
            LOG("Error: " + REG_StringShort(reg_dst) + "\n");
            assert(false);
        }
    }

    return;
}
