#include "val_shift_op.h"
#include "val_helper.h"

#include "value_core.h"
#include "vfg_nodes.h"

/* threads context */
extern thread_ctx_t *threads_ctx;
extern tag_t c_tag;

extern VFGCore *vfg_core;

extern bool val_enable;

static void PIN_FAST_ANALYSIS_CALL val_r_shift_opq(THREADID tid, uint32_t reg) {
    if (val_enable == false) return;
    for (size_t i = 0; i < 8; i++) {
        if (!tag_is_empty(RTAG[reg][i])) {
            vfg_core->addInTag(RTAG[reg][i], 0);
        }   
        RTAG[reg][i] = c_tag;
    }
}

static void PIN_FAST_ANALYSIS_CALL val_r_shift_opl(THREADID tid, uint32_t reg) {
    if (val_enable == false) return;
    for (size_t i = 0; i < 4; i++) {
        if (!tag_is_empty(RTAG[reg][i])) {
            vfg_core->addInTag(RTAG[reg][i], 0);
        }   
        RTAG[reg][i] = c_tag;
    }    
}

static void PIN_FAST_ANALYSIS_CALL val_r_shift_opw(THREADID tid, uint32_t reg) {
    if (val_enable == false) return;
    for (size_t i = 0; i < 2; i++) {
        if (!tag_is_empty(RTAG[reg][i])) {
            vfg_core->addInTag(RTAG[reg][i], 0);
        }
        RTAG[reg][i] = c_tag;
    }
}

static void PIN_FAST_ANALYSIS_CALL val_r_shift_opb_l(THREADID tid, uint32_t reg) {
    if (val_enable == false) return;
    
    if (!tag_is_empty(RTAG[reg][0])) {
        vfg_core->addInTag(RTAG[reg][0], 0);
    }

    RTAG[reg][0] = c_tag;
}

static void PIN_FAST_ANALYSIS_CALL val_r_shift_opb_u(THREADID tid, uint32_t reg) {
    if (val_enable == false) return;

    if (!tag_is_empty(RTAG[reg][1])) {
        vfg_core->addInTag(RTAG[reg][1], 0);
    }

    RTAG[reg][1] = c_tag;
}

static void PIN_FAST_ANALYSIS_CALL val_m_shift_opb(THREADID tid, ADDRINT dst) {
    if (val_enable == false) return;

    if (!tag_is_empty(MTAG(dst))) {
        vfg_core->addInTag(MTAG(dst), 0);
    }
    
    tagmap_setb(dst, c_tag);    
}

static void PIN_FAST_ANALYSIS_CALL val_m_shift_opw(THREADID tid, ADDRINT dst) {
    if (val_enable == false) return;

    for (size_t i = 0; i < 2; i++) {
        if (!tag_is_empty(MTAG(dst + i))) {
            vfg_core->addInTag(MTAG(dst + i), 0);
        }        
        tagmap_setb(dst + i, c_tag);
    }
}

static void PIN_FAST_ANALYSIS_CALL val_m_shift_opl(THREADID tid, ADDRINT dst) {
    if (val_enable == false) return;

    for (size_t i = 0; i < 4; i++) {
        if (!tag_is_empty(MTAG(dst + i))) {
            vfg_core->addInTag(MTAG(dst + i), 0);
        }             
        tagmap_setb(dst + i, c_tag);
    }
}

static void PIN_FAST_ANALYSIS_CALL val_m_shift_opq(THREADID tid, ADDRINT dst) {
    if (val_enable == false) return;

    for (size_t i = 0; i < 8; i++) {
        if (!tag_is_empty(MTAG(dst + i))) {
            vfg_core->addInTag(MTAG(dst + i), 0);
        }              
        tagmap_setb(dst + i, c_tag);
    }
}


void val_shift_op(INS ins, InsNode* node) {
    if (INS_IsMemoryWrite(ins)) {
        // std::cerr << "[WARNING] " << hexstr(INS_Address(ins)) << " val_shift(Mem): "<< INS_Disassemble(ins) << "\n";
        node->addDataFlowEdge(REG_MEM, 0);

        switch (INS_MemoryOperandSize(ins, OP_0)) {
        case 1:
            M_CALL_W(val_m_shift_opb);
            break;        
        case 2:
            M_CALL_W(val_m_shift_opw);
            break;
        case 4:
            M_CALL_W(val_m_shift_opl);
            break;
        case 8:
            M_CALL_W(val_m_shift_opq);
            break;
        default:
            assert(false);
        }
    }
    else { 
        REG reg_dst = INS_RegW(ins, 0);

        node->addDataFlowEdge(reg_dst, 0);

        if (REG_is_gr64(reg_dst)) {
            R_CALL(val_r_shift_opq, reg_dst);
        } else if (REG_is_gr32(reg_dst)) {
            R_CALL(val_r_shift_opl, reg_dst);
        } else if (REG_is_gr16(reg_dst)) {
            R_CALL(val_r_shift_opw, reg_dst);
        } else if (REG_is_Upper8(reg_dst)) {
            R_CALL(val_r_shift_opb_u, reg_dst);
        } else if (REG_is_Lower8(reg_dst)) {
            R_CALL(val_r_shift_opb_l, reg_dst);
        } else { // xmm, ymm, mm registers
            return;
        }       
    }
}