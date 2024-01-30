#include "val_unitary_op.h"
#include "val_helper.h"

#include "value_core.h"

/* threads context */
extern thread_ctx_t *threads_ctx;
extern VFGCore *vfg_core;




static void PIN_FAST_ANALYSIS_CALL r2r_unitary_opb_u(THREADID tid,
                                                     uint32_t src) {

// RAX * src
    if (val_enable == false) return;

    tag_t tmp_tag = RTAG[src][1];
    
    if (!tag_is_empty(tmp_tag)) {
        vfg_core->addInTag(tmp_tag, 0);
    }

    if (!tag_is_empty(RTAG[DFT_REG_RAX][0])) {
        vfg_core->addInTag(RTAG[DFT_REG_RAX][0], 1);
    }

    if (!tag_is_empty(RTAG[DFT_REG_RAX][1])) {
        vfg_core->addInTag(RTAG[DFT_REG_RAX][1], 1);
    }

    RTAG[DFT_REG_RAX][0] = c_tag;
    RTAG[DFT_REG_RAX][1] = c_tag;
}

static void PIN_FAST_ANALYSIS_CALL r2r_unitary_opb_l(THREADID tid,
                                                     uint32_t src) {
    if (val_enable == false) return;
    
    tag_t tmp_tag = RTAG[src][0];

    if (!tag_is_empty(tmp_tag)) {
        vfg_core->addInTag(tmp_tag, 0);
    }

    if (!tag_is_empty(RTAG[DFT_REG_RAX][0])) {
        vfg_core->addInTag(RTAG[DFT_REG_RAX][0], 1);
    }

    if (!tag_is_empty(RTAG[DFT_REG_RAX][1])) {
        vfg_core->addInTag(RTAG[DFT_REG_RAX][1], 1);
    }

    RTAG[DFT_REG_RAX][0] = c_tag;
    RTAG[DFT_REG_RAX][1] = c_tag;
}

static void PIN_FAST_ANALYSIS_CALL r2r_unitary_opw(THREADID tid, uint32_t src) {
    if (val_enable == false) return;
    tag_t tmp_tag[] = {RTAG[src][0], RTAG[src][1]};

    tag_t dst1_tag[] = {RTAG[DFT_REG_RDX][0], RTAG[DFT_REG_RDX][1]};
    tag_t dst2_tag[] = {RTAG[DFT_REG_RAX][0], RTAG[DFT_REG_RAX][1]};

    if (!tag_is_empty(tmp_tag[0])) {
        vfg_core->addInTag(tmp_tag[0], 0);
    }

    if (!tag_is_empty(tmp_tag[1])) {
        vfg_core->addInTag(tmp_tag[0], 0);
    }

    if (!tag_is_empty(dst1_tag[0])) {
        vfg_core->addInTag(dst1_tag[0], 1);
    }

    if (!tag_is_empty(dst1_tag[1])) {
        vfg_core->addInTag(dst1_tag[1], 1);
    }    

    if (!tag_is_empty(dst2_tag[0])) {
        vfg_core->addInTag(dst2_tag[0], 2);
    }

    if (!tag_is_empty(dst2_tag[1])) {
        vfg_core->addInTag(dst2_tag[1], 2);
    }    

    RTAG[DFT_REG_RDX][0] = c_tag;
    RTAG[DFT_REG_RDX][1] = c_tag;

    RTAG[DFT_REG_RAX][0] = c_tag;
    RTAG[DFT_REG_RAX][1] = c_tag;
}

static void PIN_FAST_ANALYSIS_CALL r2r_unitary_opq(THREADID tid, uint32_t src) {
    if (val_enable == false) return;
    tag_t tmp_tag[] = R64TAG(src);
    tag_t dst1_tag[] = R64TAG(DFT_REG_RDX);
    tag_t dst2_tag[] = R64TAG(DFT_REG_RAX);

    for (size_t i = 0; i < 8; i++) {
        if (!tag_is_empty(tmp_tag[i])) {
            vfg_core->addInTag(tmp_tag[i], 0);
        }

        if (!tag_is_empty(dst1_tag[i])) {
            vfg_core->addInTag(dst1_tag[i], 1);
        }

        if (!tag_is_empty(dst2_tag[i])) {
            vfg_core->addInTag(dst2_tag[i], 2);
        }

        RTAG[DFT_REG_RDX][i] = c_tag;
        RTAG[DFT_REG_RAX][i] = c_tag;
    }
}

static void PIN_FAST_ANALYSIS_CALL r2r_unitary_opl(THREADID tid, uint32_t src) {
    if (val_enable == false) return;
    tag_t tmp_tag[] = R32TAG(src);
    tag_t dst1_tag[] = R32TAG(DFT_REG_RDX);
    tag_t dst2_tag[] = R32TAG(DFT_REG_RAX);

    for (size_t i = 0; i < 4; i++) {
        if (!tag_is_empty(tmp_tag[i])) {
            vfg_core->addInTag(tmp_tag[i], 0);
        }
        
        if (!tag_is_empty(dst1_tag[i])) {
            vfg_core->addInTag(dst1_tag[i], 1);
        }

        if (!tag_is_empty(dst2_tag[i])) {
            vfg_core->addInTag(dst2_tag[i], 2);
        }

        RTAG[DFT_REG_RDX][i] = c_tag;
        RTAG[DFT_REG_RAX][i] = c_tag;
    }
}

static void PIN_FAST_ANALYSIS_CALL m2r_unitary_opb(THREADID tid, ADDRINT src) {
    if (val_enable == false) return;

    tag_t tmp_tag = MTAG(src);
    tag_t dst_tag[] = R16TAG(DFT_REG_RAX);

    if (!tag_is_empty(tmp_tag)) {
        vfg_core->addInTag(tmp_tag, 0);
    }

    if (!tag_is_empty(dst_tag[0])) {
        vfg_core->addInTag(dst_tag[0], 1);
    }
        
    if (!tag_is_empty(dst_tag[1])) {
        vfg_core->addInTag(dst_tag[1], 1);
    }

    RTAG[DFT_REG_RAX][0] = c_tag;
    RTAG[DFT_REG_RAX][1] = c_tag;
}

static void PIN_FAST_ANALYSIS_CALL m2r_unitary_opw(THREADID tid, ADDRINT src) {
    if (val_enable == false) return;

    tag_t tmp_tag[] = M16TAG(src);
    tag_t dst1_tag[] = R16TAG(DFT_REG_RDX);
    tag_t dst2_tag[] = R16TAG(DFT_REG_RAX);

    for (size_t i = 0; i < 2; i++) {
        if (!tag_is_empty(tmp_tag[i])) {
            vfg_core->addInTag(tmp_tag[i], 0);
        }

        if (!tag_is_empty(dst1_tag[i])) {
            vfg_core->addInTag(dst1_tag[i], 1);
        }
            
        if (!tag_is_empty(dst2_tag[i])) {
            vfg_core->addInTag(dst2_tag[i], 2);
        }

        RTAG[DFT_REG_RDX][i] = c_tag;
        RTAG[DFT_REG_RAX][i] = c_tag;
    }
}

static void PIN_FAST_ANALYSIS_CALL m2r_unitary_opq(THREADID tid, ADDRINT src) {
    if (val_enable == false) return;

    tag_t tmp_tag[] = M64TAG(src);
    tag_t dst1_tag[] = R64TAG(DFT_REG_RDX);
    tag_t dst2_tag[] = R64TAG(DFT_REG_RAX);

    for (size_t i = 0; i < 8; i++) {
        if (!tag_is_empty(tmp_tag[i])) {
            vfg_core->addInTag(tmp_tag[i], 0);
        }

        if (!tag_is_empty(dst1_tag[i])) {
            vfg_core->addInTag(dst1_tag[i], 1);
        }
            
        if (!tag_is_empty(dst2_tag[i])) {
            vfg_core->addInTag(dst2_tag[i], 2);
        }

        RTAG[DFT_REG_RDX][i] = c_tag;
        RTAG[DFT_REG_RAX][i] = c_tag;
    }
}

static void PIN_FAST_ANALYSIS_CALL m2r_unitary_opl(THREADID tid, ADDRINT src) {
    if (val_enable == false) return;

    tag_t tmp_tag[] = M32TAG(src);
    tag_t dst1_tag[] = R32TAG(DFT_REG_RDX);
    tag_t dst2_tag[] = R32TAG(DFT_REG_RAX);

    for (size_t i = 0; i < 4; i++) {
        if (!tag_is_empty(tmp_tag[i])) {
            vfg_core->addInTag(tmp_tag[i], 0);
        }

        if (!tag_is_empty(dst1_tag[i])) {
            vfg_core->addInTag(dst1_tag[i], 1);
        }        
            
        if (!tag_is_empty(dst2_tag[i])) {
            vfg_core->addInTag(dst2_tag[i], 2);
        }

        RTAG[DFT_REG_RDX][i] = c_tag;
        RTAG[DFT_REG_RAX][i] = c_tag;
    }
}

// @TODO: handle unitary operations
void val_unitary_op(INS ins, InsNode* node) {
    if (INS_OperandIsMemory(ins, OP_0))
        switch (INS_MemoryOperandSize(ins, OP_0)) {
        case BIT2BYTE(MEM_64BIT_LEN):
            node->addDataFlowEdge(REG_MEM, 0);
            node->addDataFlowEdge(REG_RDX, 1);
            node->addDataFlowEdge(REG_RAX, 2);
            M_CALL_R(m2r_unitary_opq);
            break;
        case BIT2BYTE(MEM_LONG_LEN):
            node->addDataFlowEdge(REG_MEM, 0);
            node->addDataFlowEdge(REG_EDX, 1);
            node->addDataFlowEdge(REG_EAX, 2);        
            M_CALL_R(m2r_unitary_opl);
            break;
        case BIT2BYTE(MEM_WORD_LEN):
            node->addDataFlowEdge(REG_MEM, 0);
            node->addDataFlowEdge(REG_DX, 1);
            node->addDataFlowEdge(REG_AX, 2);        
            M_CALL_R(m2r_unitary_opw);
            break;
        case BIT2BYTE(MEM_BYTE_LEN):
        default:
            node->addDataFlowEdge(REG_MEM, 0);
            node->addDataFlowEdge(REG_AL, 1);
            M_CALL_R(m2r_unitary_opb);
            break;
    }
    else {
        REG reg_src = INS_OperandReg(ins, OP_0);
        if (REG_is_gr64(reg_src)) {
            node->addDataFlowEdge(reg_src, 0);
            node->addDataFlowEdge(REG_RDX, 1);
            node->addDataFlowEdge(REG_RAX, 2);
            R_CALL(r2r_unitary_opq, reg_src);
        }
        else if (REG_is_gr32(reg_src)) {
            node->addDataFlowEdge(reg_src, 0);
            node->addDataFlowEdge(REG_EDX, 1);
            node->addDataFlowEdge(REG_EAX, 2);   
            R_CALL(r2r_unitary_opl, reg_src);
        }
        else if (REG_is_gr16(reg_src)) {
            node->addDataFlowEdge(reg_src, 0);
            node->addDataFlowEdge(REG_DX, 1);
            node->addDataFlowEdge(REG_AX, 2);        
            R_CALL(r2r_unitary_opw, reg_src);
        }
        else if (REG_is_Upper8(reg_src)) {
            node->addDataFlowEdge(reg_src, 0);
            node->addDataFlowEdge(REG_AL, 1);
            R_CALL(r2r_unitary_opb_u, reg_src);
        }
        else {
            node->addDataFlowEdge(reg_src, 0);
            node->addDataFlowEdge(REG_AL, 1);            
            R_CALL(r2r_unitary_opb_l, reg_src);
        }
    }
}