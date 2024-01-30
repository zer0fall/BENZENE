#include "val_cmp_op.h"
#include "val_helper.h"
#include "value_core.h"
#include <stdio.h>
#include <iostream>

/* threads context */
extern thread_ctx_t *threads_ctx;
extern tag_t c_tag;
extern VFGCore *vfg_core;

extern bool val_enable;

#define M_CMP_CALL(fn)                                                              \
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)fn, IARG_FAST_ANALYSIS_CALL,    \
        IARG_THREAD_ID, IARG_MEMORYREAD_EA, IARG_CALL_ORDER, LIBDFT_CALL_ORDER + 10,\
        IARG_END )

#define MR_CMP_CALL(fn, src)                                                        \
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)fn, IARG_FAST_ANALYSIS_CALL,    \
        IARG_THREAD_ID, IARG_UINT32, REG_INDX(src), IARG_MEMORYREAD_EA,             \
        IARG_CALL_ORDER, LIBDFT_CALL_ORDER + 10, IARG_END )

#define RR_CMP_CALL(fn, src1, src2)                 \
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)fn, IARG_FAST_ANALYSIS_CALL,    \
        IARG_THREAD_ID, IARG_UINT32, REG_INDX(src1), IARG_UINT32, REG_INDX(src2),   \
        IARG_CALL_ORDER, LIBDFT_CALL_ORDER + 10, IARG_END )        

#define R_CMP_CALL(fn, src)                 \
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)fn, IARG_FAST_ANALYSIS_CALL,    \
        IARG_THREAD_ID, IARG_UINT32, REG_INDX(src),                               \
        IARG_CALL_ORDER, LIBDFT_CALL_ORDER + 10, IARG_END )           


static void PIN_FAST_ANALYSIS_CALL val_m_cmp_opb(THREADID tid, ADDRINT src) {
    if (val_enable == false) return;

    for (size_t i = 0; i < 1; i++) {
        tag_t src_tag = MTAG(src + i);
    
        if (!tag_is_empty(src_tag)) {
            vfg_core->addInTag(src_tag, 0);                    
        } 
    } 
}

static void PIN_FAST_ANALYSIS_CALL val_m_cmp_opw(THREADID tid, ADDRINT src) {
    if (val_enable == false) return;

    for (size_t i = 0; i < 2; i++) {
        tag_t src_tag = MTAG(src + i);
    
        if (!tag_is_empty(src_tag)) {
            vfg_core->addInTag(src_tag, 0);
        } 
    } 
}

static void PIN_FAST_ANALYSIS_CALL val_m_cmp_opl(THREADID tid, ADDRINT src) {
    if (val_enable == false) return;
    
    for (size_t i = 0; i < 4; i++) {
        tag_t src_tag = MTAG(src + i);
    
        if (!tag_is_empty(src_tag)) {
            vfg_core->addInTag(src_tag, 0);      
        } 
    }      
}

static void PIN_FAST_ANALYSIS_CALL val_m_cmp_opq(THREADID tid, ADDRINT src) {
    if (val_enable == false) return;

    for (size_t i = 0; i < 8; i++) {
        tag_t src_tag = MTAG(src + i);
    
        if (!tag_is_empty(src_tag)) {
            vfg_core->addInTag(src_tag, 0);
        } 
    }    
}

static void PIN_FAST_ANALYSIS_CALL val_mr_cmp_opb_l(THREADID tid, 
                                                uint32_t src_reg, ADDRINT src_mem) {
    if (val_enable == false) return;

    tag_t src_reg_tag = RTAG[src_reg][0];

    if (!tag_is_empty(src_reg_tag)) {
        vfg_core->addInTag(src_reg_tag, 0);
    }

    tag_t src_mem_tag = MTAG(src_mem);
    if (!tag_is_empty(src_mem_tag)) {
        vfg_core->addInTag(src_mem_tag, 1);    
    }  
}

static void PIN_FAST_ANALYSIS_CALL val_mr_cmp_opb_u(THREADID tid, 
                                                uint32_t src_reg, ADDRINT src_mem) {
    if (val_enable == false) return;

    tag_t src_reg_tag = RTAG[src_reg][1];

    if (!tag_is_empty(src_reg_tag)) {
        vfg_core->addInTag(src_reg_tag, 0);
    }

    tag_t src_mem_tag = MTAG(src_mem);
    if (!tag_is_empty(src_mem_tag)) {
        vfg_core->addInTag(src_mem_tag, 1);    
    }  
}

static void PIN_FAST_ANALYSIS_CALL val_mr_cmp_opw(THREADID tid, 
                                                uint32_t src_reg, ADDRINT src_mem) {
    if (val_enable == false) return;

    tag_t *src_reg_tags = RTAG[src_reg];

    for (size_t i = 0; i < 2; i++) {
        if (!tag_is_empty(src_reg_tags[i])) {
            vfg_core->addInTag(src_reg_tags[i], 0);
        }

        tag_t src_mem_tag = MTAG(src_mem + i);
        if (!tag_is_empty(src_mem_tag)) {
            vfg_core->addInTag(src_mem_tag, 1);    
        } 
    }    
}

static void PIN_FAST_ANALYSIS_CALL val_mr_cmp_opl(THREADID tid, 
                                                uint32_t src_reg, ADDRINT src_mem) {
    if (val_enable == false) return;

    tag_t *src_reg_tags = RTAG[src_reg];

    for (size_t i = 0; i < 4; i++) {
        if (!tag_is_empty(src_reg_tags[i])) {
            vfg_core->addInTag(src_reg_tags[i], 0);
        }

        tag_t src_mem_tag = MTAG(src_mem + i);
        if (!tag_is_empty(src_mem_tag)) {
            vfg_core->addInTag(src_mem_tag, 1); 
        } 
    }    
}

static void PIN_FAST_ANALYSIS_CALL val_mr_cmp_opq(THREADID tid, 
                                                uint32_t src_reg, ADDRINT src_mem) {
    if (val_enable == false) return;

    tag_t *src_reg_tags = RTAG[src_reg];

    for (size_t i = 0; i < 8; i++) {
        if (!tag_is_empty(src_reg_tags[i])) {
            vfg_core->addInTag(src_reg_tags[i], 0);
        }

        tag_t src_mem_tag = MTAG(src_mem + i);
        if (!tag_is_empty(src_mem_tag)) {
            vfg_core->addInTag(src_mem_tag, 1); 
        } 
    }    
}

// static void PIN_FAST_ANALYSIS_CALL val_r_cmp_opq(THREADID tid, uint32_t src_reg) {
//     if (val_enable == false) return;

//     tag_t *src_reg_tags = RTAG[src_reg];

//     for (size_t i = 0; i < 8; i++) {
//         if (!tag_is_empty(src_reg_tags[i])) {
//             vfg_core->addInTag(src_reg_tags[i]);
//         }
//     }   
// }

static void PIN_FAST_ANALYSIS_CALL val_r_cmp_opb_l(THREADID tid, uint32_t src_reg) {
    if (val_enable == false) return;

    tag_t src_tag = RTAG[src_reg][0];

    if (!tag_is_empty(src_tag)) {
        vfg_core->addInTag(src_tag, 0);
    }
}

static void PIN_FAST_ANALYSIS_CALL val_r_cmp_opb_u(THREADID tid, uint32_t src_reg) {
    if (val_enable == false) return;

    tag_t src_tag = RTAG[src_reg][1];

    if (!tag_is_empty(src_tag)) {
        vfg_core->addInTag(src_tag, 0);
    }
}

static void PIN_FAST_ANALYSIS_CALL val_r_cmp_opw(THREADID tid, uint32_t src_reg) {
    if (val_enable == false) return;

    tag_t *src_reg_tags = RTAG[src_reg];

    for (size_t i = 0; i < 2; i++) {
        if (!tag_is_empty(src_reg_tags[i])) {
            vfg_core->addInTag(src_reg_tags[i], 0);
        }
    }   
}

static void PIN_FAST_ANALYSIS_CALL val_r_cmp_opl(THREADID tid, uint32_t src_reg) {
    if (val_enable == false) return;

    tag_t *src_reg_tags = RTAG[src_reg];

    for (size_t i = 0; i < 4; i++) {
        if (!tag_is_empty(src_reg_tags[i])) {
            vfg_core->addInTag(src_reg_tags[i], 0);
        }
    }   
}

static void PIN_FAST_ANALYSIS_CALL val_r_cmp_opq(THREADID tid, uint32_t src_reg) {
    if (val_enable == false) return;

    tag_t *src_reg_tags = RTAG[src_reg];

    for (size_t i = 0; i < 8; i++) {
        if (!tag_is_empty(src_reg_tags[i])) {
            vfg_core->addInTag(src_reg_tags[i], 0);
        }
    }   
}

static void PIN_FAST_ANALYSIS_CALL val_rr_cmp_opb_ll(THREADID tid, uint32_t src_reg1, uint32_t src_reg2) {
    if (val_enable == false) return;

    tag_t src_reg_tag1 = RTAG[src_reg1][0];
    tag_t src_reg_tag2 = RTAG[src_reg2][0];

    if (!tag_is_empty(src_reg_tag1)) {
        vfg_core->addInTag(src_reg_tag1, 0);
    }

    if (!tag_is_empty(src_reg_tag2)) {
        vfg_core->addInTag(src_reg_tag2, 1);
    }        
}

static void PIN_FAST_ANALYSIS_CALL val_rr_cmp_opb_ul(THREADID tid, uint32_t src_reg1, uint32_t src_reg2) {
    if (val_enable == false) return;

    tag_t src_reg_tag1 = RTAG[src_reg1][1];
    tag_t src_reg_tag2 = RTAG[src_reg2][0];

    if (!tag_is_empty(src_reg_tag1)) {
        vfg_core->addInTag(src_reg_tag1, 0);
    }

    if (!tag_is_empty(src_reg_tag2)) {
        vfg_core->addInTag(src_reg_tag2, 1);
    }        
}

static void PIN_FAST_ANALYSIS_CALL val_rr_cmp_opb_uu(THREADID tid, uint32_t src_reg1, uint32_t src_reg2) {
    if (val_enable == false) return;

    tag_t src_reg_tag1 = RTAG[src_reg1][1];
    tag_t src_reg_tag2 = RTAG[src_reg2][1];

    if (!tag_is_empty(src_reg_tag1)) {
        vfg_core->addInTag(src_reg_tag1, 0);
    }

    if (!tag_is_empty(src_reg_tag2)) {
        vfg_core->addInTag(src_reg_tag2, 1);
    }        
}

static void PIN_FAST_ANALYSIS_CALL val_rr_cmp_opw(THREADID tid, uint32_t src_reg1, uint32_t src_reg2) {
    if (val_enable == false) return;

    tag_t *src_reg_tags1 = RTAG[src_reg1];
    tag_t *src_reg_tags2 = RTAG[src_reg2];

    for (size_t i = 0; i < 2; i++) {
        if (!tag_is_empty(src_reg_tags1[i])) {
            vfg_core->addInTag(src_reg_tags1[i], 0);
        }

        if (!tag_is_empty(src_reg_tags2[i])) {
            vfg_core->addInTag(src_reg_tags2[i], 1);
        }        
    }   
}

static void PIN_FAST_ANALYSIS_CALL val_rr_cmp_opl(THREADID tid, uint32_t src_reg1, uint32_t src_reg2) {
    if (val_enable == false) return;

    tag_t *src_reg_tags1 = RTAG[src_reg1];
    tag_t *src_reg_tags2 = RTAG[src_reg2];

    for (size_t i = 0; i < 4; i++) {
        if (!tag_is_empty(src_reg_tags1[i])) {
            vfg_core->addInTag(src_reg_tags1[i], 0);
        }

        if (!tag_is_empty(src_reg_tags2[i])) {
            vfg_core->addInTag(src_reg_tags2[i], 1);
        }        
    }   
}

static void PIN_FAST_ANALYSIS_CALL val_rr_cmp_opq(THREADID tid, uint32_t src_reg1, uint32_t src_reg2) {
    if (val_enable == false) return;

    tag_t *src_reg_tags1 = RTAG[src_reg1];
    tag_t *src_reg_tags2 = RTAG[src_reg2];

    for (size_t i = 0; i < 8; i++) {
        if (!tag_is_empty(src_reg_tags1[i])) {
            vfg_core->addInTag(src_reg_tags1[i], 0);
        }

        if (!tag_is_empty(src_reg_tags2[i])) {
            vfg_core->addInTag(src_reg_tags2[i], 1);
        }        
    }   
}

void val_cmp_op(INS ins, InsNode* node) {
    uint32_t num_reg = INS_MaxNumRRegs(ins);    

    if (INS_IsMemoryRead(ins)) {
        REG base_reg = INS_MemoryBaseReg(ins);
        REG idx_reg = INS_MemoryIndexReg(ins);

        REG r = REG_INVALID_;
        for (uint32_t k = 0; k < num_reg; k++) {
            r = INS_RegR(ins, k);
            
            // pointer values are excluded from analysis (monitoring)
            if (r == base_reg || r == idx_reg) {
                r = REG_INVALID_;
                continue;
            }
            break;
        }

        if (REG_valid(r)) { // cmp rax, qword ptr [rbp-0x20]
            node->addDataFlowEdge(r, 0);
            node->addDataFlowEdge(REG_MEM, 1);

            switch(INS_MemoryReadSize(ins)) {
            case 1:          
                if (REG_is_Upper8(r))
                    MR_CMP_CALL(val_mr_cmp_opb_u, r);
                else
                    MR_CMP_CALL(val_mr_cmp_opb_l, r);
                break;
            case 2:
                MR_CMP_CALL(val_mr_cmp_opw, r);
                break;
            case 4:
                MR_CMP_CALL(val_mr_cmp_opl, r);
                break;
            case 8:   
                MR_CMP_CALL(val_mr_cmp_opq, r);
                break;
            default:
                fprintf(stderr, "Unhandled case : %s\n", INS_Disassemble(ins).c_str());
                assert(false);                        
                break;
            }                            
        }
        else { // cmp qword ptr [rdi], 0x0
            node->addDataFlowEdge(REG_MEM, 0);        

            switch(INS_MemoryReadSize(ins)) {
            case 1:
                M_CMP_CALL(val_m_cmp_opb);                   
                break;
            case 2:
                M_CMP_CALL(val_m_cmp_opw);  
                break;
            case 4:
                M_CMP_CALL(val_m_cmp_opl);
                break;
            case 8:   
                M_CMP_CALL(val_m_cmp_opq);
                break;
            default:
                fprintf(stderr, "Unhandled case : %s\n", INS_Disassemble(ins).c_str());
                assert(false);                        
                break;
            }        
        }
    }
    else { 
        if (INS_MaxNumRRegs(ins) == 1) {  
            // cmp eax, 0xffffffff
            // cmp rax, 0x0
            REG src_reg = INS_RegR(ins, 0); 

            node->addDataFlowEdge(src_reg, 0);        
            
            switch(REG_Size(src_reg)) {
            case 1:
                if (REG_is_Upper8(src_reg))
                    R_CMP_CALL(val_r_cmp_opb_u, src_reg);
                else
                    R_CMP_CALL(val_r_cmp_opb_l, src_reg);
                break;
            case 2:
                R_CMP_CALL(val_r_cmp_opw, src_reg);
                break;
            case 4:
                R_CMP_CALL(val_r_cmp_opl, src_reg);
                break;
            case 8:   
                R_CMP_CALL(val_r_cmp_opq, src_reg);
                break;
            default:
                fprintf(stderr, "Unhandled case : %s\n", INS_Disassemble(ins).c_str());
                assert(false);                        
                break;
            }              
        }
        else {
            // cmp rbx, rbp
            // cmp eax, ecx            
            REG src_reg1 = INS_RegR(ins, 0);
            REG src_reg2 = INS_RegR(ins, 1);

            node->addDataFlowEdge(src_reg1, 0);        
            node->addDataFlowEdge(src_reg2, 1);

            switch(REG_Size(src_reg1)) {
            case 1:
                if (REG_is_Upper8(src_reg1)) {
                    if (REG_is_Upper8(src_reg2))
                        RR_CMP_CALL(val_rr_cmp_opb_uu, src_reg1, src_reg2);
                    else
                        RR_CMP_CALL(val_rr_cmp_opb_ul, src_reg1, src_reg2);
                }
                else {
                    if (REG_is_Upper8(src_reg2))
                        RR_CMP_CALL(val_rr_cmp_opb_ul, src_reg2, src_reg1);
                    else
                        RR_CMP_CALL(val_rr_cmp_opb_ll, src_reg2, src_reg1);
                }
                break;
            case 2:
                RR_CMP_CALL(val_rr_cmp_opw, src_reg1, src_reg2);
                break;
            case 4:
                RR_CMP_CALL(val_rr_cmp_opl, src_reg1, src_reg2);
                break;
            case 8:   
                RR_CMP_CALL(val_rr_cmp_opq, src_reg1, src_reg2);
                break;
            default:
                fprintf(stderr, "Unhandled case : %s\n", INS_Disassemble(ins).c_str());
                assert(false);                        
                break;
            }        
        }
    }
}

void val_test_op(INS ins, InsNode* node) {
    if (INS_IsMemoryRead(ins)) {
        REG base_reg = INS_MemoryBaseReg(ins);
        REG idx_reg = INS_MemoryIndexReg(ins);

        if (REG_valid(base_reg) && REG_valid(idx_reg) && INS_MaxNumRRegs(ins) == 2) { // test byte ptr [rbx+rax*1+0x18], 0x40
            node->addDataFlowEdge(REG_MEM, 0);
            
            switch(INS_MemoryReadSize(ins)) {
            case 1:
                M_CMP_CALL(val_m_cmp_opb);                   
                break;
            case 2:
                M_CMP_CALL(val_m_cmp_opw);  
                break;
            case 4:
                M_CMP_CALL(val_m_cmp_opl);
                break;
            case 8:   
                M_CMP_CALL(val_m_cmp_opq);
                break;
            default:
                fprintf(stderr, "Unhandled case : %s\n", INS_Disassemble(ins).c_str());
                assert(false);                        
                break;
            }

            return;
        }
        else  {
            if (INS_MaxNumRRegs(ins) == 1) {  
                // test dword ptr [rbp-0x34], 0x0
                // test qword ptr [rdi], 0x0
                node->addDataFlowEdge(REG_MEM, 0);
                
                switch(INS_MemoryReadSize(ins)) {
                case 1:
                    M_CMP_CALL(val_m_cmp_opb);                   
                    break;
                case 2:
                    M_CMP_CALL(val_m_cmp_opw);  
                    break;
                case 4:
                    M_CMP_CALL(val_m_cmp_opl);
                    break;
                case 8:   
                    M_CMP_CALL(val_m_cmp_opq);
                    break;
                default:
                    fprintf(stderr, "Unhandled case : %s\n", INS_Disassemble(ins).c_str());
                    assert(false);                        
                    break;
                }
            }
            else { // register & memory operand 
                // cmp rax, qword ptr [rbp-0x20]
                REG base_reg = INS_MemoryBaseReg(ins); 
                REG src_reg = INS_RegR(ins, 0); 
                
                if (src_reg == base_reg)                // cmp qword ptr [rbp-0x18], rax
                    src_reg = INS_RegR(ins, 1); 

                node->addDataFlowEdge(src_reg, 0);
                node->addDataFlowEdge(REG_MEM, 1);

                switch(INS_MemoryReadSize(ins)) {
                case 1:          
                    if (REG_is_Upper8(src_reg))
                        MR_CMP_CALL(val_mr_cmp_opb_u, src_reg);
                    else
                        MR_CMP_CALL(val_mr_cmp_opb_l, src_reg);
                    break;
                case 2:
                    MR_CMP_CALL(val_mr_cmp_opw, src_reg);
                    break;
                case 4:
                    MR_CMP_CALL(val_mr_cmp_opl, src_reg);
                    break;
                case 8:   
                    MR_CMP_CALL(val_mr_cmp_opq, src_reg);
                    break;
                default:
                    fprintf(stderr, "Unhandled case : %s\n", INS_Disassemble(ins).c_str());
                    assert(false);                        
                    break;
                }                
            }
        }
    }
    else {
        if (INS_MaxNumRRegs(ins) == 1) {  
            // cmp eax, 0xffffffff
            // cmp rax, 0x0
            REG src_reg = INS_RegR(ins, 0); 

            node->addDataFlowEdge(src_reg, 0);
            
            switch(REG_Size(src_reg)) {
            case 1:
                if (REG_is_Upper8(src_reg))
                    R_CMP_CALL(val_r_cmp_opb_u, src_reg);
                else
                    R_CMP_CALL(val_r_cmp_opb_l, src_reg);
                break;
            case 2:
                R_CMP_CALL(val_r_cmp_opw, src_reg);
                break;
            case 4:
                R_CMP_CALL(val_r_cmp_opl, src_reg);
                break;
            case 8:   
                R_CMP_CALL(val_r_cmp_opq, src_reg);
                break;
            default:
                fprintf(stderr, "Unhandled case : %s\n", INS_Disassemble(ins).c_str());
                assert(false);                        
                break;
            }
        }
        else {
            // test rbx, rbp
            // test eax, ecx            
            REG src_reg1 = INS_RegR(ins, 0);
            REG src_reg2 = INS_RegR(ins, 1);

            node->addDataFlowEdge(src_reg1, 0);        

            if (src_reg1 == src_reg2) { // same register used: e.g., test rax, rax
                switch(REG_Size(src_reg1)) {
                case 1:
                    if (REG_is_Upper8(src_reg1)) {
                        R_CMP_CALL(val_r_cmp_opb_u, src_reg1);
                    }
                    else {
                        R_CMP_CALL(val_r_cmp_opb_l, src_reg1);
                    }
                    break;
                case 2:
                    R_CMP_CALL(val_r_cmp_opw, src_reg1);
                    break;
                case 4:
                    R_CMP_CALL(val_r_cmp_opl, src_reg1);
                    break;
                case 8:
                    R_CMP_CALL(val_r_cmp_opq, src_reg1);
                    break;
                default:
                    fprintf(stderr, "Unhandled case : %s\n", INS_Disassemble(ins).c_str());
                    assert(false);                        
                    break;
                }
            }
            else { // different registers are used: e.g., test rax, rbx
                node->addDataFlowEdge(src_reg2, 1);

                switch(REG_Size(src_reg1)) {
                case 1:
                    if (REG_is_Upper8(src_reg1)) {
                        if (REG_is_Upper8(src_reg2))
                            RR_CMP_CALL(val_rr_cmp_opb_uu, src_reg1, src_reg2);
                        else
                            RR_CMP_CALL(val_rr_cmp_opb_ul, src_reg1, src_reg2);
                    }
                    else {
                        if (REG_is_Upper8(src_reg2))
                            RR_CMP_CALL(val_rr_cmp_opb_ul, src_reg2, src_reg1);
                        else
                            RR_CMP_CALL(val_rr_cmp_opb_ll, src_reg2, src_reg1);
                    }
                    break;
                case 2:
                    RR_CMP_CALL(val_rr_cmp_opw, src_reg1, src_reg2);
                    break;
                case 4:
                    RR_CMP_CALL(val_rr_cmp_opl, src_reg1, src_reg2);
                    break;
                case 8:   
                    RR_CMP_CALL(val_rr_cmp_opq, src_reg1, src_reg2);
                    break;
                default:
                    fprintf(stderr, "Unhandled case : %s\n", INS_Disassemble(ins).c_str());
                    assert(false);                        
                    break;
                }
            }
        }
        
    }
}
