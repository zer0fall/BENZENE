#include "val_movsx_op.h"
#include "val_helper.h"
#include "val_xfer_op.h"
#include "value_core.h"

/* threads context */
extern thread_ctx_t *threads_ctx;
extern tag_t c_tag;
extern VFGCore *vfg_core;


extern bool val_enable;

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 16-bit
 * register and an 8-bit register as t[dst] = t[upper(src)]
 *
 * NOTE: special case for MOVSX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL val_movsx_r2r_opwb_u(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
    if (val_enable == false) return;

    /* temporary tag value */
    tag_t src_tag = RTAG[src][1];
    tag_t *rtag_dst = RTAG[dst];

    /* update the destination (xfer) */
    if (tag_is_empty(src_tag)) {
        rtag_dst[0] = c_tag;
        rtag_dst[1] = c_tag;
    }
    else {
        vfg_core->addInTag(src_tag, 0);
    }
}

static void PIN_FAST_ANALYSIS_CALL val_movsx_r2r_opwb_l(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
    if (val_enable == false) return;

    /* temporary tag value */
    tag_t src_tag = RTAG[src][0];
    tag_t *rtag_dst = RTAG[dst];

    /* update the destination (xfer) */
    if (tag_is_empty(src_tag)) {
        rtag_dst[0] = c_tag;
        rtag_dst[1] = c_tag;
    }
    else {
        vfg_core->addInTag(src_tag, 0);
    }
}

static void PIN_FAST_ANALYSIS_CALL val_movsx_r2r_oplb_u(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
    if (val_enable == false) return;

    /* temporary tag value */
    tag_t src_tag = RTAG[src][1];
    tag_t *rtag_dst = RTAG[dst];
    if (!tag_is_empty(src_tag))
        vfg_core->addInTag(src_tag, 0);

    /* update the destination (xfer) */
    for (size_t i = 0; i < 4; i++) {
        rtag_dst[i] = c_tag;
    }
}

static void PIN_FAST_ANALYSIS_CALL val_movsx_r2r_oplb_l(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
    if (val_enable == false) return;

    /* temporary tag value */
    tag_t src_tag = RTAG[src][0];
    tag_t *rtag_dst = RTAG[dst];

    if (!tag_is_empty(src_tag))
        vfg_core->addInTag(src_tag, 0);
    
    /* update the destination (xfer) */
    for (size_t i = 0; i < 4; i++) {
        rtag_dst[i] = c_tag;
    }
}

static void PIN_FAST_ANALYSIS_CALL val_movsx_r2r_opqb_u(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
    if (val_enable == false) return;

    /* temporary tag value */
    tag_t src_tag = RTAG[src][1];
    tag_t *rtag_dst = RTAG[dst];
    
    if (!tag_is_empty(src_tag))
        vfg_core->addInTag(src_tag, 0);

    /* update the destination (xfer) */
    for (size_t i = 0; i < 8; i++) {
        rtag_dst[i] = c_tag;
    }
}

static void PIN_FAST_ANALYSIS_CALL val_movsx_r2r_opqb_l(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
    if (val_enable == false) return;

    /* temporary tag value */
    tag_t src_tag = RTAG[src][0];
    tag_t *rtag_dst = RTAG[dst];

    if (!tag_is_empty(src_tag))
        vfg_core->addInTag(src_tag, 0);

    /* update the destination (xfer) */
    for (size_t i = 0; i < 8; i++) {
        rtag_dst[i] = c_tag;
    }
}

static void PIN_FAST_ANALYSIS_CALL val_movsx_r2r_oplw(THREADID tid, uint32_t dst,
                                                   uint32_t src) {
    if (val_enable == false) return;

    /* temporary tag values */
    tag_t *rtag_src = RTAG[src];
    tag_t *rtag_dst = RTAG[dst];

    /* update the destination (xfer) */
    for (size_t i = 0; i < 4; i++) {
        if (!tag_is_empty(rtag_src[i % 2]))
            vfg_core->addInTag(rtag_src[i % 2], 0);            
        rtag_dst[i] = c_tag;
    }
}

static void PIN_FAST_ANALYSIS_CALL val_movsx_r2r_opqw(THREADID tid, uint32_t dst,
                                                   uint32_t src) {
    if (val_enable == false) return;

    /* temporary tag values */
    tag_t *rtag_src = RTAG[src];
    tag_t *rtag_dst = RTAG[dst];

    /* update the destination (xfer) */
    for (size_t i = 0; i < 8; i++) {
        if (!tag_is_empty(rtag_src[i % 2]))
            vfg_core->addInTag(rtag_src[i % 2], 0);            
        rtag_dst[i] = c_tag;
    }
}

static void PIN_FAST_ANALYSIS_CALL val_movsx_r2r_opql(THREADID tid, uint32_t dst,
                                                   uint32_t src) {
    if (val_enable == false) return;

    /* temporary tag values */
    tag_t *rtag_src = RTAG[src];
    tag_t *rtag_dst = RTAG[dst];

    /* update the destination (xfer) */
    for (size_t i = 0; i < 8; i++) {
        if (!tag_is_empty(rtag_src[i % 4]))
            vfg_core->addInTag(rtag_src[i % 4], 0);
        
        rtag_dst[i] = c_tag;
    }
}

static void PIN_FAST_ANALYSIS_CALL val_movsx_m2r_opwb(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {
    if (val_enable == false) return;

    /* temporary tag value */
    tag_t src_tag = MTAG(src);
    tag_t *rtag_dst = RTAG[dst];

    if (!tag_is_empty(src_tag))
        vfg_core->addInTag(src_tag, 0);

    rtag_dst[0] = c_tag;
    rtag_dst[1] = c_tag;
    
}

static void PIN_FAST_ANALYSIS_CALL val_movsx_m2r_oplb(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {
    if (val_enable == false) return;
    
    /* temporary tag value */
    tag_t src_tag = MTAG(src);
    tag_t *rtag_dst = RTAG[dst];
    
    if (!tag_is_empty(src_tag))
        vfg_core->addInTag(src_tag, 0);

    /* update the destination (xfer) */
    for (size_t i = 0; i < 4; i++) {
        rtag_dst[i] = c_tag;
    }
}

static void PIN_FAST_ANALYSIS_CALL val_movsx_m2r_opqb(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {

    if (val_enable == false) return;
    
    /* temporary tag value */
    tag_t src_tag = MTAG(src);
    tag_t *rtag_dst = RTAG[dst];

    if (!tag_is_empty(src_tag))
        vfg_core->addInTag(src_tag, 0);

    /* update the destination (xfer) */
    for (size_t i = 0; i < 8; i++) {
        rtag_dst[i] = c_tag;
    }
}

static void PIN_FAST_ANALYSIS_CALL val_movsx_m2r_oplw(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {
    if (val_enable == false) return;

    /* temporary tag value */
    tag_t src_tags[] = M16TAG(src);
    tag_t *rtag_dst = RTAG[dst];

    /* update the destination (xfer) */
    for (size_t i = 0; i < 4; i++) {
        if (!tag_is_empty(src_tags[i % 2])) {
            vfg_core->addInTag(src_tags[i % 2], 0);
        }
        rtag_dst[i] = c_tag;     
    }
}

static void PIN_FAST_ANALYSIS_CALL val_movsx_m2r_opqw(THREADID tid, uint32_t dst,
                                                    ADDRINT src) {
    if (val_enable == false) return;

    /* temporary tag value */
    tag_t src_tags[] = M16TAG(src);
    tag_t *rtag_dst = RTAG[dst];

    /* update the destination (xfer) */
    for (size_t i = 0; i < 8; i++){
        if (!tag_is_empty(src_tags[i % 2])) {
            vfg_core->addInTag(src_tags[i % 2], 0);
        }
        rtag_dst[i] = c_tag;        
    }
}

static void PIN_FAST_ANALYSIS_CALL val_movsx_m2r_opql(THREADID tid, uint32_t dst,
                                                    ADDRINT src) {
    if (val_enable == false) return;

    /* temporary tag value */
    tag_t src_tags[] = M32TAG(src);

    tag_t *rtag_dst = RTAG[dst];

    /* update the destination (xfer) */
    for (size_t i = 0; i < 8; i++){
        if (!tag_is_empty(src_tags[i % 4])) {
            vfg_core->addInTag(src_tags[i % 4], 0);
        }
        rtag_dst[i] = c_tag;     
    }
}

void val_movsx_op(INS ins, InsNode* node) {

    REG reg_dst, reg_src;
    if (INS_MemoryOperandCount(ins) == 0) {
        reg_dst = INS_OperandReg(ins, OP_0);
        reg_src = INS_OperandReg(ins, OP_1);

        node->addDataFlowEdge(reg_src, 0);

        if (REG_is_gr16(reg_dst)) {
            if (REG_is_Upper8(reg_src))
                R2R_CALL(val_movsx_r2r_opwb_u, reg_dst, reg_src);
            else
                R2R_CALL(val_movsx_r2r_opwb_l, reg_dst, reg_src);
        } 
        else if (REG_is_gr16(reg_src)) {
            if (REG_is_gr64(reg_dst))
                    R2R_CALL(val_movsx_r2r_opqw, reg_dst, reg_src);
            else if (REG_is_gr32(reg_dst))
                    R2R_CALL(val_movsx_r2r_oplw, reg_dst, reg_src);
        } 
        else if (REG_is_Upper8(reg_src)) {
            if (REG_is_gr64(reg_dst))
                R2R_CALL(val_movsx_r2r_opqb_u, reg_dst, reg_src);
            else if (REG_is_gr32(reg_dst))
                R2R_CALL(val_movsx_r2r_oplb_u, reg_dst, reg_src);
        } 
        else { // lower8
            if (REG_is_gr64(reg_dst))
                R2R_CALL(val_movsx_r2r_opqb_l, reg_dst, reg_src);
            else if (REG_is_gr32(reg_dst))
                R2R_CALL(val_movsx_r2r_oplb_l, reg_dst, reg_src);
        }
    } 
    else {
        reg_dst = INS_OperandReg(ins, OP_0);

        node->addDataFlowEdge(REG_MEM, 0);

        if (REG_is_gr16(reg_dst)) {
            M2R_CALL(val_movsx_m2r_opwb, reg_dst);
        } else if (INS_MemoryOperandSize(ins, OP_0) == BIT2BYTE(MEM_WORD_LEN)) {
            if (REG_is_gr64(reg_dst)) {
                M2R_CALL(val_movsx_m2r_opqw, reg_dst);
            } else if (REG_is_gr32(reg_dst)) {
                M2R_CALL(val_movsx_m2r_oplw, reg_dst);
            }
        } else {
            if (REG_is_gr64(reg_dst)) {
                M2R_CALL(val_movsx_m2r_opqb, reg_dst);
            } else if (REG_is_gr32(reg_dst)) {
                M2R_CALL(val_movsx_m2r_oplb, reg_dst);
            }
        }
    }
}

void val_movsxd_op(INS ins, InsNode* node) {
    REG reg_dst, reg_src;
    reg_dst = INS_OperandReg(ins, OP_0);

    if (!REG_is_gr64(reg_dst)) {
        val_xfer_op(ins, node);
    }
    if (INS_MemoryOperandCount(ins) == 0) {
        reg_src = INS_OperandReg(ins, OP_1);

        node->addDataFlowEdge(reg_src, 0);

        R2R_CALL(val_movsx_r2r_opql, reg_dst, reg_src);
    } else {
        node->addDataFlowEdge(REG_MEM, 0);

        M2R_CALL(val_movsx_m2r_opql, reg_dst);
    }
}