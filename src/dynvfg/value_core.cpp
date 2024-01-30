#include "value_core.h"

#include "pin.H"

#include "val_helper.h"
#include "val_binary_op.h"
#include "val_unitary_op.h"
#include "val_xfer_op.h"
#include "val_lea_op.h"
#include "val_movsx_op.h"
#include "val_shift_op.h"
#include "val_cmp_op.h"
#include <iostream>

#include "vfg.h"

extern thread_ctx_t *threads_ctx;
tag_t c_tag;
VFGCore* vfg_core;

bool val_enable;

static bool reg_eq(INS ins) {
    return (!INS_OperandIsImmediate(ins, OP_1) &&
            INS_MemoryOperandCount(ins) == 0 &&
            INS_OperandReg(ins, OP_0) == INS_OperandReg(ins, OP_1));
}


void enableVFG() {
    val_enable = true;
}

void disableVFG() {
    val_enable = false;
}

void set_chain(VFGCore* vfg) {
    vfg_core = vfg;
}

/*
 * instruction inspection (instrumentation function)
 *
 * analyze every instruction and instrument it
 * for propagating the tag bits accordingly
 *
 * @ins:	the instruction to be instrumented
 */
void instrument_rule(INS ins, InsNode* node) {
    /* use XED to decode the instruction and extract its opcode */
    xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
    /* sanity check */
    if (unlikely(ins_indx <= XED_ICLASS_INVALID || ins_indx >= XED_ICLASS_LAST)) {
        LOG(std::string(__func__) + ": unknown opcode (opcode=" + decstr(ins_indx) +
            ")\n");
        /* done */
        return;
    }

    if (INS_FullRegWContain(ins, REG_RIP)) {
       return;
    }
    // LOGD("[ins] %s \n", INS_Disassemble(ins, node).c_str());
    /*
    char *cstr;
    cstr = new char[INS_Disassemble(ins, node).size() + 1];
    strcpy(cstr, INS_Disassemble(ins, node).c_str());
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)dasm, IARG_PTR, cstr, IARG_END);
    */

    if (node) {
        node->setType(INS_Category(ins));
        node->setDerefEdgeInfo(ins);
    }

    switch (ins_indx) {
    // **** bianry ****
    case XED_ICLASS_ADC:
    case XED_ICLASS_ADD:
    case XED_ICLASS_ADD_LOCK:
    case XED_ICLASS_ADDPD:
    case XED_ICLASS_ADDSD:
    case XED_ICLASS_ADDSS:
    case XED_ICLASS_AND:
    case XED_ICLASS_OR:
    case XED_ICLASS_POR:
        val_binary_op(ins, node);
        break;
    case XED_ICLASS_XOR:
    case XED_ICLASS_SBB:
    case XED_ICLASS_SUB:
    case XED_ICLASS_PXOR:
    case XED_ICLASS_SUBSD:
    case XED_ICLASS_PSUBB:
    case XED_ICLASS_PSUBW:
    case XED_ICLASS_PSUBD:
    case XED_ICLASS_XORPS:
    case XED_ICLASS_XORPD:
        if (!reg_eq(ins)) {
            val_binary_op(ins, node);
        } 
        else {
            val_binary_clean(ins, node);
        }
        break;
    case XED_ICLASS_DIV:
    case XED_ICLASS_IDIV:
    case XED_ICLASS_MUL:
        val_unitary_op(ins, node);
        break;
    case XED_ICLASS_IMUL:
        if (INS_OperandIsImplicit(ins, OP_1)) {
            val_unitary_op(ins, node);
        } else {
            val_binary_op(ins, node);
        // if ternary // TODO
        }
        break;
    case XED_ICLASS_MULSD:
    case XED_ICLASS_MULPD:
    case XED_ICLASS_DIVSD:
        val_binary_op(ins, node);
        break;
    // **** xfer ****
    case XED_ICLASS_BSF:
    case XED_ICLASS_BSR:
    case XED_ICLASS_TZCNT:
    case XED_ICLASS_MOV:
        if ( !(INS_OperandIsReg(ins, OP_1) &&
            REG_is_seg(INS_OperandReg(ins, OP_1))) ) {
            val_xfer_op(ins, node);
        }
        break;
    case XED_ICLASS_MOVD:
    case XED_ICLASS_MOVQ:
    case XED_ICLASS_MOVAPS:
    case XED_ICLASS_MOVAPD:
    case XED_ICLASS_MOVDQU:
    case XED_ICLASS_MOVDQA:
    case XED_ICLASS_MOVUPS:
    case XED_ICLASS_MOVUPD:
    case XED_ICLASS_MOVSS:
    // only xmm, ymm
    case XED_ICLASS_VMOVD:
    case XED_ICLASS_VMOVQ:
    case XED_ICLASS_VMOVAPS:
    case XED_ICLASS_VMOVAPD:
    case XED_ICLASS_VMOVDQU:
    case XED_ICLASS_VMOVDQA:
    case XED_ICLASS_VMOVUPS:
    case XED_ICLASS_VMOVUPD:
    case XED_ICLASS_VMOVSS:
    case XED_ICLASS_MOVSD_XMM:
    case XED_ICLASS_CVTSI2SD:
    case XED_ICLASS_CVTSD2SI:
        val_xfer_op(ins, node);
        break;
    case XED_ICLASS_MOVLPD:
    case XED_ICLASS_MOVLPS:
        val_movlp(ins, node);
        break;
    // case XED_ICLASS_VMOVLPD:
    // case XED_ICLASS_VMOVLPS:
    case XED_ICLASS_MOVHPD:
    case XED_ICLASS_MOVHPS:
        val_movhp(ins, node);
        break;
    // case XED_ICLASS_VMOVHPD:
    // case XED_ICLASS_VMOVHPS:
    // case XED_ICLASS_MOVHLPS:
    // case XED_ICLASS_VMOVHLPS:
    case XED_ICLASS_CMOVB:
    case XED_ICLASS_CMOVBE:
    case XED_ICLASS_CMOVL:
    case XED_ICLASS_CMOVLE:
    case XED_ICLASS_CMOVNB:
    case XED_ICLASS_CMOVNBE:
    case XED_ICLASS_CMOVNL:
    case XED_ICLASS_CMOVNLE:
    case XED_ICLASS_CMOVNO:
    case XED_ICLASS_CMOVNP:
    case XED_ICLASS_CMOVNS:
    case XED_ICLASS_CMOVNZ:
    case XED_ICLASS_CMOVO:
    case XED_ICLASS_CMOVP:
    case XED_ICLASS_CMOVS:
    case XED_ICLASS_CMOVZ:
        val_xfer_op_predicated(ins, node);
        break;
    case XED_ICLASS_MOVBE:
        val_movbe_op(ins, node);
        break;
    case XED_ICLASS_MOVSX:
    case XED_ICLASS_MOVZX:
        val_movsx_op(ins, node);
        break;
    case XED_ICLASS_MOVSXD:
        val_movsxd_op(ins, node);
        break;
    case XED_ICLASS_CBW:
    case XED_ICLASS_CWD:
    case XED_ICLASS_CWDE:
    case XED_ICLASS_CDQ:
    case XED_ICLASS_CDQE:
    case XED_ICLASS_CQO:
        break;

    // ****** clear op ******
    // TODO: add rules with CMP
    case XED_ICLASS_SETB:
    case XED_ICLASS_SETBE:
    case XED_ICLASS_SETL:
    case XED_ICLASS_SETLE:
    case XED_ICLASS_SETNB:
    case XED_ICLASS_SETNBE:
    case XED_ICLASS_SETNL:
    case XED_ICLASS_SETNLE:
    case XED_ICLASS_SETNO:
    case XED_ICLASS_SETNP:
    case XED_ICLASS_SETNS:
    case XED_ICLASS_SETNZ:
    case XED_ICLASS_SETO:
    case XED_ICLASS_SETP:
    case XED_ICLASS_SETS:
    case XED_ICLASS_SETZ:
    case XED_ICLASS_STMXCSR:
    case XED_ICLASS_SMSW:
    case XED_ICLASS_STR:
    case XED_ICLASS_LAR:
    case XED_ICLASS_RDPMC:
    case XED_ICLASS_RDTSC:
    case XED_ICLASS_CPUID:
    case XED_ICLASS_LAHF:
    case XED_ICLASS_CMPXCHG:
    case XED_ICLASS_CMPXCHG_LOCK:
    case XED_ICLASS_XCHG:
        break;
    case XED_ICLASS_XADD:
    case XED_ICLASS_XADD_LOCK:
        // ins_xadd_op(ins, node);
        break;
    case XED_ICLASS_XLAT:
        node->addDataFlowEdge(REG_MEM, 0);
        M2R_CALL(val_m2r_xfer_opb_l, REG_AL);
        break;
    case XED_ICLASS_LODSB:
        node->addDataFlowEdge(REG_MEM, 0);
        M2R_CALL_P(val_m2r_xfer_opb_l, REG_AL);
        break;
    case XED_ICLASS_LODSW:
        node->addDataFlowEdge(REG_MEM, 0);
        M2R_CALL_P(val_m2r_xfer_opw, REG_AX);
        break;
    case XED_ICLASS_LODSD:
        node->addDataFlowEdge(REG_MEM, 0);
        M2R_CALL_P(val_m2r_xfer_opl, REG_EAX);
        break;
    case XED_ICLASS_LODSQ:
        node->addDataFlowEdge(REG_MEM, 0);
        M2R_CALL_P(val_m2r_xfer_opq, REG_RAX);
        break;
    case XED_ICLASS_STOSB:
        val_stosb(ins, node);
        break;
    case XED_ICLASS_STOSW:
        val_stosw(ins, node);
        break;
    case XED_ICLASS_STOSD:
        val_stosd(ins, node);
        break;
    case XED_ICLASS_STOSQ:
        val_stosq(ins, node);
        break;
    case XED_ICLASS_MOVSQ:
        node->addDataFlowEdge(REG_MEM, 0);
        M2M_CALL(val_m2m_xfer_opq);
        break;
    case XED_ICLASS_MOVSD:
        node->addDataFlowEdge(REG_MEM, 0);
        M2M_CALL(val_m2m_xfer_opl);
        break;
    case XED_ICLASS_MOVSW:
        node->addDataFlowEdge(REG_MEM, 0);
        M2M_CALL(val_m2m_xfer_opw);
        break;
    case XED_ICLASS_MOVSB:
        node->addDataFlowEdge(REG_MEM, 0);
        M2M_CALL(val_m2m_xfer_opb);
        break;
    case XED_ICLASS_SALC:
    case XED_ICLASS_POP:
        val_pop_op(ins, node);
        break;
    case XED_ICLASS_PUSH:
        val_push_op(ins, node);
        break;
    case XED_ICLASS_POPA:
    case XED_ICLASS_POPAD:
    case XED_ICLASS_PUSHA:
    case XED_ICLASS_PUSHAD:
    case XED_ICLASS_PUSHF:
    case XED_ICLASS_PUSHFD:
    case XED_ICLASS_PUSHFQ:
        break;
    case XED_ICLASS_LEA:
        // TODO: lea case handling
        val_lea_op(ins, node);
        break;
    case XED_ICLASS_PCMPEQB:
        val_binary_op(ins, node);
        break;
        // TODO
    case XED_ICLASS_XGETBV:
    case XED_ICLASS_PMOVMSKB:
    case XED_ICLASS_VPMOVMSKB:
    case XED_ICLASS_PUNPCKLBW:
    case XED_ICLASS_PUNPCKLWD:
    case XED_ICLASS_PSHUFD:
    case XED_ICLASS_PMINUB:
    case XED_ICLASS_PSLLDQ:
    case XED_ICLASS_PSRLDQ:
    case XED_ICLASS_VPCMPEQB:
    case XED_ICLASS_VPBROADCASTB:
    case XED_ICLASS_VZEROUPPER:
    case XED_ICLASS_BSWAP:
    case XED_ICLASS_UNPCKLPD:
    case XED_ICLASS_PSHUFB:
    case XED_ICLASS_VPTEST:
        // TODO: ternary
    case XED_ICLASS_VMULSD:
    case XED_ICLASS_VDIVSD:
    case XED_ICLASS_VPOR:
    case XED_ICLASS_VPXOR:
    case XED_ICLASS_VPSUBB:
    case XED_ICLASS_VPSUBW:
    case XED_ICLASS_VPSUBD:
    case XED_ICLASS_VPXORD:
    case XED_ICLASS_VPXORQ:
    case XED_ICLASS_VPAND:
    case XED_ICLASS_VPANDN:
    case XED_ICLASS_VPSLLDQ:
    case XED_ICLASS_VPCMPGTB:
    case XED_ICLASS_VPALIGNR:
    case XED_ICLASS_VPCMPISTRI:
        break;
    case XED_ICLASS_CMP:
        val_cmp_op(ins, node);
        break;    
    case XED_ICLASS_CMPSB: // @TODO : handle these instructions
    case XED_ICLASS_CMPSW:
    case XED_ICLASS_CMPSD:
    case XED_ICLASS_CMPSQ:
    case XED_ICLASS_CMPSS: // FIXME, 3arg
        break;
    case XED_ICLASS_UCOMISS:
    case XED_ICLASS_UCOMISD:
    case XED_ICLASS_VPMINUB:
    case XED_ICLASS_PCMPISTRI:
        break;
    // Ignore
    case XED_ICLASS_JMP:
    case XED_ICLASS_JZ:
    case XED_ICLASS_JNZ:
    case XED_ICLASS_JB:
    case XED_ICLASS_JNB:
    case XED_ICLASS_JBE:
    case XED_ICLASS_JNBE:
    case XED_ICLASS_JL:
    case XED_ICLASS_JNL:
    case XED_ICLASS_JLE:
    case XED_ICLASS_JNLE:
    case XED_ICLASS_JS:
    case XED_ICLASS_JNS:
    case XED_ICLASS_JP:
    case XED_ICLASS_JNP:
    case XED_ICLASS_RET_FAR:
    case XED_ICLASS_RET_NEAR:
    case XED_ICLASS_CALL_FAR:
    case XED_ICLASS_CALL_NEAR:
    case XED_ICLASS_LEAVE:
    case XED_ICLASS_SYSCALL:
        break;
    case XED_ICLASS_TEST:
        val_test_op(ins, node);
        break;
    case XED_ICLASS_RCL:
    case XED_ICLASS_RCR:
    case XED_ICLASS_ROL:
    case XED_ICLASS_ROR:
    case XED_ICLASS_SHL:
    case XED_ICLASS_SAR:
    case XED_ICLASS_SHR:
    case XED_ICLASS_SHLD:
    case XED_ICLASS_SHRD:
        val_shift_op(ins, node);
        break;
    case XED_ICLASS_NEG: // @TODO : handle these instructions
    case XED_ICLASS_NOT:
    case XED_ICLASS_NOP:
    case XED_ICLASS_BT:
    case XED_ICLASS_DEC:
    case XED_ICLASS_DEC_LOCK:
    case XED_ICLASS_INC:
    case XED_ICLASS_INC_LOCK:
    case XED_ICLASS_XSAVEC:
    case XED_ICLASS_XRSTOR:
        break;

    default:
        // https://intelxed.github.io/ref-manual/xed-extension-enum_8h.html#ae7b9f64cdf123c5fda22bd10d5db9916
        // INT32 num_op = INS_OperandCount(ins, node);
        // INT32 ins_ext = INS_Extension(ins, node);
        // if (ins_ext != 0 && ins_ext != 10)
        LOGD("[uninstrumented] opcode=%d, %s\n", ins_indx,
            INS_Disassemble(ins, node).c_str());
        break;
    }

    // edge parsing process should be done only once. Notify this.
    if (node)
        node->setEdgeFlag();
}



bool check_ins(INS ins) {
    /* use XED to decode the instruction and extract its opcode */
    xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
    /* sanity check */
    if (unlikely(ins_indx <= XED_ICLASS_INVALID || ins_indx >= XED_ICLASS_LAST)) {
        LOG(std::string(__func__) + ": unknown opcode (opcode=" + decstr(ins_indx) +
            ")\n");
        /* done */
        return false;
    }

   if (INS_FullRegWContain(ins, REG_RIP))
       return false;

    switch (ins_indx) {
    case XED_ICLASS_ADC:
    case XED_ICLASS_ADD:
    case XED_ICLASS_ADD_LOCK:
    case XED_ICLASS_ADDPD:
    case XED_ICLASS_ADDSD:
    case XED_ICLASS_ADDSS:
    case XED_ICLASS_AND:
    case XED_ICLASS_OR:
    case XED_ICLASS_POR:
        return true;
        break;
    case XED_ICLASS_XOR:
    case XED_ICLASS_SBB:
    case XED_ICLASS_SUB:
    case XED_ICLASS_PXOR:
    case XED_ICLASS_SUBSD:
    case XED_ICLASS_PSUBB:
    case XED_ICLASS_PSUBW:
    case XED_ICLASS_PSUBD:
    case XED_ICLASS_XORPS:
    case XED_ICLASS_XORPD:
        // if (!reg_eq(ins, node)) {
        //     return true;
        // }
        return true;
        break;
    case XED_ICLASS_DIV:
    case XED_ICLASS_IDIV:
    case XED_ICLASS_MUL:
        return true;
        break;
    case XED_ICLASS_IMUL:
        if (INS_OperandIsImplicit(ins, OP_1)) {
            return true;
        } else {
            return true;
        // if ternary // TODO
        }
        break;
    case XED_ICLASS_MULSD:
    case XED_ICLASS_MULPD:
    case XED_ICLASS_DIVSD:
        return true;
        break;
    // **** xfer ****
    case XED_ICLASS_BSF:
    case XED_ICLASS_BSR:
    case XED_ICLASS_TZCNT:
    case XED_ICLASS_MOV:
        if ( !(INS_OperandIsReg(ins, OP_1) &&
            REG_is_seg(INS_OperandReg(ins, OP_1))) ) {
            return true;
        }
        break;
    case XED_ICLASS_MOVD:
    case XED_ICLASS_MOVQ:
    case XED_ICLASS_MOVAPS:
    case XED_ICLASS_MOVAPD:
    case XED_ICLASS_MOVDQU:
    case XED_ICLASS_MOVDQA:
    case XED_ICLASS_MOVUPS:
    case XED_ICLASS_MOVUPD:
    case XED_ICLASS_MOVSS:
    // only xmm, ymm
    case XED_ICLASS_VMOVD:
    case XED_ICLASS_VMOVQ:
    case XED_ICLASS_VMOVAPS:
    case XED_ICLASS_VMOVAPD:
    case XED_ICLASS_VMOVDQU:
    case XED_ICLASS_VMOVDQA:
    case XED_ICLASS_VMOVUPS:
    case XED_ICLASS_VMOVUPD:
    case XED_ICLASS_VMOVSS:
    case XED_ICLASS_MOVSD_XMM:
    case XED_ICLASS_CVTSI2SD:
    case XED_ICLASS_CVTSD2SI:
        return true;
        break;
    case XED_ICLASS_MOVLPD:
    case XED_ICLASS_MOVLPS:
        return true;
        break;
    // case XED_ICLASS_VMOVLPD:
    // case XED_ICLASS_VMOVLPS:
    case XED_ICLASS_MOVHPD:
    case XED_ICLASS_MOVHPS:
        return true;
        break;
    // case XED_ICLASS_VMOVHPD:
    // case XED_ICLASS_VMOVHPS:
    // case XED_ICLASS_MOVHLPS:
    // case XED_ICLASS_VMOVHLPS:
    case XED_ICLASS_CMOVB:
    case XED_ICLASS_CMOVBE:
    case XED_ICLASS_CMOVL:
    case XED_ICLASS_CMOVLE:
    case XED_ICLASS_CMOVNB:
    case XED_ICLASS_CMOVNBE:
    case XED_ICLASS_CMOVNL:
    case XED_ICLASS_CMOVNLE:
    case XED_ICLASS_CMOVNO:
    case XED_ICLASS_CMOVNP:
    case XED_ICLASS_CMOVNS:
    case XED_ICLASS_CMOVNZ:
    case XED_ICLASS_CMOVO:
    case XED_ICLASS_CMOVP:
    case XED_ICLASS_CMOVS:
    case XED_ICLASS_CMOVZ:
        return true;
        break;
    case XED_ICLASS_MOVBE:
        return true;
        break;
    case XED_ICLASS_MOVSX:
    case XED_ICLASS_MOVZX:
        return true;
        break;
    case XED_ICLASS_MOVSXD:
        return true;
        break;
    case XED_ICLASS_CBW:
    case XED_ICLASS_CWD:
    case XED_ICLASS_CWDE:
    case XED_ICLASS_CDQ:
    case XED_ICLASS_CDQE:
    case XED_ICLASS_CQO:
        break;

    // ****** clear op ******
    // TODO: add rules with CMP
    case XED_ICLASS_SETB:
    case XED_ICLASS_SETBE:
    case XED_ICLASS_SETL:
    case XED_ICLASS_SETLE:
    case XED_ICLASS_SETNB:
    case XED_ICLASS_SETNBE:
    case XED_ICLASS_SETNL:
    case XED_ICLASS_SETNLE:
    case XED_ICLASS_SETNO:
    case XED_ICLASS_SETNP:
    case XED_ICLASS_SETNS:
    case XED_ICLASS_SETNZ:
    case XED_ICLASS_SETO:
    case XED_ICLASS_SETP:
    case XED_ICLASS_SETS:
    case XED_ICLASS_SETZ:
    case XED_ICLASS_STMXCSR:
    case XED_ICLASS_SMSW:
    case XED_ICLASS_STR:
    case XED_ICLASS_LAR:
    case XED_ICLASS_RDPMC:
    case XED_ICLASS_RDTSC:
    case XED_ICLASS_CPUID:
    case XED_ICLASS_LAHF:
    case XED_ICLASS_CMPXCHG:
    case XED_ICLASS_CMPXCHG_LOCK:
    case XED_ICLASS_XCHG:
        break;
    case XED_ICLASS_XADD:
    case XED_ICLASS_XADD_LOCK:
        // ins_xadd_op(ins, node);
        break;
    case XED_ICLASS_XLAT:
        return true;
        break;
    case XED_ICLASS_LODSB:
        return true;
        break;
    case XED_ICLASS_LODSW:
        return true;
        break;
    case XED_ICLASS_LODSD:
        return true;
        break;
    case XED_ICLASS_LODSQ:
        return true;
        break;
    case XED_ICLASS_STOSB:
        return true;
        break;
    case XED_ICLASS_STOSW:
        return true;
        break;
    case XED_ICLASS_STOSD:
        return true;
        break;
    case XED_ICLASS_STOSQ:
        return true;
        break;
    case XED_ICLASS_MOVSQ:
        return true;
        break;
    case XED_ICLASS_MOVSD:
        return true;
        break;
    case XED_ICLASS_MOVSW:
        return true;
        break;
    case XED_ICLASS_MOVSB:
        return true;
        break;
    case XED_ICLASS_SALC:
    case XED_ICLASS_POP:
        return true;
        break;
    case XED_ICLASS_PUSH:
        return true;
        break;
    case XED_ICLASS_POPA:
    case XED_ICLASS_POPAD:
    case XED_ICLASS_PUSHA:
    case XED_ICLASS_PUSHAD:
    case XED_ICLASS_PUSHF:
    case XED_ICLASS_PUSHFD:
    case XED_ICLASS_PUSHFQ:
        break;
    case XED_ICLASS_LEA:
        return true;
        break;
    case XED_ICLASS_PCMPEQB:
        return true;
        break;
        // TODO
    case XED_ICLASS_XGETBV:
    case XED_ICLASS_PMOVMSKB:
    case XED_ICLASS_VPMOVMSKB:
    case XED_ICLASS_PUNPCKLBW:
    case XED_ICLASS_PUNPCKLWD:
    case XED_ICLASS_PSHUFD:
    case XED_ICLASS_PMINUB:
    case XED_ICLASS_PSLLDQ:
    case XED_ICLASS_PSRLDQ:
    case XED_ICLASS_VPCMPEQB:
    case XED_ICLASS_VPBROADCASTB:
    case XED_ICLASS_VZEROUPPER:
    case XED_ICLASS_BSWAP:
    case XED_ICLASS_UNPCKLPD:
    case XED_ICLASS_PSHUFB:
    case XED_ICLASS_VPTEST:
        // TODO: ternary
    case XED_ICLASS_VMULSD:
    case XED_ICLASS_VDIVSD:
    case XED_ICLASS_VPOR:
    case XED_ICLASS_VPXOR:
    case XED_ICLASS_VPSUBB:
    case XED_ICLASS_VPSUBW:
    case XED_ICLASS_VPSUBD:
    case XED_ICLASS_VPXORD:
    case XED_ICLASS_VPXORQ:
    case XED_ICLASS_VPAND:
    case XED_ICLASS_VPANDN:
    case XED_ICLASS_VPSLLDQ:
    case XED_ICLASS_VPCMPGTB:
    case XED_ICLASS_VPALIGNR:
    case XED_ICLASS_VPCMPISTRI:
        break;
    case XED_ICLASS_CMP:
    case XED_ICLASS_CMPSB: 
    case XED_ICLASS_CMPSW:
    case XED_ICLASS_CMPSD:
    case XED_ICLASS_CMPSQ:
    case XED_ICLASS_CMPSS: // FIXME, 3arg
        break;
    case XED_ICLASS_UCOMISS:
    case XED_ICLASS_UCOMISD:
    case XED_ICLASS_VPMINUB:
    case XED_ICLASS_PCMPISTRI:
        break;

    // Ignore
    case XED_ICLASS_JMP:
    case XED_ICLASS_JZ:
    case XED_ICLASS_JNZ:
    case XED_ICLASS_JB:
    case XED_ICLASS_JNB:
    case XED_ICLASS_JBE:
    case XED_ICLASS_JNBE:
    case XED_ICLASS_JL:
    case XED_ICLASS_JNL:
    case XED_ICLASS_JLE:
    case XED_ICLASS_JNLE:
    case XED_ICLASS_JS:
    case XED_ICLASS_JNS:
    case XED_ICLASS_JP:
    case XED_ICLASS_JNP:
    case XED_ICLASS_RET_FAR:
    case XED_ICLASS_RET_NEAR:
    case XED_ICLASS_CALL_FAR:
    case XED_ICLASS_CALL_NEAR:
    case XED_ICLASS_LEAVE:
    case XED_ICLASS_SYSCALL:
    case XED_ICLASS_TEST:
        break;
    case XED_ICLASS_RCL:
    case XED_ICLASS_RCR:
    case XED_ICLASS_ROL:
    case XED_ICLASS_ROR:
    case XED_ICLASS_SHL:
    case XED_ICLASS_SAR:
    case XED_ICLASS_SHR:
    case XED_ICLASS_SHLD:
    case XED_ICLASS_SHRD:
        return true;
        break;
    case XED_ICLASS_NEG: // @TODO: handle these instructions
    case XED_ICLASS_NOT:
    case XED_ICLASS_NOP:
    case XED_ICLASS_BT:
    case XED_ICLASS_DEC:
    case XED_ICLASS_DEC_LOCK:
    case XED_ICLASS_INC:
    case XED_ICLASS_INC_LOCK:
    case XED_ICLASS_XSAVEC:
    case XED_ICLASS_XRSTOR:
        break;

    default:
        // https://intelxed.github.io/ref-manual/xed-extension-enum_8h.html#ae7b9f64cdf123c5fda22bd10d5db9916
        // INT32 num_op = INS_OperandCount(ins, node);
        // INT32 ins_ext = INS_Extension(ins, node);
        // if (ins_ext != 0 && ins_ext != 10)
        LOGD("[uninstrumented] opcode=%d, %s\n", ins_indx,
            INS_Disassemble(ins, node).c_str());
        break;
    }

    return false;
}

bool isCMP(INS ins) {
    switch(INS_Opcode(ins)) {
    case XED_ICLASS_CMP:
    case XED_ICLASS_CMPSB:
    case XED_ICLASS_CMPSW:
    case XED_ICLASS_CMPSD:
    case XED_ICLASS_CMPSQ:
    case XED_ICLASS_CMPSS: // FIXME, 3arg
    case XED_ICLASS_TEST:
        return true;
    default:
        return false;
    }   
}
