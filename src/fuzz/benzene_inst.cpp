#include "benzene_inst.h"

int BenzeneInst::parse(void* drcontext, instr_t* ins) {

    if (is_parsed_) /* parsing needs to be done only once */
        return BENZENE_SUCCESS;

    BenzeneOp* tmp_op;
    reg_id_t reg_cache = DR_REG_NULL;

    for (int i = 0; i < instr_num_srcs(ins); i++) {
        opnd_t op = instr_get_src(ins, i);
        tmp_op = nullptr;

        // 0x1e2f43 : mov    rbp,rsi
        if (opnd_is_reg(op))  {
            tmp_op = new BenzeneOp(op, offset_);
            /* if operand's read size is zero, there's no need to handle it */
            if(!tmp_op->read_size() || reg_cache == tmp_op->getReg() || tmp_op->getReg() == DR_REG_RSP) {
                delete tmp_op;
                continue;   
            }

            addSrcOp(tmp_op);
            reg_cache = tmp_op->getReg();
        }
        else if (opnd_is_memory_reference(op)) {
            if (instr_get_opcode(ins) == OP_lea) {
                // LEA instruction can bahave like transfer or binary operation
                // In DR, LEA's operands are treated as memory operands
                
                // issue : opnd_get_base() function returns a weird register. e.g., lea r13, [rip+0x73ceb5] -> zmm3 register
                reg_id_t base_reg = opnd_get_reg_used(op, 0);
                reg_id_t index_reg = opnd_get_reg_used(op, 1);

                if (base_reg != DR_REG_NULL) {
                    tmp_op = new BenzeneOp(opnd_create_reg(base_reg), offset_);
                    addSrcOp(tmp_op);

                    if (index_reg != DR_REG_NULL && index_reg != base_reg) {
                        tmp_op = new BenzeneOp(opnd_create_reg(index_reg), offset_);
                        addSrcOp(tmp_op);
                    }
                }
            }
            else {
                // it's a memory read operand
                tmp_op = new BenzeneOp(op, offset_);
                addSrcOp(tmp_op);
            }
        }
        else {
            continue;
        }
    }

    // if an instruction has no operand to trace, then instrumentation on that instruction is skipped.
    // However we have to count the instruction hit for crash triage.
    // Therefore, we add dummy `BenzeneOp` if triage instruction has nothing.
    if (option.triage_offset == getOffset() && getSrcOpsSize() == 0) {
        opnd_t dummy = {0, };
        tmp_op = new BenzeneOp(dummy, offset_);
        addSrcOp(tmp_op); // add `BenzeneOp` just for hit count check
    }

    // instr_disassemble_to_buffer(drcontext, ins, disasm_, sizeof(disasm_));
    is_parsed_ = true;

    return BENZENE_SUCCESS;
}

int BenzeneInst::parse() {
    void* drcontext = dr_get_current_drcontext();
    instr_t ins;

    instr_init(drcontext, &ins);
    DR_ASSERT(decode(drcontext, addr_, &ins));
    parse(drcontext, &ins);
    instr_free(drcontext, &ins);

    return BENZENE_SUCCESS;
}

int BenzeneInst::instrument(void* drcontext, instrlist_t* bb, instr_t* ins) {
    BenzeneOp* benz_op;

    for (size_t i = 0; i < SRC_OPS_SIZE(); i++) {
        benz_op = getSrcOp(i);

        if (benz_op->isRegOp()) {
            reg_id_t r;

            // extend src operand register (e.g., eax -> rax)
            if (benz_op->read_size() < 8) 
                r = reg_resize_to_opsz(benz_op->getReg(), OPSZ_8);
            else
                r = benz_op->getReg();

            /* 
             * @TODO #1: optimize register read instrumentation
             * @TODO #2: check usage of dr_clena_call_ex() with flags argument DR_CLEANCALL_READS_APP_CONTEXT
             *           refer: https://dynamorio.org/dr__ir__utils_8h.html#a175c7c2531aa70017d2fb020f93e374f 
             */
            dr_insert_clean_call(drcontext, bb, ins, (void*)BenzeneOp::processRegRead, false, 3, 
                                OPND_CREATE_INT32(r),
                                OPND_CREATE_INT32(benz_op->read_size()),
                                OPND_CREATE_INTPTR(benz_op)
                                );
        }
        else if (benz_op->isMemOp()) {
            reg_id_t reg_mem_ref, reg_tmp;

            if (drreg_reserve_register(drcontext, bb, ins, NULL, &reg_mem_ref) != DRREG_SUCCESS 
                || drreg_reserve_register(drcontext, bb, ins, NULL, &reg_tmp) != DRREG_SUCCESS)
            {
                DR_ASSERT(false);
            }


            // get memory reference value
            DR_ASSERT(drutil_insert_get_mem_addr(drcontext, bb, ins, 
                                        benz_op->getDrOpnd(), reg_mem_ref, reg_tmp));
            

            dr_insert_clean_call(drcontext, bb, ins, (void*)BenzeneOp::processMemRead, false, 3, 
                                opnd_create_reg(reg_mem_ref), 
                                OPND_CREATE_INT32(benz_op->read_size()),
                                OPND_CREATE_INTPTR(benz_op)
                                );

            if (drreg_unreserve_register(drcontext, bb, ins, reg_tmp) != DRREG_SUCCESS ||
                drreg_unreserve_register(drcontext, bb, ins, reg_mem_ref) != DRREG_SUCCESS ) {
                DR_ASSERT(false);
                }
        }
        else {
            // no operand (reg or mem) to monitor. just increase hit count
            dr_insert_clean_call(drcontext, bb, ins, (void*)BenzeneOp::processDummyOp, false, 1, 
                                OPND_CREATE_INTPTR(benz_op)
                                );
        }
    }
    
    // instrlist_disassemble(drcontext, 0, bb, STDERR);
    // dr_fprintf(STDERR, "\n");

    return BENZENE_SUCCESS;
}


json_val_t BenzeneInst::toJSON(rapidjson_allocator_t allocator) {
    BenzeneOp* op;
    json_val_t obj(kObjectType);
    json_val_t val(kNullType);

    obj.AddMember("offset", val.SetUint(offset_), allocator);
    obj.AddMember("img_name", val.SetString(img_name_, strlen(img_name_)), allocator);
    obj.AddMember("addr", val.SetUint64((uint64_t)addr_), allocator);
    obj.AddMember("parsed", val.SetBool(is_parsed_), allocator);

    val.SetArray();    

    // append information of existing operands 
    for (size_t i = 0; i < SRC_OPS_SIZE(); i++) {
        op = SRC_OP_AT(i);
        val.PushBack(op->toJSON(allocator), allocator);
    }

    obj.AddMember("ops", val.GetArray(), allocator);
    
    return obj;
}

void BenzeneInst::fromJSON(json_val_t inst_json) {
    BenzeneOp* op;

    SANITIZE_CONFIG(inst_json, "offset");
    SANITIZE_CONFIG(inst_json, "img_name");
    SANITIZE_CONFIG(inst_json, "addr");
    SANITIZE_CONFIG(inst_json, "parsed");
    SANITIZE_CONFIG(inst_json, "ops");

    offset_ = inst_json["offset"].GetUint();
    strncpy(img_name_, inst_json["img_name"].GetString(), MAX_MODULE_NAME_LEN);
    addr_   = (app_pc)inst_json["addr"].GetUint64();
    is_parsed_ = inst_json["parsed"].GetBool();

    json_val_t ops_json = inst_json["ops"].GetArray();

    for (size_t i = 0; i < ops_json.Size(); i++) {
        op = new BenzeneOp(ops_json[i].GetObject());
        addSrcOp(op);
    }

    return;
}
