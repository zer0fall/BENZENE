#include "benzene_fuzz.h"
#include "benzene_shared.h"
#include "dr_defines.h"
#include "sqlite3.h"
#include <fstream>
#include <string>
#include <fcntl.h>

extern uint32_t mem_violation_offset;
extern dict_values_t* g_dict_arr;

app_pc      fuzz_addr = (app_pc)0xffffffffffffffff;
uint32_t       dryrun_corpus_id;
sqlite3_stmt * v_insert_stmt;
sqlite3_stmt * v_insert_seed_stmt;
benzene_proc_t* proc;
benzene_opt_t option;

// for edge coverage measurement
uint32_t prev_offset = 0x0;
unsigned char cov_map[EDGE_COV_MAP_SIZE] = {0, };
bool      collect_cov = true;

// dynamorio file-system write helper
int writeToFile(const char* path, const char* buf, size_t sz) {
    file_t f = dr_open_file(path, DR_FILE_WRITE_OVERWRITE  | DR_FILE_ALLOW_LARGE);

    if (f == INVALID_FILE) {
        dr_fprintf(STDERR, "Error: file open failed. (\"%s\")\n", path);
        return BENZENE_ERROR;
    }

    DR_ASSERT(dr_write_file(f, buf, sz) == sz);
    dr_close_file(f);

    return BENZENE_SUCCESS;
}

/**
 *  @brief initialize information for each mutation target
 */
int BenzeneFuzz::initMutationTargets() {
    BenzeneInst* mt_inst;
    BenzeneOp* mt_op;
    app_pc mt_addr;
    uint32_t mt_offset;
    BenzeneInst* dict_inst;
    BenzeneOp* dict_op;
    app_pc dict_addr;
    uint32_t dict_offset;
    instr_t instr;

    void* drcontext = dr_get_current_drcontext();
    instr_init(drcontext, &instr);


    /*
     * Before start, we setup `value dictionary` of each mutation target
     * For performance and synchronization, we leverage shared memory for dictionary management.
     */ 
    g_dict_arr = (dict_values_t*)benzene_shm_malloc(sizeof(dict_values_t) * config_["mutation_targets"].Size());
    memset(g_dict_arr, 0, sizeof(dict_values_t) * config_["mutation_targets"].Size());
    dict_values_t* cur_dict_vals_ptr = g_dict_arr;

    for (size_t i = 0; i < config_["mutation_targets"].Size(); i++) {
        // mt: mutation target
        auto mt_obj = config_["mutation_targets"][i].GetObject();

        // first checks validity
        SANITIZE_CONFIG(mt_obj, "op_name");
        SANITIZE_CONFIG(mt_obj, "addr");
        SANITIZE_CONFIG(mt_obj, "img_name");
        SANITIZE_CONFIG(mt_obj, "dict_offset");
        SANITIZE_CONFIG(mt_obj, "dict_img_name");
        SANITIZE_CONFIG(mt_obj, "dict_op_name");
        SANITIZE_CONFIG(mt_obj, "dictionary");

        uint32_t mt_offset = mt_obj["offset"].GetUint();
        dict_offset = mt_obj["dict_offset"].GetUint();

        const char* mt_op_name = mt_obj["op_name"].GetString();
        const char* mt_img_name = mt_obj["img_name"].GetString();
        const char* dict_op_name = mt_obj["dict_op_name"].GetString();
        const char* dict_img_name = mt_obj["dict_img_name"].GetString();

        app_pc target_module_base = modules_->getModuleBase(mt_img_name);
        app_pc dict_module_base = modules_->getModuleBase(dict_img_name);


        DR_ASSERT_MSG(target_module_base, "mutation target's module not found");
        DR_ASSERT_MSG(dict_module_base, "dict's module not found");

        mt_addr = DR_APP_PC_ADD(target_module_base, mt_offset);
        dict_offset = mt_obj["dict_offset"].GetUint();
        dict_addr = DR_APP_PC_ADD(dict_module_base, dict_offset);


        // check if mutation target already exists in insts_
        auto iter = insts_.find(mt_addr);
        if (iter == insts_.end()) {
            if (!checkMode(option, BENZENE_MODE_DRYRUN)) {
                dr_fprintf(STDERR, "it's not a dryrun mode, but inst not found (addr: 0x%lx)\n", mt_addr);
                DR_ASSERT(false);
            }
            // doesn't exist, create a new one and add it.
            mt_inst = createInst(drcontext, mt_addr, mt_offset, mt_img_name);
        }
        else {
            mt_inst = iter->second;
        }

        if (!mt_inst) {
            dr_fprintf(STDERR, "invalid `mt_inst`: 0x%lx (%s)\n", mt_inst->getOffset(), mt_op_name);            
            DR_ASSERT(mt_inst != NULL);
        }

        mt_op = mt_inst->getSrcOp(mt_op_name);
        if (!mt_op) {
            dr_fprintf(STDERR, "invalid `mt_op`: 0x%lx (%s)\n", mt_inst->getOffset(), mt_op_name);
            DR_ASSERT(mt_op != NULL);
        }
        appendMutationTarget(mt_op); // For fuzzing, append the mutation targets in benzene_inst if any of them exist in `target_inst`.


        /*****************************************
            update mutation dict information
        ******************************************/
        if (mt_inst->getSrcOpsSize() == 0) {
            // Note that registers such as rsp are excluded from mutation target
            dr_fprintf(STDERR, 
                    "[WARN] mutation target 0x%lx has no operand (original op : %s).\n", 
                    mt_inst->getOffset(), mt_op_name);
            continue;
        }

        for(size_t i = 0; i < mt_inst->getSrcOpsSize(); i++) {
            // first get BenzeneOp for the corresponding operand (e.g., rax, ecx, ...)
            mt_op = mt_inst->getSrcOp(i);
            DR_ASSERT_MSG(mt_op, "mt_op is nullptr");

            // ensure that its a valid BenzeneOp
            if (strncmp(mt_op->getOpName(), mt_op_name, strlen(mt_op_name))) {
                mt_op = nullptr;
                continue;
            }

            // set mutation dict offset for the given BenzeneOp `mt_op`
            mt_op->setMutationTarget();
            mt_op->setDictOffset(dict_offset);

            // check if mutation dict instruction is in `insts_`. if not, add it.
            auto iter = insts_.find(dict_addr);
            if (iter == insts_.end()) { // it wasn't found
                dict_inst = createInst(drcontext, dict_addr, dict_offset, dict_img_name);

                DR_ASSERT_MSG(insts_[dict_addr], "dict not found in insts_");

                // assure there exists only one source operand in dict_inst
                if (dict_inst->getSrcOpsSize() != 1) {
                    dr_fprintf(STDERR, "Error: dict(0x%lx) has invalid source operand count (SrcOpsSize: %d, seed: 0x%x)\n",
                                dict_inst->getOffset(), dict_inst->getSrcOpsSize(), mt_inst->getOffset());
                    // instr_disassemble(drcontext, ins, STDERR);
                    DR_ASSERT(false);
                }

                instr_reset(drcontext, &instr);
            }
            else {
                dict_inst = iter->second;
                DR_ASSERT(dict_inst);
            }

            for (size_t op_idx = 0; op_idx < dict_inst->getSrcOpsSize(); op_idx++) {
                dict_op = dict_inst->getSrcOp(op_idx);
                if (!strncmp(dict_op->getOpName(), dict_op_name, strlen(dict_op_name)))
                    break; // match found, break the loop
                dict_op = nullptr;
            }

            if (!dict_op) { // desirable operand not found
                dr_fprintf(STDERR, "dict instruction 0x%lx has no operands \"%s\"\n", dict_inst->getOffset(), dict_op_name);
                DR_ASSERT(false);
            }

            // to trace the value that appeared in `dict_op`
            dict_op->setDictOp();
            
            // set flags of the dict instruction.
            if (!dict_op->isHitAfterFuzz()) {                
                // do not dump it
                dict_op->disableDump();
            }

            mt_op->setMutationDictOp(dict_op);
            
            break;
        }

        // Now we read dictionary values from config json
        // Note that these values are obtained from the previous dryrun
        uint64_t dict_val;
        if (checkMode(option, BENZENE_MODE_FUZZ)) {
            auto dict_values_arr = mt_obj["dictionary"].GetArray();
            mt_op->initDictValuesShm(cur_dict_vals_ptr++);

            for (size_t j = 0; j < dict_values_arr.Size(); j++) {
                dict_val = dict_values_arr[j].GetUint64();
                mt_op->pushDictValue(dict_val);
            }
        }

        mt_op = nullptr;
    }

    instr_free(drcontext, &instr);
    return BENZENE_SUCCESS;
}

/* If current crash is a false crash, returns false. */
bool BenzeneFuzz::isTriageHit() {
    DR_ASSERT(option.triage_offset);
    // dr_fprintf(STDERR, "crash at 0x%lx\n", crash_addr);
    auto r = insts_.find(option.triage_addr);

    if (r == insts_.end()) {
        dr_fprintf(STDERR, "Error: triage instruction not found (0x%lx, 0x%lx)\n", 
                                                        option.triage_addr, option.triage_offset);
        return false;
    }

    BenzeneInst* triage_inst = r->second;

    if (triage_inst->getHitCnt()) {
        return true;
    }
 
    return false;
}

void BenzeneFuzz::adjustCovStatus() {
    if (triage_inst_ == nullptr) {
        triage_inst_ = getInst(option.triage_addr);

        if (triage_inst_ == nullptr)
            return;
    }
    
    /*
     *  To mitigate coverage bias between crashes and non-crashes, 
     *  restrict the coverage measurement from stepping further beyond the crashing site.
     */
    if (triage_inst_->getHitCnt() == option.hitcnt_for_triage) {
        // disable measurement of edge coverage
        collect_cov = false;
    }
}


/**
 *  @brief send mutation history (i.e., what, when and how it was mutated) and fuzzing result (i.e., crash or non-crash) to fuzz managing server
 */
void BenzeneFuzz::sendFuzzedMutationTarget() {
    mt_pick_t data_for_send = { 0, };
    BenzeneOp* mut_target;
    uint32_t op_idx;

    /* get instruction hit data */
    for (int i = 0; i < mt_picks.cnt; i++) {
        op_idx = mt_picks.picks[i];
        mut_target = MUTATION_TARGET_AT(op_idx);
        DR_ASSERT(mut_target);
        if (mut_target->isPickedForFuzz()) {
            if (!mut_target->isFuzzed()) {
                dr_fprintf(STDERR, "id %d: mutation target 0x%lx (%s) was picked, but not fuzzed (hit: %d)\n", 
                        getCorpusId(), mut_target->getOffset(), mut_target->getOpName(), mut_target->getHitCnt());
                DR_ASSERT(false);
            }
            data_for_send.picks[data_for_send.cnt++] = op_idx;
        }
    }

    if (!data_for_send.cnt) {
        setStatus(proc,  PROC_STATUS_ERROR);
        dr_fprintf(STDERR, "error, no mutation target are fuzzed\n");
        dr_exit_process(-1);
    }

    /* send data to server */
    if (sendDataToServer(proc, (const char*)&data_for_send, sizeof(mt_pick_t)) < 0) {
        perror("sending feedback data failed");
    }
    return;
}

void BenzeneFuzz::pickMutationTargets() {
    proc_cmd_pkt_t cmd;
    BenzeneOp* picked_op;
    /* receive fuzz target operand picks from the server */
    if (recvDataFromServer(proc, (char*)&cmd, sizeof(proc_cmd_pkt_t)) <= 0) {
        dr_fprintf(STDERR, "BenzeneFuzz: failed to receive seeds to mutate.\n");
        setStatus(proc,  PROC_STATUS_ERROR);
        dr_exit_process(-1);
    };

    if (cmd.cmd != PROC_CMD_PICK_SEED) {
        dr_fprintf(STDERR, "pickMutationTargets(): wrong command received\n");
        setStatus(proc,  PROC_STATUS_ERROR);
        dr_exit_process(-1);
    }

    /* copy received picked-operands to member variable */
    dr_safe_write(&mt_picks, sizeof(mt_pick_t), &cmd.data.mt_pick, NULL);

    /* do pick() for the received operands */
    for (int i = 0; i < mt_picks.cnt; i++) {
        if (mt_picks.picks[i] > MUTATION_TARGET_SIZE) {
            dr_fprintf(STDERR, 
                "fatal: received pick %d is out-of-range (MUTATION_TARGET_SIZE: %d)\n", mt_picks.picks[i], MUTATION_TARGET_SIZE);
            DR_ASSERT(false);
        }
        picked_op = MUTATION_TARGET_AT(mt_picks.picks[i]);
        DR_ASSERT_MSG(picked_op != nullptr, "given index not found in `mutation_targets_`");
        picked_op->pick();
    }
}

void BenzeneFuzz::setMutationForTrace() {
    proc_cmd_pkt_t cmd;

    /* receive fuzz target operand picks from the server */
    if (recvDataFromServer(proc, (char*)&cmd, sizeof(proc_cmd_pkt_t)) <= 0) {
        dr_fprintf(STDERR, "setMutationForTrace(): failed to receive seeds to mutate (runid: %d)\n", getCorpusId());
        setStatus(proc,  PROC_STATUS_ERROR);
        dr_exit_process(-1);
    }

    if (cmd.cmd != PROC_CMD_TRACE_SEED) {
        dr_fprintf(STDERR, "setMutationForTrace(): wrong command received (cmd : %d)\n", cmd.cmd);
        setStatus(proc,  PROC_STATUS_ERROR);
        dr_exit_process(-1);
    }

    /* set mutation history information */
    history_ = cmd.data.history;

    /* set mutation targets for trace */
    BenzeneOp* mt; // mutation target
    mutation_t* mutation;
    for (size_t i = 0; history_.mutations[i].offset != 0; i++) {
        mutation = (mutation_t*)dr_global_alloc(sizeof(mutation_t));
        *mutation = history_.mutations[i];
        
        for (size_t j = 0; j < MUTATION_TARGET_SIZE; j++) {
            mt = MUTATION_TARGET_AT(j);
            // dr_fprintf(STDERR, "seed : 0x%lx (%s)\n", seed->getOffset(), seed->getOpName());

            if (mt->getOffset() == mutation->offset) {
                if (!strncmp(mt->getOpName(), mutation->op_name, MAX_OP_NAME)) {
                    mt->pick();
                    mt->appendMutation(mutation);

                    // setReplay(mt, mutation);
                    break;
                }
            }
        }
    }
}


void BenzeneFuzz::fuzz() {
    int status;
    pid_t child_pid;
    proc_cmd_pkt_t cmd_pkt;

    // PROC_STATUS_EXECUTE means this program is already being fuzzed now. Do not initiate it again.
    if (getStatus(proc) == PROC_STATUS_EXECUTE) return;

    if (initProc(proc) < 0) {
        dr_fprintf(STDERR, "parent process setup failed\n");
        exit(-1);
    }

    /* write-protection for shared memory smashing during the fuzzing */
    if (!benzene_shm_set_readonly()) {
        dr_fprintf(STDERR, "fuzz(): benzene_shm_set_readonly() failed\n");
        exit(-1);
    }

    // parent and child process share the opened file pointer.
    // So, we need to keep it consistent.
    for (size_t i = 0; i < MAXIMUM_FD_CNT; i++) {
        if (opened_fds_[i].fd == INVALID_FD)
            break;
        // get current file position
        opened_fds_[i].tell = dr_file_tell(opened_fds_[i].fd);
    }   

    /* Do the fuzz */
    while (true) {
        cmd_pkt = { PROC_CMD_NONE, 0 };

        // receive command from BenzeneFuzzServer

        if (recvDataFromServer(proc, (char*)&cmd_pkt, sizeof(cmd_pkt)) <= 0) {
            dr_fprintf(STDERR, "fuzz(): command recv failed... abort\n");
            setStatus(proc,  PROC_STATUS_DONE); // get ready for the termination of process group
            dr_exit_process(-1);
        }

        if (cmd_pkt.cmd == PROC_CMD_EXIT) { /* exit command received */
            break;
        }

        if (cmd_pkt.cmd == PROC_CMD_RUN) {
            for (int j = 0; j < cmd_pkt.data.num_run; j++) {
                child_pid = spawnChild(proc);

                if (!proc->is_parent) { /* For child processes */
                    // make file position consistent
                    for (size_t i = 0; i < MAXIMUM_FD_CNT; i++) {
                        if (opened_fds_[i].fd == INVALID_FD)
                            break;
                        dr_file_seek(opened_fds_[i].fd, opened_fds_[i].tell, SEEK_SET);
                    }

                    pickMutationTargets();
                    return; /* release child process */
                }
            }
        }
    }
    
    dr_fprintf(STDERR, "[!] exit command received!\n");

    setStatus(proc,  PROC_STATUS_DONE);
    dr_exit_process(0);
}


void BenzeneFuzz::trace() {
    int status;
    pid_t child_pid;
    proc_cmd_pkt_t cmd_pkt;

    // PROC_STATUS_EXECUTE means this program is already being fuzzed now. Do not initiate it again.
    if (getStatus(proc) == PROC_STATUS_EXECUTE) return;

    if (initProc(proc) < 0) {
        dr_fprintf(STDERR, "trace(): master setup failed\n");
        exit(-1);
    }

    for (size_t i = 0; i < MAXIMUM_FD_CNT; i++) {
        if (opened_fds_[i].fd == INVALID_FD)
            break;
        // get current file position
        opened_fds_[i].tell = dr_file_tell(opened_fds_[i].fd);
    }

    /* Do the trace */
    while (true) {
        cmd_pkt = { PROC_CMD_NONE, 0 };

        // receive command from BenzeneFuzzServer

        if (recvDataFromServer(proc, (char*)&cmd_pkt, sizeof(cmd_pkt)) <= 0) {
            dr_fprintf(STDERR, "trace(): command recv failed... abort\n");
            
            setStatus(proc,  PROC_STATUS_DONE); // ready for process group termination
            
            dr_exit_process(-1);
        }

        if (cmd_pkt.cmd == PROC_CMD_EXIT) { /* exit command received */
            break;
        }

        if (cmd_pkt.cmd == PROC_CMD_RUN) {
            for (int j = 0; j < cmd_pkt.data.num_run; j++) {
                child_pid = spawnChild(proc);
                if (!proc->is_parent) { /* For child processes */
                    // make file position consistent
                    for (size_t i = 0; i < MAXIMUM_FD_CNT; i++) {
                        if (opened_fds_[i].fd == INVALID_FD)
                            break;
                        dr_file_seek(opened_fds_[i].fd, opened_fds_[i].tell, SEEK_SET);
                    }

                    setMutationForTrace();

                    return; /* release child process for runing */
                }
            }
        }
    }
    
    dr_fprintf(STDERR, "[!] exit command received!\n");

    /* wait until all child processes' termination */
    // while(true) {
    //     dr_fprintf(STDERR, "waiting\n");
    //     child_pid = waitpid(0, NULL, WNOHANG);

    //     if (child_pid == 0) /* none left */
    //         break;
    // }
    
    setStatus(proc,  PROC_STATUS_DONE);

    dr_exit_process(0);
}


void BenzeneFuzz::instrument_trace(void *drcontext, instrlist_t *bb, instr_t *inst, app_pc pc) {
    BenzeneInst* cur_inst;

    auto iter = insts_.find(pc);

    // all the target instructions under analysis have already been created during dry run.
    // Therefore, `insts_` should contain them.
    if (iter != insts_.end()) {
        cur_inst = iter->second;

        cur_inst->parse(drcontext, inst);
        cur_inst->instrument(drcontext, bb, inst);
    }
}

void BenzeneFuzz::instrument_fuzz(void *drcontext, instrlist_t *bb, instr_t *inst, app_pc pc) {
    BenzeneInst* cur_inst;

    auto iter = insts_.find(pc);

    if (iter != insts_.end()) {
        cur_inst = iter->second;
        cur_inst->instrument(drcontext, bb, inst);
    }
}

void BenzeneFuzz::instrument_dryrun_fuzz(void *drcontext, instrlist_t *bb, instr_t *inst, app_pc pc) {
    BenzeneInst* cur_inst;  

    auto iter = insts_.find(pc);

    // In the fuzz mode, `insts_` already contains all the instructions that requires instrumentation.
    if (iter != insts_.end()) {
        cur_inst = iter->second;
        cur_inst->instrument(drcontext, bb, inst);
    }
}

void BenzeneFuzz::instrument_dryrun_trace(void *drcontext, instrlist_t *bb, instr_t *inst, app_pc pc) {
    BenzeneInst* cur_inst;

    auto iter = insts_.insert({pc, nullptr});

    if (iter.second) {
        benzene_module_t* module = modules_->getModule(pc);
        /* All Instructions after fuzzing start are dump targets */
        cur_inst = new BenzeneInst(pc, (uint32_t)(pc - module->module_base), module->img_name);
        iter.first->second = cur_inst;

        cur_inst->parse(drcontext, inst);
    }
    else {
        /* 
         * [IMPORTANT NOTICE] 
         *  Note that instructions that already have been instrumented before can also invoke registered callback funcion 
         *  of drmgr_register_bb_instrumentation_event().
         *  So, `MAKE SURE` that instructions are intrumented "consistently" for every callback invocation.
         */
        cur_inst = iter.first->second;
    }

    cur_inst->instrument(drcontext, bb, inst);
}

void countEdge(uint32_t masked_offset) {
    if (collect_cov == false)
        return;
    cov_map[prev_offset ^ masked_offset]++;
    prev_offset = (masked_offset >> 1)&(EDGE_COV_MAP_SIZE - 1);
    return;
}

// edge coverage of AFL
void BenzeneFuzz::instrument_edge_coverage(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst) {
    app_pc start_pc;
    uint offset;

    if (!drmgr_is_first_instr(drcontext, inst))
        return;

    start_pc = dr_fragment_app_pc(tag);

    app_pc module_base = modules_->getModuleBase(start_pc);

    if (!module_base)
        return;

    offset = (uint)(start_pc - module_base);
    offset &= EDGE_COV_MAP_SIZE - 1;

    dr_insert_clean_call(drcontext, bb, inst, (void*)countEdge, false, 1, OPND_CREATE_INT32(offset));
/*
    reg_id_t reg, reg2, reg3;
    opnd_t opnd1, opnd2;
    instr_t *new_instr;
    instr_t* skip_label;

    // create label for skip
    skip_label = INSTR_CREATE_label(drcontext);

    drreg_reserve_aflags(drcontext, bb, inst);
    drreg_reserve_register(drcontext, bb, inst, NULL, &reg);
    drreg_reserve_register(drcontext, bb, inst, NULL, &reg2);
    drreg_reserve_register(drcontext, bb, inst, NULL, &reg3);

    // load &go to reg
    opnd1 = opnd_create_reg(reg);
    opnd2 = OPND_CREATE_INTPTR(&collect_cov_);
    new_instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);    
    instrlist_meta_preinsert(bb, inst, new_instr);
    
    opnd1 = opnd_create_reg(reg);
    opnd2 = OPND_CREATE_MEMPTR(reg, 0);
    new_instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);

    // TEST reg, reg
    opnd1 = opnd_create_reg(reg);
    new_instr = INSTR_CREATE_test(drcontext, opnd1, opnd1);
    instrlist_meta_preinsert(bb, inst, new_instr);

    // jz skip_label
    opnd1 = opnd_create_instr(skip_label);
    instrlist_meta_preinsert(bb, inst, INSTR_CREATE_jcc(drcontext, OP_jz, opnd1));

    //reg2 stores AFL area, reg 3 stores previous offset

    //load the pointer to previous offset in reg3
    drmgr_insert_read_tls_field(drcontext, tls_slot_, bb, inst, reg3);

    //load address of shm into reg2
    opnd1 = opnd_create_reg(reg2);
    opnd2 = OPND_CREATE_INTPTR(cov_map_);
    new_instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);


    //load previous offset into register
    opnd1 = opnd_create_reg(reg);
    opnd2 = OPND_CREATE_MEMPTR(reg3, 0);
    new_instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);

    //xor register with the new offset
    opnd1 = opnd_create_reg(reg);
    opnd2 = OPND_CREATE_INT32(offset);
    new_instr = INSTR_CREATE_xor(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);

    //increase the counter at reg + reg2
    opnd1 = opnd_create_base_disp(reg2, reg, 1, 0, OPSZ_1);
    new_instr = INSTR_CREATE_inc(drcontext, opnd1);
    instrlist_meta_preinsert(bb, inst, new_instr);

    //store the new value
    offset = (offset >> 1)&(EDGE_COV_MAP_SIZE - 1);

    opnd1 = OPND_CREATE_MEMPTR(reg3, 0);
    opnd2 = OPND_CREATE_INT32(offset);
    new_instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);

    // insert skip label here
    instrlist_meta_preinsert(bb, inst, skip_label);

    drreg_unreserve_register(drcontext, bb, inst, reg3);
    drreg_unreserve_register(drcontext, bb, inst, reg2);
    drreg_unreserve_register(drcontext, bb, inst, reg);
    drreg_unreserve_aflags(drcontext, bb, inst);
*/
    return;
}


void BenzeneFuzz::onProcessExit() {
    if (checkMode(option, BENZENE_MODE_DRYRUN)) {
        exitDryrun(getCorpusId());
        return;
    }

    if (!proc->is_parent) {
        // child process
        if (getStatus(proc) == PROC_STATUS_EXECUTE) {  
            // non-crashes should enter here              
            setStatus(proc,  PROC_STATUS_NON_CRASH);        
        }

        saveFuzzResult();
    }
    else {
        DR_ASSERT(getStatus(proc) == PROC_STATUS_DONE);
    }

    DR_ASSERT_MSG(notifyStatus(proc) == 0, "notifyStatus failed");

    if (checkMode(option, BENZENE_MODE_FUZZ)) {
        if (!proc->is_parent) {
            sendFuzzedMutationTarget();
        }
        else {
            // clear the occupied shared memory
            removeShm();
        }
    }
    exitProc(proc);
}


void BenzeneFuzz::handleCrash(app_pc crash_addr) {
    // check crash location
    if (dr_memory_is_dr_internal(crash_addr)) {
        dr_fprintf(STDERR, "Error: Segmentation fault in bfuzz 0x%lx (corpus: %d)\n", crash_addr, getCorpusId());
        return;
    }

    if (checkMode(option, BENZENE_MODE_DRYRUN)) {
        module_data_t* module_data;

        setStatus(proc, PROC_STATUS_CRASH);
        option.initial_crash_addr = crash_addr;
        // get the module where crash happened
        module_data = dr_lookup_module(crash_addr);

        // check if crash instruction's location is addressable (valid).
        // If not, use absolute value of crash addr instead of crash offset.        
        if (!module_data) {
            option.initial_crash_offset = 0;

            dr_fprintf(STDERR, "[BENZENE] crash image : None\n");
            dr_fprintf(STDERR, "[BENZENE] crash address : 0x%lx\n", crash_addr);
            dr_fprintf(STDERR, "[BENZENE] crash offset : None\n");
            // dr_fprintf(STDERR, "[BENZENE] access address : 0x%lx\n", siginfo->access_address);
        }
        else {
            option.initial_crash_offset = (uint32_t)(crash_addr - module_data->start);
            strncpy(option.crash_img_name, module_data->names.file_name, sizeof(option.crash_img_name));

            dr_fprintf(STDERR, "[BENZENE] crash image : %s\n", module_data->names.file_name);
            dr_fprintf(STDERR, "[BENZENE] crash address : 0x%lx\n", crash_addr);
            dr_fprintf(STDERR, "[BENZENE] crash offset : 0x%lx\n", option.initial_crash_offset);
            // dr_fprintf(STDERR, "[BENZENE] access address : 0x%lx\n", siginfo->access_address);

            dr_free_module_data(module_data);
        }
    }
    else if (checkMode(option, BENZENE_MODE_FUZZ | BENZENE_MODE_TRACE)) {
        checkFalseCrash(crash_addr);
    }        
    else {
        DR_ASSERT_MSG(false, "invalid mode");
    }


}


void BenzeneFuzz::onSignal(void *drcontext, dr_siginfo_t *siginfo) {
    app_pc crash_addr;

    switch(siginfo->sig) {
    case SIGILL:
    case SIGABRT:
        // @TODO: If a segmentation fault occurs where BenzeneInst::processMemRead() is instrumented, 
        //        siginfo->mcontext contains a wrong pc value (it has 0x0).
        if (!siginfo->mcontext->pc && mem_violation_offset) {
            DR_ASSERT(false);
            // crash_addr = DR_APP_PC_ADD(getFuzzModuleStart(), mem_violation_offset);
        }
        else {
            crash_addr = siginfo->mcontext->pc;
        }
        handleCrash(crash_addr);
        break;
    case SIGBUS: 
        /* 
         * Since Benzene synthesize predicates in "r > a" format, signal SIGBUS cases cause some noise of predicate synthesis.
         * Therefore, we discard such cases.
         */
        setStatus(proc, PROC_STATUS_FALSE_CRASH);
        dr_exit_process(0);
        break;
    case SIGFPE:
        setStatus(proc, PROC_STATUS_FALSE_CRASH);
        dr_exit_process(0);
        break;
    case SIGSEGV:
        // @TODO: If a segmentation fault occurs where BenzeneInst::processMemRead() is instrumented, 
        //        siginfo->mcontext contains a wrong pc value (it has 0x0).
        if (!siginfo->mcontext->pc && mem_violation_offset) {
            DR_ASSERT(false);
            // crash_addr = DR_APP_PC_ADD(getFuzzModuleStart(), mem_violation_offset);
        }
        else {
            crash_addr = siginfo->mcontext->pc;
        }

        // check crash location
        if (dr_memory_is_dr_internal(crash_addr)) {
            dr_fprintf(STDERR, "Error: segmentation fault in bfuzz 0x%lx (corpus: %d)\n", crash_addr, getCorpusId());
            setStatus(proc, PROC_STATUS_FALSE_CRASH);
            dr_exit_process(0);
            return;
        }
        handleCrash(crash_addr);
        dr_exit_process(0);
        break;
    case SIGTERM: 
        benzene_sem_quit(SEM_NUM_SHM); /* release the semaphore its using */
        
        if (!option.pass_hang)
            setStatus(proc, PROC_STATUS_HANG);
        else
            setStatus(proc, PROC_STATUS_NON_CRASH);
        
        dr_exit_process(0);
        break;
    case SIGSTOP:
        setStatus(proc, PROC_STATUS_HANG);
        dr_exit_process(0);
        break;
    default:
        fprintf(stderr, "signal! : %d (master : %d, pid : %d)\n", siginfo->sig, proc->is_parent, dr_get_process_id());
    }
}

int BenzeneFuzz::requestDBSlot() {
    proc_cmd_pkt_t cmd_pkt;
    
    if (recvDataFromServer(proc, (char*)&cmd_pkt, sizeof(cmd_pkt)) <= 0) {
        setStatus(proc,  PROC_STATUS_ERROR);
        dr_fprintf(STDERR, "requestDBSlot(): DB slot receive from the server failed (corpus_id: %d)\n", getCorpusId());
        DR_ASSERT(false);
    }
    
    if (cmd_pkt.cmd != PROC_CMD_ASSIGN_SLOT) {
        setStatus(proc,  PROC_STATUS_ERROR);
        DR_ASSERT_MSG(false, "requestDBSlot(): wrong command received");
    }

    return cmd_pkt.data.db_num;
}

int BenzeneFuzz::saveFuzzResult() {
    char path_buf[MAXIMUM_PATH];
    int slot;
    
    // decide whether to execute dumping process or not
    if (getStatus(proc) == PROC_STATUS_FALSE_CRASH
        || getStatus(proc) == PROC_STATUS_HANG)
        return BENZENE_ERROR;

    // request a DB slot
    if (notifyStatus(proc, PROC_STATUS_DUMP) < 0) {
        dr_fprintf(STDERR, "saveFuzzResult(): notifyStatus failed (id: %d)\n", proc->run_id);
        DR_ASSERT(false);
    }
    slot = requestDBSlot();

    if (!checkMode(option, BENZENE_MODE_FUZZ) && !checkMode(option, BENZENE_MODE_TRACE)) {
        dr_fprintf(STDERR, "saveFuzzResult(): invalid mode");
        return BENZENE_ERROR;
    }    
    
    if (checkMode(option, BENZENE_MODE_FUZZ)){
        saveMutationResult(proc->run_id);
        dr_snprintf(path_buf, sizeof(path_buf), "%s/cov/cov.0x%04x.bin", option.output_dir, proc->run_id);
        DR_ASSERT_MSG(saveEdgeCoverage(path_buf) == 0, "BenzeneFuzz::saveEdgeCoverage() failed");
    }
    else if (checkMode(option, BENZENE_MODE_TRACE)) {

        dr_snprintf(path_buf, sizeof(path_buf), "%s/trace/trace.%d.db", option.output_dir, slot);
        /* pre-defined corpus's crash info and it's trace result should match */
        if ( (getStatus(proc) == PROC_STATUS_CRASH && history_.crash)
            || (getStatus(proc) == PROC_STATUS_NON_CRASH && !history_.crash)) {

            dumpTrace(path_buf, history_.corpus_id);
            // saveMutationResult(db_name, proc->run_id);
        }
        else {
            dr_fprintf(STDERR, "Error: corpus-id %d execution result mismatch (`fuzz: %s != trace: %s`)\n", 
                    getCorpusId(),
                    history_.crash ? "crash" : "non-crash",
                    getStatus(proc) == PROC_STATUS_CRASH ? "crash" : "non-crash");
            
            notifyStatus(proc, PROC_STATUS_CRASH_MISMATCH);
        }
    }
    else {
        DR_ASSERT_MSG(false, "invalid mode");
    }
    
    return BENZENE_SUCCESS;
}

int BenzeneFuzz::dumpCorpus(const char* db_name, int corpus_id) {
    sqlite3* db;
    char sql_buf[128];
    char* err_msg;

    if (sqlite3_open_v2(db_name, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
        dr_fprintf(STDERR, "%s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return BENZENE_ERROR;
    }       

    dr_snprintf(sql_buf, sizeof(sql_buf), "INSERT INTO Corpus VALUES (NULL, %d, %d, %d)", 
                    corpus_id,
                    getStatus(proc) == PROC_STATUS_CRASH ? 1 : 0,
                    isTriageHit() ? 1 : 0
                );
    
    if (sqlite3_exec(db, sql_buf, 0, 0, &err_msg) != SQLITE_OK) {
        dr_fprintf(STDERR, "sqlite3_exec(): %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return BENZENE_ERROR;
    }


    sqlite3_close(db);

    return BENZENE_SUCCESS;
}


/* Dump trace result of the current run using SQLite3 */
int BenzeneFuzz::dumpTrace(const char* db_name, int corpus_id) {
    BenzeneInst* inst;
    src_ops_t* ops;
    sqlite3* db;
    int r;
    char* err_msg;
    module_data_t* main_module = dr_get_main_module();

    if (sqlite3_open_v2(db_name, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
        dr_fprintf(STDERR, "dumpTrace(): %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        DR_ASSERT(false);
    }       

    if (sqlite3_prepare_v2(db, "INSERT INTO 'Traces' VALUES (?, ?, ?, ?, ?);", -1, &v_insert_stmt, 0) != SQLITE_OK) {
        dr_fprintf(STDERR, "sqlite3_prepare_v2(): %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        DR_ASSERT(false);
    }

    sqlite3_exec(db, "PRAGMA cache_size=100000", 0, 0, &err_msg);
    if (sqlite3_exec(db, "BEGIN TRANSACTION", 0, 0, &err_msg) != SQLITE_OK) {
        dr_fprintf(STDERR, "sqlite3_exec(): %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return BENZENE_ERROR;
    }

    // dump collected traces
    for (const auto& iter : insts_) {
        inst = iter.second;

        // dump register's traces
        trace_val_t value;

        for (size_t i = 0; i < inst->getSrcOpsSize(); i++) {
            BenzeneOp* op = inst->getSrcOp(i);
            if (!op->dump_flag()) {
                continue;
            }

            size_t trace_cnt = op->getTraceCount();

            if (trace_cnt == 0) continue;
            if (trace_cnt < UNIQUE_TRACE_THRESHOLD) {
                trace_entry_t* trace_ent = op->getLastEntry();

                for (trace_ent; trace_ent != nullptr; trace_ent = trace_ent->next) {
                    value = trace_ent->val;
                    store(corpus_id, inst->getImgName(), inst->getOffset(), op->getOpName(), &value);
                }
            }
            else { // For the performance, only consider max & min values
                trace_val_t max = 0;
                trace_val_t min = 0;

                bool is_first = true;

                trace_entry_t* trace_ent = op->getLastEntry();

                for (trace_ent; trace_ent != nullptr; trace_ent = trace_ent->next) {
                    value = trace_ent->val;
                    if (is_first) {
                        max = value;
                        min = value;
                        is_first = false;
                    }
                    else {
                        if (value > max) max = value;
                        else if (value < min) min = value;
                    }                    
                }

                store(corpus_id, inst->getImgName(), inst->getOffset(), op->getOpName(), &max);
                store(corpus_id, inst->getImgName(), inst->getOffset(), op->getOpName(), &min);
            }
        }
    }

    if (sqlite3_exec(db, "END TRANSACTION", 0, 0, &err_msg) != SQLITE_OK) {
        dr_fprintf(STDERR, "sqlite3_exec(): %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return BENZENE_ERROR;
    }

    sqlite3_close(db);
    
    dr_free_module_data(main_module);
    return BENZENE_SUCCESS;
}

int BenzeneFuzz::saveMutationResult(int corpus_id) {    
    BenzeneOp* mt_op;
    Document d; // json to store mutation information
    rapidjson_allocator_t allocator = d.GetAllocator();
    json_val_t val(kNullType);

    d.SetObject();

    d.AddMember("corpus_id", val.SetUint(corpus_id), allocator);
    d.AddMember("crash", val.SetUint(getStatus(proc) == PROC_STATUS_CRASH ? 1 : 0), allocator);
    d.AddMember("triage_hit", val.SetUint(isTriageHit() ? 1 : 0), allocator);
    
    val.SetArray();
    json_val_t mut_history(kNullType); // information of what is mutated and when it happened
    json_val_t tmp(kNullType);
    for (int i = 0; i < mt_picks.cnt; i++) {
        mt_op = MUTATION_TARGET_AT(mt_picks.picks[i]);
        for (int j = 0; j < mt_op->getMutationCnt(); j++) {
            mt_op = MUTATION_TARGET_AT(mt_picks.picks[i]);
            mutation_t* mut = mt_op->getMutation(j);

            mut_history.SetObject();
            
            mut_history.AddMember("offset", tmp.SetUint(mt_op->getOffset()), allocator);
            mut_history.AddMember("op_name", tmp.SetString(mt_op->getOpName(), strlen(mt_op->getOpName())), allocator);
            mut_history.AddMember("hit_cnt", tmp.SetUint(mut->hit_cnt), allocator);
            mut_history.AddMember("from", tmp.SetUint64(mut->from), allocator);
            mut_history.AddMember("to", tmp.SetUint64(mut->to), allocator);
            mut_history.AddMember("mut_type", tmp.SetUint(mut->type), allocator);

            val.PushBack(mut_history, allocator);
        }
    }
    
    // assure that at least one mutation has been performed during one fuzzing cycle.
    if (!checkMode(option, BENZENE_MODE_DRYRUN) && val.Size() == 0) {
        dr_fprintf(STDERR, "corpus_id %d's mutation not found\n", corpus_id);
        for (int i = 0; i < mt_picks.cnt; i++) {
            mt_op = MUTATION_TARGET_AT(mt_picks.picks[i]);
            dr_fprintf(STDERR, "\t0x%x (%s) picked\n", mt_op->getOffset(), mt_op->getOpName());
        }
        DR_ASSERT(false);
    }

    d.AddMember("mutation", val, allocator);

    StringBuffer strbuf;
    strbuf.Clear();
    Writer<StringBuffer> writer(strbuf);
    d.Accept(writer);
    
    char path[MAXIMUM_PATH];
    memset(path, 0, MAXIMUM_PATH);

    // create "corpus" directory if it doesnt exist.
    dr_snprintf(path, MAXIMUM_PATH, "%s/corpus", option.output_dir);
    if (!dr_file_exists(path)) {
        if (!dr_create_dir(path)) {
            dr_fprintf(STDERR, "creating directory \"%s\" failed\n", path);
            return BENZENE_ERROR;
        }
    }

    dr_snprintf(path, MAXIMUM_PATH, "%s/corpus/0x%04x.%s.json", 
            option.output_dir, corpus_id, getStatus(proc) == PROC_STATUS_CRASH ? "crash" : "non-crash");

    // write mutation history to file
    if (writeToFile(path, strbuf.GetString(), strbuf.GetSize()) != BENZENE_SUCCESS) {
        dr_fprintf(STDERR, "writeToFile \"%s\" failed\n", path);
        return BENZENE_ERROR;
    }

    return BENZENE_SUCCESS;    
}

int BenzeneFuzz::createDB(const char* db_name) {
    int r;
    char* err_msg;
    sqlite3* db;
    BenzeneInst* node;
    char sql_buf[256] = {0, };
    module_data_t* main_module = dr_get_main_module();

    if (sqlite3_open(db_name, &db) != SQLITE_OK) {
        dr_fprintf(STDERR, "sqlite3_open failed\n");
        sqlite3_close(db);
        return BENZENE_ERROR;
    }    

    sqlite3_exec(db, "PRAGMA cache_size=10000", 0, 0, &err_msg);

    dr_free_module_data(main_module);

    r = sqlite3_exec(db, "DROP TABLE IF EXISTS Traces;"
                        "CREATE TABLE 'Traces' (CorpusId INT, Offset INT, Image TEXT, Operand TEXT, Value BLOB);", 0, 0, &err_msg);
    SQL_CHECK(r, err_msg);

    r = sqlite3_exec(db, "DROP TABLE IF EXISTS Corpus;"
                        "CREATE TABLE 'Corpus' (Idx INTEGER PRIMARY KEY, CorpusId INTEGER NOT NULL, Crash INT NOT NULL, Triage INT NOT NULL);", 0, 0, &err_msg);
    SQL_CHECK(r, err_msg);

    r = sqlite3_exec(db, "DROP TABLE IF EXISTS UsedSeeds;"
                        "CREATE TABLE 'UsedSeeds' (CorpusId INT, Offset INT, Image TEXT, Operand INT, HitCount INT, OldValue BLOB, Value BLOB, SeedType INT);", 0, 0, &err_msg);
    SQL_CHECK(r, err_msg);

    // r = sqlite3_exec(db, "DROP TABLE IF EXISTS Coverage;"
    //                     "CREATE TABLE 'Coverage' (CorpusId INT, Offset INT, Image TEXT, HitCount INT);", 0, 0, &err_msg);
    // SQL_CHECK(r, err_msg);

    sqlite3_close(db);

    return BENZENE_SUCCESS;
}

/**
 * @brief initialize sqlite3 database for trace storing
 * @details 
 */
int BenzeneFuzz::initDB() {
    char db_path[MAXIMUM_PATH] = {0, };
    char copied_path[MAXIMUM_PATH] = {0, };
    char trace_dir[MAXIMUM_PATH] = { 0, };

    dr_fprintf(STDERR, "[BENZENE] Initializing trace database\n");

    dr_snprintf(trace_dir, sizeof(trace_dir), "%s/trace", option.output_dir);

    if (!checkMode(option, BENZENE_MODE_TRACE)) {
        dr_fprintf(STDERR, "initDB(): invalid mode\n");
        return BENZENE_ERROR;
    }

    /* If trace DB is not initialized yet, initialize it */
    if (!dr_file_exists(trace_dir)) {
        if (!dr_create_dir(trace_dir))
            return BENZENE_ERROR;
    }
    dr_snprintf(db_path, sizeof(db_path), "%s/trace.%d.db", trace_dir, 0);
    if (dr_file_exists(db_path)) {
        dr_fprintf(STDERR, "[BENZENE] %s already exists, skip init\n", db_path);
        return BENZENE_SUCCESS;
    }

    if (createDB(db_path) < 0) {
        dr_fprintf(STDERR, "createDB failed (\"%s\")\n", db_path);
        return BENZENE_ERROR;
    }

    dr_fprintf(STDERR, "[BENZENE] Make the copies of the created database\n");
    file_t src_file = dr_open_file(db_path, DR_FILE_READ);

    /* create multiple databases for trace dump */
    for (int i = 1; i < MAX_PROCESSES; i++) {
        memset(copied_path, 0, sizeof(copied_path));            
        dr_snprintf(copied_path, sizeof(copied_path), "%s/trace.%d.db", trace_dir, i);

        // copy db
        file_t src_file = dr_open_file(db_path, DR_FILE_READ);
        file_t dst_file = dr_open_file(copied_path, DR_FILE_WRITE_OVERWRITE); 

        char read_buf[512];
        size_t read_cnt;

        while(read_cnt = dr_read_file(src_file, read_buf, sizeof(read_buf))) {
            dr_write_file(dst_file, read_buf, read_cnt);
        }

        dr_close_file(dst_file);
    }

    dr_close_file(src_file);

    return BENZENE_SUCCESS;
}

/**
 * @brief dump `/proc/[pid]/maps` file to store memory map information
 * @param char* outdir_path output directory path
 */
void BenzeneFuzz::dumpMemoryMaps(const char* outdir_path) {
    char tmp_path[MAXIMUM_PATH] = {0x0, };
    char map_out_path[MAXIMUM_PATH] = {0x0, };
    
    dr_snprintf(tmp_path, MAXIMUM_PATH, "/proc/%d/maps", dr_get_process_id());
    dr_snprintf(map_out_path, MAXIMUM_PATH, "%s/maps", outdir_path);

    file_t f = dr_open_file(tmp_path, DR_FILE_READ | DR_FILE_ALLOW_LARGE);
    file_t out_f = dr_open_file(map_out_path, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    
    DR_ASSERT(f != INVALID_FILE);
    DR_ASSERT(out_f != INVALID_FILE);
    
    char memmap_buf[4096] = {0, };
    // ssize_t memmap_size = sizeof(memmap);
    ssize_t read_size;
    while ((read_size = dr_read_file(f, memmap_buf, 4096)) > 0){
        dr_write_file(out_f, memmap_buf, read_size);   
    }

    dr_close_file(f);
    dr_close_file(out_f);
}


int BenzeneFuzz::writeConfig(const char* out_filename) {
    BenzeneInst * benz_inst;
    rapidjson_allocator_t allocator = config_.GetAllocator();
    // only dryrun mode can use this function.
    DR_ASSERT(checkMode(option, BENZENE_MODE_DRYRUN));

    config_["dryrun_done"].SetInt(0x1);
    config_["crash_addr"].SetUint64((uint64_t)option.initial_crash_addr);
    config_["crash_offset"].SetUint64((uint64_t)option.initial_crash_offset);
    config_["crash_img"].SetString( (const char*) (option.crash_img_name), strlen(option.crash_img_name));

    // check if triage instruction was valid.
    if (triage_inst_ == nullptr) {
        triage_inst_ = getInst(option.triage_addr);
        DR_ASSERT(triage_inst_);
    }
    config_["hitcnt_for_triage"].SetUint(triage_inst_->getHitCnt());

    // we should recheck the validity of the mutation targets. 
    // @TODO: too complicated. simplify it
    Value new_mt_arr(kArrayType);
    uint32_t resolved_mt_cnt = 0;
    for (size_t i = 0; i < config_["mutation_targets"].Size(); i++) {
        // mt: mutation target
        auto mt_obj = config_["mutation_targets"][i].GetObject();

        // first check validity of rapidjson
        SANITIZE_CONFIG(mt_obj, "op_name");
        SANITIZE_CONFIG(mt_obj, "addr");
        SANITIZE_CONFIG(mt_obj, "img_name");
        SANITIZE_CONFIG(mt_obj, "dict_offset");
        SANITIZE_CONFIG(mt_obj, "dict_img_name");
        SANITIZE_CONFIG(mt_obj, "dict_op_name");
        SANITIZE_CONFIG(mt_obj, "dictionary");

        uint32_t mt_offset = mt_obj["offset"].GetUint();
        int32_t dict_offset = mt_obj["dict_offset"].GetUint();

        const char* mt_op_name = mt_obj["op_name"].GetString();
        const char* mt_img_name = mt_obj["img_name"].GetString();
        const char* dict_op_name = mt_obj["dict_op_name"].GetString();
        const char* dict_img_name = mt_obj["dict_img_name"].GetString();

        app_pc mt_module_base = modules_->getModuleBase(mt_img_name);
        app_pc dict_module_base = modules_->getModuleBase(dict_img_name);

        // find existing `BenzeneInst` with offset `mt_offset`
        auto iter = insts_.find(DR_APP_PC_ADD(mt_module_base, mt_offset));
        if (iter == insts_.end()) {
            dr_fprintf(STDERR, "[WARN] mutation target 0x%lx (%s) not found.\n", mt_offset, mt_op_name);
            continue;
        }

        BenzeneInst* mt_inst = iter->second;

        if (mt_inst->getSrcOpsSize() == 0) {
            // Note that registers such as rsp are excluded from mutation target
            dr_fprintf(STDERR, "[WARN] mutation target instruction 0x%lx has no operand (original op : %s).\n", 
                        mt_inst->getOffset(), mt_op_name);
            continue;
        }

        for(size_t i = 0; i < mt_inst->getSrcOpsSize(); i++) {
            BenzeneOp* mt_op = mt_inst->getSrcOp(i);
            DR_ASSERT(mt_op);
            if (strncmp(mt_op->getOpName(), mt_op_name, strlen(mt_op_name))
                || !mt_op->isMutationTarget()) {
                mt_op = nullptr;
                continue;
            }

            if (!mt_op->isHitAfterFuzz() /* check if the seed has been executed */
                || (mt_op->getOffset() == option.initial_crash_offset)) {
                // it's not a valid seed, exclude it from fuzzing
                mt_op->disableFuzz();
                mt_op = nullptr;
                continue;   
            }

            // add dictionary values for fuzzing
            size_t trace_cnt;
            trace_val_t* dict_traces = mt_op->collectDictValues(&trace_cnt);

            if (dict_traces != nullptr) { // non-empty dictionary values
                for (size_t j = 0; j < trace_cnt; j++) {
                    mt_obj["dictionary"].PushBack(dict_traces[j], allocator);
                }
                // we should free the allocated buffer to prevent mem leaks
                dr_global_free(dict_traces, sizeof(trace_val_t)*trace_cnt);                
            }

            // all the tasks for the current mutation target is done.
            // we append this mutation target to config json.
            new_mt_arr.PushBack(mt_obj, allocator);
            resolved_mt_cnt++;
        }
    }
    config_["mutation_targets"] = new_mt_arr;

    dr_fprintf(STDERR, "[BENZENE] mutation target count : %d\n", resolved_mt_cnt);
    dr_fprintf(STDERR, "[BENZENE] triage offset : 0x%lx, cnt : %d\n", option.triage_offset, triage_inst_->getHitCnt());
    dr_fprintf(STDERR, "[BENZENE] total instrumented insts : %d\n", insts_.size());

    // @TODO: insts to monitor
    auto insts_json = config_["insts"].GetArray();
    for (auto iter = insts_.begin(); iter != insts_.end(); iter++) {
        benz_inst = iter->second;

        if (!benz_inst->getHitCnt())
            continue;

        insts_json.PushBack(benz_inst->toJSON(allocator), allocator);
    }

    dumpMemoryMaps(option.output_dir);

    SANITIZE_CONFIG(config_, "dryrun_done");
    SANITIZE_CONFIG(config_, "fuzz_offset");
    SANITIZE_CONFIG(config_, "hit_cnt");
    SANITIZE_CONFIG(config_, "crash_addr");
    SANITIZE_CONFIG(config_, "crash_offset");
    SANITIZE_CONFIG(config_, "crash_img");
    SANITIZE_CONFIG(config_, "triage_offset");
    SANITIZE_CONFIG(config_, "hitcnt_for_triage");
    SANITIZE_CONFIG(config_, "mutation_targets");
    SANITIZE_CONFIG(config_, "insts");

    StringBuffer strbuf;
    strbuf.Clear();
    Writer<StringBuffer> writer(strbuf);
    config_.Accept(writer);

    if (writeToFile(out_filename, strbuf.GetString(), strbuf.GetSize()) != BENZENE_SUCCESS) {
        DR_ASSERT_MSG(false, "writeConfig() failed");
    }

    return BENZENE_SUCCESS;
}

int BenzeneFuzz::readConfigFromJSON(const char* path) {
    using namespace rapidjson;

    size_t file_sz;
    file_t fd = dr_open_file(path, DR_FILE_READ);

    if (fd == INVALID_FILE) {
        dr_fprintf(STDERR, "Error: failed to open \"%s\"\n", path);
        DR_ASSERT(false);
    }
    dr_file_size(fd, &file_sz);
    dr_fprintf(STDERR, "[BENZENZE] config file size : %ld\n", file_sz);
    char* config_buf = (char*)dr_global_alloc(file_sz);
    
    if (dr_read_file(fd, config_buf, file_sz) != file_sz) {
        dr_fprintf(STDERR, "dr_read_file() file size mismatch (file_sz: %d)\n", file_sz);
    }

    config_.Parse(config_buf);
    if (config_.HasParseError())
        return BENZENE_ERROR;

    SANITIZE_CONFIG(config_, "dryrun_done");
    SANITIZE_CONFIG(config_, "fuzz_offset");
    SANITIZE_CONFIG(config_, "hit_cnt");
    SANITIZE_CONFIG(config_, "crash_addr");
    SANITIZE_CONFIG(config_, "crash_offset");
    SANITIZE_CONFIG(config_, "crash_img");
    SANITIZE_CONFIG(config_, "triage_offset");
    SANITIZE_CONFIG(config_, "hitcnt_for_triage");
    SANITIZE_CONFIG(config_, "pass_hang");
    SANITIZE_CONFIG(config_, "mutation_targets");
    SANITIZE_CONFIG(config_, "insts");

    // initialize (original) crash's information
    option.initial_crash_addr = (app_pc)config_["crash_addr"].GetUint64();
    option.initial_crash_offset = config_["crash_offset"].GetInt();
    strncpy(option.crash_img_name, config_["crash_img"].GetString(), MAX_MODULE_NAME_LEN);

    if (!checkMode(option, BENZENE_MODE_DRYRUN)) {
        if ( (option.crash_img_name[0] == '\x00' /* invalid crash module name */ || option.initial_crash_offset == 0x0 ) 
          && option.initial_crash_addr == 0x0) {
            DR_ASSERT_MSG(false, "invalid crash address (0x0)");
        }
    }

    // set triage offset for crash / non-crash classfication.
    option.triage_offset = config_["triage_offset"].GetInt64();
    option.hitcnt_for_triage = config_["hitcnt_for_triage"].GetInt();
    
    if (!option.triage_offset) {
        DR_ASSERT_MSG(false, "`triage_offset == 0`");        
    }
    if (!checkMode(option, BENZENE_MODE_DRYRUN) && option.hitcnt_for_triage == 0) {
        DR_ASSERT_MSG(false, "`option.hitcnt_for_triage == 0`");
    }

    // set fuzzing target offset for fork()-iteration.
    option.fuzz_offset = (app_pc)config_["fuzz_offset"].GetUint64();
    if (!option.fuzz_offset) DR_ASSERT_MSG(false, "`option.fuzz_offset == 0`");
    
    option.hitcnt_for_kickoff = config_["hit_cnt"].GetUint(); 
    if (!option.hitcnt_for_kickoff) DR_ASSERT_MSG(false, "`option.hitcnt_for_kickoff == 0`");

    option.pass_hang = config_["pass_hang"].GetBool();

    BenzeneInst* benz_inst;
    module_insts_t* mod_insts;
    // BENZENE_MODE_FUZZ and BENZENE_MODE_TRACE uses pre-parsed data to create BenzeneInst (for performance)
    if (!checkMode(option, BENZENE_MODE_DRYRUN)) {
        json_val_t insts_json = config_["insts"].GetArray();
        // FUZZ & TRACE modes use existing BenzeneInst information

        DR_ASSERT_MSG(insts_json.Size() != 0, "empty `insts` array.");

        for(size_t i = 0; i < insts_json.Size(); i ++) {
            auto inst_json = insts_json[i].GetObject();
            uint32_t    offset = inst_json["offset"].GetUint();
            const char* img_name = inst_json["img_name"].GetString();

            mod_insts = nullptr;

            for (int i = 0; insts_module_load_waiting_[i] != nullptr; i++) {
                if (!strncmp(insts_module_load_waiting_[i]->module_name, img_name, MAX_MODULE_NAME_LEN)) {
                    mod_insts = insts_module_load_waiting_[i];
                    break;
                }
            }

            if (!mod_insts) {
                dr_fprintf(STDERR, "module name \"%s\" not found in `insts_module_load_waiting_`\n", img_name);
                DR_ASSERT(false);
            }

            benz_inst = new BenzeneInst(inst_json);

            if (checkMode(option, BENZENE_MODE_FUZZ)) {
                if (! (benz_inst->hasMutationTarget() || benz_inst->hasDictTargetOp() || benz_inst->getOffset() == option.triage_offset)) {
                    delete benz_inst;
                    continue;
                }
            }
            // append current instruction
            drvector_append(&mod_insts->insts, benz_inst);
        }
    }

    dr_global_free(config_buf, file_sz);
    dr_close_file(fd);

    return BENZENE_SUCCESS;
}

int BenzeneFuzz::saveEdgeCoverage(const char* path) {
    return writeToFile(path, (const char*)cov_map, sizeof(cov_map));
}

int BenzeneFuzz::exitDryrun(int corpus_id) {
    char db_name[MAXIMUM_PATH];
    char tmp_path[MAXIMUM_PATH] = {0, };

    const char* prefix;

    if (getStatus(proc) == PROC_STATUS_NONE) { /* if process exits normally, it's a non crash */
        setStatus(proc, PROC_STATUS_NON_CRASH);
    }
    else if (getStatus(proc) != PROC_STATUS_CRASH) {
        DR_ASSERT_MSG(false, "Error: crash has not happened\n");
    }

    DR_ASSERT_MSG(is_reached, "target function has not been reached");

    if (isTriageHit() == false) {
        dr_fprintf(STDERR, "triage offset 0x%lx has not been reached\n", option.triage_offset);
        DR_ASSERT(false);
        // DR_ASSERT_MSG(isTriageHit() == true, "triage offset has not been reached");
    }
    if (checkMode(option, BENZENE_MODE_TRACE)) {
        if (initDB() != BENZENE_SUCCESS) {
            DR_ASSERT_MSG(false, "initDB() failed");
        }
        dr_snprintf(db_name, sizeof(db_name), "%s/trace/trace.%d.db", option.output_dir, 0);
        dr_fprintf(STDERR, "[BENZENE] Dump traces into \"%s\".\n", db_name);
        DR_ASSERT_MSG(dumpTrace(db_name, dryrun_corpus_id) == 0, "dumpTrace() failed"); // dump trace to the first db
    }
    else { // fuzzing dryrun
        DR_ASSERT_MSG(saveMutationResult(dryrun_corpus_id) == BENZENE_SUCCESS, "saveMutationResult() failed");

        // get edge coverage data
        dr_snprintf(tmp_path, sizeof(tmp_path), "%s/cov", option.output_dir);

        if (!dr_file_exists(tmp_path)) {
            DR_ASSERT_MSG(dr_create_dir(tmp_path), "dr_create_dir() failed");
        }
        dr_snprintf(tmp_path, sizeof(tmp_path), "%s/cov/cov.0x%04x.bin", option.output_dir, dryrun_corpus_id);

        DR_ASSERT_MSG(saveEdgeCoverage(tmp_path) == BENZENE_SUCCESS, "BenzeneFuzz::saveEdgeCoverage() failed");

    }

    dr_snprintf(tmp_path, sizeof(tmp_path), "%s/%s.config.json", 
                                option.output_dir, checkMode(option, BENZENE_MODE_FUZZ) ? "fuzz" : "trace");
    writeConfig(tmp_path);
    
    dr_fprintf(STDERR, "[BENZENE] dryrun successfully done\n");
    return BENZENE_SUCCESS;
}


bool BenzeneFuzz::handleModuleLoad(const module_data_t* mod) {
    module_insts_t* mod_insts = nullptr;
    app_pc inst_addr;
    modules_->resolveModule(mod);

    for (int i = 0; insts_module_load_waiting_[i] != nullptr; i++) {
        if (!strncmp(insts_module_load_waiting_[i]->module_name, mod->names.file_name, MAX_MODULE_NAME_LEN)) {
            mod_insts = insts_module_load_waiting_[i];
            break;
        }
    }

    if (!mod_insts)
        return false;

    for (int i = 0; i < mod_insts->insts.entries; i++) {
        BenzeneInst* benz_inst = (BenzeneInst*)drvector_get_entry(&mod_insts->insts, i);
        
        if (!benz_inst->getAddr()) {
            // resolve instruction's address from offset
            inst_addr = DR_APP_PC_ADD(mod->start, benz_inst->getOffset());
            benz_inst->setAddr(inst_addr);
        }

        auto r = insts_.insert({benz_inst->getAddr(), benz_inst});
        if (r.second == false) { // alreadly exists
            DR_ASSERT_MSG(false, "inst already exists");
            continue;
        }     
    }
    // delete mod_inst
    drvector_delete(&mod_insts->insts);
    if (!strncmp(mod->names.file_name, option.fuzz_module_name, sizeof(option.fuzz_module_name))) {
        dr_fprintf(STDERR, "[INFO] **** fuzz target module loaded (\"%s\") ****\n", option.fuzz_module_name);

        /**
         *  first get opened file descriptors information
         */
        DIR *dp;
        struct dirent *ep;
        size_t fd_cnt = 0;
        char tmp_path[MAXIMUM_PATH] = {0, };
        dr_snprintf(tmp_path, MAXIMUM_PATH, "/proc/%d/fd", dr_get_process_id());

        // setup opened_fds_
        for (int i = 0; i < MAXIMUM_FD_CNT; i++) {
            opened_fds_[i].fd = INVALID_FD;
        }

        dp = opendir (tmp_path);
        if (dp != NULL)
        {
            while ((ep = readdir(dp)) != NULL) {
                if (ep->d_name[0] == '.')
                    continue;
                
                // skip STDOUT and STDERR
                if (ep->d_name[0] == '1' || ep->d_name[0] == '2')
                    continue;
                
                // puts (ep->d_name);
                opened_fds_[fd_cnt].fd = atoi(ep->d_name);
                opened_fds_[fd_cnt].tell = -1;
                fd_cnt++;
            }
                
            closedir(dp);
        }
        else
        {
            perror ("Couldn't open the directory");
        }

        /* 
         * initialize the shared memory 
         * we use this memory to store dictionary values for fuzzing
         */
        if (!setupShm(MAXIMUM_SHM_SIZE)) {
            DR_ASSERT_MSG(false, "setupShm() failed... abort");
        }

        initMutationTargets();
        DR_ASSERT_MSG(MUTATION_TARGET_SIZE != 0, "mutation target is 0");

        // set fuzzing address
        fuzz_addr = DR_APP_PC_ADD(mod->start, option.fuzz_offset);
        dr_fprintf(STDERR, "[BENZENE]\tfuzz addr: 0x%lx\n", fuzz_addr);

        // set triage address
        option.triage_addr = DR_APP_PC_ADD(option.triage_offset, mod->start);
        BenzeneInst* triage_inst;

        auto iter = insts_.insert( {option.triage_addr, nullptr} );

        if (iter.second) {
            triage_inst = new BenzeneInst(DR_APP_PC_ADD(option.triage_offset, mod->start), option.triage_offset, option.fuzz_module_name);
            iter.first->second = triage_inst;
            triage_inst->parse();
        }
        else {
            triage_inst = iter.first->second;
        }
    }

    return true;
}

void BenzeneFuzz::addTargetModule(const char* module_name) { 
    module_insts_t * mod_inst;
    
    if (!modules_->addTargetModule(module_name))
        return;

    dr_fprintf(STDERR, "[BENZENE] module \"%s\" checked\n", module_name);
    for (int i = 0; i < MAXIMUM_MODULE_CNT; i++) {
        if (insts_module_load_waiting_[i] == nullptr) {
            mod_inst = (module_insts_t*)dr_global_alloc(sizeof(module_insts_t));
            strncpy(mod_inst->module_name, module_name, MAX_MODULE_NAME_LEN);
            if (!drvector_init(&mod_inst->insts, 0, false, NULL)) {
                dr_fprintf(STDERR, "drvector_init() failed\n");
                dr_exit_process(-1);
            }
            insts_module_load_waiting_[i] = mod_inst;
            break;
        }
    }
};