#include "benzene_op.h"
#include "benzene_modules.h"

// for debug
#include "benzene_proc.h"
extern benzene_proc_t* proc;

uint32_t mem_violation_offset = 0;
bool is_reached = false;
uint32_t cur_exec_order = 0;
dict_values_t* g_dict_arr = nullptr;

#define DISABLE_MUTATION -1

bool isString(char* ptr) {
    char* cur = ptr;
    char ch;
    uint32_t len = 0;

    // investigate string length
    while(dr_safe_read(cur, 1, &ch, nullptr)) {
        if (ch == '\x00') break;
        
        if ((ch & 0x7F)==ch) { // it's an ascii character
            len++;
            cur++;
            continue;
        } 
        len = 0;
        break;
    }
    
    if (len > 0) {
        // DR_ASSERT(str_len <= 8);
        return true;
    }
    return false;
}

BenzeneOp::BenzeneOp(opnd_t op, uint32_t offset) :
    dr_opnd_(op),
    offset_(offset)
{
    if (opnd_is_reg(op)) {
        reg_ = opnd_get_reg(op);
        read_size_ = opnd_size_in_bytes(opnd_get_size(op));
        strncpy(op_name_, get_register_name(reg_), MAX_OP_NAME);
    }
    else if (opnd_is_memory_reference(op)) {
        read_size_ = opnd_size_in_bytes(opnd_get_size(op));
        if (!read_size_) {
            dr_fprintf(STDERR, "0x%x's read size is 0\n", offset);
            DR_ASSERT(read_size_);
        }
        strncpy(op_name_, "mem", MAX_OP_NAME);
    }
    else if (opnd_is_immed(op)) {
        read_size_ = 0;
    }
    else {
        return;
        // DR_ASSERT(false);
    }

    hashtable_init(&traces_, 4, HASH_INTPTR, false);
}

json_val_t BenzeneOp::toJSON(rapidjson_allocator_t allocator) {
    json_val_t obj(kObjectType);
    json_val_t val(kNullType);

    obj.AddMember("offset", val.SetUint(offset_), allocator);    
    obj.AddMember("op_name", val.SetString(op_name_, strlen(op_name_)), allocator);
    obj.AddMember("read_size", val.SetUint(read_size_), allocator);
    obj.AddMember("max_hit_cnt", val.SetUint(hit_cnt_), allocator);
    obj.AddMember("exec_order", val.SetUint(exec_order_), allocator);    

    // for dynamorio instruction parsing 
    obj.AddMember("drreg", val.SetUint64(reg_), allocator);
    obj.AddMember("opnd1", val.SetUint64(*(uint64_t*)&dr_opnd_), allocator);
    obj.AddMember("opnd2", val.SetUint64(*((uint64_t*)&dr_opnd_ + 1)), allocator);
    
    obj.AddMember("trace_flag", val.SetBool(trace_flag_), allocator);
    obj.AddMember("dump_flag", val.SetBool(dump_flag_), allocator);

    obj.AddMember("mut_type", val.SetUint(mut_type_), allocator);
    obj.AddMember("is_dict", val.SetBool(is_dict_), allocator);
    obj.AddMember("dict_offset", val.SetUint(dict_offset_), allocator);

    return obj;
}

void BenzeneOp::replayMutation(char* content, size_t len) {
    int ascii_len;
    mutation_t* mut_for_replay;
    for (int i = 0; i < mutations_.entries; i++) {
        // @TODO: This implementation is ugly: DynamoRIO's drvector does not support `pop` operation.
        mut_for_replay = (mutation_t*)drvector_get_entry(&mutations_, i); 
        
        if (mut_for_replay->hit_cnt > hit_cnt_)
            return;            

        if (mut_for_replay->hit_cnt == hit_cnt_) {
            break;
        }
        mut_for_replay = nullptr;
    }

    // mutation for current `hit_cnt` is not found. return without mutation.
    if (!mut_for_replay) return;

    switch(mut_for_replay->type) {
    case MUTATION_TYPE_CONST:
    case MUTATION_TYPE_PTR:
        // overwrite current content with the given mutation history (`replay.mutations[replay.cur_idx]`)
        dr_safe_write(content, len, &mut_for_replay->to, NULL);
        break;
    case MUTATION_TYPE_STR:
    // @TODO
        ascii_len = strlen((char*)&mut_for_replay->to);
        // overwrite current content with the given mutation history (`replay.mutations[replay.cur_idx]`)            
        dr_safe_write(*(char**)content, ascii_len, &mut_for_replay->to, NULL);
        break;
    case MUTATION_TYPE_STRLEN:
        // resize string length
        //   @mut_for_replay->from : original string's length
        //   @mut_for_replay->to   : mutated string's length
        memset((*(char**)content) + mut_for_replay->to, 0, mut_for_replay->from - mut_for_replay->to);
        break;
    default:
        DR_ASSERT_MSG(false, "invalid seed type");
        break;
    }

    fuzzed(); // mark that the content of this BenzeneOp has been mutated.
    return;
}


void BenzeneOp::fuzzContent(char* content, size_t len) {
    int ascii_len;

    if (picked_ <= 0) // "picked_ < 0" means mutation is disabled at this `BenzeneOp` (DISABLE_MUTATION)
        return;
    
    if (picked_ != hit_cnt_) {
        if (hit_cnt_ > max_hit_cnt_) {
            /* 
             *  hit_cnt_ > max_hit_cnt means that unknown additional edge has been discovered by fuzzing.
             *  We randomly decide whether to fuzz the current state.
             */
            if (util_rnd64() & 1) {
                picked_ = DISABLE_MUTATION; // disable further mutation with 50% chance
                return;
            }
        }
        else { 
            return;
        }
    }

    mutation_t* mut = (mutation_t*)dr_global_alloc(sizeof(mutation_t));
    DR_ASSERT_MSG(mut != nullptr, "dr_global_alloc() failed");
    
    // record mutation time
    mut->hit_cnt = getHitCnt();

    switch(getMutationType()) {
    case MUTATION_TYPE_CONST:
        // save its original value before mutation
        mut->from = *(trace_val_t*)content;
        if (util_rnd64() & 1) {
            if (fuzzContentByDict(content, len) < 0) {
                FUZZ_BY_RANDOM(content, len) // honggfuzz's mutation
            }
        }
        else {
            FUZZ_BY_RANDOM(content, len) // honggfuzz's mutation
        } 
        mut->to = *(trace_val_t*)content;
        mut->type = MUTATION_TYPE_CONST;
        break;
    case MUTATION_TYPE_PTR: 
        // save its original value before mutation
        mut->from = *(trace_val_t*)content;

        // @TODO: if there's no usable dict value
        if (fuzzContentByDict(content, len) < 0) {
            FUZZ_BY_RANDOM(content, len)
        }
        mut->to = *(trace_val_t*)content;
        mut->type = MUTATION_TYPE_PTR;
        break;
    case MUTATION_TYPE_STR:
    case MUTATION_TYPE_STRLEN: 
        // WATCH for the type: string pointer is `*(char**)content`, NOT `content`
        ascii_len = strlen(*(char**)content);

        if (ascii_len > sizeof(trace_val_t)) {
            mut->from = ascii_len;
            mangle_strlen(*(char**)content, ascii_len);
            mut->to = strlen(*(char**)content);
            mut->type = MUTATION_TYPE_STRLEN;
        }
        else {
            // save its original value before mutation
            dr_safe_write(&mut->from , ascii_len, *(const void**)content, nullptr);

            if (fuzzASCII((char*)*(char**)content, ascii_len, (char*)&mut->from) < 0) {
                DR_ASSERT(false);
                // if (fuzzContentByDict(content, len) < 0) {
                //     FUZZ_BY_RANDOM(content, len)
                // }
            }
            dr_safe_write(&mut->to, ascii_len, *(const void**)content, nullptr);
            mut->type = MUTATION_TYPE_STR;
        }
        break;
    default:
        DR_ASSERT_MSG(false, "mutation type not specified");
        break;
    } 
    appendMutation(mut);
    fuzzed();
}

int BenzeneOp::fuzzASCII(char* content, int len, char* old_content) {
    do {
        mangle_str(content, len);        
    } while (!strncmp(content, old_content, len));

    return len;
}

int BenzeneOp::fuzzContentByDict(char* content, size_t len) {       
    trace_entry_t* prev;
    trace_entry_t* next;

    DR_ASSERT_MSG(dict_op_, "dict_op is NULL");
    
    benzene_sem_wait(SEM_NUM_SHM);
    setShmProt(SHM_WRITE);

    if (!dict_values_->first) // no dicts available
        return BENZENE_ERROR;

    trace_entry_t* ent = pickRandomDictValue();
    // avoid modifying the contents with the same value
    if (ent->val == *(trace_val_t*)content) {
        setShmProt(SHM_READONLY);
        benzene_sem_quit(SEM_NUM_SHM);
        return BENZENE_ERROR;
    }

    popDictValue(ent);  // pop used dict entry from the dict value list

    setShmProt(SHM_READONLY);
    benzene_sem_quit(SEM_NUM_SHM);

    dr_safe_write(content, len, &ent->val, NULL);
    return BENZENE_SUCCESS;
}

void BenzeneOp::processRegRead (reg_id_t reg, uint32_t read_size, BenzeneOp* op) {
    // @TODO : consider the offset. ex) ah, dl, ...
    byte read_buf[16] = {0, };
    byte trace_buf[16] = {0, };
    void* drcontext;
    dr_mcontext_t mc;

    op->hit();

    if (!op->hitAfterFuzz() && !op->isDictOp()) 
        return;
    // @TODO: handle the case - read_size is over 64
    if (read_size > sizeof(read_buf)) return;

    if (op->isPickedForFuzz() || op->isTraced()) {
        drcontext = dr_get_current_drcontext();

        mc = { sizeof(mc), DR_MC_ALL }; // flag : DR_MC_ALL

        dr_get_mcontext(drcontext, &mc);

        reg_get_value_ex(reg, &mc, read_buf);
    }

    if (op->isPickedForFuzz()) {
        if (checkMode(option, BENZENE_MODE_TRACE)) {
            // replay the mutation previously performed for monitoring the used values            
            op->replayMutation((char *)read_buf, read_size);
        } else {
            // `BENZENE_MODE_FUZZ`
            op->fuzzContent((char *)read_buf, read_size);
        }
        // @Issue : Why does DR_REG_EDI recognize the first byte of the buffer as a null byte...???
        DR_ASSERT(reg_set_value_ex(reg, &mc, (byte*)read_buf));

        dr_set_mcontext(drcontext, &mc);
    }

    /* 
     *  DynamoRIO's reg_get_value() doesn't care the given register's size. So, we mask the buffer with read size
     *  @TODO: consider the offset of the register. e.g., ah, dl, cl, ...
     */
    dr_safe_write(trace_buf, read_size, read_buf, NULL);

    if (op->isTraced()) {
        // collect trace
        op->addTrace(*((trace_val_t*)trace_buf));
    }
}

void BenzeneOp::processMemRead (void* mem_addr, uint32_t read_size, BenzeneOp* op) {
    size_t bytes_read;
    char mem_read_buf[128] = {0, }; // @TODO : handle buffer size

    // dr_fprintf(STDERR, "0x%lx (0x%lx) : read_size : %d, bytes_read : %d\n", 
    //         inst->getAddr(), inst->getOffset(), read_size, bytes_read);
    op->hit();    

    if (!op->hitAfterFuzz() && !op->isDictOp()) return;

    if (op->isPickedForFuzz() || op->isTraced()) {
        if(!dr_safe_read(mem_addr, read_size, mem_read_buf, &bytes_read)) {
            // DynamoRIO Issue: Sometimes `dr_siginfo_t`'s `mcontext` returns an inaccurate value when the application crashes.
            // To assure retrieving the accurate crashing addresss, 
            // we manually check and record the crash address (due to the invalid memory access).
            mem_violation_offset = op->getOffset();
            return;
        }
    }

    if (op->isPickedForFuzz()) {
        if (checkMode(option, BENZENE_MODE_TRACE)) {
            op->replayMutation(mem_read_buf, read_size); // replay the mutation performed at fuzzing.
        } else { // BENZENE_MODE_FUZZ
            op->fuzzContent(mem_read_buf, read_size); // perform mutation
        }
        if(!dr_safe_write(mem_addr, read_size, mem_read_buf, NULL))
            return;
    }

    if (op->isTraced()) {
        // collect trace
        op->addTrace(*((trace_val_t*)mem_read_buf));
    }
}


void BenzeneOp::processDummyOp (BenzeneOp* op) {
    // dr_fprintf(STDERR, "0x%lx (0x%lx) : read_size : %d, bytes_read : %d\n", 
    //         inst->getAddr(), inst->getOffset(), read_size, bytes_read);
    op->hit();
}


void BenzeneOp::fromJSON(json_val_t op_json) {
    offset_ = op_json["offset"].GetUint();
    strncpy(op_name_, op_json["op_name"].GetString(), MAX_OP_NAME);
    trace_flag_ = op_json["trace_flag"].GetBool();
    mut_type_ = (mut_type_t) op_json["mut_type"].GetUint();
    is_dict_ = op_json["is_dict"].GetBool();
    reg_ = op_json["drreg"].GetUint64();
    read_size_ = op_json["read_size"].GetUint();
    max_hit_cnt_ = op_json["max_hit_cnt"].GetUint();
    exec_order_ = op_json["exec_order"].GetUint();

    if (isMutationTarget()) {
        dict_offset_ = op_json["dict_offset"].GetUint();
    }

    // interpret opnd_t as uint64_t[2]
    *(uint64_t*)&dr_opnd_ = op_json["opnd1"].GetUint64();
    *((uint64_t*)&dr_opnd_ + 1) = op_json["opnd2"].GetUint64();

    hashtable_init(&traces_, 4, HASH_INTPTR, false);
}

void BenzeneOp::addTrace(trace_val_t val) {
    if (!isDictOp() && getTraceCount() >= UNIQUE_TRACE_THRESHOLD) return;

    uint prot;
    if ( checkMode(option, BENZENE_MODE_DRYRUN) && isMutationTarget()) {
        // Here we keep updating BENZENE_MT_TYPE
        // This is need to be done *only* at the dryrun-fuzz mode
        if (dr_query_memory((app_pc)val, NULL, NULL, &prot) /* checks if the given `val` is a pointer value */
            && !dr_memory_is_dr_internal((app_pc)val)
                && mut_type_ != MUTATION_TYPE_STR) {
            // @TODO: should enhance string recognization feature
            if (isString((char*)val) && (prot & DR_MEMPROT_WRITE) /* check if it's a string in the writable memory */) {
                setMutationType(MUTATION_TYPE_STR);
            }
            else {
                setMutationType(MUTATION_TYPE_PTR);
            }
        }
    }

    // hashtable_t does not support traverse of it's contents directly...
    trace_entry_t* trace_ent = (trace_entry_t*)dr_global_alloc(sizeof(trace_entry_t));

    if (trace_ent == nullptr) {
        DR_ASSERT_MSG(false, "dr_global_alloc() failed\n");
    }

    // traces_.insert(val);
    if (hashtable_add(&traces_, (void*)val, trace_ent)) {
        /*
         * @TODO: current implementation of tracing strlen is very ugly.
         *        It NEEDS to be re-designed in the near future.
         */
        if (getMutationType() == MUTATION_TYPE_STR) {
            if (dr_query_memory((app_pc)val, NULL, NULL, NULL)) {
                trace_ent->val = strlen((char*)val);
            }
            else {
                trace_ent->val = val;
            }
        }
        else {
            trace_ent->val = val;
        }
        trace_ent->next = uniq_traces_tail_;

        uniq_traces_tail_ = trace_ent;
    }
    else {
        dr_global_free(trace_ent, sizeof(trace_entry_t));
    }
}