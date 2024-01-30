#ifndef __BENZENE_OP_H__
#define __BENZENE_OP_H__

#include <stdio.h>
#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drx.h"
#include "drutil.h"
#include "dr_config.h"
#include "droption.h"
#include "drreg.h"
#include "benzene_common.h"
#include "benzene_opt.h"
#include "benzene_mutation.h"
#include "benzene_shared.h"
#include "hashtable.h"

#define TRACE_SIZE() traces_.entries
#define INIT_MUTATION_CNT 0x2

#define FUZZ_BY_RANDOM(content, len) while(1) { \
                                        mangle(content, len); \
                                        if (mut->from != *(trace_val_t*)content) \
                                            break; \
                                        }

bool isString(char* ptr);

extern benzene_opt_t option;

class BenzeneOp;

struct dict_values_t {
    BenzeneOp*      mt; // mutation target
    BenzeneOp*      dict;
    trace_entry_t*  first;
    uint32_t        cnt;
};

extern uint32_t cur_exec_order;
extern bool is_reached;
extern dict_values_t* g_dict_arr;

void setReplay(BenzeneOp* op, mutation_t* mutations);

class BenzeneOp {
private:
    opnd_t dr_opnd_;
    uint32_t offset_ = 0;
    reg_id_t reg_;
    char op_name_[MAX_OP_NAME] = {0, };
    hashtable_t traces_;    // hashtable holding unique traces for this operand.
    drvector_t mutations_;
    uint32_t read_size_ = 0; // read size of this operand

    bool trace_flag_ = false;
    bool dump_flag_ = false;
    mut_type_t mut_type_ = MUTATION_TYPE_NONE;
    uint32_t exec_order_ = 0;   // to find out the execution order of each instruction
    int32_t picked_ = 0x0;      // the inst was picked for fuzzing target. it will be fuzzed at "picked_"-th hit.
    bool is_fuzzed_ = false;    // the flag is set if the inst has been actually fuzzed.
    bool is_dict_ = false;

    /* mutation dict information */
    uint32_t            dict_offset_ = 0;
    BenzeneOp*          dict_op_ = nullptr;
    dict_values_t*  dict_values_ = nullptr;

    trace_entry_t* uniq_traces_tail_ = nullptr;

    uint32_t hit_cnt_ = 0;
    bool     is_hit_after_fuzz_ = false;
    uint32_t max_hit_cnt_ = 0;
public:
    BenzeneOp(opnd_t op, uint32_t offset);
    BenzeneOp(const char* opname, uint32_t offset) :
        offset_(offset)
    {
        strncpy(op_name_, opname, MAX_OP_NAME);
    };
    
    BenzeneOp(json_val_t op_json) {
        DR_ASSERT(op_json.IsObject() == true);
        fromJSON(op_json.GetObject());
    }

    ~BenzeneOp() {};

    void fromJSON(json_val_t obj);

    bool isRegOp() { return opnd_is_reg(dr_opnd_); }
    bool isMemOp() { return opnd_is_memory_reference(dr_opnd_); }

    void addTrace(trace_val_t val);

    opnd_t getDrOpnd() { return dr_opnd_; }
    const char* getOpName() { return op_name_; }
    BenzeneOp* getDictOp() { return dict_op_; }
    void set_trace_flag(bool flag) { trace_flag_ = flag; }
    void setDump() {
        trace_flag_ = true;
        dump_flag_ = true; 
    }
    void disableDump() {
        dump_flag_ = false;
    }
    void setMutationTarget() { 
        DR_ASSERT(drvector_init(&mutations_, INIT_MUTATION_CNT, false, NULL));
        if (getMutationType() == MUTATION_TYPE_NONE) {
            DR_ASSERT(checkMode(option, BENZENE_MODE_DRYRUN));
            setMutationType(MUTATION_TYPE_CONST); // default type is `MUTATION_TYPE_CONST`
        }
    }
    void disableFuzz() { setMutationType(MUTATION_TYPE_NONE); }
    mut_type_t getMutationType() { return mut_type_; }
    void setMutationType(mut_type_t type) { mut_type_ = type; }
    void setDictOffset(uint32_t offset) { dict_offset_ = offset; }

    void setMutationDictOp(BenzeneOp* op) { 
        op->setDictOp();
        dict_op_ = op;
    }

    void setDictOp() { 
        is_dict_ = true;
        // dict's operand values should be traced for future mutations.
        trace_flag_ = true;
    }
    
    bool isDictOp() { return is_dict_; }
    trace_entry_t* pickRandomDictValue() {
        trace_entry_t* ent;
        size_t pick = mangle_get_index(dict_values_->cnt);
        if (!dict_values_->cnt) // no remaining dict value. return empty
            return nullptr;
        
        ent = dict_values_->first;
        for (int i = 0; i < pick; i++) {
            DR_ASSERT(ent != nullptr);
            ent = ent->next;
            // size_t read;
            // if (!dr_safe_read(&(ent->next), sizeof(ent), &ent, &read)) {
            //     dr_fprintf(STDERR, "dict list smashing detected... i : %d, ent : 0x%lx, cnt : %d\n", i, ent, dict_values_->cnt);
            //     dr_exit_process(-1);
            // }
        }

        return ent;
    }

    uint32_t getOffset() { return offset_; }
    bool isTraced() { return trace_flag_; }
    bool isMutationTarget() { 
        // `MUTATION_TYPE_NONE` indicates that it's not a mutation target.
        return mut_type_ != MUTATION_TYPE_NONE; 
    }
    bool dump_flag() { return dump_flag_; }
    mut_type_t getTraceType() { return mut_type_; }

    /**
     *  @brief mark this `BenzeneOp` for fuzzing (i.e., mutation target)
     */
    void pick() {
        DR_ASSERT_MSG(max_hit_cnt_, "max_hit_cnt_ is 0");
        // mutation-time (when this will be mutated) is randomly selected
        picked_ = util_rndGet(hit_cnt_ + 1, max_hit_cnt_);
    }
    bool isPickedForFuzz() { return picked_ == 0 ? false : true; }
    void fuzzed() {
        is_fuzzed_ = true;
    }
    bool isFuzzed() { return is_fuzzed_; }
    void appendMutation(mutation_t* p_mutation) {
        DR_ASSERT(drvector_append(&mutations_, p_mutation));
    }
    size_t getMutationCnt() {
        return mutations_.entries;
    }

    mutation_t* getMutation(int i) {
        return (mutation_t*)drvector_get_entry(&mutations_, i);
    }

    void fuzzContent(char* content, size_t len);
    int fuzzContentByDict(char* content, size_t len);
    int fuzzASCII(char* content, int len, char* old_content);

    trace_val_t* getTraces() {
        if (getTraceCount() == 0) {
            return nullptr;
        }

        trace_entry_t* cur_ent = uniq_traces_tail_;
        trace_val_t* traces = (trace_val_t*)dr_global_alloc(getTraceCount()*sizeof(trace_val_t));

        if (traces == nullptr) {
            DR_ASSERT_MSG(false, "dr_global_alloc() failed");
        }
        size_t trace_cnt = 0;
        
        // first item for traces
        traces[trace_cnt++] = cur_ent->val;

        // we iterate over all the observed (unique) trace values
        while (cur_ent->next) {
            cur_ent = cur_ent->next;
            traces[trace_cnt++] = cur_ent->val;
        }

        DR_ASSERT(trace_cnt == getTraceCount());

        return traces;
    }

    reg_id_t getReg() {
        if (!isRegOp())
            return DR_REG_NULL;
        return opnd_get_reg(dr_opnd_);
    }

    uint32_t read_size() { return read_size_; }

    uint getTraceCount() {
        return TRACE_SIZE();
    }

    json_val_t toJSON(rapidjson_allocator_t allocator);
    trace_val_t trace_val_at(uint32_t idx) {
        trace_entry_t* ent = uniq_traces_tail_;

        for (int i = 0; i < idx; i++) {
            DR_ASSERT(ent != nullptr);

            ent = ent->next;
        }

        return ent->val;
    }

    trace_entry_t* getLastEntry() {
        return uniq_traces_tail_;
    }

    uint32_t getHitCnt() { return hit_cnt_; }
    uint32_t getMaxHitCnt() { return max_hit_cnt_; }

    void hit() { hit_cnt_++; }
    
    bool hitAfterFuzz() {
        // this flag is set when is_reached is enabled
        // So, we check this flag for checking that the fuzzing target has been reached and other flags at the same time.
        if (is_hit_after_fuzz_)
            return true;

        if (is_reached) {
            trace_flag_ |= true;
            dump_flag_ |= true;
            is_hit_after_fuzz_ |= true;
            exec_order_ = cur_exec_order++;
            return true;
        }

        return false;
    }

    bool isHitAfterFuzz() {
        return is_hit_after_fuzz_;
    }

    void initDictValuesShm(dict_values_t* dict_values) {
        DR_ASSERT(dict_op_);

        dict_values->mt = this;
        dict_values->dict = dict_op_;
        dict_values->first = nullptr;
        dict_values->cnt = 0;
        dict_values_ = dict_values;
    }

    /**
     *
     */ 
    trace_val_t* collectDictValues(size_t* OUT cnt) {        
        DR_ASSERT(isMutationTarget());
        DR_ASSERT(dict_op_);

        // if (dict_op_->getTraceCount() > UNIQUE_TRACE_THRESHOLD) {
        //      /* do something */
        // }
        if (dict_op_->getTraceCount() == 0) {
            dr_fprintf(STDERR, "[WARNING] BenzeneOp(0x%lx): dict_op_(0x%lx)'s trace count is 0\n", getOffset(), dict_op_->getOffset());
            return nullptr;
        }
        trace_val_t* traces = dict_op_->getTraces();
        if (!traces) {
            DR_ASSERT_MSG(false, "failed to retreive trace values from `dict_op_`");
        }
        *cnt = dict_op_->getTraceCount();
        
        // WARNING: traces should be free'd after it's usage
        return traces;
    }


    void pushDictValue(trace_val_t val) {
        trace_entry_t* dict_ent = (trace_entry_t*)benzene_shm_malloc(sizeof(trace_entry_t));
        if (!dict_ent) {
            dr_fprintf(STDERR, "benzene_shm_malloc() failed (all memory exhausted)\n");
            dr_fprintf(STDERR, "offset 0x%lx(%s)'s trace_entry count : %d\n", getOffset(), getOpName(), getTraceCount());
            removeShm();
            DR_ASSERT(false);
        }
        dict_ent->val = val;
        dict_ent->prev = nullptr;
        dict_ent->next = nullptr;

        if (dict_values_->cnt == 0) {
            dict_values_->first = dict_ent;
            dict_values_->cnt++;
            return;
        }

        // push `dict_ent` in front of `dict_values_`
        trace_entry_t* next = dict_values_->first;
        dict_values_->first = dict_ent;
        dict_ent->next = next;
        next->prev = dict_ent;

        dict_values_->cnt++;
    }

    void popDictValue(trace_entry_t* ent) {
        trace_entry_t* prev = ent->prev;
        trace_entry_t* next = ent->next;
        if (prev) prev->next = next;
        if (next) next->prev = prev;

        dict_values_->cnt--;

        if (!dict_values_->cnt) { // all dicts are exhausted
            dict_values_->first = nullptr;
        }
    }

    void replayMutation(char* content, size_t len);

    static void processRegRead(reg_id_t reg, uint32_t read_size, BenzeneOp* op);
    static void processMemRead(void* mem_addr, uint32_t read_size, BenzeneOp* op);
    static void processDummyOp(BenzeneOp* op);
};

// typedef std::vector<BenzeneOp*> src_ops_t;
typedef drvector_t src_ops_t;

#endif