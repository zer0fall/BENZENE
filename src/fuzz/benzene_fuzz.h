#ifndef __BENZENE_FUZZ_H__
#define __BENZENE_FUZZ_H__

#include <stddef.h> /* for offsetof */
#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drx.h"
#include "drutil.h"
#include "dr_config.h"
#include "droption.h"

#include <map>
#include "sqlite3.h"
#include "benzene_common.h"
#include "benzene_opt.h"
#include "benzene_proc.h"
#include "benzene_inst.h"
#include "benzene_mutation.h"
#include "benzene_shared.h"
#include "benzene_modules.h"
#include <dirent.h>

#ifndef DR_APP_PC_ADD
#define DR_APP_PC_ADD(x, y) (app_pc)((uint64_t)(x) + (uint64_t)(y))
#endif

#define SQL_CHECK(r, err)  if (r != SQLITE_OK) { \
                                    sqlite3_free(err); \
                                    sqlite3_close(db); \
                                    return -1; }

#define STORE_TRACE(id, img_name, offset, p_trace_val)  store(id, \
                                            img_name, \
                                            offset, \
                                            op->getOpName().c_str(), \
                                            p_trace_val)


#define MUTATION_TARGET_AT(idx)     ((BenzeneOp*)(drvector_get_entry(&mutation_targets_, idx)))
#define MUTATION_TARGET_SIZE      mutation_targets_.entries

#define EDGE_COV_MAP_SIZE 65536

extern bool is_reached;
extern sqlite3_stmt * v_insert_stmt;
extern sqlite3_stmt * v_insert_seed_stmt;
extern benzene_proc_t* proc;
extern benzene_opt_t option;

typedef struct {
    char module_name[MAX_MODULE_NAME_LEN];
    drvector_t insts;
} module_insts_t;


#define MAXIMUM_FD_CNT 128
#define INVALID_FD     -1
typedef struct {
    int fd;
    int64_t tell;
} opened_fd_t;

class BenzeneFuzz {

private:
    BenzeneModule* modules_;
    std::map<app_pc, BenzeneInst*> insts_;
    module_insts_t* insts_module_load_waiting_[MAXIMUM_MODULE_CNT] = { nullptr, };

    benzene_config_t config_;

    drvector_t mutation_targets_; // array of mutation targets (i.e., operands in instruction)
    mt_pick_t mt_picks = { 0, };  // chosen indices of `mutation_targets_` for mutation

    uint32_t    cur_fuzz_addr_hit_ = 0;
    BenzeneInst* triage_inst_ = nullptr;

    // edge coverage measurement related variables
    int         tls_slot_; // for edge coverage measurement
    // unsigned char cov_map_[EDGE_COV_MAP_SIZE] = {0, };
    // uint64_t      collect_cov_ = 1;

    mut_history_t history_;

    opened_fd_t opened_fds_[MAXIMUM_FD_CNT] = {-1, };


    int createDB(const char* dbname);
    void store(uint32_t id, const char* img, uint32_t offset, const char* op_name, trace_val_t* p_val) {
        sqlite3_bind_int(v_insert_stmt, 1, id);
        sqlite3_bind_int(v_insert_stmt, 2, offset);
        sqlite3_bind_text(v_insert_stmt, 3, img, -1, SQLITE_STATIC);
        sqlite3_bind_text(v_insert_stmt, 4, op_name, -1, SQLITE_STATIC);
        sqlite3_bind_blob64(v_insert_stmt, 5, p_val, sizeof(uint64_t), NULL);
        // sqlite3_bind_int64(stmt, 5, val);
        
        DR_ASSERT_MSG(sqlite3_step(v_insert_stmt) == SQLITE_DONE, "sqlite3_step() failed");
        sqlite3_reset(v_insert_stmt);
    }

    void store_used_val(uint32_t id, 
                        const char* img, 
                        uint32_t offset, 
                        const char* op_name, 
                        uint32_t hit_cnt, 
                        trace_val_t* p_old, 
                        trace_val_t* p_val, 
                        mut_type_t seed_type) {
        int r;
        char* err_msg;

        sqlite3_bind_int(v_insert_seed_stmt, 1, id);
        sqlite3_bind_int(v_insert_seed_stmt, 2, offset);
        sqlite3_bind_text(v_insert_seed_stmt, 3, img, -1, SQLITE_STATIC);
        sqlite3_bind_text(v_insert_seed_stmt, 4, op_name, -1, SQLITE_STATIC);
        sqlite3_bind_int(v_insert_seed_stmt, 5, hit_cnt);
        sqlite3_bind_blob64(v_insert_seed_stmt, 6, p_old, sizeof(uint64_t), NULL);
        sqlite3_bind_blob64(v_insert_seed_stmt, 7, p_val, sizeof(uint64_t), NULL);
        sqlite3_bind_int(v_insert_seed_stmt, 8, seed_type);
        
        sqlite3_step(v_insert_seed_stmt);
        sqlite3_reset(v_insert_seed_stmt);
    }

    bool checkSanity();
    int saveFuzzResult();

    int initMutationTargets();
    void pickMutationTargets();
    void setMutationForTrace();
    void dumpMemoryMaps(const char* path);

public:
    BenzeneFuzz() {
        // runner_ = new BenzeneRunner();
        proc = (benzene_proc_t*)dr_global_alloc(sizeof(benzene_proc_t));
        modules_ = new BenzeneModule();
        
        /* prevent memory corruption of current class */
        // dr_memory_protect(proc, sizeof(benzene_proc_t), BENZENE_PROT_READ);

        if (!drvector_init(&mutation_targets_, 0, false, NULL)) {
            dr_fprintf(STDERR, "drvector_init() failed\n");
            dr_exit_process(-1);
        }

        tls_slot_ = drmgr_register_tls_field();
        if(tls_slot_ == -1) 
            DR_ASSERT_MSG(false, "error reserving TLS field");
    };
    int getTLS() { return tls_slot_; }

    bool handleModuleLoad(const module_data_t* mod);
    void addTargetModule(const char* module_name);
    app_pc getModuleBase(app_pc addr) {
        return modules_->getModuleBase(addr);
    }
    void sendFuzzedMutationTarget();

    void appendMutationTarget(BenzeneOp* op) {
        drvector_append(&mutation_targets_, op);    
    };

    void hitFuzzTarget() {
        DR_ASSERT_MSG(option.hitcnt_for_kickoff, "hit count for fuzzing kick-off is not provided");

        cur_fuzz_addr_hit_++;

        if (cur_fuzz_addr_hit_ == option.hitcnt_for_kickoff) {
            is_reached = true;

            // dryrun mode does not perform fuzzing
            if (checkMode(option, BENZENE_MODE_DRYRUN)) return;

            // double-check the initialization of each seed's information
            for (uint i = 0; i < MUTATION_TARGET_SIZE; i++) {
                BenzeneOp* seed = MUTATION_TARGET_AT(i);

                if (!seed) {
                    dr_fprintf(STDERR, "Error: seed (0x%lx, %s) is not initialized.\n", seed->getOffset(), seed->getOpName());
                    DR_ASSERT(false);
                }
                
                if (!seed->getDictOp()) {
                    dr_fprintf(STDERR, "Error: dict is not initialized (seed: 0x%lx (%s)).\n", seed->getOffset(), seed->getOpName());
                    DR_ASSERT(false);
                }
            }

            if (checkMode(option, BENZENE_MODE_FUZZ))
                fuzz(); // kick off the fuzzing
            else if (checkMode(option, BENZENE_MODE_TRACE))
                trace();
        }
    }

    void fuzz();
    void trace();
    
    void instrument_trace(void *drcontext, instrlist_t *bb, instr_t *inst, app_pc pc);
    void instrument_fuzz(void *drcontext, instrlist_t *bb, instr_t *inst, app_pc pc);
    void instrument_dryrun_fuzz(void *drcontext, instrlist_t *bb, instr_t *inst, app_pc pc);
    void instrument_dryrun_trace(void *drcontext, instrlist_t *bb, instr_t *inst, app_pc pc);    
    void instrument_edge_coverage(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst);

    // to check non-crash manually
    void instrumentCrashAddr(void *drcontext, instrlist_t *bb, instr_t *inst, app_pc pc, void* fn) {
        if (pc == option.initial_crash_addr) {
            dr_insert_clean_call(drcontext, bb, inst, fn,
                                    false, 1, OPND_CREATE_INTPTR(this));
        }        
    }

    int requestDBSlot();
    
    void onSignal(void *drcontext, dr_siginfo_t *siginfo);
    void onProcessExit();

    int readConfigFromJSON(const char* path);
    int writeConfig(const char* out_filename);
    int deserialize(const char* input, size_t length);

    int initDB();

    bool isTriageHit();
    void adjustCovStatus();

    uint32_t getCorpusId() { return proc->run_id; }

    bool isInstrumentAddr(app_pc addr) {
        if (modules_->isTargetModule(addr))
            return true;
        return false;
    }

    BenzeneInst* createInst(void* drcontext, app_pc addr, uint32_t offset, const char* img_name) {
        instr_t instr;
        BenzeneInst* inst = new BenzeneInst(addr, offset, img_name);
        DR_ASSERT(decode(drcontext, addr, &instr));
        inst->parse(drcontext, &instr);

        auto iter = insts_.insert({addr, inst});

        return inst;
    }

    void handleCrash(app_pc crash_addr);
    void checkFalseCrash(app_pc crash_addr) {
        if (crash_addr != option.initial_crash_addr || !isTriageHit()) {        
            // if current crash's location is different from the original poc, we assume it as "false crash"
            setStatus(proc, PROC_STATUS_FALSE_CRASH);
        }
        else {
            setStatus(proc, PROC_STATUS_CRASH);
        }
    }

    int dumpCorpus(const char* db_name, int corpus_id);
    int dumpTrace(const char* db_name, int corpus_id);
    int saveMutationResult(int corpus_id);

    size_t getInstSize() { return insts_.size(); };
    BenzeneInst* getInst(app_pc addr) {
        auto iter = insts_.find(addr);

        if (iter == insts_.end())
            return nullptr;
        
        return iter->second;
    }

    static void hitFuzzTarget_wrapper(BenzeneFuzz* bfuzz) {
        bfuzz->hitFuzzTarget();
    }

    int saveEdgeCoverage(const char* path);
    int exitDryrun(int corpus_id);
};

#endif