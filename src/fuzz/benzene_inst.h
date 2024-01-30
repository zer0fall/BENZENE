#ifndef __BENZENE_INST_H__
#define __BENZENE_INST_H__

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
#include "benzene_modules.h"
#include "benzene_op.h"
#include "benzene_mutation.h"

#include "drvector.h"

#ifndef DR_APP_PC_ADD
#define DR_APP_PC_ADD(x, y) (app_pc)((uint64_t)(x) + (uint64_t)(y))
#endif

#ifndef DR_APP_PC_SUB
#define DR_APP_PC_SUB(x, y) (app_pc)((uint64_t)(x) - (uint64_t)(y))
#endif

#define SRC_OPS_SIZE() (src_ops_.entries)
#define SRC_OP_AT(i)    ((BenzeneOp*)drvector_get_entry(&src_ops_, i))

extern benzene_opt_t option;

class BenzeneInst {
private:
    app_pc addr_ = 0x0;
    uint32_t offset_ = 0x0;
    char img_name_[MAX_MODULE_NAME_LEN];
    bool is_parsed_ = false;
    bool is_triage_inst_ = false;
    src_ops_t src_ops_;     // BenzeneOps for this instruction
    // char disasm_[64];

public:
    BenzeneInst(app_pc addr, uint32_t offset, const char* img_name) :
        addr_(addr),
        offset_(offset) 
    {
        DR_ASSERT(offset);
        strncpy(img_name_, img_name, sizeof(img_name_));
        if (!drvector_init(&src_ops_, 0, false, NULL)) {
            dr_fprintf(STDERR, "drvector_init() failed\n");
            dr_exit_process(-1);
        }
    };
    BenzeneInst(uint32_t offset, const char* img_name) :
        offset_(offset)
    {
        DR_ASSERT(offset);
        strncpy(img_name_, img_name, sizeof(img_name_));
        if (!drvector_init(&src_ops_, 0, false, NULL)) {
            dr_fprintf(STDERR, "drvector_init() failed\n");
            dr_exit_process(-1);
        }
    };

    BenzeneInst(json_val_t obj) {
        if (!drvector_init(&src_ops_, 0, false, NULL)) {
            dr_fprintf(STDERR, "drvector_init() failed\n");
            dr_exit_process(-1);
        }
        DR_ASSERT(obj.IsObject() == true);
        fromJSON(obj.GetObject());
    }    

    int parse(void *drcontext, instr_t* ins);
    int parse();
    bool isParsed() {
        // parsed instruction would have src operands
        return is_parsed_;
    }

    void setParseFlag() {
        is_parsed_ = true;
    }
    void setAddr(app_pc addr) { addr_ = addr; }
    app_pc getAddr() { return addr_; }
    uint32_t getOffset() { return offset_; }
    char* getImgName() { return img_name_; }
    size_t getSrcOpsSize() { return SRC_OPS_SIZE(); }

    drvector_t* getSrcOps() { return &src_ops_; }
    BenzeneOp* getSrcOp(int i) { return SRC_OP_AT(i); }
    BenzeneOp* getSrcOp(const char* op_name) { 
        BenzeneOp* op;

        for (int i = 0; i < SRC_OPS_SIZE(); i++) {
            op = SRC_OP_AT(i);
            if (!strncmp(op->getOpName(), op_name, strlen(op_name))) {
                return op;
            }
        }        

        return nullptr;
    }

    void addSrcOp(BenzeneOp* op) {
        drvector_append(&src_ops_, op);
    }

    size_t getMutTargetCnt(BenzeneOp** ops_buf) {
        BenzeneOp* op;
        size_t cnt = 0;
        

        for (int i = 0; i < SRC_OPS_SIZE(); i++) {
            op = SRC_OP_AT(i);
            if (op->isMutationTarget()) {
                ops_buf[cnt] = op;
                cnt++;
            }
        }        

        return cnt;
    }
    
    void disableTrace() {
        for (int i = 0; i < SRC_OPS_SIZE(); i++) {
            SRC_OP_AT(i)->set_trace_flag(false);
        }
    }

    bool hasMutationTarget() { 
        for (int i = 0; i < SRC_OPS_SIZE(); i++) {
            if (SRC_OP_AT(i)->isMutationTarget())
                return true;
        }
        return false;
    }

    bool hasDictTargetOp() { 
        for (int i = 0; i < SRC_OPS_SIZE(); i++) {
            if (SRC_OP_AT(i)->isDictOp())
                return true;
        }
        return false;
    }

    bool isTraced() {
        for (int i = 0; i < SRC_OPS_SIZE(); i++) {
            if (SRC_OP_AT(i)->isTraced())
                return true;
        }
        return false; 
    }

    bool isDumpTarget() { 
        for (int i = 0; i < SRC_OPS_SIZE(); i++) {
            if (SRC_OP_AT(i)->dump_flag())
                return true;
        }

        return false; 
    }

    int instrument(void* drcontext, instrlist_t* bb, instr_t* ins);

    uint32_t getHitCnt() {
        if(!getSrcOpsSize()) {
            return 0;
        }
        
        BenzeneOp* first_src_op = getSrcOp(0);

        DR_ASSERT(first_src_op);

        return first_src_op->getHitCnt();
    }

    json_val_t toJSON(rapidjson_allocator_t alloc);
    void fromJSON(json_val_t inst_json);
};

#endif


