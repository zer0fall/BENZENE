#ifndef __DYN_CHAIN_H__
#define __DYN_CHAIN_H__

#include "pin.H"
#include <iostream>
#include "signal.h"

#include "libdft_api.h"
#include "libdft_core.h"
#include "tag_traits.h"
#include "ins_helper.h"

#include "linux_fn.h"
#include "callstack_manager.h"
#include "vfg_modules.h"
#include "value_core.h"
#include "vfg.h"

#ifdef DEBUG_FILTER
#define FILTER_LOG(...) \
do {                          \
    fprintf(stderr, __VA_ARGS__); \
} while (0)
#else
#define FILTER_LOG(...)
#endif

class DynVFG {
public:

typedef uint32_t taint_t;
typedef std::string name_t;

private:
    VFGModules* modules_; // module (image) management
    VFGCore* core_;
    CallstackManager* cstack_manager;
    std::string out_name_;

    // images which are waiting to be resolved
    std::map<name_t, IMG> imgs_;
    bool checkASLR();

public:
    DynVFG();
    ~DynVFG() {
        delete modules_;
    }

    VOID activate();

    VOID setCurrentVFGNode(InsNode* node) { core_->setCurrentNode(node); }
    VOID setCurrentVFGCMPNode(InsNode* node) { core_->setCurrentCMPNode(node); }
    
    static VOID instrumentTrace(TRACE trace, void* v);

    VOID handleInst(THREADID tid, ADDRINT addr, InsNode* node) {
        core_->handleInst(tid, addr, node);
    };

    VOID handleCMPInst(THREADID tid, ADDRINT addr, InsNode* node) {
        core_->handleCMPInst(tid, addr, node);
    }

    InsNode* requestNode(INS ins) {
        InsNode* node = core_->requestNode(INS_Address(ins));
        node->setType(INS_Category(ins));
        return node;
    }

    static PIN_FAST_ANALYSIS_CALL 
    VOID onInstExec(THREADID tid, ADDRINT ip, DynVFG* vfg, InsNode* node);

    static PIN_FAST_ANALYSIS_CALL
    VOID onCMPInstExec(THREADID tid, ADDRINT ip, DynVFG* vfg, InsNode* node);

    LinuxFn* getCallstackTopFn(THREADID tid) { return cstack_manager->getCallstackTopElem(tid)->fn; };
    
    VOID handleIMG(IMG img);
    VOID addTargetIMG(std::string img_name);
    VOID handleRegResult(THREADID tid, REG reg);
    VOID handleMemResult(ADDRINT mem_addr, uint32_t mem_size);
    
    // int createResultJSON();
    int createResult(std::string out_dir);

    bool isAddrInAnalysisTarget(ADDRINT addr) { return modules_->checkAddr(addr); };

    VOID PrintTaints();
};

#endif