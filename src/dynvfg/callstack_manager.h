#ifndef __FN_TRACKER_H__
#define __FN_TRACKER_H__

#include "pin.H"

#include "tag_traits.h"
#include "linux_fn.h"
#include <iostream>

#include <map>

#ifdef DEBUG_TRACK
#define TRACK_LOG(...)            \
do {                              \
    fprintf(stderr, __VA_ARGS__); \
} while (0)
#else
#define TRACK_LOG(...)
#endif


class CallstackManager {
public:
#define REGISTER_CALLBACK_ON_CALL(i, cb, r, t) INS_InsertCall(i, IPOINT_BEFORE, (AFUNPTR)cb, \
                                                        IARG_FAST_ANALYSIS_CALL, \
                                                        IARG_THREAD_ID, \
                                                        IARG_INST_PTR, \
                                                        IARG_BRANCH_TARGET_ADDR, \
                                                        IARG_ADDRINT, r, \
                                                        IARG_PTR, t, IARG_END)
#define REGISTER_CALLBACK_ON_BRANCH(i, cb, fn, t) INS_InsertCall(i, IPOINT_BEFORE, (AFUNPTR)cb, \
                                                        IARG_FAST_ANALYSIS_CALL, \
                                                        IARG_THREAD_ID, \
                                                        IARG_INST_PTR, \
                                                        IARG_BRANCH_TARGET_ADDR, \
                                                        IARG_PTR, fn, \
                                                        IARG_PTR, t, IARG_END)

#define DECLARE_CALL_CALLBACK(f, x)    static PIN_FAST_ANALYSIS_CALL VOID f(THREADID tid, ADDRINT ip, ADDRINT target_addr, ADDRINT ret, x xthis);
#define DECLARE_BRANCH_CALLBACK(f, x)  static PIN_FAST_ANALYSIS_CALL VOID f(THREADID tid, ADDRINT ip, ADDRINT target_addr, LinuxFn* fn, x xthis);

// information of function in callstack
typedef struct callstack_element {
    ADDRINT target_addr;
    ADDRINT ret_addr;
    ADDRINT caller_addr;
    LinuxFn* fn;
    bool is_heap_fn;
    uint32_t hit_cnt;
} cs_elem_t;

typedef std::vector<cs_elem_t> cstack_t; // callstack type

private:
    std::vector<cstack_t*> callstacks_; // callstack for each thread
    std::map<ADDRINT, LinuxFn*> functions_; // set of executed functions

    std::map<std::string, IMG> loaded_imgs_;
    std::map<std::string, std::vector<fn_call_t>> fns_unresolved_; // {image name, fn_call_t list} pair

    cs_elem_t dummy_cs_;
    cstack_t callstack_setjmp_;

public:
    CallstackManager();
    
    int activate();

    // Instrumentation functions
    static VOID instrumentTrace(TRACE trace, void * v);
    VOID instrumentCall(INS ins, void* v);
    VOID instrumentRet(INS ins, void* v);
    VOID instrumentDirectJmp(INS ins, void* v);
    VOID instrumentIndirectJmp(INS ins, void* v);
    VOID instrumentPLTStub(TRACE trace, INS ins, void* v);

    static VOID onIMGLoad(IMG img, void* v);
    static VOID onThreadAlloc(THREADID threadIndex, CONTEXT* ctxt, INT32 flags, VOID* v);
    static VOID onThreadExit(THREADID threadIndex, const CONTEXT* ctxt, INT32 code, VOID* v);

    // @TODO: implement setjmp_handler, longjmp_handler
    static PIN_FAST_ANALYSIS_CALL VOID  setjmp_handler(THREADID tid, CallstackManager* xthis);
    static PIN_FAST_ANALYSIS_CALL VOID longjmp_handler(THREADID tid, CallstackManager* xthis);

    void allocCallstack(THREADID tid);
    void freeCallstack(THREADID tid);

    /*
     * if `addr` exists in `functions_`, returns that function.
     * else, NULL is returned.
     */
    LinuxFn* searchFn(ADDRINT addr) { 
        std::map<ADDRINT, LinuxFn*>::iterator iter = functions_.find(addr);
        if (iter == functions_.end())
            return NULL;
        return iter->second;
    }
    LinuxFn* requestFn(ADDRINT a); //https://stackoverflow.com/questions/8800770/stl-map-operator-bad
    
    void resolvePLT();
    static bool isPLT(ADDRINT a);
    static bool isPLT(TRACE trace);

    cstack_t* getCallstack(THREADID tid) { return callstacks_[tid]; }
    cs_elem_t* getCallstackTopElem(THREADID tid) { return &(callstacks_[tid]->back()); }

    void pushCallstack(THREADID tid, ADDRINT a, ADDRINT r) {
        LinuxFn* p_fn = searchFn(a);

        assert(p_fn != NULL);

        p_fn->hit();

        // For performance boost, p_fn's value is not checked (whether it is NULL or not).
        cs_elem_t e = {a, r, callstacks_[tid]->back().target_addr, p_fn, false, p_fn->getHitCnt()};
        callstacks_[tid]->push_back(e);        
    }

    void pushCallstack(THREADID tid, ADDRINT to_where, ADDRINT ret_addr, LinuxFn* p_fn) {
        p_fn->hit();

        cs_elem_t e = {to_where, ret_addr, callstacks_[tid]->back().target_addr, p_fn, false, p_fn->getHitCnt()};
        callstacks_[tid]->push_back(e);
    }

    void popCallstack(THREADID tid) { callstacks_[tid]->pop_back(); }

    void replaceCallstackTopElem(THREADID tid, LinuxFn* p_fn) {
        assert(p_fn != NULL);

        p_fn->hit();

        cs_elem_t* e = getCallstackTopElem(tid);
        
        assert(e);

        e->target_addr = p_fn->getAddr();
        e->hit_cnt = p_fn->getHitCnt();
        e->fn = p_fn;
    }

    bool checkCallstack(THREADID tid, ADDRINT r) { // check callstack's return address mismatch        
        if (callstacks_[tid]->back().ret_addr != r) {
            LOG("[WARNING] Callstack check failed (tid:" 
                    + decstr(tid) + ", ret addr : " + hexstr(r) +")\n");
            return false;
        }
        return true;
    }

    void adjustCallstack(THREADID tid, ADDRINT ret_addr);
    void saveCallstackForSetJmp(THREADID tid);
    void restoreCallstackForLongJmp(THREADID tid);
    int toCSV(std::string path);

private:
    static PIN_FAST_ANALYSIS_CALL 
    VOID DirectCallCB(THREADID tid, ADDRINT ip, ADDRINT target_addr, ADDRINT ret, CallstackManager* xthis, LinuxFn* fn);
    
    static PIN_FAST_ANALYSIS_CALL 
    VOID IndirectCallCB(THREADID tid, ADDRINT ip, ADDRINT target_addr, ADDRINT ret, CallstackManager* xthis);

    static PIN_FAST_ANALYSIS_CALL 
    VOID DirectJmpCB(THREADID tid, ADDRINT ip, ADDRINT target_addr, CallstackManager* xthis);

    static PIN_FAST_ANALYSIS_CALL 
    VOID IndirectJmpCB(THREADID tid, ADDRINT ip, ADDRINT target_addr, CallstackManager* xthis);

    static PIN_FAST_ANALYSIS_CALL 
    VOID PLTCallCB(THREADID tid, ADDRINT ip, ADDRINT target_addr, ADDRINT ret, CallstackManager* xthis, LinuxFn* fn);
    
    static PIN_FAST_ANALYSIS_CALL 
    VOID RetCB(THREADID tid, ADDRINT ip, ADDRINT target_addr, CallstackManager* xthis);

    DECLARE_BRANCH_CALLBACK(PLTStubCB, CallstackManager*);

public: // Debugging methods
    void print();
    void printFnKind();
    void printCallstack(THREADID tid);
};


inline VOID CallstackManager::instrumentCall(INS ins, void* v ) {
    ADDRINT ret = INS_Address(ins) + INS_Size(ins); // return address of this call

    if( INS_IsDirectControlFlow(ins) ) {
        ADDRINT to_where = INS_DirectBranchOrCallTargetAddress(ins);
        
        LinuxFn* p_fn = requestFn(to_where);
        if ( (p_fn->isExternal() == true)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CallstackManager::PLTCallCB,
                        IARG_FAST_ANALYSIS_CALL, 
                        IARG_THREAD_ID, 
                        IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, 
                        IARG_ADDRINT, ret, 
                        IARG_PTR, v, 
                        IARG_PTR, p_fn,
                        IARG_END);
        }
        else {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CallstackManager::DirectCallCB, 
                        IARG_FAST_ANALYSIS_CALL, 
                        IARG_THREAD_ID, 
                        IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, 
                        IARG_ADDRINT, ret, 
                        IARG_PTR, v, 
                        IARG_PTR, p_fn,
                        IARG_END);
        }
    }
    else { // Indirect call
        // fprintf(stderr, "INS : 0x%lx => %s\n", INS_Address(ins), INS_Disassemble(ins).c_str());
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CallstackManager::IndirectCallCB, 
                    IARG_FAST_ANALYSIS_CALL, 
                    IARG_THREAD_ID, 
                    IARG_INST_PTR, 
                    IARG_BRANCH_TARGET_ADDR, 
                    IARG_ADDRINT, ret, 
                    IARG_PTR, v, 
                    IARG_END);
    }
}

inline VOID CallstackManager::instrumentRet(INS ins, void* v) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CallstackManager::RetCB,
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_THREAD_ID,
                    IARG_INST_PTR,
                    IARG_BRANCH_TARGET_ADDR,
                    IARG_PTR, v, IARG_END);
}

inline VOID CallstackManager::instrumentDirectJmp(INS ins, void* v) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CallstackManager::DirectJmpCB, 
                    IARG_FAST_ANALYSIS_CALL, 
                    IARG_THREAD_ID, 
                    IARG_INST_PTR, 
                    IARG_BRANCH_TARGET_ADDR, 
                    IARG_PTR, v, 
                    IARG_END);
}

inline VOID CallstackManager::instrumentIndirectJmp(INS ins, void* v) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CallstackManager::IndirectJmpCB, 
                    IARG_FAST_ANALYSIS_CALL, 
                    IARG_THREAD_ID, 
                    IARG_INST_PTR, 
                    IARG_BRANCH_TARGET_ADDR, 
                    IARG_PTR, v, 
                    IARG_END);
}

inline VOID CallstackManager::instrumentPLTStub(TRACE trace, INS ins, void* v) {
    LinuxFn* p_fn = searchFn(TRACE_Address(trace)); // TRACE_Address(trace) : @plt's head
    if (p_fn != NULL) {
        // fprintf(stderr, "searchFn p_fn : %s(0x%lx)\n", p_fn->getFnName().c_str(), p_fn->getAddr() );
        if (INS_IsIndirectControlFlow(ins)) { // check "jmp qword ptr [rip+0x~]" format    
            // fprintf(stderr, "[%s] %s : 0x%lx\n", p_fn->getPLTFnName().c_str(), INS_Disassemble(tail).c_str(), INS_MemoryDisplacement(tail));
            p_fn->setGOTAddr(p_fn->getPltAddr() + INS_Size(ins) + INS_MemoryDisplacement(ins));
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CallstackManager::PLTStubCB, 
                        IARG_FAST_ANALYSIS_CALL, 
                        IARG_THREAD_ID, 
                        IARG_INST_PTR, 
                        IARG_BRANCH_TARGET_ADDR, 
                        IARG_PTR, p_fn, 
                        IARG_PTR, v, 
                        IARG_END);
        }
    }
}

inline bool CallstackManager::isPLT(ADDRINT a) { // check if current address is in plt routine.
    PIN_LockClient();
    RTN rtn = RTN_FindByAddress(a);
    PIN_UnlockClient();

    // All .plt thunks have a valid RTN
    if (!RTN_Valid(rtn))
        return false;

    if (".plt" == SEC_Name(RTN_Sec(rtn)))
        return true;
    return false;
}

inline bool CallstackManager::isPLT(TRACE trace) {
    RTN rtn = TRACE_Rtn(trace);

    // All .plt thunks have a valid RTN
    if (!RTN_Valid(rtn))
        return false;

    if (".plt" == SEC_Name(RTN_Sec(rtn)))
        return true;
    return false;
}

#endif