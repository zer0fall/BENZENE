#include "callstack_manager.h"
#include <fstream>

CallstackManager::CallstackManager()
{
    callstacks_.reserve(20);
    dummy_cs_ = { 0, 0, 0, new LinuxFn(0, true, 0), false}; // for empty callstack
};

/*
 * activate instrumentation for tracking Call/Ret pair
 */
int CallstackManager::activate() { // CallstackManager starts to track functions...
    TRACE_AddInstrumentFunction(instrumentTrace, this);
    PIN_AddThreadStartFunction(onThreadAlloc, this);
    PIN_AddThreadFiniFunction(onThreadExit, this);
    IMG_AddInstrumentFunction(onIMGLoad, this);
    return 0;
}

VOID CallstackManager::instrumentTrace(TRACE trace, void* v) {
    CallstackManager *xthis = reinterpret_cast<CallstackManager*>(v);

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        INS tail = BBL_InsTail(bbl);

        if (INS_IsCall(tail)) {
            xthis->instrumentCall(tail, xthis);
        }
        else if (CallstackManager::isPLT(trace)) { // .plt stub case            
            xthis->instrumentPLTStub(trace, tail, xthis);
        }
        else if( INS_IsRet(tail)) {
            xthis->instrumentRet(tail, xthis);
        }
        else if (INS_IsControlFlow(tail)) {
            if (INS_IsDirectBranchOrCall(tail)) {
                xthis->instrumentDirectJmp(tail, xthis);
            }
            else if (INS_IsIndirectBranchOrCall(tail)) {
                xthis->instrumentIndirectJmp(tail, xthis);
            }
        }
    }
}

/*
 * if the funtion at address `addr` already exists in `functions_`, returns that function.
 * else, creates one and returns it.
 */
LinuxFn* CallstackManager::requestFn(ADDRINT addr) {
    LinuxFn* p_fn;
    auto r = functions_.insert( {addr, NULL} );

    if (r.second == false) { // alreadly exists
        return r.first->second;
    } 
    else { 
        uint32_t cur_idx = functions_.size();
        p_fn = new LinuxFn(addr, cur_idx);
        
        r.first->second = p_fn;

        if (isPLT(addr)) {
            p_fn->convertFnPLT();
        }

        return p_fn;
    }
}

void CallstackManager::resolvePLT() {
    std::map<ADDRINT, LinuxFn*>::iterator iter;
    
    for (iter = functions_.begin(); iter != functions_.end(); iter++) {
        LinuxFn* p_fn = iter->second;
        TRACK_LOG(stderr, "resolving 0x%lx (%s)\n", p_fn->getAddr(), p_fn->getFnName().c_str());
        p_fn->setActualAddrFromPLT();
    }
}

VOID CallstackManager::onIMGLoad(IMG img, void* v) {
    RTN rtn;
    CallstackManager* cs_manager = reinterpret_cast<CallstackManager*>(v);

    // setjmp, longjmp handler
    rtn = RTN_FindByName(img, "__longjmp_chk");
    if (RTN_Valid(rtn)) {
        LOG("__longjmp_chk found in " + IMG_Name(img) + "\n");
        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)longjmp_handler, 
                        IARG_THREAD_ID,
                        IARG_PTR, cs_manager,
                        IARG_END);
        RTN_Close(rtn);
    }

    rtn = RTN_FindByName(img, "longjmp");
    if (RTN_Valid(rtn)) {
        LOG("longjmp found in " + IMG_Name(img) + "\n");
        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)longjmp_handler, 
                        IARG_THREAD_ID,
                        IARG_PTR, cs_manager,
                        IARG_END);
        RTN_Close(rtn);
    }

    rtn = RTN_FindByName(img, "siglongjmp");
    if (RTN_Valid(rtn)) {
        LOG("siglongjmp found in " + IMG_Name(img) + "\n");
        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)longjmp_handler, 
                        IARG_THREAD_ID,
                        IARG_PTR, cs_manager,
                        IARG_END);
        RTN_Close(rtn);
    }

    rtn = RTN_FindByName(img, "setjmp");
    if (RTN_Valid(rtn)) {
        LOG("setjmp found in " + IMG_Name(img) + "\n");
        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)setjmp_handler, 
                        IARG_THREAD_ID,
                        IARG_PTR, cs_manager,
                        IARG_END);
        RTN_Close(rtn);
    }

    rtn = RTN_FindByName(img, "_setjmp");
    if (RTN_Valid(rtn)) {
        LOG("_setjmp found in " + IMG_Name(img) + "\n");
        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)setjmp_handler, 
                        IARG_THREAD_ID,
                        IARG_PTR, cs_manager,
                        IARG_END);
        RTN_Close(rtn);
    }

    rtn = RTN_FindByName(img, "__sigsetjmp");
    if (RTN_Valid(rtn)) {
        LOG("__sigsetjmp found in " + IMG_Name(img) + "\n");
        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)setjmp_handler, 
                        IARG_THREAD_ID,
                        IARG_PTR, cs_manager,
                        IARG_END);
        RTN_Close(rtn);
    }
}

VOID CallstackManager::setjmp_handler(THREADID tid, CallstackManager* xthis) {
    LOG("setjmp called\n");
    xthis->printCallstack(tid);
    xthis->saveCallstackForSetJmp(tid);
}

void CallstackManager::saveCallstackForSetJmp(THREADID tid) {
    cstack_t* cur_callstack = callstacks_[tid];
    ASSERT(cur_callstack != nullptr, "invalid callstack");
    
    if (callstack_setjmp_.size() != 0) {
        // cleanup stored setjmp callstack
        callstack_setjmp_.clear();
    }

    for (size_t i = 0; i < cur_callstack->size() - 1; i++) { // copy current callstack except the setjmp call itself
        callstack_setjmp_.push_back(cur_callstack->at(i));
    }
}

void CallstackManager::restoreCallstackForLongJmp(THREADID tid) {
    ASSERT(callstack_setjmp_.size() != 0, "setjmp callstack is not set");

    cstack_t* cur_callstack = callstacks_[tid];

    cur_callstack->clear();

    for (size_t i = 0; i < callstack_setjmp_.size(); i++) {
        cur_callstack->push_back(callstack_setjmp_.at(i));
    }
}


VOID CallstackManager::longjmp_handler(THREADID tid, CallstackManager* xthis) {
    LOG("longjmp called (tid:" + decstr(tid) + ")\n");
    // xthis->printCallstack(tid);
    xthis->restoreCallstackForLongJmp(tid);
}


VOID CallstackManager::onThreadAlloc(THREADID threadIndex, CONTEXT* ctxt, INT32 flags, VOID* v) {
    CallstackManager* xthis = reinterpret_cast<CallstackManager*>(v);
    // new thread is just created, allocate a new callstack
    xthis->allocCallstack(threadIndex);
}

VOID CallstackManager::onThreadExit(THREADID threadIndex, const CONTEXT* ctxt, INT32 code, VOID* v) {
    CallstackManager* xthis = reinterpret_cast<CallstackManager*>(v);
    xthis->freeCallstack(threadIndex);
}

void CallstackManager::allocCallstack(THREADID tid) {
    TRACK_LOG("CallstackManager::allocCallstack - tid %d\n", tid);

    ASSERT(callstacks_.capacity() > tid, "current callstack size is small, extend it");

    ASSERT(callstacks_[tid] == NULL, "tid " + decstr(tid) + " already exists!\n");

    cstack_t* p_cstack = new cstack_t(0);
    p_cstack->reserve(20);

    callstacks_[tid] = p_cstack;

    // // insert dummy FnElem to filtered function stack
    p_cstack->push_back(dummy_cs_);
}

void CallstackManager::freeCallstack(THREADID tid) {
    TRACK_LOG("CallstackManager::freeCallstack - tid %d\n", tid);

    ASSERT(callstacks_[tid] != NULL, "tid " + decstr(tid) + " does not exists!\n");

    delete callstacks_[tid];
    callstacks_[tid] = NULL;
}

void CallstackManager::adjustCallstack(THREADID tid, ADDRINT ret_addr) {
    LOG("[INFO] Adjusting callstack for handling \"longjmp\"...\n");

    cstack_t* cs = getCallstack(tid);
    
    while(cs->size() != 0) {
        if (cs->back().ret_addr == ret_addr) {
            LOG("[INFO] Callstack adjusted successfully (current function : " + cs->back().fn->getFnName() +")\n");
            break;
        }
        cs->pop_back();
    }

    if (cs->size() == 0) {
        if (!PIN_CheckReadAccess((VOID*)ret_addr)) { // handle return address corruption due to the stack overflow vulnerability
            LOG("[INFO] stack corruption detected\n");
            return;
        }

        ASSERT(cs->size() != 0, 
            "Cannot find matching return address " + hexstr(ret_addr) + " in the current callstack\n");
    }

    return;
}

VOID PIN_FAST_ANALYSIS_CALL CallstackManager::DirectCallCB(THREADID tid,
                                ADDRINT ip,
                                ADDRINT target_addr,
                                ADDRINT ret, 
                                CallstackManager* xthis,
                                LinuxFn* fn) 
{
    TRACK_LOG("[0x%lx:%d] Direct Call: 0x%lx (ret : 0x%lx)\n",  ip, tid, target_addr, ret);
    xthis->pushCallstack(tid, target_addr, ret, fn);
}

VOID PIN_FAST_ANALYSIS_CALL CallstackManager::IndirectCallCB(THREADID tid,
                                    ADDRINT ip,
                                    ADDRINT target_addr, 
                                    ADDRINT ret, 
                                    CallstackManager* xthis) 
{
    TRACK_LOG("[0x%lx:%d] Indirect Call: 0x%lx (ret : 0x%lx)\n",  ip, tid,target_addr, ret);
    xthis->pushCallstack(tid, target_addr, ret, xthis->requestFn(target_addr));
}

VOID PIN_FAST_ANALYSIS_CALL CallstackManager::DirectJmpCB(THREADID tid,
                                    ADDRINT ip,
                                    ADDRINT target_addr, 
                                    CallstackManager* xthis) 
{
    TRACK_LOG("[0x%lx:%d] direct Jmp: 0x%lx (ret : 0x%lx)\n",  ip, tid,target_addr, ret);
    LinuxFn* p_fn = xthis->searchFn(target_addr);
    if (p_fn) {
        xthis->replaceCallstackTopElem(tid, p_fn);
    }
}

VOID PIN_FAST_ANALYSIS_CALL CallstackManager::IndirectJmpCB(THREADID tid,
                                    ADDRINT ip,
                                    ADDRINT target_addr, 
                                    CallstackManager* xthis) 
{
    TRACK_LOG("[0x%lx:%d] Indirect Jmp: 0x%lx (ret : 0x%lx)\n",  ip, tid,target_addr, ret);
    xthis->replaceCallstackTopElem(tid, xthis->requestFn(target_addr));
}

VOID PIN_FAST_ANALYSIS_CALL CallstackManager::PLTCallCB(THREADID tid, 
                                ADDRINT ip, 
                                ADDRINT target_addr, 
                                ADDRINT ret, 
                                CallstackManager* xthis,
                                LinuxFn* fn) 
{
    // TRACK_LOG("[0x%lx] Call(.plt): 0x%lx (ret : 0x%lx)\n", ip, target_addr, ret);
    xthis->pushCallstack(tid, target_addr, ret, fn);
}

VOID PIN_FAST_ANALYSIS_CALL CallstackManager::RetCB(THREADID tid,
                            ADDRINT ip,
                            ADDRINT target_addr, 
                            CallstackManager* xthis) 
{
    TRACK_LOG("[0x%lx:%d] Ret: 0x%lx\n", ip, tid, target_addr);

    if (!xthis->checkCallstack(tid, target_addr)) {
        xthis->adjustCallstack(tid, target_addr);
    }
    
    xthis->popCallstack(tid);
}

VOID PIN_FAST_ANALYSIS_CALL CallstackManager::PLTStubCB(THREADID tid,
                            ADDRINT ip,
                            ADDRINT target_addr,
                            LinuxFn* fn,
                            CallstackManager* xthis)  
{
    // TRACK_LOG("[0x%lx] plt stub target : 0x%lx\n", ip, target_addr);
    // LinuxFn* p_fn = xthis->mcallstacks_[tid]->back().fn;

    if (fn->getAddr() == target_addr )
        return;

    if (fn->isResolved() == false) { // first visit, .plt is not resolved yet...
        fn->setResolvedFlag();
        return;
    }
    else { // Now .plt is resolved, "target_addr" is actual external function's address
        fn->setAddr(target_addr);
        PIN_LockClient();
        fn->setImgName(IMG_Name(IMG_FindByAddress(target_addr)));
        PIN_UnlockClient();

        // TRACK_LOG("[ip. 0x%lx] PLTStub : %s(idx. %d), %lx->%lx, got addr : 0x%lx (=> 0x%lx)\n", 
        //         ip, fn->getFnName().c_str(), fn->getIdx(), fn->getCallAddr(), fn->getAddr(), fn->getGOTAddr(), target_addr);

        // Remove plt's callback??
    }
}

// Debugging functions
void CallstackManager::print() {
    TRACK_LOG("CallstackManager here! :D\n");
}

void CallstackManager::printFnKind() {
    TRACK_LOG("Total : %ld\n", functions_.size());

    resolvePLT();

    std::map<ADDRINT, LinuxFn*>::iterator iter;
    for (iter = functions_.begin(); iter != functions_.end(); iter++) {
        LinuxFn* f = iter->second;
        if (f->isExternal() == true)
            TRACK_LOG("%s : 0x%lx(.plt) 0x%lx(real) | (.got) 0x%lx\n", f->getPLTFnName().c_str(), f->getPltAddr(),f->getAddr(), f->getGOTAddr());
        else
            TRACK_LOG("%s : 0x%lx\n", f->getFnName().c_str(), f->getAddr());

    }
}

void CallstackManager::printCallstack(THREADID tid) {
    cstack_t* stack = callstacks_[tid];
    ASSERT(stack, "invalid cstack_t");

    LOG("\t[callstack] (tid. " + decstr(tid) + ", size: " + decstr(stack->size()) + ")\n");

    LOG("\t\t\tFnAddr\t\t\t   Ret Addr\t\t\tName\n");

    char log_buf[256];
    for (size_t i = stack->size() - 1; i > 0; i--) {
        
        cs_elem_t cs = stack->at(i);
        
        sprintf(log_buf, "\t\t0x%012lx \t|\t0x%012lx\t|\t%s\t(%s)\n", 
                cs.fn->getAddr(), 
                cs.ret_addr,
                cs.fn->getFnName().c_str(),
                cs.fn->getImgName().c_str()
                );

        LOG(log_buf);
    }
    
}

int CallstackManager::toCSV(std::string path) {
    std::ofstream out(path.c_str());
    ADDRINT fn_offset;
    LinuxFn* cur_fn;
    IMG img;
    std::string img_name;

    out << "id,addr,offset,fnname,img,hitcnt\n";

    for (auto &iter : functions_) {
        cur_fn = iter.second;
        img = IMG_FindByAddress(cur_fn->getAddr());
        if (!IMG_Valid(img))
            continue;
        img_name = IMG_Name(img);
        fn_offset = cur_fn->getAddr() - IMG_LowAddress(img);

        out << decstr(cur_fn->getIdx()) + ","
                    + decstr(cur_fn->getAddr()) + "," 
                    + decstr(fn_offset) + "," 
                    + cur_fn->getFnName() + "," 
                    + img_name + "," 
                    + decstr(cur_fn->getHitCnt()) + "\n";
    }

    out.close();

    return 0;
}
