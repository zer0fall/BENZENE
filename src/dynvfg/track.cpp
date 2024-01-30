#include "debug.h"
#include "pin.H"

#include <iostream>
#include <unistd.h>

#include "callstack_manager.h"
#include "whitelist.h"

CallstackManager* track;
// VFGModules* vfg_modules;
FnList* flist;
KNOB<std::string> fnlist(KNOB_MODE_WRITEONCE, "pintool", "f", "", "Filtered functions list.");


VOID onSIGSEGV(THREADID tid, INT32 sig, CONTEXT *ctxt, 
            BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v) {


    LOG("\n\n[!] SEGV signal detected...!! Extract data from current exception...\n\n");

    PIN_ExitProcess(-1);
}

VOID onFini(INT32 code, VOID* v) {

    LOG("\n\n[!] Fini...!! Extract data from current status...\n\n");

}

VOID onIMGLoad(IMG img, void* v) {
    LOG("[INFO] img load : " + IMG_Name(img) + " | " + hexstr(IMG_LowAddress(img)) +"\n");
}


VOID onIMGUnload(IMG img, void* v) {
    LOG("[INFO] img unload : " + IMG_Name(img) +"\n");
        
    /*
     *  PIN's IMG object is unavailble(unloaded from memory) when Fini callback starts.
     *  So, handling results in Fini Callback is infeasible (resolving call target's IMG information is impossible).
     *  We employ some heuristic way to recognize program's exit before IMG objects become invalid
     */ 
    if (IMG_IsMainExecutable(img)) {
        PIN_ExitProcess(0);
    }

}

int main (int argc, char *argv[]) {

    PIN_InitSymbols();

    track = new CallstackManager();
    // vfg_modules = new VFGModules();
    
    if (PIN_Init(argc, argv)) {
        LOG("PIN_Init failed, check command line options\n");
        
        return -1;
    }
    
    // vfg_modules->activate();
    track->activate();
    flist = new FnList(fnlist.Value());

    IMG_AddInstrumentFunction(onIMGLoad, 0);
    IMG_AddUnloadFunction(onIMGUnload, 0);

    PIN_InterceptSignal(SIGSEGV, (INTERCEPT_SIGNAL_CALLBACK)onSIGSEGV, track);
    PIN_AddFiniFunction(onFini, track);
    PIN_StartProgram();

    return 0;
}