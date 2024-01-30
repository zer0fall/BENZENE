#include "pin.H"
#include "dynvfg.h"

KNOB<std::string> output_dirname(KNOB_MODE_WRITEONCE, "pintool", "out", "./", "target offset.");
KNOB<std::string> target_module(KNOB_MODE_APPEND, "pintool", "m", "", "target modules");

VOID onSIGSEGV(THREADID tid, INT32 sig, CONTEXT *ctxt, BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v) {
    libdft_enable();
    DynVFG* vfg = reinterpret_cast<DynVFG*>(v);

    LOG("\n\n[!] Application's SEGV signal detected...!! Extract data from current exception...\n\n");

    ADDRINT except_addr = PIN_GetExceptionAddress(pExceptInfo);
    // FAULTY_ACCESS_TYPE access_type;

    LOG("\nException Info :\n\t" + PIN_ExceptionToString(pExceptInfo) + "\n"); 
    RTN rtn = RTN_FindByAddress(except_addr);
    INS except_ins;
 
    if (RTN_Valid(rtn)) {
        RTN_Open(rtn);
        if (  !((RTN_Address(rtn) <= except_addr) && (except_addr <= INS_Address(RTN_InsTail(rtn))))) {
            fprintf(stderr, "\n\terror : PIN didn't get valid INS object for exception address...abort\n");
            // PIN_ExitProcess(-1);
        }
        else {
            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
                if (INS_Address(ins) == except_addr) {                       
                    except_ins = ins;                
                    break;
                }
            }
        }
        RTN_Close(rtn);
    }    

    if (!PIN_CheckReadAccess((VOID*)except_addr)) {
        LOG("\t[!] Address " + hexstr(except_addr) + " can't be read\n");
        // vfg->createResultJSON();
        vfg->createResult(output_dirname.Value());

        LOG("\t\trax value : " + hexstr(PIN_GetContextReg(ctxt, REG_RAX)) + "\n");
        vfg->handleRegResult(tid, REG_RAX);
        
        ADDRINT rsp_val = PIN_GetContextReg(ctxt, REG_RSP);
        ADDRINT ret_addr_ptr = rsp_val - sizeof(void*);
        ADDRINT ret_addr;
        PIN_SafeCopy(&ret_addr, (const void*)ret_addr_ptr, sizeof(void*));
        
        LOG("\t\tstack ret value : " + hexstr(ret_addr) + "\n");
        vfg->handleMemResult(ret_addr_ptr, sizeof(void*));

        PIN_ExitProcess(0);
    }

    xed_tables_init();

    xed_machine_mode_enum_t  mmode = XED_MACHINE_MODE_LONG_64;
    xed_address_width_enum_t stack_addr_width = XED_ADDRESS_WIDTH_64b;

    xed_decoded_inst_t xedd;
    unsigned int bytes;

    for (bytes = 0; bytes <= 15; bytes++) {
        xed_error_enum_t xed_err;
        xed_decoded_inst_zero(&xedd);
        xed_decoded_inst_set_mode(&xedd, mmode, stack_addr_width);
        
        xed_err = xed_decode(&xedd,
                            XED_STATIC_CAST(const xed_uint8_t*, except_addr),
                            bytes);

        if (xed_err == XED_ERROR_NONE)
            break;
    }
    
    unsigned int i, memops = xed_decoded_inst_number_of_memory_operands(&xedd);

    xed_reg_enum_t base;
    xed_reg_enum_t indx;  

    REG base_reg = REG_INVALID_;
    REG idx_reg = REG_INVALID_;

    bool is_memread = false;

    for( i=0;i<memops ; i++)   {

        if ( xed_decoded_inst_mem_read(&xedd,i)) {
            is_memread = true;
        }
        if (xed_decoded_inst_mem_written(&xedd,i)) {
            is_memread = false;
        }

        base = xed_decoded_inst_get_base_reg(&xedd,i);
        if (base != XED_REG_INVALID) {
            base_reg = INS_XedExactMapToPinReg(base);
        }
        indx = xed_decoded_inst_get_index_reg(&xedd,i);
        if (i == 0 && indx != XED_REG_INVALID) {
            idx_reg = INS_XedExactMapToPinReg(indx);
        }
    }
    /*
     * IMPORTANT NOTICE :
     * 
     * Taint propagation of libdft64 is processed BEFORE the execution of instruction.
     * Hence, taint information of register may be different than expected in the following kind of situation.
     * 
     *                  mov rax, qword ptr [rax]
     * 
     * If above instruction crashes, analyzer usually wants to figure out rax's taint value BEFORE execution.
     * However, since taint propagation occurs before crash process (regardless of the exception), rax's taint value may differ from the expected.
     */
    if (is_memread == false) {
        LOG("\n\tMemory [ Write ] Exception...!!\n");

        if (REG_valid(base_reg)) {
            LOG("\tBase register : " + REG_StringShort(base_reg) + "\n");
            LOG("\t\tvalue : " + hexstr(PIN_GetContextReg(ctxt, base_reg)) + "\n");            
            vfg->handleRegResult(tid, base_reg);     
        }

        if (REG_valid(idx_reg)) {
            LOG("\tIndex register : " + REG_StringShort(idx_reg) + "\n");
            LOG("\t\tvalue : " + hexstr(PIN_GetContextReg(ctxt, idx_reg)) + "\n");  
            vfg->handleRegResult(tid, idx_reg);      
        }        
    }
    if (is_memread == true) {
        LOG("\n\tMemory [ Read ] Exception...!!\n");

        if (REG_valid(base_reg)) {
            LOG("\tBase register : " + REG_StringShort(base_reg) + "\n");
            LOG("\t\tvalue : " + hexstr(PIN_GetContextReg(ctxt, base_reg)) + "\n");            
            vfg->handleRegResult(tid, base_reg);
        }

        if (REG_valid(idx_reg)) {
            LOG("\tIndex register : " + REG_StringShort(idx_reg) + "\n");
            LOG("\t\tvalue : " + hexstr(PIN_GetContextReg(ctxt, idx_reg)) + "\n");            
            vfg->handleRegResult(tid, idx_reg);     
        }        
    }    

    // vfg->createResultJSON();
    vfg->createResult(output_dirname.Value());

    PIN_ExitProcess(0);
}

VOID onIMGUnload(IMG img, void* v) {
    LOG("img unload : " + IMG_Name(img) +"\n");
    
    /*
     *  PIN's IMG object is unavailble(unloaded from memory) when Fini callback starts.
     *  So, instead of handling results in Fini Callback, we employ a heuristic way to recognize program's exit 
     *  before IMG objects becoming invalid
     */ 
    if (IMG_IsMainExecutable(img)) {
        LOG("Program exits... Getting results...!\n");
        DynVFG* vfg = reinterpret_cast<DynVFG*>(v);
        vfg->createResult(output_dirname.Value());
        PIN_ExitProcess(0);
    }   
}


VOID onIMGLoad(IMG img, void* v) {
    LOG("img load : " + IMG_Name(img) + " | " + hexstr(IMG_LowAddress(img)) +"\n");
}

int main (int argc, char* argv[]) {

    PIN_InitSymbols();

    DynVFG* vfg = new DynVFG();

    if (PIN_Init(argc, argv)) {
        LOG("PIN_Init failed, check command line options\n");
        return -1;
    }

    vfg->activate();

    for (uint32_t i = 0; i < target_module.NumberOfValues(); i++) {
        std::string img_name = target_module.Value(i);
        vfg->addTargetIMG(img_name);
    }

    IMG_AddInstrumentFunction(onIMGLoad, vfg);
    IMG_AddUnloadFunction(onIMGUnload, vfg);
    PIN_InterceptSignal(SIGSEGV, (INTERCEPT_SIGNAL_CALLBACK)onSIGSEGV, vfg);
    
    PIN_StartProgram();
    return 0;
}