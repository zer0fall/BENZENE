#include "benzene_fuzz.h"
#include "drcovlib.h"
#include "drsyms.h"
#include "drwrap.h"

static droption_t<std::string> opt_run_module(DROPTION_SCOPE_CLIENT, "run_module", "", "module-name", "fuzz target module name");
static droption_t<std::string> opt_work_dir(DROPTION_SCOPE_CLIENT, "work_dir", ".", "<path>", "Longer desc of some param.");
static droption_t<std::string> opt_mode(DROPTION_SCOPE_CLIENT, "mode", "fuzz", "mode-name", "Select mode (fuzz / trace)");
static droption_t<bool> opt_dryrun(DROPTION_SCOPE_CLIENT, "dryrun", false, "dryrun mode", "");
static droption_t<bool> opt_asan(DROPTION_SCOPE_CLIENT, "asan", false, "<bool>", "Option for ASAN-compiled binary.");
static droption_t<uint32_t> opt_corpus_id(DROPTION_SCOPE_CLIENT, "corpus_id", 0, "<id>", "Corpus ID for dryrun.");
static droption_t<std::string> opt_target_modules(DROPTION_SCOPE_CLIENT, "m", DROPTION_FLAG_ACCUMULATE, "", "module-name", "target module name");


static std::string output_dir;
static BenzeneFuzz* bfuzz = NULL;

extern uint32_t dryrun_corpus_id;
extern app_pc fuzz_addr;

#define ASAN_REPORT_FUNC_CNT sizeof(asan_report_names) / sizeof(*asan_report_names)
#define MSAN_REPORT_FUNC_CNT sizeof(msan_report_names) / sizeof(*msan_report_names)
const char *asan_report_names[] = {"__asan_on_error", "__asan_report_error", "__asan_report_exp_store4", "__asan_report_load4_noabort", "__asan_report_store2", "__asan_report_exp_load1", "__asan_report_exp_store8", "__asan_report_load8", "__asan_report_store2_noabort", "__asan_report_exp_load16", "__asan_report_exp_store_n", "__asan_report_load8_noabort", "__asan_report_store4", "__asan_report_exp_load2", "__asan_report_load1", "__asan_report_load_n", "__asan_report_store4_noabort", "__asan_report_exp_load4", "__asan_report_load16", "__asan_report_load_n_noabort", "__asan_report_store8", "__asan_report_exp_load8", "__asan_report_load16_noabort", "__asan_report_present", "__asan_report_store8_noabort", "__asan_report_exp_load_n", "__asan_report_load1_noabort", "__asan_report_store1", "__asan_report_store_n", "__asan_report_exp_store1", "__asan_report_load2", "__asan_report_store16", "__asan_report_store_n_noabort", "__asan_report_exp_store16", "__asan_report_load2_noabort", "__asan_report_store16_noabort", "__asan_report_exp_store2", "__asan_report_load4", "__asan_report_store1_noabort"};
const char *msan_report_names[] = {"__msan_warning_noreturn"};

app_pc asan_report_addrs[ ASAN_REPORT_FUNC_CNT ] = {0, };
app_pc msan_report_addrs[ MSAN_REPORT_FUNC_CNT ] = {0, };

void asan_check_wrap(void* wrapcxt, void** user_data) {
    dr_fprintf(STDERR, "ASAN internal check-fail function invoked!!\n");
    // bfuzz->setStatus(PROC_STATUS_FALSE_CRASH);
    app_pc crash_addr = drwrap_get_retaddr(wrapcxt) - 0x5;     /* direct call instruction size : 0x5 */
    bfuzz->handleCrash(crash_addr);

    dr_exit_process(0);
}

/* wrapper function of ASAN report function family */
void asan_report_wrap(void* wrapcxt, void** user_data) {
    /* 
     *  (For x64 architecture) ASAN report function family accepts faulty as its argument
     *  call ~
     *  Benzene assumes callsite of ASAN report function as crash address.
     */    
    app_pc crash_addr = drwrap_get_retaddr(wrapcxt) - 0x5;     /* direct call instruction size : 0x5 */
    bfuzz->handleCrash(crash_addr);

    dr_exit_process(0);
}

int asan_lookup(const module_data_t* module_data) {
    size_t off = 0;
    app_pc mod_start = 0x0;

    if (drsym_init(0) != DRSYM_SUCCESS) {
        return -1;
    }

    mod_start = module_data->start;

    for (int i = 0; i < ASAN_REPORT_FUNC_CNT; i++) {
        off = 0;
        if (drsym_lookup_symbol(module_data->full_path, asan_report_names[i], &off, DRSYM_DEFAULT_FLAGS ) != DRSYM_SUCCESS) {
            dr_fprintf(STDERR, "ASAN function symbol not found in \"%s\" : %s\n", module_data->names.file_name, asan_report_names[i]);
            drsym_exit();
            return -1;
        }
        asan_report_addrs[i] = mod_start + off;
    }


    if (!drwrap_init()) {
        dr_fprintf(STDERR, "Error: drwrap_init failed\n");
        return -1;
    }

    for (int i = 0; i < ASAN_REPORT_FUNC_CNT; i++) {
        if (!asan_report_addrs[i])
            continue;

        if (!drwrap_wrap(asan_report_addrs[i], asan_report_wrap, NULL)) {
            dr_fprintf(STDERR, "Error: drwrap_wrap failed on %s\n", asan_report_names[i]);
            return -1;
        }
    }

    /*
     * ASAN's internal check functions cause the process to restart. 
     * We monitor the function call and suppress this functionality before restart.
     */
    if (drsym_lookup_symbol(module_data->full_path, "__sanitizer::CheckFailed", &off, DRSYM_DEFAULT_FLAGS ) != DRSYM_SUCCESS) {
        dr_fprintf(STDERR, "Error: ASAN function symbol lookup failed : %s\n", "__sanitizer::CheckFailed");
        drsym_exit();
        return -1;
    }
    app_pc CheckFailed_addr = mod_start + off;
    if (!drwrap_wrap(CheckFailed_addr, asan_check_wrap, NULL)) {
        dr_fprintf(STDERR, "Error: drwrap_wrap failed : %s\n", "__sanitizer::CheckFailed");
        return -1;
    }

    drsym_exit();
    return 0;
}

int msan_lookup(const module_data_t* module_data) {
    size_t off = 0;
    app_pc mod_start = 0x0;

    if (drsym_init(0) != DRSYM_SUCCESS) {
        return -1;
    }

    mod_start = module_data->start;

    for (int i = 0; i < MSAN_REPORT_FUNC_CNT; i++) {
        off = 0;
        if (drsym_lookup_symbol(module_data->full_path, msan_report_names[i], &off, DRSYM_DEFAULT_FLAGS ) != DRSYM_SUCCESS) {
            dr_fprintf(STDERR, "MSAN function symbol not found : %s\n", msan_report_names[i]);
            drsym_exit();
            return -1;
        }
        msan_report_addrs[i] = mod_start + off;
    }


    if (!drwrap_init()) {
        dr_fprintf(STDERR, "Error: drwrap_init failed\n");
        return -1;
    }

    for (int i = 0; i < MSAN_REPORT_FUNC_CNT; i++) {
        if (!drwrap_wrap(msan_report_addrs[i], asan_report_wrap, NULL)) {
            dr_fprintf(STDERR, "Error: drwrap_wrap failed : %s\n", msan_report_names[i]);
            return -1;
        }
    }

    drsym_exit();

    return 0;
}

static void triage_hit(BenzeneFuzz* bfuzz) {
    if (is_reached) {
        // if program covered the original crashing execution, disable coverage tracking
        bfuzz->adjustCovStatus();
    }
}

static void event_thread_init(void *drcontext)
{
    void **thread_data;

    thread_data = (void **)dr_thread_alloc(drcontext, 2 * sizeof(void *));
    thread_data[0] = 0;
    thread_data[1] = 0;

    drmgr_set_tls_field(drcontext, bfuzz->getTLS(), thread_data);
}

static void event_thread_exit(void *drcontext)
{
    void *data = drmgr_get_tls_field(drcontext, bfuzz->getTLS());
    dr_thread_free(drcontext, data, 2 * sizeof(void *));
}

static void
event_exit(void)
{
    bfuzz->onProcessExit();
    
    /* 
     *  [NOTICE]
     *   It seems fork syscall within the DynamoRIO client causes some messes to DynamoRIO's internal core when it comes to process exits.
     *   To avoid this, force the process shutdown using exit(0).
     */
    exit(0);
    
    // drreg_exit();
    // drmgr_exit();
}

static dr_signal_action_t
event_signal(void *drcontext, dr_siginfo_t *siginfo) {
    bfuzz->onSignal(drcontext, siginfo);
    return DR_SIGNAL_DELIVER;
}


static dr_emit_flags_t 
event_app_instruction_fuzz(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                      bool for_trace, bool translating, void *user_data)
{
    app_pc pc = instr_get_app_pc(inst);

    if (pc == fuzz_addr) {
        dr_insert_clean_call(drcontext, bb, inst, (void*)BenzeneFuzz::hitFuzzTarget_wrapper, 
                                false, 1, OPND_CREATE_INTPTR(bfuzz));           
    }
        
    if (instr_is_app(inst) && bfuzz->isInstrumentAddr(pc)) {        
        // @TODO: use dr_module_contains_addr(), as modules are not always contiguous.
        bfuzz->instrument_fuzz(drcontext, bb, inst, pc);
    }

    // instrument the address after inital_crash_addr to stop gathering coverage
    bfuzz->instrumentCrashAddr(drcontext, bb, inst, pc, (void*)triage_hit);

    /* 
     *  @issue : if `instrument_edge_coverage` is instrumented BEFORE `instrument_dryrun_fuzz`, 
     *           it results unexpected register value.
     *           
     *           reference : typespeed (cve-2005-0105), at 0x40b5 offset (mov rcx, rax)
     *           rax value after `get_env` function call
     *              * observed : 0x7fffffff0200 (wrong)
     *              * expected : 0x7fffffffe434
     */             
    bfuzz->instrument_edge_coverage(drcontext, tag, bb, inst);

    return DR_EMIT_DEFAULT;
}


static dr_emit_flags_t 
event_app_instruction_trace(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                      bool for_trace, bool translating, void *user_data)
{
    app_pc pc = instr_get_app_pc(inst);

    if (pc == fuzz_addr) {
        dr_insert_clean_call(drcontext, bb, inst, (void*)BenzeneFuzz::hitFuzzTarget_wrapper, 
                                false, 1, OPND_CREATE_INTPTR(bfuzz));           
    }    

    if (instr_is_app(inst) && bfuzz->isInstrumentAddr(pc)) {        
        // @TODO: use dr_module_contains_addr(), as modules are not always contiguous.
        bfuzz->instrument_trace(drcontext, bb, inst, pc);
    }

    // instrument the address after inital_crash_addr to stop gathering coverage
    bfuzz->instrumentCrashAddr(drcontext, bb, inst, pc, (void*)triage_hit);

    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
event_app_instruction_dryrun(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                      bool for_trace, bool translating, void *user_data)
{
    app_pc pc = instr_get_app_pc(inst);

    if (pc == fuzz_addr) {
        dr_insert_clean_call(drcontext, bb, inst, (void*)BenzeneFuzz::hitFuzzTarget_wrapper, 
                                false, 1, OPND_CREATE_INTPTR(bfuzz));           
    }

    if (instr_is_app(inst) && bfuzz->isInstrumentAddr(pc)) {
        if (checkMode(option, BENZENE_MODE_FUZZ))
            bfuzz->instrument_dryrun_fuzz(drcontext, bb, inst, pc);
        else
            bfuzz->instrument_dryrun_trace(drcontext, bb, inst, pc);
    }

    // instrument the address after inital_crash_addr to check non-crash
    bfuzz->instrumentCrashAddr(drcontext, bb, inst, pc, (void*)triage_hit);

    /* 
     *  @issue : if `instrument_edge_coverage` is instrumented BEFORE `instrument_dryrun_fuzz`, 
     *           it results in unexpected register values.
     *           
     *           reference : typespeed (cve-2005-0105), at 0x40b5 offset (mov rdi, rax)
     *           rax value after `get_env` function call
     *              * observed : 0x7fffffff0200 (wrong)
     *              * expected : 0x7fffffffe434
     */             
    if (checkMode(option, BENZENE_MODE_FUZZ))
        bfuzz->instrument_edge_coverage(drcontext, tag, bb, inst);

    return DR_EMIT_DEFAULT;
}

static void
event_module_load(void*drcontext, const module_data_t *info, bool loaded) {
    dr_fprintf(STDERR, "[BENZENE] Module \"%s\" loaded (base : 0x%lx)\n", info->names.file_name, info->start);
    bfuzz->handleModuleLoad(info);
}

static void 
options_init(int argc, const char* argv[]) {
    std::string parse_err;
    if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, &parse_err, NULL)) {
        dr_fprintf(STDERR, "Usage error: %s", parse_err.c_str());
        dr_exit_process(-1);
    }

    option = {0, };

    // copy output directory path
    strncpy(option.output_dir, opt_work_dir.get_value().c_str(), sizeof(option.output_dir));

    option.is_asan = opt_asan.get_value();
    
    if (opt_dryrun.get_value()) {
        dryrun_corpus_id = opt_corpus_id.get_value();
        setMode(option, BENZENE_MODE_DRYRUN);
    }

    if (opt_mode.get_value() == "fuzz")
        setMode(option, BENZENE_MODE_FUZZ);
    else if (opt_mode.get_value() == "trace")
        setMode(option, BENZENE_MODE_TRACE);
    else {
        dr_fprintf(STDERR, "Error: invalid mode %s\n", opt_mode.get_value().c_str());
        DR_ASSERT(false);
    }

    std::string target_modules = opt_target_modules.get_value();

    if (target_modules != "") {
        size_t prev = 0;
        size_t cur = target_modules.find(' ');
        std::string module_name;
        while (1) {
            module_name = target_modules.substr(prev, cur - prev);
            bfuzz->addTargetModule(module_name.c_str());
            prev = cur + 1;
            cur = target_modules.find(' ', prev);

            if (cur == std::string::npos) {
                if (prev != 0) {
                    module_name = target_modules.substr(prev, cur - prev);
                    bfuzz->addTargetModule(module_name.c_str());                
                }
                break;
            }
        } 
    }
    
    std::string run_module = opt_run_module.get_value();
    DR_ASSERT_MSG(run_module != "", "run_module option is not specified");
    bfuzz->addTargetModule(run_module.c_str());
    strncpy(option.fuzz_module_name, run_module.c_str(), MAX_MODULE_NAME_LEN);

    // By default, we track the main executable
    module_data_t* main_module = dr_get_main_module();
    bfuzz->addTargetModule(main_module->names.file_name);

    char config_path[MAXIMUM_PATH];

    if (checkMode(option, BENZENE_MODE_DRYRUN))
        dr_snprintf(config_path, sizeof(config_path), "%s/dryrun.config.json", opt_work_dir.get_value().c_str());
    else if (checkMode(option, BENZENE_MODE_FUZZ))
        dr_snprintf(config_path, sizeof(config_path), "%s/fuzz.config.json", opt_work_dir.get_value().c_str());
    else if (checkMode(option, BENZENE_MODE_TRACE))
        dr_snprintf(config_path, sizeof(config_path), "%s/trace.config.json", opt_work_dir.get_value().c_str()); 
    else {
        dr_fprintf(STDERR, "invalid mode\n");
        DR_ASSERT(false);
    }

    dr_fprintf(STDERR, "[BENZENE] config path : \"%s\"\n", config_path);

    // read JSON-format configure file.
    if (bfuzz->readConfigFromJSON(config_path) < 0) {
        dr_fprintf(STDERR, "read config failed\n");
        dr_exit_process(-1);        
    }
}


DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    drreg_options_t drreg_ops = { sizeof(drreg_ops), 1 /*max slots needed: aflags*/, false };
    
    dr_set_client_name("bfuzz", "");    

    if (!drmgr_init() || drreg_init(&drreg_ops) != DRREG_SUCCESS)
        DR_ASSERT(false);

    drutil_init();

    bfuzz = new BenzeneFuzz();

    options_init(argc, argv);
    
    // @TODO: handle ASAN in another module
    if (option.is_asan) {
        module_data_t* main_module = dr_get_main_module();
        if (!main_module) {
            dr_fprintf(STDERR, "Error: dr_get_main_module() failed\n");
            dr_exit_process(-1);
        }

        if (asan_lookup(main_module) < 0 && msan_lookup(main_module)) {
            dr_fprintf(STDERR, "Error: wrapping sanitizer report function failed\n");
            dr_exit_process(-1);
        }
    }

    if (checkMode(option, BENZENE_MODE_DRYRUN)) {
        DR_ASSERT(drmgr_register_bb_instrumentation_event(NULL, event_app_instruction_dryrun, NULL));
        drmgr_register_signal_event(event_signal);
    }
    else if (checkMode(option, BENZENE_MODE_FUZZ)) {
        DR_ASSERT(drmgr_register_bb_instrumentation_event(NULL, event_app_instruction_fuzz, NULL));
        drmgr_register_signal_event(event_signal);        
    }
    else if (checkMode(option, BENZENE_MODE_TRACE)) {
        DR_ASSERT(drmgr_register_bb_instrumentation_event(NULL, event_app_instruction_trace, NULL));
        drmgr_register_signal_event(event_signal);        
    }

    dr_register_exit_event(event_exit);
    drmgr_register_thread_init_event(event_thread_init);
    drmgr_register_thread_exit_event(event_thread_exit);

    drmgr_register_module_load_event(event_module_load);

    /* make it easy to tell, by looking at log file, which client executed */
    // dr_log(NULL, DR_LOG_ALL, 1, "Client 'trace' initializing\n");
}