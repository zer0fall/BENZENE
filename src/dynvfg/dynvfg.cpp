#include "dynvfg.h"
#include "fcntl.h"
#include <fstream>
#include <iostream>
#include "cJSON.h"

extern "C" {
#include "xed-interface.h"
}

#define C_(x) x.c_str()

DynVFG::DynVFG()
{
    modules_ = new VFGModules();
    cstack_manager = new CallstackManager();

    // core_ is initialized in DynVFG::activate
    core_ = NULL;

}

bool DynVFG::checkASLR() {
    int fd = open("/proc/sys/kernel/randomize_va_space", O_RDONLY);
    if (fd  < 0) {
        LOG("Cannot open \"/proc/sys/kernel/randomize_va_space\"...!\n");
        return false;
    }
    else {
        char tmp;
        if (read(fd, &tmp, 1) != 1) {
            LOG("Cannot read \"/proc/sys/kernel/randomize_va_space\"\n");
            return false;
        }

        if (tmp != '0') {
            fprintf(stderr, "\nIt seems ASLR is enabled in this system... Please disable it :D\n");
            fprintf(stderr, "  \"echo 0 | sudo tee /proc/sys/kernel/randomize_va_space\" would work!\n");
            return false;
        }
        close(fd);
    }

    return true;
}

VOID DynVFG::activate() {
    modules_->activate();
    cstack_manager->activate();
    core_ = new VFGCore(40000);
    set_chain(core_);

    // check ASLR
    LOG("[+] checking ASLR status of the system...\n");
    if (checkASLR() == false) PIN_ExitProcess(0);

    if (unlikely(libdft_init_no_instrument() != 0)) {
        LOG("libdft_init error\n");
        return;
    }

    libdft_enable();
    // disable value creation tracking until one of the analysis target functions executes   
    enableVFG();

    TRACE_AddInstrumentFunction(instrumentTrace, this);
    // IMG_AddInstrumentFunction(onIMGLoad, this);
    // IMG_AddUnloadFunction(onIMGUnload, this);
}

VOID DynVFG::instrumentTrace(TRACE trace, void* v) {
    DynVFG* xthis = reinterpret_cast<DynVFG*>(v);
    InsNode* node;

    if (!xthis->isAddrInAnalysisTarget(TRACE_Address(trace))) {
        // only libdft 
        for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
            for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
                ins_inspect(ins);
            }
        }
        return;
    }

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            if (check_ins(ins)) {
                node = xthis->requestNode(ins);
                node->setInstBytes(ins);

                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)onInstExec,
                            IARG_FAST_ANALYSIS_CALL,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_ADDRINT, xthis,
                            IARG_ADDRINT, node,
                            IARG_CALL_ORDER, CALL_ORDER_DEFAULT - 5, // value_core : CALL_ORDER_DEFAULT + 10
                            IARG_END);                   
            }
            else if (isCMP(ins)) { // check if current node is cmp family node
                node = xthis->requestNode(ins);
                node->setInstBytes(ins);

                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)onCMPInstExec,
                            IARG_FAST_ANALYSIS_CALL,
                            IARG_THREAD_ID,
                            IARG_INST_PTR,
                            IARG_ADDRINT, xthis,
                            IARG_ADDRINT, node,
                            IARG_CALL_ORDER, CALL_ORDER_DEFAULT - 5, // value_core : CALL_ORDER_DEFAULT + 10
                            IARG_END);                      
            }
            else {
                node = nullptr;
                // ins_inspect(ins);
            }
            instrument_rule(ins, node); // instrument value creation instructions... 
        }
    }
}

VOID PIN_FAST_ANALYSIS_CALL 
DynVFG::onCMPInstExec(THREADID tid, ADDRINT ip, DynVFG* vfg, InsNode* node) {
    if (val_enable == false) {
        /*
            [ Issue ] : When a function is called through @plt, several code stub execute to resolve actual function address(_dl_resolve).
                        But it seems actual function is executed via a JMP instruction(not a CALL instruction) after address resolve.
                        Such cases cannot be handled in current design (function tracking via CALL/RET instrumentation)
        */
        val_enable = true;
    }
    
    if (node->getFn() == nullptr) // if current node's function data is not set, resolve it
        node->setFn(vfg->getCallstackTopFn(tid));
    
    vfg->handleCMPInst(tid, ip, node);
    return;
}

VOID PIN_FAST_ANALYSIS_CALL 
DynVFG::onInstExec(THREADID tid, ADDRINT ip, DynVFG* vfg, InsNode* node) {
    if (val_enable == false) {
        /*
            [ Issue ] : When a function is called through @plt, several code stub execute to resolve actual function address(_dl_resolve).
                        But it seems actual function is executed via a JMP instruction(not a CALL instruction) after address resolve.
                        Such cases cannot be handled in current design (function tracking via CALL/RET instrumentation)
        */
        val_enable = true;
    }

    if (node->getFn() == nullptr) // if current node's function data is not set, resolve it
        node->setFn(vfg->getCallstackTopFn(tid));
    
    vfg->handleInst(tid, ip, node);

    return;
}

VOID DynVFG::addTargetIMG(std::string img_name) {
    modules_->addTargetModuleName(img_name);
}

VOID DynVFG::handleIMG(IMG img) {
}

VOID DynVFG::handleRegResult(THREADID tid, REG reg) {
    
    tag_t t = tagmap_getn_reg(tid, REG_INDX(reg), REG_Size(reg));
    LOG("\t\ttaint : " + tag_sprint(t) + "\n");

    std::vector<tag_seg> t_seg = tag_get(t);
    LOG("\t\ttotal tag size : " + decstr(t_seg.size()) + "\n");

    taint_t cur_taint;
    char log_buf[256];

    for (auto iter = t_seg.begin(); iter != t_seg.end(); ++iter) {
        cur_taint = iter->begin;
        InsNode* node = core_->getNode(cur_taint);

        ASSERT(node != NULL, "DynVFG::handleRegResult : Taint value is out of range");

        INT32* col = nullptr;
        INT32* line = nullptr;
        std::string* filename = nullptr;

        PIN_GetSourceLocation(node->getAddr(), col, line, filename);

        sprintf(log_buf, "\t\t\ttaint. %4d => 0x%012lx\n", 
                        cur_taint, 
                        node->getAddr());

        LOG(log_buf);
    }

    return;
}

VOID DynVFG::handleMemResult(ADDRINT mem_addr, uint32_t mem_size) {

    tag_t t = tagmap_getn(mem_addr, mem_size);
    LOG("\t\ttaint : " + tag_sprint(t) + "\n");

    std::vector<tag_seg> t_seg = tag_get(t);
    LOG("\t\ttotal tag size : " + decstr(t_seg.size()) + "\n");

    taint_t cur_taint;
    char log_buf[256];

    for (auto iter = t_seg.begin(); iter != t_seg.end(); ++iter) {
        cur_taint = iter->begin;
        InsNode* node = core_->getNode(cur_taint);

        ASSERT(node != NULL, "DynVFG::handleMemResult : Taint value is out of range");

        INT32* col = nullptr;
        INT32* line = nullptr;
        std::string* filename = nullptr;

        PIN_GetSourceLocation(node->getAddr(), col, line, filename);

        sprintf(log_buf, "\t\t\ttaint. %4d => 0x%012lx\n", 
                        cur_taint, 
                        node->getAddr());

        LOG(log_buf);
    }

    return;
}

int DynVFG::createResult(std::string out_dir) {
    std::string funcs_path = out_dir + "/funcs.csv";

    ADDRINT offset;
    std::string img_name;

    auto taint_dir = core_->getTaintDir();
    auto node_dir = core_->getNodeDir();

    taint_t* taints = nullptr;
    size_t num_item = 0;
    InsNode* tmp_node;

    // resolve real addresses of functions with @plt
    cstack_manager->resolvePLT();
    cstack_manager->toCSV(funcs_path);

    cJSON* result = cJSON_CreateObject();
    cJSON* insts_json = cJSON_CreateArray();

    for (size_t i = 0; i < node_dir->size(); i++) {
        cJSON* inst_json = cJSON_CreateObject();
        InsNode* n = node_dir->at(i);
        IMG img = IMG_FindByAddress(n->getAddr());
        if (!IMG_Valid(img))
            continue;
        ADDRINT img_addr = IMG_LowAddress(img);
        offset = n->getAddr() - img_addr;
        img_name = IMG_Name(img);

        cJSON_AddNumberToObject(inst_json, "id", i);
        cJSON_AddNumberToObject(inst_json, "addr", n->getAddr());
        cJSON_AddNumberToObject(inst_json, "offset", offset);
        cJSON_AddNumberToObject(inst_json, "taint", n->getTaint());
        cJSON_AddStringToObject(inst_json, "img", img_name.c_str());
        cJSON_AddNumberToObject(inst_json, "type", n->getType());

        char bytesstr[64] = {0, };
        for (size_t i = 0; i < n->getInstSize(); i++) {    
            sprintf(&bytesstr[2*i], "%02x", (unsigned char)(n->getInstBytes()[i]));
        }
        cJSON_AddStringToObject(inst_json, "inst_bytes", bytesstr);

        if (n->getFn() && n->getFnAddr()) {
            cJSON_AddNumberToObject(inst_json, "fnoffset", n->getFnAddr() - img_addr);
            cJSON_AddStringToObject(inst_json, "fnname", n->getFnName().c_str());
        }
        else {
            cJSON_AddNumberToObject(inst_json, "fnoffset", 0);
            cJSON_AddStringToObject(inst_json, "fnname", "none");          
        }    
    
        // add dataflow edges
        cJSON* data_edges_json = cJSON_CreateObject();
        for (int edge_idx = 0; edge_idx < MAX_EDGE_COUNT; edge_idx++) {
            Edge* e = n->getDataFlowEdge(edge_idx);
            if (!e) break;
            cJSON* edge_json = cJSON_CreateArray();

            if (!e->resolveTags(&taints, &num_item)) {
                /*
                 *  [NOTE] If data source of current edge is from the outside of analysis range,
                 *      taint buffer can be empty.
                 */
                for (size_t i = 0; i < num_item; i++) {
                    tmp_node = taint_dir->at(taints[i]);
                    cJSON_AddItemToArray(edge_json, cJSON_CreateNumber(tmp_node->Id()));
                }
                free(taints);
            }

            cJSON_AddItemToObject(data_edges_json, decstr(e->getReg()).c_str(), edge_json);
        }
        cJSON_AddItemToObject(inst_json, "data", data_edges_json);


        cJSON* deref_edges_json = cJSON_CreateObject();
        for (int edge_idx = 0; edge_idx < MAX_EDGE_COUNT; edge_idx++) {
            Edge* e = n->getDerefEdge(edge_idx);
            if (!e) break;
            cJSON* edge_json = cJSON_CreateArray();

            if (!e->resolveTags(&taints, &num_item)) {
                /*
                 *  [NOTE] If data source of current edge is from the outside of analysis range,
                 *      taint buffer can be empty.
                 */
                for (size_t i = 0; i < num_item; i++) {
                    tmp_node = taint_dir->at(taints[i]);
                    cJSON_AddItemToArray(edge_json, cJSON_CreateNumber(tmp_node->Id()));
                }
                free(taints);
            }
            
            cJSON_AddItemToObject(deref_edges_json, decstr(e->getReg()).c_str(), edge_json);
        }
        cJSON_AddItemToObject(inst_json, "deref", deref_edges_json);

        cJSON_AddItemToArray(insts_json, inst_json);
    }

    cJSON_AddItemToObject(result, "insts", insts_json);
    char* str = cJSON_Print(result);

    if (str == NULL) {
        fprintf(stderr, "failed to create json\n");
        return -1;
    }
    std::string json_path = out_dir + "/vfg.json";
    std::ofstream jsonfile(json_path.c_str());
    jsonfile << str;

    cJSON_Delete(result);

    return 0;
}