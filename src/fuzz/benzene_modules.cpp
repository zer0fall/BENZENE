#include "benzene_modules.h"
#include <cstring>


bool BenzeneModule::addTargetModule(const char* module_name) {
    if (module_cnt_ == MAXIMUM_MODULE_CNT)
        DR_ASSERT_MSG(false, "maximum module count exceeded");

    // check if module_name is listed
    for (int i = 0; i < module_cnt_; i++) {
        if (!strncmp(target_modules_[i], module_name, MAX_MODULE_NAME_LEN)) {
            return false;
        }
    }
    
    target_modules_[module_cnt_++] = __wrap_strdup(module_name);
    return true;
}


void BenzeneModule::resolveModule(const module_data_t * m) {
    benzene_module_t* bmodule = nullptr; 

    for (int i = 0; i < module_cnt_; i++) {
        if (!strncmp(target_modules_[i], m->names.file_name, MAX_MODULE_NAME_LEN)) {
            bmodule = (benzene_module_t*)dr_global_alloc(sizeof(benzene_module_t));
            strncpy(bmodule->img_name, target_modules_[i], MAX_MODULE_NAME_LEN);

            if (!cache_) {
                cache_ = bmodule;
            }

            if (cur_module_cnt_ >= MAXIMUM_MODULE_CNT) {
                DR_ASSERT(false);
            }

            modules_[cur_module_cnt_++] = bmodule;
            bmodule->module_base = m->start;
            bmodule->module_end = m->end;
            break;
        }
    }
}

app_pc BenzeneModule::getModuleBase(const char* module_name) {
    for (int i = 0; i < cur_module_cnt_; i++) {
        if (!strncmp(modules_[i]->img_name, module_name, MAX_MODULE_NAME_LEN)) {
            return modules_[i]->module_base;
        }
    }

    return nullptr;
}