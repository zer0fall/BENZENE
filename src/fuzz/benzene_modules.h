#ifndef __BENZENE_MODULES_H__
#define __BENZENE_MODULES_H__
#include <stdint.h>
#include "dr_api.h"
#include "benzene_common.h"

typedef struct {
    char img_name[MAX_MODULE_NAME_LEN];
    app_pc  module_base;
    app_pc  module_end;
} benzene_module_t;


class BenzeneModule {
private:
    benzene_module_t* modules_[MAXIMUM_MODULE_CNT] = { nullptr, };
    char* target_modules_[MAXIMUM_MODULE_CNT];
    
    uint32_t cur_module_cnt_ = 0;
    uint32_t module_cnt_ = 0;

    benzene_module_t* cache_ = nullptr;

public:
    BenzeneModule() {};

    bool addTargetModule(const char* module_name);
    void resolveModule(const module_data_t * m);

    bool isTargetModule(app_pc pc) {
        DR_ASSERT(cache_);
        if (pc >= cache_->module_base && pc <= cache_->module_end)
            return true;
        
        for (int i = 0; i < cur_module_cnt_; i++) {
            if (pc >= modules_[i]->module_base && pc <= modules_[i]->module_end) {
                cache_ = modules_[i];
                return true;
            }
        }
        return false;
    }

    benzene_module_t* getModule(app_pc addr) {
        if (addr >= cache_->module_base && addr <= cache_->module_end)
            return cache_;
        
        for (int i = 0; i < cur_module_cnt_; i++) {
            if (addr >= modules_[i]->module_base && addr <= modules_[i]->module_end) {
                return modules_[i];
            }
        }

        return nullptr;        
    }

    app_pc getModuleBase(const char* module_name);
    app_pc getModuleBase(app_pc addr) {
        if (addr >= cache_->module_base && addr <= cache_->module_end)
            return cache_->module_base;
        
        for (int i = 0; i < cur_module_cnt_; i++) {
            if (addr >= modules_[i]->module_base && addr <= modules_[i]->module_end) {
                return modules_[i]->module_base;
            }
        }

        return nullptr;        
    }
};

#endif