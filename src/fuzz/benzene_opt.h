#ifndef __BENZENE_OPT_H__
#define __BENZENE_OPT_H__

#include "benzene_common.h"
#include "dr_api.h"

typedef struct _benzene_opt_t {
    char        output_dir[MAXIMUM_PATH];
    benzene_mode_t mode;
    bool        pass_hang;
    app_pc      fuzz_offset;
    uint32_t    hitcnt_for_kickoff; // hit count for fuzzing kick off
    // original crash's information
    app_pc      initial_crash_addr;
    uint32_t    initial_crash_offset;
    char        crash_img_name[MAX_MODULE_NAME_LEN];
    char        fuzz_module_name[MAX_MODULE_NAME_LEN];
    uint32_t    triage_offset;
    app_pc      triage_addr;
    uint32_t    hitcnt_for_triage;
    bool is_reached;
    bool is_asan;
} benzene_opt_t;

inline void setMode(benzene_opt_t& option, benzene_mode_t mode) { 
    option.mode ^= mode;
};

inline bool checkMode(benzene_opt_t& option, benzene_mode_t mode) {
    return (option.mode & mode);
};
#endif