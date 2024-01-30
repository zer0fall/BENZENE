/*
 * Author : Younggi Park
 * email : grill66@korea.ac.kr
 * 
 */

#ifndef __VFG_MODULES_H__
#define __VFG_MODULES_H__

#include <iostream>
#include <stdlib.h>
#include <list>
#include <set>

#include "pin.H"

#define likely(x)       __builtin_expect((x), 1)
#define unlikely(x)     __builtin_expect((x), 0)

class Module {

#define MAX_IMG_NAME 128
#define MAX_FULL_IMG_NAME 256

struct section {
    char        img_name[MAX_IMG_NAME];
    char        full_img_name[MAX_FULL_IMG_NAME];
    ADDRINT     start_addr;
    uint64_t    size;
    bool        is_plt; // for Linux
};

private:
    char img_name_[MAX_IMG_NAME];
    char m_full_img_name[MAX_FULL_IMG_NAME];

    ADDRINT start_addr_;
    ADDRINT end_addr_;

    std::list<struct section> exec_sections_;

public:
    Module(IMG img);
    bool checkAddrInCodeSection(ADDRINT addr);
    bool checkAddr(ADDRINT addr);
    const char * getIMGName() { return (const char *)img_name_; }
    const char * getFullIMGName() { return (const char *)m_full_img_name; }
};

class VFGModules {
private:
    std::list<class Module *> modules_;
    std::list<std::string> target_modules_;
    std::set<ADDRINT> module_addrs_;

    ADDRINT cache_; // last vistited valid whitelist-ed module start address

public:
    VFGModules() {};
    bool checkAddrInWList(ADDRINT addr);

    void addModule(IMG module);
    void addTargetModuleName(std::string img_name);

    bool searchTargetModule(std::string img_name) {
        for ( std::list<std::string>::iterator iter = target_modules_.begin(); iter != target_modules_.end(); ++iter) {
            if (*iter == img_name)
                return true;
        }

        return false;
    };

    bool checkAddr(ADDRINT a) {
        PIN_LockClient();
        IMG img = IMG_FindByAddress(a);
        PIN_UnlockClient();
        
        if (unlikely(!IMG_Valid(img))) {
            // fprintf(stderr, "invalid img at 0x%lx\n", a);
            return false;
        }
        ADDRINT img_addr = IMG_LowAddress(img);
        
        // if (cache_ == img_addr)
        //     return true;

        if (module_addrs_.find(img_addr) != module_addrs_.end()) {
            // cache_ = img_addr;
            return true;
        }

        return false;
    }

    void activate() {
        IMG_AddInstrumentFunction(instrumentIMG, this);
    }

private:
    static VOID instrumentIMG(IMG img, void* v);

};

#endif