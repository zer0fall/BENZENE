/*
 * Author : Younggi Park
 * email : grill66@korea.ac.kr
 * 
 */
#include "vfg_modules.h"
#include "pin.H"
#include <iostream>

Module::Module(IMG img) {
    std::string img_name = IMG_Name(img);

    memset(m_full_img_name, 0, sizeof(m_full_img_name));
    memcpy(m_full_img_name, img_name.c_str(), strlen(img_name.c_str()));
    memset(img_name_, 0, sizeof(img_name_));     
    const char * short_img_name = img_name.substr(img_name.rfind("/") + 1).c_str();

    memcpy(img_name_, short_img_name, strlen(short_img_name));

    LOG("Module : " + img_name + " | " + hexstr(IMG_LowAddress(img)) + "\n");

    // IMG address information
    start_addr_ = IMG_LowAddress(img);
    end_addr_ = IMG_HighAddress(img);

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec) ) {
        if(SEC_IsExecutable(sec)) { // get code section            
            struct section sec_info;
                        
            if (SEC_Name(sec) == ".plt") sec_info.is_plt = true;
            else sec_info.is_plt = false;

            sec_info.start_addr = SEC_Address(sec);
            sec_info.size = SEC_Size(sec);

            exec_sections_.push_back(sec_info);
        }
    }
}

bool Module::checkAddrInCodeSection(ADDRINT addr) {
    for ( std::list<Module::section>::iterator iter = exec_sections_.begin(); iter != exec_sections_.end(); ++iter) {
        if (addr >= iter->start_addr) {
            if (addr <= iter->start_addr + iter->size)
                return true;
        }
    }
    return false;
}

bool Module::checkAddr(ADDRINT addr) {
    if (addr >= start_addr_ && addr <= end_addr_)
        return true;
    
    return false;
}

/*
 * handle IMG load event 
 */
VOID VFGModules::instrumentIMG(IMG img, void* v) {
    VFGModules* vfg_modules = reinterpret_cast<VFGModules*>(v);

    // get name of image
    std::string full_img_name = IMG_Name(img);
    std::string short_img_name = full_img_name.substr(full_img_name.rfind("/") + 1);

    // fprintf(stderr, "img load! : %s\n", short_img_name.c_str());
    if (vfg_modules->searchTargetModule(short_img_name) || vfg_modules->searchTargetModule(full_img_name) || IMG_IsMainExecutable(img)) {
        vfg_modules->addModule(img);    
    }
}


bool VFGModules::checkAddrInWList(ADDRINT addr) {
    for (std::list<class Module *>::iterator iter = modules_.begin(); iter != modules_.end(); ++iter ) {
        if ((*iter)->checkAddr(addr))
            return true;
    }

    return false;
}


void VFGModules::addModule(IMG img) {
    Module* module = new Module(img);
    modules_.push_back(module);
    module_addrs_.insert(IMG_LowAddress(img));
}

void VFGModules::addTargetModuleName(std::string img_name) {
    target_modules_.push_back(img_name);    
}
