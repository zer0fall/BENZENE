#ifndef __FN_BASE_H__
#define __FN_BASE_H__

#include "pin.H"

#include <assert.h>
#include <iostream>

#define likely(x)       __builtin_expect((x), 1)
#define unlikely(x)     __builtin_expect((x), 0)

class FnBase {
/*
* function base class
*/
private:
    ADDRINT addr_;
    bool is_rtn_valid_;
    std::string fn_name_;
    std::string img_name_;

public:    
    ADDRINT img_addr_;
    ADDRINT offset_; // offset from its image

    FnBase(ADDRINT fn_addr);

    ~FnBase() {};

    FnBase(ADDRINT fn_addr, std::string fn_name, std::string img_name) :
        addr_(fn_addr),
        fn_name_(fn_name),
        img_name_(img_name)
    {};

    FnBase(ADDRINT fn_addr, RTN rtn);
    FnBase(ADDRINT fn_addr, IMG img);
    FnBase(ADDRINT fn_addr, RTN rtn, IMG img);
    FnBase(ADDRINT fn_addr, bool dummy) : 
        addr_(fn_addr),
        is_rtn_valid_(false)
    {};
    
    ADDRINT getAddr() { return addr_; };
    std::string getFnName() { return fn_name_; }
    void setFnName(std::string fn_name) { fn_name_ = fn_name; }
    std::string getImgName() {
        if (img_name_ == "") {
            PIN_LockClient();
            IMG img = IMG_FindByAddress(addr_);
            PIN_UnlockClient();

            if (!IMG_Valid(img))
                img_name_ = "unknown";
            else
                img_name_ = IMG_Name(img);
        }        
        return img_name_; 
    }
    void setImgName(std::string img_name) { img_name_ = img_name; }
    void setAddr(ADDRINT a) { addr_ = a; }
    bool isRTNValid() { return is_rtn_valid_; };
};

#endif