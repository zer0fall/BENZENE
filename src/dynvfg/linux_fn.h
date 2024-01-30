#ifndef __LINUX_FN_H__
#define __LINUX_FN_H__

#include "pin.H"
#include "fn_base.h"
#include <set>

typedef struct {
    ADDRINT addr;       
    ADDRINT caller_addr;    // Address which used on call
    ADDRINT offset;         // relative offset from its image
    ADDRINT caller_offset;
    uint32_t idx;
    std::string fn_name;    // function name
    std::string img_name;   // image name of the function
    std::string caller_img_name;
    uint32_t is_plt;
} fn_call_t;

typedef std::set<fn_call_t*> fn_calls_t;

class LinuxFn : public FnBase {

#define INVALID_FN_ADDR     0
#define INVALID_GOT_ADDR    0
#define INVALID_PLT_ADDR    0

private:
    ADDRINT plt_addr_;
    std::string plt_fn_name_;
    bool is_plt_;
    bool is_resolved_;

    ADDRINT got_addr_;
    uint32_t idx_;
    uint32_t hit_cnt_;

public:
    LinuxFn() :
        FnBase(0),
        plt_addr_(0),
        is_plt_(false),
        is_resolved_(false),
        got_addr_(0),
        idx_(0)  
    {};

    LinuxFn(ADDRINT addr, uint32_t idx) : 
        FnBase(addr),
        plt_addr_(0),
        is_plt_(false),
        is_resolved_(false),
        got_addr_(0),
        idx_(idx)
    {}; 

    ~LinuxFn() {};

    LinuxFn(ADDRINT fn_addr, bool dummy, uint32_t idx) :
        FnBase(fn_addr, dummy),
        plt_addr_(0),
        is_plt_(false),
        is_resolved_(false),
        got_addr_(0),
        idx_(0)
    {};

    ADDRINT getCallTargetAddr() {
        if (is_plt_)
            return plt_addr_;
        else
            return getAddr();
    }

    void setPLTAddr(ADDRINT addr) {
        plt_addr_ = addr;
        is_plt_ = true;
    };

    void    convertFnPLT();
    ADDRINT setActualAddrFromPLT();

    ADDRINT getPltAddr() { return plt_addr_; };
    bool isExternal() { return is_plt_; }
    std::string getPLTFnName() { return plt_fn_name_; }

    bool isResolved() { return is_resolved_; };

    void setResolvedFlag() { is_resolved_ = true; };

    ADDRINT getGOTAddr() { return got_addr_; };
    void setGOTAddr(ADDRINT a){ got_addr_ = a; };

    uint32_t getIdx() { return idx_; };

    /*
     * increase function hit count
     */
    void hit() { hit_cnt_++; }
    uint32_t getHitCnt() { return hit_cnt_; }
};

#endif