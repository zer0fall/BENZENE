#include "fn_base.h"

FnBase::FnBase(ADDRINT fn_addr) :
    addr_(fn_addr)
{
    PIN_LockClient();
    RTN rtn = RTN_FindByAddress(fn_addr);

    if (unlikely(!RTN_Valid(rtn))) {
        fn_name_ = "sub_";
        
        char temp[32] = { 0, };
        sprintf(temp, "0x%012lx", fn_addr);
        fn_name_ += temp;

        is_rtn_valid_ = false;
    }
    else {
        fn_name_ = RTN_Name(rtn);
        is_rtn_valid_ = true;
    }

    IMG img = IMG_FindByAddress(fn_addr);

    // assert(IMG_Valid(img));
    if (!IMG_Valid(img))
        return;

    img_addr_ = IMG_LowAddress(img);
    img_name_ = IMG_Name(img);

    PIN_UnlockClient();
};    

FnBase::FnBase(ADDRINT fn_addr, RTN rtn) :
    addr_(fn_addr),
    fn_name_("INVALID"),
    img_name_("INVALID")
{
    PIN_LockClient();

    ASSERT(RTN_Valid(rtn), "RTN is invalid : " + hexstr(fn_addr));

    fn_name_ = RTN_Name(rtn);
    is_rtn_valid_ = true;

    IMG img = IMG_FindByAddress(fn_addr);

    img_addr_ = IMG_LowAddress(img);
    img_name_ = IMG_Name(img);

    PIN_UnlockClient();
}

FnBase::FnBase(ADDRINT fn_addr, IMG img) :
    addr_(fn_addr)
{
    PIN_LockClient();

    img_addr_ = IMG_LowAddress(img);
    img_name_ = IMG_Name(img);
    
    offset_ = fn_addr - img_addr_;

    RTN rtn = RTN_FindByAddress(fn_addr);

    assert(RTN_Valid(rtn));

    is_rtn_valid_ = true;
    fn_name_ = RTN_Name(rtn);

    PIN_UnlockClient();
}

FnBase::FnBase(ADDRINT fn_addr, RTN rtn, IMG img) :
    addr_(fn_addr)
{
    PIN_LockClient();

    if (!RTN_Valid(rtn))
        return;

    fn_name_ = RTN_Name(rtn);
    is_rtn_valid_ = true;

    if (!IMG_Valid(img))
        return;

    img_addr_ = IMG_LowAddress(img);
    img_name_ = IMG_Name(img);
    offset_ = fn_addr - img_addr_;

    PIN_UnlockClient();
}
