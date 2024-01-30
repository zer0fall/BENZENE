#include "linux_fn.h"

void LinuxFn::convertFnPLT(){
    setPLTAddr(getAddr());
    plt_fn_name_ = getFnName();

    // check if it has "@plt" string
    size_t pos = plt_fn_name_.find("@plt", 0);

    if (pos != std::string::npos) {
        // string conversion : "func@plt" to "func"
        setFnName(plt_fn_name_.substr(0, plt_fn_name_.size() - 4));
    }
}

ADDRINT LinuxFn::setActualAddrFromPLT() {
    if (!isExternal())
        return INVALID_FN_ADDR;        

    if (getAddr() == plt_addr_) { // current address is not set with got address
        if (!isResolved())
            return INVALID_FN_ADDR;
        
        ADDRINT resolved_addr;

        if (got_addr_ == INVALID_GOT_ADDR)
            return INVALID_FN_ADDR;
        
        PIN_SafeCopy(&resolved_addr, (ADDRINT*)got_addr_, sizeof(ADDRINT));
        setAddr(resolved_addr);
        IMG img = IMG_FindByAddress(resolved_addr);
        if (!IMG_Valid(img))
            return INVALID_FN_ADDR;

        setImgName(IMG_Name(IMG_FindByAddress(resolved_addr)));
        return resolved_addr;
    } 
    else { // got address is already successfully set
        return getAddr();
    }
}