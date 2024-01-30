#ifndef __VALUE_CORE_H__
#define __VALUE_CORE_H__
#include "pin.H"
#include "tag_traits.h"
#include "vfg.h"

extern tag_t c_tag;     // current tag
// extern VFGCore *vfg_core;

extern bool val_enable; // on/off value

VOID enableVFG();
VOID disableVFG();

void set_chain(VFGCore* vfg);

void instrument_rule(INS ins, InsNode* node);

bool check_ins(INS ins);
bool isCMP(INS ins);
#endif