#include "vfg_nodes.h"


int Edge::resolveTags(taint_t** taints, size_t* num_item) {
    std::set<taint_t> taint_set;

    for (auto i = edge_tags_.begin(); i != edge_tags_.end(); i++) {
        tag_t t = *i;

        std::vector<tag_seg> tag_seg = tag_get(t);

        for (auto j = tag_seg.begin(); j != tag_seg.end(); j++) {
            taint_set.insert(j->begin);
        }
    }

    *num_item = taint_set.size();
    
    if (*num_item == 0) {
        *taints = nullptr;
        return -1;
    }
    
    *taints = new taint_t[*num_item];
    
    int i = 0;
    for (auto taint : taint_set) {
        (*taints)[i] = taint;
        i++;
    }

    return 0;
}    


InsNode::InsNode(ADDRINT a) :
    ins_addr_(a),
    parent_fn_(nullptr),
    tag_(CLEARED_TAG_VAL),
    taint_(0),
    type_(0) {};

InsNode::InsNode(ADDRINT a, taint_t taint, tag_t t, LinuxFn* p_fn) :
    ins_addr_(a),
    parent_fn_(p_fn),
    tag_(t),
     taint_(taint),
    type_(0)
{
};

void InsNode::setDerefEdgeInfo(INS ins) {
    int cnt = 0;
    REG tmp_reg;

    if (edge_parsed_) return;

    if (INS_IsMemoryRead(ins) || INS_IsMemoryWrite(ins)) {
        is_deref_ = true;

        deref_regs_.reserve(3);

        tmp_reg = INS_MemoryBaseReg(ins);
        if (REG_valid(tmp_reg)) {
            addDerefFlowEdge(tmp_reg, cnt++);
        }

        tmp_reg = INS_MemoryIndexReg(ins);
        if (REG_valid(tmp_reg))
            addDerefFlowEdge(tmp_reg, cnt++);

        // there is no register for dereference
        if (!cnt)
            is_deref_ = false;

        // LOG("deref count : " + decstr(deref_regs_.size()) + "\n");
    }
    else {
        is_deref_ = false;
    }
}

int InsNode::resolveDataFlowTags(taint_t** taints, size_t* num_item, uint32_t edge_idx) {
    // LOG("Node " + hexstr(getAddr()) + "\n");
    if (df_edges_[edge_idx] == nullptr) {
        // LOG("\t" + REG_StringShort(edge->getReg()) + "\n");
        return df_edges_[edge_idx]->resolveTags(taints, num_item);
    }
    else {
        return -1;
    }
}

int InsNode::resolveDerefTags(taint_t** taints, size_t* num_item, uint32_t edge_idx) {
    if (deref_edges_[edge_idx] == nullptr) {
        // LOG("\t" + REG_StringShort(edge->getReg()) + "\n");
        return deref_edges_[edge_idx]->resolveTags(taints, num_item);
    }
    else {
        return -1;
    }
}    
