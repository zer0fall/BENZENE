#ifndef __VFG_H__
#define __VFG_H__

#include "pin.H"
#include <iostream>
#include <map>

#include "tag_traits.h"
#include "vfg_nodes.h"

#ifdef DEBUG_VFG
#define VFG_LOG(...)              \
do {                              \
    fprintf(stderr, __VA_ARGS__); \
} while (0)
#else
#define VFG_LOG(...)
#endif

extern tag_t c_tag;

class VFGCore {
public:
    VFGCore(size_t total_taint_sz);
    VFGCore();
    ~VFGCore();

private:
    std::map<ADDRINT, InsNode*> nodes_;
    
    std::vector<InsNode*> taint_dir_;
    std::vector<InsNode*> node_dir_;

    size_t total_taint_size_;

    InsNode* cur_node_;
    InsNode* cur_cmp_; // dominant cmp node

    size_t node_cnt_;
    size_t taint_cnt_;
    size_t hit_cnt_ = 0;

public:
    void removeNode(InsNode *node) { nodes_.erase(node->getAddr()); }
    InsNode* addNode(InsNode* node);
    InsNode* requestNode(ADDRINT addr);
    InsNode* handleInst(THREADID tid, ADDRINT addr, InsNode* node);
    InsNode* handleCMPInst(THREADID tid, ADDRINT addr, InsNode* node);

    InsNode* getNode(taint_t taint) {
        return taint_dir_.at(taint);
    }

    std::vector<InsNode*>* getTaintDir() { return &taint_dir_; };
    std::vector<InsNode*>* getNodeDir() { return &node_dir_; };

    // InsNode* requestInsNode(ADDRINT addr);
    InsNode* getCurrentNode() { return cur_node_; };
    InsNode* getCurrentCMPNode() { return cur_cmp_; };
    void setCurrentNode(InsNode* n) { 
        cur_node_ = n;
        c_tag = n->getTag();
    };
    void setCurrentCMPNode(InsNode* n) { // execute only at CMP instruction family
        cur_cmp_ = n; 
        c_tag = CLEARED_TAG_VAL;    
    };

    // void addInTag(InsNode* node, tag_t t) {
    //     node->addInTag(t);
    // }

    void addInCMPNode(InsNode* node) { node->addCMPNode(cur_cmp_); };
    void addDerefFlowEdges(THREADID tid, InsNode* node);

    void addInTag(tag_t t, uint32_t edge_idx);
    
    void allocTaint(InsNode* node);
    void allocTaint(InsNode* node, taint_t taint);
};






#endif