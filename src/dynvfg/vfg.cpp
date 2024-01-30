#include "vfg.h"
#include "val_helper.h"

extern tag_t c_tag;
extern thread_ctx_t *threads_ctx;


VFGCore::VFGCore(size_t total_taint_sz) :
    total_taint_size_(total_taint_sz),
    node_cnt_(0) 
{
    /* 
     * [ Important Notice ]
     * If the number of elements in taint_dir_ is over its original size, PIN emits error message : 
     *      "E: Unexpected memory deallocation request of aligned memory ~"
     */
    // taint_dir_ = new std::vector<InsNode*>(); 
    taint_dir_.reserve(30000);
    node_dir_.reserve(30000);
}

// VFGCore::VFGCore() {
//     taint_dir_ = new std::vector<InsNode*>(total_taint_size_ + 1); 
//     node_cnt = 0;
// }

void VFGCore::addInTag(tag_t t, uint32_t edge_idx) {
    if (cur_node_ == nullptr) // current node is unavailable, do nothing
        return;
    cur_node_->addInTag(t, edge_idx);
}

InsNode* VFGCore::requestNode(ADDRINT addr) {
    auto r = nodes_.insert({addr, NULL});
        
    if (r.second == false) { // alreadly exists
        return r.first->second;
    } 
    else { // key doesn't exist, create new one
        InsNode* node = new InsNode(addr);
        node->setId(node_cnt_++);
        
        node_dir_.push_back(node);

        r.first->second = node;
        
        return node;
    }
}

void VFGCore::addDerefFlowEdges(THREADID tid, InsNode* node) {
    if (!node->isMemDeref())
        return;
    Edge* e;
    tag_t* deref_tags;
    REG deref_reg;
    for (size_t i = 0; i < MAX_EDGE_COUNT; i++) {
        e = node->getDerefEdge(i);

        if (!e) 
            continue;

        deref_reg = e->getReg();
        deref_tags = RTAG[deref_reg];

        switch(REG_Size(deref_reg)) {
        case 1:
            LOG("@TODO : Unhandled derefence register " + REG_StringShort(deref_reg) + "\n");
            break;
        case 2:
            LOG("@TODO : Unhandled derefence register " + REG_StringShort(deref_reg) + "\n");
            break;
        case 4:
            for (int j = 0; j < 4; j++)
                e->addTag(deref_tags[j]);
            break;
        case 8:
            for (int j = 0; j < 8; j++)
                e->addTag(deref_tags[j]);
            break;
        case 16:
            for (int j = 0; j < 8; j++)
                e->addTag(deref_tags[j]);
            break;
        default:
            LOG("unhandled case\n");
            assert(false);
        }

    }
}


InsNode* VFGCore::handleInst(THREADID tid, ADDRINT addr, InsNode* node) {
    allocTaint(node);    
    setCurrentNode(node);
    addDerefFlowEdges(tid, node);
    hit_cnt_++;

    return node;
}


// InsNode* VFGCore::handleInst(ADDRINT addr, InsNode* node, taint_t taint) {
//     // Add instruction to this class
//     allocTaint(node, taint);
    
//     addInCMPNode(node);
//     setCurrentNode(node);

//     return node;
// }

void VFGCore::allocTaint(InsNode* node) {
    if (node->getTag() == CLEARED_TAG_VAL) { // current node hasn't been asssigned a taint value yet
        // if (taint_cnt_ > total_taint_size_) {
        //     total_taint_size_ = total_taint_size_ * 2;

        //     taint_dir_->resize(total_taint_size_ + 1);

        //     LOG("VFGCore::handleInst : resize \"total_taint_size_\" => "
        //         + decstr(total_taint_size_) + "\n");
        // }

        tag_t new_t = tag_alloc<tag_t>(taint_cnt_);
        
        node->setTag(new_t);
        node->setTaint(taint_cnt_);

        taint_dir_.push_back(node);

        taint_cnt_++;
    }
}

void VFGCore::allocTaint(InsNode* node, taint_t taint) {
    tag_t new_t = tag_alloc<tag_t>(taint);
    
    node->setTag(new_t);
    node->setTaint(taint);
}


InsNode* VFGCore::handleCMPInst(THREADID tid, ADDRINT addr, InsNode* node) {
    // Add instruction to this class

    addInCMPNode(node);

    setCurrentNode(node);       // for getting src taint
    setCurrentCMPNode(node);    // for handling dominant cmps

    addDerefFlowEdges(tid, node);

    return node;
}

