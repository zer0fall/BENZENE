#ifndef __VFG_NODES_H__
#define __VFG_NODES_H__

#include "pin.H"
#include "linux_fn.h"
#include "tag_traits.h"

#include <map>
#include <set>

#define REG_MEM REG_NONE
#define MAX_EDGE_COUNT 3

typedef uint32_t idx_t;
typedef uint32_t taint_t;

class Edge {
public:

enum EdgeType {
    EDGE_NONE,
    EDGE_DATA_FLOW,
    EDGE_CNTL_FLOW,
    EDGE_DEREF_FLOW
};  

    Edge (REG reg, EdgeType type) {
        reg_ = reg;
        type_ = type;
    };

    REG getReg() { return reg_; };

    void addTag(tag_t t) { edge_tags_.insert(t); };
    bool isMemEdge() { return reg_ == REG_MEM; };
    int resolveTags(taint_t** taints, size_t* num_item);
    size_t getTagCount() { return edge_tags_.size(); };

private:
    REG reg_;
    EdgeType type_;
    uint32_t op_idx_;
    std::set<tag_t> edge_tags_;
};


class InsNode {
public:
    InsNode(ADDRINT a);
    InsNode(ADDRINT a, taint_t taint, tag_t t, LinuxFn* p_fn);
    ~InsNode();
private:
    ADDRINT     ins_addr_;
    LinuxFn*    parent_fn_ = nullptr;

    bool is_parsed_ = false;
    bool edge_parsed_ = false;

    idx_t id_;
    tag_t tag_;
    uint32_t taint_;
    uint32_t type_;   // the category of an instruction. use CATEGORY_StringShort to get a string formats
    bool     is_deref_;

    std::vector<REG> deref_regs_;
    std::set<InsNode*> cf_nodes_;        // control-flow nodes

    Edge* df_edges_[MAX_EDGE_COUNT] = {nullptr, };
    Edge* deref_edges_[MAX_EDGE_COUNT] = {nullptr, };

    uint32_t inst_size_ = 0;
    char inst_bytes_[16] = {0, };

public:
    idx_t Id() { return id_; };
    tag_t getTag() { return tag_; };

    bool isParsed() { return is_parsed_; };

    void setEdgeFlag()  { edge_parsed_ = true; };
    bool isEdgeParsed() { return edge_parsed_; };

    bool isMemDeref() {return is_deref_; };

    void setTag(tag_t t) { tag_ = t; };
    void setTaint(uint32_t taint) { taint_ = taint; };
    void setType(uint32_t type) { type_ = type; };
    void setId(idx_t id) { id_ = id; };

    void setDerefEdgeInfo(INS ins);

    ADDRINT getAddr() { return ins_addr_; };
    ADDRINT getFnAddr() { return parent_fn_->getAddr(); };
    LinuxFn* getFn() { return parent_fn_; };
    std::string getFnName() { return parent_fn_->getFnName(); };

    char* getInstBytes() { return inst_bytes_; };
    uint32_t getInstSize() { return inst_size_; };

    void setFn(LinuxFn* fn) { parent_fn_ = fn; };
    void setInstBytes(INS ins) {
        inst_size_ = INS_Size(ins);
        assert(inst_size_ <= sizeof(inst_bytes_));
        PIN_SafeCopy(&inst_bytes_, (void*)getAddr(), inst_size_);
    }
    uint32_t getTaint() { return  taint_; };
    uint32_t getType() { return type_; }

    void addCMPNode(InsNode* node) { 
        if (node == nullptr) return;
        cf_nodes_.insert(node); 
    };

    std::set<InsNode*>* getCntlFlows() { return &cf_nodes_; };

    void addInTag(tag_t t, uint32_t idx) { 
        if (!df_edges_[idx]) {
            LOG("Error: edge is not allocated (addr: " + hexstr(getAddr()) + ", edge_idx: " + decstr(idx) + ")\n");
            assert(false);
        }

        df_edges_[idx]->addTag(t);
    }
    
    Edge* getDataFlowEdge(uint32_t edge_idx) { return df_edges_[edge_idx]; };
    Edge* getDerefEdge(uint32_t edge_idx) { return deref_edges_[edge_idx]; };

    void addDerefFlowEdge(REG reg, uint32_t edge_idx) { 
        if (edge_parsed_)
            return;

        // maximum number of edge for intel x86/64 architecture is 3
        assert(edge_idx < 3);
        
        if(deref_edges_[edge_idx] != nullptr) {
            LOG("Duplicate allocation (addr: " + hexstr(getAddr()) + ", idx: " + decstr(edge_idx) + ")\n");
            assert(false);
        }

        deref_edges_[edge_idx] = new Edge(reg, Edge::EdgeType::EDGE_DEREF_FLOW);        
    };

    void addDataFlowEdge(REG reg, uint32_t edge_idx) {
        if (edge_parsed_)
            return;

        // maximum number of edge for intel x86/64 architecture is 3
        assert(edge_idx < 3);
        
        if(df_edges_[edge_idx] != nullptr) {
            LOG("Duplicate allocation (addr: " + hexstr(getAddr()) + ", idx: " + decstr(edge_idx) + ")\n");
            assert(false);
        }

        df_edges_[edge_idx] = new Edge(reg, Edge::EdgeType::EDGE_DATA_FLOW);
    }

    int resolveDataFlowTags(taint_t** taints, size_t* num_item, uint32_t edge_idx);
    int resolveDerefTags(taint_t** taints, size_t* num_item, uint32_t edge_idx);        
    
};


#endif





