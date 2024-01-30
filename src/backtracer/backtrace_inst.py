import capstone
from capstone.x86 import *
from enum import Enum

from typing import Dict
from typing import List
from typing import Tuple

from backtrace_module import *
from dynvfg import *
try:
    import gdb
except ModuleNotFoundError:
    pass

vfg: DynVFG = DynVFG()

def init_vfg(dir_path: str):
    vfg.parse(dir_path)

regs_to_skip = [REG.rsp, REG.rip, REG.rflags, REG.fs]

class EdgeType(Enum):
    DATA_FLOW = 0
    DEREF_FLOW = 1
    CONTROL_FLOW = 2


class BacktraceEdge:
    def __init__(self, src: REG, edge_type: EdgeType):
        self.src: REG = src
        self.break_addrs: list[int] = None
        self.edge_type: EdgeType = edge_type
        self.base_reg: REG = None
        self.index_reg: REG = None
        self.scale: int = None
        self.disp: int = None
        self.read_size: int = 0

    def convert_op_to_eval(self) -> str:
        if self.src == REG.mem: # operand is memory
            res = ""

            if self.base_reg != None:
                res += "$%s" % (self.base_reg.name)

            if self.index_reg != None:
                res += "+$%s" % (self.index_reg.name)
                
                if self.scale != None:
                    res += "*%d" % (self.scale)


            if self.disp != None:
                res += "+%d" % (self.disp)

            return res
        else: # operand is register
            return "$%s" % (self.src.name)

    def current_memref_addr(self):
        base_val: int = 0
        index_val: int = 0
        disp_val: int = 0  
        
        if self.base_reg != None:
            base_val = int(gdb.parse_and_eval('$%s' % (self.base_reg.name)))

        if self.index_reg != None:
            index_val = int(gdb.parse_and_eval('$%s' % (self.index_reg.name)))

            if self.scale != None:
                index_val *= self.scale

        if self.disp != None:
            disp_val = self.disp

        return base_val + index_val + disp_val


class BacktraceInst():
    def __init__(self, addr):
        self.addr = addr
        self.disasm_str = ""

        self.data_flow_edges: list[BacktraceEdge] = []
        self.deref_flow_edges: list[BacktraceEdge] = []
        # self.cntl_flow_ops = list()

        self.in_edges: List[Tuple[BacktraceEdge, BacktraceInst, int]] = []
        self.out_edges: List[Tuple[BacktraceEdge, BacktraceInst, int]] = []
        # self.ops = list()

        self.node: DynNode = None
        self.module_base: int = None
        self.offset: int = 0
        self.img_name: str = None

    def extract(self):
        self.extract_edges(self.disassemble())


    def disassemble(self) -> capstone.CsInsn:
        
        infer = gdb.inferiors()[0]
        
        codes = infer.read_memory(self.addr, 16).tobytes()

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True

        for disas in md.disasm(codes, 0):
            break

        self.disasm_str = disas.mnemonic + " " + disas.op_str
        
        return disas # return CsInsn


    def extract_edges_with_node(self, insn: capstone.CsInsn):
        regs_read = insn.regs_access()[0] # regs_read, regs_write = insn.regs_access()

        # _regs_read = self.filter(regs_read, insn)

        if self.node.type == NodeType.TYPE_POP:
            # capstone recognize POP instruction as a non-memory operation. So handle it in advance.
            mem_op = BacktraceEdge(REG.mem, EdgeType.DATA_FLOW)
            mem_op.base_reg = REG.rsp
            self.data_flow_edges.append(mem_op)
            return

        for opnd in insn.operands:
            if opnd.type == X86_OP_MEM: # memory operand exists
                # check if current operand is not memory read                
                if (opnd.access & capstone.CS_AC_READ == 0) and (opnd.access & capstone.CS_AC_WRITE == 0):
                    continue                
                
                # capstone package recognizes LEA instruction as memory read... :(
                if insn.opcode[0] == 0x8D: # opcode of LEA is 0x8d
                    # LEA instruction is used as binary operation.
                    for src in self.node.data_srcs:
                        edge = BacktraceEdge(src, EdgeType.DATA_FLOW) # we assume LEA instruction as data-flow operation
                        
                        edge.break_addrs = [df_node.offset + get_module_by_name(df_node.img_name).base for df_node in self.node.get_edges(src)]
                        
                        if len(edge.break_addrs) != 0:
                            self.data_flow_edges.append(edge)

                    continue

                base_reg = None
                index_reg = None
                scale = None
                disp = None

                regs_to_remove_dup = set()

                if opnd.value.mem.base != 0:
                    regs_to_remove_dup.add(opnd.value.mem.base)     # It's dereference operand, remove it from data-flow operands
                    base_reg = REG[insn.reg_name(opnd.value.mem.base)]

                if opnd.value.mem.index != 0:
                    regs_to_remove_dup.add(opnd.value.mem.index)     # It's dereference operand, remove it from data-flow operands
                    index_reg = REG[insn.reg_name(opnd.value.mem.index)]

                if opnd.value.mem.scale != 0:
                    scale = opnd.value.mem.scale

                if opnd.value.mem.disp != 0:
                    disp = opnd.value.mem.disp                

                # remove base-reg & index-reg from data-flow operands
                regs_read = [ reg for reg in regs_read if reg not in regs_to_remove_dup ]             

                # consider dereference flows : both read & write
                for src in self.node.deref_srcs:
                    
                    # skip dereference flow using RSP, which is a stack pointer
                    if src in regs_to_skip:
                        continue

                    edge = BacktraceEdge(src, EdgeType.DEREF_FLOW)
                    
                    edge.break_addrs = [deref_node.offset + get_module_by_name(deref_node.img_name).base for deref_node in self.node.get_edges(src)]
                    self.deref_flow_edges.append(edge)

                # data flow for memory read 
                if (opnd.access & capstone.CS_AC_READ):
                    # It's memory read operand, create it!
                    mem_op = BacktraceEdge(REG.mem, EdgeType.DATA_FLOW)

                    mem_op.base_reg = base_reg
                    mem_op.index_reg = index_reg
                    mem_op.scale = scale
                    mem_op.disp = disp
                    mem_op.read_size = opnd.size

                    self.data_flow_edges.append(mem_op)

        # there exists data flow with source register. e.g., rcx register in "mov [rax], rcx"
        if len(regs_read) != 0:
            for src in self.node.data_srcs:
                if src in regs_to_skip:
                    continue
                
                edge = BacktraceEdge(src, EdgeType.DATA_FLOW)
                edge.break_addrs = [df_node.offset + get_module_by_name(df_node.img_name).base for df_node in self.node.get_edges(src)]
                self.data_flow_edges.append(edge)
        


    def extract_edges_without_node(self, insn: capstone.CsInsn):
        regs_read = insn.regs_access()[0] # regs_read, regs_write = insn.regs_access()

        # _regs_read = self.filter(regs_read, insn)

        if insn.mnemonic[:3] == 'rep':
            edge = BacktraceEdge(REG.mem, EdgeType.DATA_FLOW)
            edge.base_reg = REG.rsi
            self.data_flow_edges.append(edge)

            edge = BacktraceEdge(REG.rdi, EdgeType.DEREF_FLOW)
            self.deref_flow_edges.append(edge)
            
            edge = BacktraceEdge(REG.rsi, EdgeType.DEREF_FLOW)
            self.deref_flow_edges.append(edge)            

            return

        # @TODO: handle clear instructions (e.g., xor eax, eax)
        if insn.mnemonic[:5] == 'vpxor': # skip
            return

        for i in insn.operands:
            if i.type == X86_OP_MEM: # memory operand exists
                # check if current operand is not memory read/write                
                if (i.access & capstone.CS_AC_READ == 0) and (i.access & capstone.CS_AC_WRITE == 0):
                    continue

                base_reg: REG = None
                index_reg: REG = None
                scale = None
                disp = None

                regs_to_remove_dup = set()

                if i.value.mem.base != 0:
                    regs_to_remove_dup.add(i.value.mem.base)     # It's dereference operand, remove it from data-flow operands
                    base_reg = REG[insn.reg_name(i.value.mem.base)]

                if i.value.mem.index != 0:
                    regs_to_remove_dup.add(i.value.mem.index)     # It's dereference operand, remove it from data-flow operands
                    index_reg = REG[insn.reg_name(i.value.mem.index)]

                if i.value.mem.scale != 0:
                    scale = i.value.mem.scale

                if i.value.mem.disp != 0:
                    disp = i.value.mem.disp

                # capstone package recognizes LEA instruction as memory read... :(
                if insn.opcode[0] == 0x8D: # opcode of LEA is 0x8d
                    if base_reg != None:
                        edge = BacktraceEdge(base_reg, EdgeType.DATA_FLOW)
                        self.data_flow_edges.append(edge)
                                                    
                    elif index_reg != None:
                        edge = BacktraceEdge(index_reg, EdgeType.DATA_FLOW)
                        self.data_flow_edges.append(edge)

                    # it's all done, skip this memory operand
                    continue

                # remove base-reg & index-reg from data-flow operands
                regs_read = [ reg for reg in regs_read if reg not in regs_to_remove_dup ]
                
                # consider dereference flows : both read & write
                if base_reg != None and base_reg not in regs_to_skip:
                    edge = BacktraceEdge(base_reg, EdgeType.DEREF_FLOW)
                    self.deref_flow_edges.append(edge)
                                                
                elif index_reg != None and index_reg not in regs_to_skip:
                    edge = BacktraceEdge(index_reg, EdgeType.DEREF_FLOW)
                    self.deref_flow_edges.append(edge)
                

                # data flow for memory read 
                if (i.access & capstone.CS_AC_READ):
                    # It's memory read operand, create it!
                    mem_op = BacktraceEdge(REG.mem, EdgeType.DATA_FLOW)

                    mem_op.base_reg = base_reg
                    mem_op.index_reg = index_reg
                    mem_op.scale = scale
                    mem_op.disp = disp

                    self.data_flow_edges.append(mem_op)


        # there exists data flow with source register. e.g., rcx register in "mov [rax], rcx"
        if len(regs_read) != 0:
            for reg in regs_read:
                _ = REG[insn.reg_name(reg)]
                
                if _ in regs_to_skip:
                    continue

                edge = BacktraceEdge(_, EdgeType.DATA_FLOW)

                # edge = BacktraceEdge(REG[insn.reg_name(reg)], EdgeType.DATA_FLOW)                
                self.data_flow_edges.append(edge)        


    def extract_edges(self, insn : capstone.CsInsn):        
        if len(insn.operands) <= 0:
            print("no operands")

        if self.node:
            self.extract_edges_with_node(insn)
        else:
            self.extract_edges_without_node(insn)