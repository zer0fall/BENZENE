from __future__ import annotations
import json
import pandas as pd
from .dynnode import *

from typing import Dict
from typing import List
import os

class Module:
    def __init__(self, module_name: str):
        self.name: str = module_name
        self.nodes_with_offset: Dict[int, DynNode] = {}
        self.funcs_with_offset: Dict[int, DynFn] = {}

    def node_at(self, offset: int) -> DynNode:
        try:
            return self.nodes_with_offset[offset]
        except KeyError:
            return None

    def func_at(self, offset: int) -> DynFn:
        try:
            return self.funcs_with_offset[offset]
        except KeyError:
            return None

    def addNode(self, n: DynNode):
        self.nodes_with_offset[n.offset] = n

    def addFunc(self, fn: DynFn):
        self.funcs_with_offset[fn.offset] = fn


class DynVFG:
    def __init__(self):
        # self.nodes_df = pd.DataFrame()
        self.nodes_with_id: List[DynNode] = []
        self.nodes_with_addr: Dict[int, DynNode] = {}
        # self.nodes_with_offset: Dict[int, DynNode] = {}
        self.modules: Dict[str, Module] = {}
        self.funcs_with_addr: Dict[int, DynFn] = {}
        self.funcs_with_offset: Dict[int, DynFn] = {}

        return

    @property
    def nodes(self) -> List[DynNode]:
        return self.nodes_with_id

    def node(self, id: int) -> DynNode:
        return self.nodes_with_id[id]

    def node_at(self, addr: int = None, offset: int = None, img: str = None) -> DynNode:
        if addr == None and offset == None:
            raise ValueError("no argument")
        
        if addr:
            try:
                return self.nodes_with_addr[addr]
            except KeyError:
                return None
        elif offset:
            if img == None:
                raise ValueError("image is not provided")

            try:
                return self.modules[img].node_at(offset)
            except KeyError:
                return None

    def func_at(self, addr: int = None, offset: int = None, img: str = None) -> DynFn:
        if addr == None and offset == None:
            raise ValueError("no argument")
        
        if addr:
            try:
                return self.funcs_with_addr[addr]
            except KeyError:
                return None
        elif offset:
            if img == None:
                raise ValueError("image is not provided")

            try:
                return self.modules[img].func_at(offset)
            except KeyError:
                return None

    def parse(self, outdir_path: str):
        self.parse_json(os.path.join(outdir_path, 'vfg.json'))
        self.parse_funcs_csv(os.path.join(outdir_path, 'funcs.csv'))

    def parse_json(self, json_path: str):
        with open(json_path, 'r') as f:
            s = json.load(f)

        insts = s['insts']

        # first we register all the observed insts
        for inst in insts:
            node = DynNode(inst['id'], 
                        inst['addr'], 
                        inst['offset'], 
                        inst['img'],
                        bytearray.fromhex(inst['inst_bytes']), 
                        NodeType(inst['type']), 
                        inst['fnoffset'], 
                        inst['fnname'])

            self.nodes_with_id.append(node)
            self.nodes_with_addr[node.addr] = node

            short_img_name = os.path.basename(inst['img'])

            if short_img_name not in self.modules.keys():
                m = Module(short_img_name)
                self.modules[short_img_name] = m
                m.addNode(node)
            else:
                self.modules[short_img_name].addNode(node)

        # now we resolve data/deref edges
        for inst in insts:
            cur_node = self.node(inst['id'])
            
            dataflow = inst['data']
            for src, id_list in dataflow.items():
                src_op = REG(int(src, 10))
                cur_node.data_edges[src_op] = []

                for id in id_list:
                    cur_node.add_data_edge(src_op, self.node(id))

            deref = inst['deref']
            for src, id_list in deref.items():
                src_op = REG(int(src, 10))
                cur_node.deref_edges[src_op] = []

                for id in id_list:
                    cur_node.add_deref_edge(src_op, self.node(id))

    def parse_funcs_csv(self, csv_path: str):
        funcs_df = pd.read_csv(csv_path)

        for i in range(len(funcs_df)):
            r = funcs_df.loc[i]
            fn = DynFn(int(r['addr']),
                        int(r['offset']),
                        r['img'],
                        int(r['hitcnt']),
                        r['fnname'])

            self.funcs_with_addr[r['addr']] = fn

            short_img_name = os.path.basename(r['img'])

            if short_img_name not in self.modules.keys():
                m = Module(short_img_name)
                self.modules[short_img_name] = m
                m.addFunc(fn)
            else:
                self.modules[short_img_name].addFunc(fn)

    def get_edges(self, node_id: int, src: REG) -> List[DynNode]:
        n = self.nodes_with_id[node_id]
        return n.get_edges(src)

    def get_edges_by_addr(self, addr: int, src: REG) -> List[DynNode]:
        n = self.nodes_with_addr[addr]
        return n.get_edges(src)


    def get_all_parents(self, node_id, data_flow_only=False) -> List[DynNode]:
        start_node = self.nodes_with_id[node_id]

        result = list()
        is_visited = [0] * len(self.nodes_with_id)

        queue = []

        queue += start_node.dataflow_edges
        queue += start_node.cf_edges

        while len(queue) != 0:
            cur_node = queue[0]

            if is_visited[cur_node.id] == 1:
                queue.pop(0)
                continue
            
            result.append(cur_node)

            queue += cur_node.dataflow_edges

            if data_flow_only == False:
                for cf_node_id in cur_node.cf_edges:
                    if is_visited[cf_node_id] == 0:
                        result.append(cf_node_id)
                        is_visited[cf_node_id] = 1
                
            # queue += cur_node.cf_edges

            is_visited[cur_node.id] = 1

        return result

    def get_all_parents_by_addr(self, addr):
        target_node = self.nodes_with_addr[addr]
        
        return self.get_all_parents(target_node.id)

