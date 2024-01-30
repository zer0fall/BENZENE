import time
import subprocess
import sys
import os
from typing import Dict
from typing import List
from typing import Tuple
import json
import logging

BENZENE_HOME = os.environ['BENZENE_HOME']
sys.path.append(os.path.join(BENZENE_HOME, 'src'))
sys.path.append(os.path.join(BENZENE_HOME, 'src/backtracer'))

from backtrace_inst import *
from backtrace_module import *
from dynvfg import *

from functools import wraps
import errno
import os
import signal

class TimeoutError(Exception):
    pass

class BacktracerError(Exception):
    def __init__(self, msg):
        super().__init__(msg)

class BacktracerDebug(Exception):
    def __init__(self, msg):
        super().__init__(msg)

def check_ASLR():
    with open("/proc/sys/kernel/randomize_va_space", 'r') as f:
        if f.read()[0] != '0':
            print("It seems ASLR is currently enabled in this system... Please disable it :D")
            print('"echo 0 | sudo tee /proc/sys/kernel/randomize_va_space" would work!')
            return -1
    return 0

def timeout(seconds=10, error_message=os.strerror(errno.ETIME)):
    def decorator(func):
        def _handle_timeout(signum, frame):
            gdb.execute('interrupt')
            print('timed out')
            print('elapsed time : ', time.time() - t)
            logging.info('elapsed time : %s', str(time.time() - t))

            graph_txt = bt.graph()

            try:
                with open(os.path.join(out_dir, "rev_graph.txt"), 'w') as f:
                    f.write(graph_txt)
                
                logging.info('get_json --> \"%s\"', 'origins.json')
                result = bt.get_json()
                with open(os.path.join(out_dir, 'origins.json'), 'w') as f:
                    f.write(result)
            except Exception as e:
                print(str(e))
                exit(-1)
                pass
            exit(0)
            # raise TimeoutError(error_message)

        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result

        return wraps(func)(wrapper)

    return decorator

########################################################

if 'out_dir' not in vars():
    print("out_dir variable is not declared (default: \"%s\")" % (os.path.realpath(os.path.curdir)))
    out_dir = os.path.realpath(os.path.curdir)

try:
    with open(os.path.join(out_dir, 'backtracer.json'), 'r') as f:
        config = json.load(f)
except FileNotFoundError:
    print("backtracer json is not found in %s" % (os.path.join(out_dir, 'backtracer.json')))
    exit(-1)


vfg_dir = config['vfg_dir']
target_modules = [module_name for module_name in config['modules']]
timeout_ = config['timeout']

if 'extra' in config.keys():
    extra_roots = [ extra_root for extra_root in config['extra']]
else:
    extra_roots = []

# it's an ASAN-enabled binary
if 'asan_type' in config.keys():
    asan_type = config['asan_type']
    asan_report_call = config['asan_report_call']

    print(asan_type, hex(asan_report_call))
else:
    asan_type = None

if vfg_dir is None:
    print("Error: node information file is not provided")

try:
    target_modules
except NameError:
    target_modules: List[str] = []


# init logging
logging.basicConfig(filename=os.path.join(out_dir, 'backtracer.log'), filemode='w', level=logging.INFO)

init_vfg(vfg_dir)

######################################################## 

def gdb_get_current_addr() -> int:
    return int(gdb.parse_and_eval('$rip'))

def addr2line(filename, offset):
    if not type(offset) is int:
        print("Error : offset is not int type :", type(offset))
        return None
    args = ["addr2line", '-e', filename, hex(offset)]
    try:
        r = subprocess.check_output(args)[:-1] # [:-1] : get rid of '\n'
    except subprocess.CalledProcessError:
        print("Error : addr2line failed (%s)" % (args))
        return None

    return str(r, 'utf-8')

def gdb_get_inferior_name():
    text = gdb.execute('info inferiors', to_string=True)
    
    lines = text.split('\n')

    first_line = lines[1]

    return first_line.split()[-1]


class FnHit:
    def __init__(self, fn_addr) -> None:
        self.addr: int = fn_addr
        self.total_hit_cnt: int = 0
        self.hot: bool = False

class backtracer:
    def __init__(self, dbg_start=0):
        self.bt_insts: dict[int, BacktraceInst] = {}
        self.queue: List[Tuple[int, BacktraceEdge, int]] = []
        self.root_insts: List[BacktraceInst] = []
        self.targets = list()

        self.checkpoints = set()
        self.total_checkpoint = 0
        self.cur_checkpoint = 0

        self.dbg_start = dbg_start
        self.crash_addr = 0

        self.fn_reached: Dict[int, FnHit] = {}

    def request_inst(self, addr: int) -> BacktraceInst:        
        if addr in self.bt_insts.keys():
            return self.bt_insts[addr]
        
        bt_inst = BacktraceInst(addr)

        module = get_module(addr)
        if module != None:
            bt_inst.offset = addr - module.base
            bt_inst.img_name = module.filename
            bt_inst.node = vfg.node_at(offset=bt_inst.offset, img=module.filename)
            bt_inst.module_base = module.base

        bt_inst.extract()
        self.bt_insts[addr] = bt_inst

        return bt_inst


    def backtrace_to_source(self, inst: BacktraceInst, edge: BacktraceEdge) -> int:
        logging.info('\tbacktrace (0x%x, %s)' % (inst.addr, edge.src.name))
        if edge.src == REG.mem:
            mem_addr = edge.current_memref_addr()

            if edge.base_reg == REG.rip:
                # `rip` based mem reference is next instruction.
                #  e.g., 0x55555555a990 :	mov    rbp,QWORD PTR [rip+0x1ec71] <= execute here
                #        0x55555555a997 :	test   rbp,rbp
                #     in this case, $rip value is calculated as 0x55555555a997, not 0x55555555a990                
                mem_addr += len(inst.disassemble().bytes)

            if mem_addr == None or mem_addr > 0x7ffffffff000 or mem_addr <= 0:
                return -1
            
            if inst.node == None:
                # check if current address is in RR's internal implementation
                if is_skip_module(inst.addr):
                    logging.info('\t\tskip module detected : (0x%x, %s)' % (inst.addr, edge.src.name))
                    return -1

            # hardware breakpoint
            b = gdb.Breakpoint("*0x%x" % (mem_addr), gdb.BP_WATCHPOINT, gdb.WP_WRITE, False, False)
            b.silent = True

            if inst.node != None and edge.read_size > 4:
                # [Issue] : Hardware breakpoint only supports 4-byte r/w access, and it works only when data has been modified.
                #           Therefore, even if current operation is 8-byte-write access, 
                #           hardware bp will not respond if upper bytes are not changed by the write.
                # [Example]
                # * original 8-byte memory value pointed by `[rbp-0x10]`: (little-endian) 0x00000000 0x00000000
                # (backtrack target) mov QWORD PTR [rbp-0x10], rax 
                #                    # `rax` : 0x300000000 ⇒ (little-endian) 0x00000000 0x00000003
                #          ...          ...
                # (current inst)     mov rax, QWORD PTR [rbp-0x10]  # hardware bp on 4-byte memory pointed by `[rbp-0x10]`
                #                    # But, hardware bp doesn't work
                # In this case, we need
                b = gdb.Breakpoint("*0x%x" % (mem_addr + 4), gdb.BP_WATCHPOINT, gdb.WP_WRITE, False, False)
                b.silent = True
            
            gdb.execute('rc')

        else:
            if inst.node != None and len(edge.break_addrs) != 0:
                for break_addr in edge.break_addrs:
                    b = gdb.Breakpoint("*0x%x" % (break_addr), gdb.BP_BREAKPOINT, gdb.WP_WRITE, False, False)
                    b.silent = True
            else:
                # @TODO: watch command is unstable. it only watches the changed value.
                # if a same value is written to the register being watched, it skips that instruction.
                b = gdb.Breakpoint(edge.convert_op_to_eval(), gdb.BP_WATCHPOINT, gdb.WP_WRITE, False, False)
                b.silent = True

            gdb.execute('rc')

        gdb.execute('d')

        return 0        
        

    def get_func_hit_cnt(self, inst: BacktraceInst) -> int:
        if inst.node is None:
            return None

        if inst.node.fn_offset == 0:
            return None

        module_base = get_module_base(inst.addr)
        if module_base == None:
            return None

        fn_addr = module_base + inst.node.fn_offset   # module_tup[1]: module's base address
        
        self.fn_reached.setdefault(fn_addr, FnHit(fn_addr))

        fn_hit = self.fn_reached[fn_addr]

        if fn_hit.hot == True or fn_hit.total_hit_cnt == None:
            return None

        if fn_hit.total_hit_cnt == 0:
            fn = vfg.func_at(offset=inst.node.fn_offset, img=inst.node.img_name)

            if fn.hit_cnt == 0:
                fn_hit.total_hit_cnt = None
                return None

            fn_hit.total_hit_cnt = fn.hit_cnt
            
            if fn.hit_cnt > 50:
                fn_hit.hot = True
                return None

        # b = gdb.Breakpoint()
        b = gdb.Breakpoint("*0x%x" % (fn_addr), gdb.BP_BREAKPOINT, gdb.WP_WRITE, False, False)
        b.silent = True
        b.ignore_count = fn_hit.total_hit_cnt
        gdb.execute('continue')

        fn_hit_remains = b.hit_count
        b.delete()

        # fn_hit_remains = int(gdb.parse_and_eval('$hit_cnt'))
        return fn_hit.total_hit_cnt - fn_hit_remains

    def execute_queue(self): # execute one checkpoint in the queue
        (checkpoint, cur_inst, trav_edge, cur_depth) = self.queue.pop(0)

        print("(checkpoint %d, depth %d) current node : 0x%x" % (checkpoint, cur_depth, cur_inst.addr))

        if cur_inst.addr == self.dbg_start:    # skip current node
            print("dbg start address reached, skip it")
            return
        elif cur_depth > self.max_depth:
            print("depth is over %d, skip it" % (self.max_depth))       
            return

        # @TODO: optimize checkpoint handling
        retry = 0
        while retry != 5:
            try:
                gdb.execute('restart %d' % (checkpoint))
            except gdb.error:
                print("restart %d failed (retry %d)" % (checkpoint, retry))
                time.sleep(3)                
                print(gdb.execute('interrupt', to_string=True))
                retry += 1
                continue
            
            break
        
        if retry == 5:
            print("restart %d failed" % (checkpoint))
            exit(-1)

        if gdb_get_current_addr() != cur_inst.addr:
            print("address mismatch (restart %d)" % (checkpoint))
            exit(-1)

        if self.backtrace_to_source(cur_inst, trav_edge) == 0:
            next_pc = gdb_get_current_addr()
            next_inst = self.request_inst(next_pc)

            self.push_edge(next_inst, cur_depth + 1)
            
            if next_inst.node != None:
                fn_hit = self.get_func_hit_cnt(next_inst)
            else:
                fn_hit = 0

            # save edge information
            cur_inst.in_edges.append((trav_edge, next_inst, fn_hit))
            next_inst.out_edges.append((trav_edge, cur_inst, fn_hit))

            return

    def assign_checkpoint(self):
        gdb.execute('checkpoint')
        self.total_checkpoint += 1
        new_checkpoint = self.total_checkpoint

        print("The number of edge is over 1, checkpoint %d is created" % (new_checkpoint))

        self.checkpoints.add(new_checkpoint)

        return new_checkpoint

    def add_root_inst(self, inst: BacktraceInst):
        # root instruction found, push it
        self.push_edge(inst, 0)

        if inst not in self.root_insts:
            self.root_insts.append(inst)     

    def set_backtrace_roots(self): # find root nodes based on the analysis range
        cur_pc = gdb_get_current_addr()
        gdb.execute('d')

        if asan_type is not None:
            logging.info("ASAN mode detected")
            gdb.execute('r') # clean program state
            gdb.execute('c')

            b = gdb.Breakpoint('*0x%x' % (asan_report_call), gdb.BP_BREAKPOINT, gdb.WP_WRITE, False, False)
            b.silent = True
            
            gdb.execute('rc')            
            gdb.execute('d')

            if gdb_get_current_addr() != asan_report_call:
                print("Error: it's not the asan_report function call")
                logging.info('finding call-site of asan report function failed (0x%x != 0x%x)' % (gdb_get_current_addr(), asan_report_call))
                exit(-1)

            # rdi register contains the problematic (i.e., crashing) pointer
            # we backtrack the rdi register
            gdb.execute('watch $rdi')
            gdb.execute('rc')
            gdb.execute('d')
            
            cur_inst = self.request_inst(gdb_get_current_addr())
            self.add_root_inst(cur_inst)

            return

        while cur_pc != self.crash_addr:
            gdb.execute('c')
            cur_pc = gdb_get_current_addr()

        # In RR, the first reverse-continue at crashing address is trapped.
        # So, we need to reverse-continue for the 1-time in advance
        gdb.execute('rc')
        if cur_pc != self.crash_addr:
            print("crash address mismatch")
            exit(-1)

        queue_for_root_find = []

        # check if crash addresss is RET instruction
        infer = gdb.selected_inferior()
        mem_view = infer.read_memory(cur_pc, 1)
        if mem_view.tobytes() == b'\xc3': # 0xc3: ret
            logging.info('*** return address corruption ***')
            # handle return address corruption\

            # adhoc: we use instruction before RET because RET is currently not handled by DynVFG
            gdb.execute('rsi')
            self.root_insts.append(self.request_inst(gdb_get_current_addr()))
            gdb.execute('stepi')

            # now we backtrace the origin of stack corruption value
            rsp_val = int(gdb.parse_and_eval('$rsp'))

            b = gdb.Breakpoint("*0x%x" % (rsp_val), gdb.BP_WATCHPOINT, gdb.WP_WRITE, False, False)
            b.silent = True
            
            # backtrace to the moment where the return address is overwritten
            gdb.execute('rc')
            gdb.execute('d')

            print(hex(gdb_get_current_addr()))
            cur_pc = gdb_get_current_addr()

            tmp_inst = self.request_inst(cur_pc)

            logging.info('start : 0x%x', tmp_inst.addr)

            checkpoint = self.assign_checkpoint()

            # follow the data flow of the corrupted return address
            for edge in tmp_inst.data_flow_edges:
                queue_for_root_find.append((tmp_inst, edge, checkpoint))
        
        # crash occurs because of invalid memory dereference
        else: 
            tmp_inst = self.request_inst(cur_pc)
            logging.info('start : 0x%x', tmp_inst.addr)

            checkpoint = self.assign_checkpoint()

            if len(tmp_inst.deref_flow_edges) == 0:
                logging.fatal('crash instruction (0x%x) has no dereference edge to follow' % (tmp_inst.addr))
                print('crash instruction has no dereference edge to follow')
                exit(-1)

            for edge in tmp_inst.deref_flow_edges:
                queue_for_root_find.append((tmp_inst, edge, checkpoint))

        logging.info('extracting root instructions for backtrace')

        if get_module_base(cur_pc):
            # crash address in the target executable
            for cur_inst, edge, checkpoint in queue_for_root_find:
                gdb.execute('restart %d' % (checkpoint))

                cur_pc = gdb_get_current_addr()
                cur_inst = self.request_inst(cur_pc)

                if get_module_base(cur_pc) != None:
                    logging.info("\troot found: 0x%x", cur_inst.addr)
                    self.add_root_inst(cur_inst)
                    continue

        else: # crash address not in the target executable
            while len(queue_for_root_find) != 0:
                tmp_inst, tmp_edge, checkpoint = queue_for_root_find.pop()
                gdb.execute('restart %d' % (checkpoint))

                if self.backtrace_to_source(tmp_inst, tmp_edge) != 0:
                    continue

                cur_pc = gdb_get_current_addr()
                cur_inst = self.request_inst(cur_pc)

                if get_module_base(cur_pc) != None:
                    logging.info("\troot found: 0x%x", cur_inst.addr)
                    self.add_root_inst(cur_inst)
                    continue

                logging.info('\tfollow data flow of 0x%x' % (cur_inst.addr))
                checkpoint = self.assign_checkpoint()

                # follow dataflow until it finds the target executable
                for edge in cur_inst.data_flow_edges:
                    queue_for_root_find.append((cur_inst, edge, checkpoint))


        self.clean_checkpoints()
        gdb.execute('d')

        for extra_root in extra_roots:
            addr = int(extra_root['addr'], 16)
            reg = extra_root['reg']
            value = int(extra_root['value'], 16)
            
            gdb.execute('r')
            
            b = gdb.Breakpoint('*0x%x' %(addr), gdb.BP_BREAKPOINT, gdb.WP_WRITE, False, False)
            b.silent = True

            while True:
                gdb.execute('c')

                cur_pc = gdb_get_current_addr()

                if cur_pc == dbg_start_addr:
                    print("extra root address not found (0x%x, %s, 0x%x)" % (addr, reg, value))
                    exit(-1)

                if value != int(gdb.parse_and_eval('$%s' % (reg))):
                    continue

                root_inst = self.request_inst(cur_pc)

                self.add_root_inst(root_inst)
                break

        gdb.execute('d')

        logging.info('backtrace root insts:')
        for inst in self.root_insts:
            logging.info('\t0x%x' % (inst.addr))


    def push_edge(self, bt_inst: BacktraceInst, depth):
        if len(bt_inst.data_flow_edges) + len(bt_inst.deref_flow_edges) != 0:
            # @TODO: it needs optimization
            new_checkpoint = self.assign_checkpoint()

            for edge in bt_inst.data_flow_edges:
                self.queue.append((new_checkpoint, bt_inst, edge, depth)) # push stack

            for edge in bt_inst.deref_flow_edges:
                self.queue.append((new_checkpoint, bt_inst, edge, depth)) # push stack     

    @timeout(seconds=timeout_)
    def backtrace(self, max_depth=10):
        logging.info('backtrace starts')
        logging.info('\tmax depth : %d' % (max_depth))
        logging.info('\ttimeout : %d' % (timeout_))        
        
        self.max_depth = max_depth

        self.set_average_fn_hit()
        
        # prevent waits for user-input
        gdb.execute('set pagination off')
        # suppress gdb's default STDOUT output
        gdb.execute('set print address off')
        gdb.execute('set print symbol-filename off')
        gdb.execute('set trace-commands off')
        gdb.execute('set confirm off')
        bt.set_backtrace_roots()

        while True:
            if len(self.checkpoints) > 20:
                self.clean_checkpoints()
            
            if len(self.queue) == 0: # traversal is done
                print("traversal is done")
                break
            
            self.execute_queue()


    def clean_checkpoints(self):
        print("[+] clean checkpoints (total : %d)" % (len(self.checkpoints)))

        remnant_points = set()

        for tup in self.queue:
            remnant_points.add(tup[0])
        
        deletes_ = self.checkpoints - remnant_points

        for point in deletes_:
            gdb.execute('delete checkpoint %d' % (point))

        self.checkpoints = remnant_points
                

    def graph(self):
        graph_txt = ""
        module_name = gdb_get_inferior_name()
        resolved = set()

        queue: list[BacktraceInst] = []
        
        for root_inst in self.root_insts:
            queue.append(root_inst)

        for extra_root in extra_roots:
            addr = int(extra_root['addr'], 16)
            root_inst = self.bt_insts[addr]
            queue.append(root_inst)

        while len(queue) != 0:
            cur_inst: BacktraceInst = queue.pop(0)
            
            if cur_inst.node != None:
                node_offset = cur_inst.node.offset
            else:
                node_offset = 0
            
            if node_offset < 0:
                node_offset = 0


            if cur_inst.node != None:
                graph_txt +="%s (%s): %s (%s, %s)\n" \
                        % (hex(cur_inst.addr), hex(node_offset), cur_inst.disasm_str, cur_inst.node.fn_name, addr2line(module_name, node_offset))
            else:
                graph_txt +="%s (%s): %s (none, %s)\n" \
                        % (hex(cur_inst.addr), hex(node_offset), cur_inst.disasm_str, addr2line(module_name, node_offset))

            for edge in cur_inst.in_edges:
                _, in_node, fn_hit = edge

                if in_node.addr in resolved:
                    continue
                
                queue.append(in_node)

                resolved.add(in_node.addr)

                if in_node.node != None and fn_hit != None:
                    fn = vfg.func_at(offset=in_node.node.fn_offset, img=in_node.node.img_name)

                    graph_txt +="| %s : %s (fn : 0x%x, hit cnt : %d)\n" % (hex(in_node.addr), in_node.disasm_str, fn.addr, fn_hit)
                else:
                    graph_txt +="| %s : %s (hit cnt : None)\n" % (hex(in_node.addr), in_node.disasm_str)

        return graph_txt

    def set_average_fn_hit(self):
        fn_cnt = 0
        total_fn_hit = 0

        for fn in vfg.funcs_with_addr.values():
            if get_module_base(fn.addr) != None:
                total_fn_hit += fn.hit_cnt
                fn_cnt += 1

        if fn_cnt == 0:
           print("total function count is 0")
           logging.error("set_average_fn_hit(): `fn_cnt` is 0")
           exit(-1)

        self.fn_hit_avg = total_fn_hit / fn_cnt

    def get_backtrace_graph(self) -> List[List[Tuple[BacktraceInst, int]]]:
        self.set_average_fn_hit()

        resolved: set[int] = set()
        # target_hashes: set[int] = set()
        
        tree: List[List[Tuple[BacktraceInst, int]]] = []
        
        cur_depth = 0
        tree.append([])

        for root_inst in self.root_insts:
            if root_inst.node != None:
                root_inst.offset = root_inst.addr - root_inst.module_base
                fn = vfg.func_at(offset=root_inst.node.fn_offset, img=root_inst.node.img_name)
            
                root_inst.img_name = root_inst.node.img_name

                # queue: List[BacktraceInst] = []
                tree[cur_depth].append((root_inst, fn.hit_cnt))
            else:
                tree[cur_depth].append((root_inst, None))

        for extra_root in extra_roots:
            root_addr = int(extra_root['addr'], 16)
            root_inst = self.bt_insts[root_addr]

            if root_inst.node != None:
                root_inst.offset = root_inst.addr - root_inst.module_base
                fn = vfg.func_at(offset=root_inst.node.fn_offset, img=root_inst.node.img_name)
            
                root_inst.img_name = root_inst.node.img_name

                # queue: List[BacktraceInst] = []
                tree[cur_depth].append((root_inst, fn.hit_cnt))
            else:
                tree[cur_depth].append((root_inst, None))


        while True:
            if len(tree[cur_depth]) == 0:
                break
            
            tree.append([]) # tree[cur_depth + 1]

            for inst, _ in tree[cur_depth]:
                for edge, edge_inst, fn_hit in inst.in_edges:

                    if edge_inst.addr in resolved:
                        continue
                    
                    if edge_inst.node != None:
                        edge_inst.img_name = edge_inst.node.img_name
                        edge_inst.offset = edge_inst.addr - edge_inst.module_base
                    
                    tree[cur_depth + 1].append((edge_inst, fn_hit))

                    resolved.add(edge_inst.addr)
        
            cur_depth += 1
        
        if len(tree[-1]) == 0:
            tree.pop()

        return tree

    def get_json(self):
        backtrace_tree = self.get_backtrace_graph()

        if len(backtrace_tree) == 0:
            print("Error: backtrace graph is empty")
            exit(-1)

        logging.info("finding triage insts")
        insts_for_triage = []
        visited = set()
        for root_inst, fn_hit in backtrace_tree[0]:
            cur_inst = root_inst

            if cur_inst.node == None:
                # check if current inst is out of analysis range
                if get_module_base(cur_inst.addr) == None:
                    logging.error("triage inst 0x%x is not available" % (cur_inst.addr))
                    exit(-1)

                insts_for_triage.append(cur_inst)
                continue

            # follow the data flows to find the instruction for triage
            while True:
                visited.add(cur_inst)

                if len(cur_inst.node.data_edges) != 1:
                    insts_for_triage.append(cur_inst)
                    break

                try:
                    next_inst = cur_inst.in_edges[0][1]
                except IndexError:
                    insts_for_triage.append(cur_inst)                    
                    break

                if next_inst.node == None:
                    insts_for_triage.append(cur_inst)                    
                    break

                # filter out immediate operand only cases
                if len(next_inst.node.data_edges) == 0:
                    insts_for_triage.append(cur_inst)
                    break
                
                if next_inst in visited:
                    insts_for_triage.append(cur_inst)
                    break

                cur_inst = next_inst

        result = {}
        result['triage'] = [inst.offset for inst in insts_for_triage]
        result['tree'] = []
        for insts in backtrace_tree:
            inst_jsons = []

            for inst, fn_hit in insts:
                inst_json = {'addr': inst.addr, 'offset': inst.offset, 'img_name': inst.img_name, 'fn_hit': fn_hit}
                inst_jsons.append(inst_json)
        
            result['tree'].append(inst_jsons)

        return json.dumps(result, indent=2)

    def get_module_range(self):
        # find main module's base address and its range

        text = gdb.execute('info proc mappings', to_string=True)
        lines = text.split('\n')
        skip_modules = [ 'librrpreload.so', 'ld-2.31.so']
        mod_found = {}

        for module_name in target_modules:
            mod_found[module_name] = {}

        for module_name in skip_modules:
            mod_found[module_name] = {}

        for line in lines:
            words = line.split()

            try:
                start_addr, end_addr, size, offset, file_path = words
            except ValueError:
                continue
            
            file_name = os.path.basename(file_path)

            if file_name not in target_modules and file_name not in skip_modules:
                continue

            if len(mod_found[file_name]) == 0: # first touch
                logging.info('%s start addr : 0x%x' % (file_name, int(start_addr, base=16)))
                mod_found[file_name] = {'start_addr': int(start_addr, base=16), 'end_addr': int(end_addr, base=16)}
            else: # update end address of the module
                mod_found[file_name]['end_addr'] = int(end_addr, base=16)

        for name, info in mod_found.items():
            if len(info) == 0:
                continue
                # raise BacktracerError("\"%s\" not found in mapping" % (name))
            if name in skip_modules:
                bt_modules.add_skip_module(name, info['start_addr'], info['end_addr'])        
            else:
                add_module(name, info['start_addr'], info['end_addr'])

        return

t = time.time()

if check_ASLR() != 0:
    exit(-1)

print("timeout: %d" % (timeout_))

dbg_start_addr = gdb_get_current_addr()

gdb.execute('c')
# gdb.execute('rc') # RR's reverse-continue catches crash address twice. skip one of them

bt = backtracer(dbg_start=dbg_start_addr)

bt.crash_addr = gdb_get_current_addr()

# make sure all shared libraries are loaded
bt.get_module_range()
try:
    bt.backtrace(max_depth=50)
except TimeoutError:
    print("timeout!")

print('elapsed time : ', time.time() - t)
logging.info('elapsed time : %s', str(time.time() - t))

graph_txt = bt.graph()

with open("rev_graph.txt", 'w') as f:
    f.write(graph_txt)

result = bt.get_json() 
logging.info('get_json --> \"%s\"', 'origins.json')
with open(os.path.join(out_dir, 'origins.json'), 'w') as f:
    f.write(result)

exit(0)