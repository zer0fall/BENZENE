import os
import subprocess
import logging
import os
import sqlite3
import logging
import json
from benzene_config import *
from benzene_pred import *
from benzene_rca import *
from dynvfg import *
from typing import List
from typing import Dict
from typing import Tuple
from capstone import *
from capstone.x86 import *

pin_path = os.path.join(os.environ['PIN_ROOT'], 'pin')
drrun_path = os.path.join(os.environ['DR_BUILD'], 'bin64/drrun')
dr_path = os.path.join(os.environ['DR_BUILD'])
tool_dir = os.path.join(os.environ['BENZENE_HOME'], 'tools')

skip_insts_for_seed = [NodeType.TYPE_PUSH, NodeType.TYPE_POP]
ops_to_skip : List[REG] = [REG.rsp, REG.rip]

vfg: DynVFG = DynVFG()

def auto_int(x):
    return int(x, 0)

class BenzeneError(Exception):
    def __init__(self, msg):
        super().__init__(msg)

# @TODO: Parsing disassembly string is an ugly implementation.
#        Instead, use disassembly-related library such as capstone
def extract_branch_bytes(node: DynNode) -> int: 
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    csinsn: CsInsn = None
    for i in md.disasm(node.inst_bytes, 0x0, count=1):
        csinsn = i

    if csinsn.mnemonic == 'cmp':
        for op in csinsn.operands:
            if op.type == X86_OP_IMM: # get cmp value. e.g., 0x41414141 in cmp eax, 0x41414141
                val = op.value.imm
                if val < 0:
                    # make it unsigned
                    val = val + (1 << (csinsn.imm_size * 8)) # csinsn.imm_size * 8 : num of bit
                return val
    elif csinsn.mnemonic == 'test':
        ops = []
        for op in csinsn.operands:
            if op.type == X86_OP_REG:
                if op.reg in ops: # e.g., test eax, eax
                    return 0x0
                ops.append(op.reg)
            elif op.type == X86_OP_MEM:
                if op.mem in ops: # e.g., test eax, eax                
                    return 0x0
                ops.append(op.mem)

    return None


class BenzeneFuzzSession:
    def __init__(self,
            benzene_config: BenzeneConfig,
            target_offset: int, 
            target_img:str, 
            target_hit_cnt: int, 
            triage_offset: int, 
            fn_name: str = "none", 
            iter_per_target: int = 15, 
            depth: int = 0, 
            timeout: int = 3,
        ):
        self.benzene_config: BenzeneConfig = benzene_config
        self.fn_offset: int = target_offset
        self.target_img: str = target_img
        self.hit_cnt: int = target_hit_cnt
        self.triage_offset: int = triage_offset
        self.fn_name: str = fn_name
        self.pred_manager: PredicateManager = None
        self.name: str = "0x%x.%s.%s.%d" % (self.fn_offset, self.target_img, self.fn_name, target_hit_cnt)        
        self.session_dir: str = os.path.join(benzene_config.outdir_path, 'session.%s' % (self.name))
        self.corpus = []

        if os.path.exists(self.session_dir) == False:
            os.mkdir(self.session_dir)

        # config file paths are defined
        self.mut_target_path: str = os.path.join(self.session_dir, 'mutation.targets.0x%x.csv' % (self.fn_offset))
        self.summary_filepath: str = os.path.join(self.session_dir, 'summary.0x%x.txt' % (self.fn_offset))
        self.fuzz_config_path: str = os.path.join(self.session_dir, "fuzz.config.json")
        self.trace_config_path: str = os.path.join(self.session_dir, "trace.config.json")
        self.dryrun_config_path: str = os.path.join(self.session_dir, "dryrun.config.json")

        self.corpus_path: str = os.path.join(self.session_dir, 'corpus')
        self.trace_db_path: str = os.path.join(self.session_dir, 'trace/trace.db')

        self.auto_iter: int = None
        self.iter_per_target: int = iter_per_target

        self.corpus_range: Tuple(int, int) = None

        self.fuzz_result: Dict = None

        self.depth: int = depth
        self.merge: bool = False
        self.synthesized: bool = False
        self.timeout: int = timeout

    def get_mutation_targets(self)->List[Tuple[DynNode, REG]]:
        mutation_targets = []

        for node in vfg.nodes:
            # PUSH and POP are excluded
            if node.type in skip_insts_for_seed:
                continue
            
            if node.fn_offset == self.fn_offset: # for node in target function
                # check data-flow edges
                for src_op, edges in node.data_edges.items():
                    if src_op in ops_to_skip:
                        continue

                    if len(edges) == 0:
                        # there are data flow edges, but no available DynNode
                        # we assume the data source is from the outside of the funtion
                        mutation_targets.append((node, src_op))
                        break

                    for src_node in edges:
                        if src_node.fn_offset != self.fn_offset:
                            mutation_targets.append((node, src_op))
                            break

        return mutation_targets

    def check_dict_op(self, dict_node: DynNode) -> bool:      
        if len(dict_node.data_srcs) != 1:
            logging.warning("dict(0x%x, 0x%x) has no single dataflow source" % (dict_node.addr, dict_node.offset))
            return False

        if dict_node.data_srcs[0] in ops_to_skip:
            logging.warning("dict(0x%x, %s) is non-mutatable" % (dict_node.offset, dict_node.data_srcs[0].name))
            return False
        
        return True

    def read_config(self) -> dict:
        try:
            with open(self.fuzz_config_path, 'r') as f:
                config_json = json.load(f)
        except FileNotFoundError:
            return None
        return config_json

    def serialize_config(self) -> int:
        mut_targets = self.get_mutation_targets()

        if len(mut_targets) < 0:
            logging.error("session %s: no mutation target identified ( `len(mut_targets) < 0` )" % (self.name))
            return -1
        
        # set value: iteration per target.
        self.auto_iter = len(mut_targets) * self.iter_per_target

        logging.info('\tmutation targets: ')
        for node, op_name in mut_targets:
            logging.info('\t\t0x%x (%s)' % (node.offset, op_name.name))
        
        if len(mut_targets) == 0:
            logging.error("mutation target count is 0 ( `len(mut_targets) == 0` )")
            # there is no instruction to fuzz with
            return -1

        mut_targets_json = []

        for mut_node, op in mut_targets:
            addr = mut_node.addr
            op_name = op.name
            offset = mut_node.offset
            img_name = mut_node.img_name

            # set dictionary values for fuzzing
            dictionary = []

            dict_val = extract_branch_bytes(mut_node) # mut_node itself is a control instruction. e.g., cmp, test, ...
            if dict_val is not None:
                dictionary.append(dict_val)

            # get dictionary values used in program branches (e.g., cmp, test)
            # @TODO: consider out-going edges further
            cntl_nodes = []
            for outgoing_node in mut_node.out_data_edges:
                if outgoing_node.disassemble().split()[0] in ['cmp', 'test']:
                    cntl_nodes.append(outgoing_node)

            for cntl_node in cntl_nodes:
                dict_val = extract_branch_bytes(cntl_node)
                if dict_val is None:
                    continue
                dictionary.append(dict_val)

            # get an instruction for mutation dict 
            # last node of single data flow is needed only
            dict_node = mut_node.follow_single_edge(op)

            if len(dict_node.data_edges) == 0:
                logging.warning("dict node has no dataflow edges (dict: 0x%x, 0x%x)" % (dict_node.addr, dict_node.offset))
                dict_node = mut_node

            if dict_node.offset == mut_node.offset:
                mut_targets_json.append({"offset": offset,
                                        "addr": addr, 
                                        "op_name": op_name, 
                                        "img_name": img_name, 
                                        "dict_offset": offset, 
                                        "dict_img_name": img_name, 
                                        "dict_op_name": op_name,
                                        "dictionary": dictionary})
                continue
            elif not self.check_dict_op(dict_node):
                logging.info('check_dict_op() failed, skip the mutation target (0x%x, 0x%x, %s)' % (mut_node.addr, mut_node.offset, op_name))
                continue

            mut_targets_json.append({"offset": offset, 
                                    "addr": addr,
                                    "op_name": op_name, 
                                    "img_name": img_name, 
                                    "dict_offset": dict_node.offset, 
                                    "dict_img_name": dict_node.img_name, 
                                    "dict_op_name": dict_node.data_srcs[0].name,
                                    "dictionary": dictionary})

        ############################################################
        dryrun_config_json = {}

        dryrun_config_json['dryrun_done'] = 0
        dryrun_config_json['triage_offset'] = self.triage_offset
        dryrun_config_json['fuzz_offset'] = self.fn_offset
        dryrun_config_json['hit_cnt'] = self.hit_cnt
        dryrun_config_json['seed_cnt'] = len(mut_targets_json)
        dryrun_config_json['crash_addr'] = 0x0
        dryrun_config_json['crash_offset'] = 0x0
        dryrun_config_json['crash_img'] = ''
        dryrun_config_json['triage_offset'] = self.triage_offset
        dryrun_config_json['hitcnt_for_triage'] = 0
        dryrun_config_json['pass_hang'] = self.benzene_config.pass_hang
        dryrun_config_json['mutation_targets'] = mut_targets_json
        dryrun_config_json['insts'] = []

        with open(os.path.join(self.session_dir, 'dryrun.config.json'), 'w') as f:
            json.dump(dryrun_config_json, f, indent=4)

        return 0

    def first_id(self) -> int:
        if self.corpus_range == None:
            corpus_id_list = []
            for filename in os.listdir(self.corpus_path):
                corpus_id = int(filename.split('.')[0], 16) # file format : 0x0001.crash.json, 0x0023.non-crash.json, ...
                corpus_id_list.append(corpus_id)

            return min(corpus_id_list)

        return self.corpus_range[0]

    def last_id(self) -> int:
        if self.corpus_range == None:
            corpus_id_list = []
            for filename in os.listdir(self.corpus_path):
                corpus_id = int(filename.split('.')[0], 16) # file format : 0x0001.crash.json, 0x0023.non-crash.json, ...
                corpus_id_list.append(corpus_id)

            return max(corpus_id_list)

        return self.corpus_range[1]

    def parse_fuzz_result(self) -> int:
        self.fuzz_result = {}

        self.fuzz_result['corpus-db'] = self.corpus_path
        self.fuzz_result['trace-db'] = self.trace_db_path

        with open(self.summary_filepath, 'r') as f:
            lines = f.read().splitlines()
            
            self.fuzz_result['seeds'] = {}

            for line in lines:
                if len(line) == 0:
                    break

                if 'fuzz_offset' in line:
                    val_token = line.split('=')[1]
                    self.fuzz_result['fuzz_offset'] = auto_int(val_token)
                elif 'seed' in line:
                    seed_offset, false_crash, total_hit, ratio = line.split(',')
                    
                    seed_offset = auto_int(seed_offset.split('=')[1])

                    info = {}
                    self.fuzz_result['seeds'][seed_offset] = info
                    
                    info['false_crash'] = auto_int(false_crash.split('=')[1])
                    info['total_hit'] = auto_int(total_hit.split('=')[1])
                    info['ratio'] = float(ratio.split('=')[1])
                elif 'false_crash_cnt' in line:
                    val_token = line.split('=')[1]
                    self.fuzz_result['false_crash'] = auto_int(val_token)                    
                elif 'hit_cnt' in line:
                    val_token = line.split('=')[1]
                    self.fuzz_result['hit_cnt'] = auto_int(val_token)
                elif 'non_crash' in line:
                    val_token = line.split('=')[1]
                    self.fuzz_result['non_crash'] = auto_int(val_token)                
                elif 'crash' in line:
                    val_token = line.split('=')[1]
                    self.fuzz_result['crash'] = auto_int(val_token)
                elif 'total_run' in line:
                    val_token = line.split('=')[1]
                    self.fuzz_result['total_run'] = auto_int(val_token) 

        with open(os.path.join(self.session_dir, 'fuzz_result.json'), 'w') as f:
            json.dump(self.fuzz_result, f)            

        # sanitize the result
        for seed_offset, seed_result in self.fuzz_result['seeds'].items():
            if seed_result['total_hit'] == 0:
                logging.error('fuzz result of session 0x%x (%s) got error' % (self.fn_offset, self.fn_name))
                logging.error("mutation target 0x%x is not selected" % (seed_offset))
                logging.error('check session\'s log : \"%s\"' % (os.path.join(self.session_dir, 'session.log')))
                # logging.error('fuzz result : \n%s' % (json.dumps(self.fuzz_result, sort_keys=True, indent=4)))

                return -1
                # raise ValueErException("seed 0x%x is not selected" % (seed_offset))

        return 0

    def dryrun(self, mode="fuzz") -> int:
        bfuzz_path = os.path.join(tool_dir, 'bfuzz.so')

        if mode != "fuzz" and mode != "trace":
            logging.fatal("invalid mode %s" % (mode))
            exit(-1)
        
        # handle STDIN-based program input if any exists
        stdin = subprocess.PIPE
        if self.benzene_config.stdin_filepath:
            logging.info('stdin mode enabled: \"%s\"' % (self.benzene_config.stdin_filepath))
            stdin = open(self.benzene_config.stdin_filepath, 'rb')
        
        cmd_list = [drrun_path, '-root', dr_path,
                '-c', bfuzz_path,
                '-work_dir', self.session_dir,
                '-corpus_id', str(self.corpus_range[0]), # assign the first id from the given corpus range
                '-run_module', self.target_img,
                '-mode', mode,
                '-dryrun',
                '--'] + self.benzene_config.target_cmd.split()

        if self.benzene_config.asan:
            cmd_list.insert(cmd_list.index('--'), '-asan')

        logging.info("session %s dryrun (cmd : \"%s\")" %((self.name, subprocess.list2cmdline(cmd_list))))

        # first dry run
        ret = subprocess.run(cmd_list, stdin=stdin, stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'))
        # ret = subprocess.run(cmd_list)

        if ret.returncode != 0:
            logging.error("session %s dryrun failed" % (self.name))
            return -1
        logging.info("session %s dryrun done" %(self.name))

        if self.benzene_config.stdin_filepath: stdin.close()

        return 0


    def fuzz(self):
        if self.corpus_range == None:
            raise ValueError('session %s corpus range not set' % (self.name))
        # self.corpus_range = (first_id, first_id + self.auto_iter)
        
        bfuzz_path = os.path.join(tool_dir, 'bfuzz.so')
        bfuzz_server_path = os.path.join(tool_dir, 'bfuzz_server')

        server_proc = subprocess.Popen([
                            bfuzz_server_path, 
                            '--proc', str(self.benzene_config.num_proc), 
                            '--iter', str(self.auto_iter), 
                            '--corpus_id', str(self.first_id() + 1), # first-id is assigned to the dryrun 
                            '--config', self.fuzz_config_path,
                            '--summary', self.summary_filepath,
                            '--timeout', str(self.timeout),
                            ],
                            stdout=open(os.devnull, 'wb'),
                            stderr=open(os.devnull, 'wb'))

        logging.info("fuzz() server (cmd : \"%s\")" % (subprocess.list2cmdline(server_proc.args)))

        fuzz_cmd_list = [drrun_path, '-root', dr_path,
                        '-c', bfuzz_path,
                        '-work_dir', self.session_dir,
                        '-run_module', self.target_img,
                        '--'] + self.benzene_config.target_cmd.split()

        if self.benzene_config.asan:
            fuzz_cmd_list.insert(fuzz_cmd_list.index('--'), '-asan')

        stdin = subprocess.PIPE
        if self.benzene_config.stdin_filepath:
            logging.info('stdin mode enabled: \"%s\"' % (self.benzene_config.stdin_filepath))
            stdin = open(self.benzene_config.stdin_filepath, 'rb')

        # @TODO: unexpected results with subprocess.Popen() (https://github.com/grill66/Benzene/issues/17)
        # os.system(subprocess.list2cmdline(fuzz_cmd_list))
        # proc_run = subprocess.Popen(fuzz_cmd_list, stdin=stdin)
        proc_run = subprocess.Popen(fuzz_cmd_list,
                                stdin=stdin,
                                stdout=open(os.devnull, 'wb'),
                                stderr=open(os.devnull, 'wb'))
        
        logging.info("fuzz() bfuzz (cmd : \"%s\")" % (subprocess.list2cmdline(fuzz_cmd_list)))

        proc_run.wait()
        if proc_run.returncode != 0:
            logging.error("fuzzing failed (bfuzz return code : %d)" % (proc_run.returncode))
            server_proc.kill()
            return -1

        server_proc.wait()

        if server_proc.returncode != 0:
            logging.error('fuzzing failed (server return code : %d)' % (server_proc.returncode))
            return -1

        if self.benzene_config.stdin_filepath: stdin.close()

        return 0


    def trace(self):
        bfuzz_path = os.path.join(tool_dir, 'bfuzz.so')
        bfuzz_server_path = os.path.join(tool_dir, 'bfuzz_server')

        # set timeout properly
        if self.benzene_config.pass_hang:
            timeout = self.timeout + 10
        else:
            timeout = self.timeout + 60
        
        server_proc = subprocess.Popen([
                            bfuzz_server_path, 
                            '--proc', str(self.benzene_config.num_proc), 
                            '--trace', str(self.corpus_path),
                            '--config', self.fuzz_config_path,
                            '--summary', self.summary_filepath,
                            '--timeout', str(timeout),
                            ],
                            stdout=open(os.devnull, 'wb'),
                            stderr=open(os.devnull, 'wb'))

        logging.info("trace() server (cmd : \"%s\")" % (subprocess.list2cmdline(server_proc.args)))

        fuzz_cmd_list = [drrun_path, '-root', dr_path,
                        '-c', bfuzz_path,
                        '-work_dir', self.session_dir,
                        '-run_module', self.target_img,
                        '-mode', 'trace', # enable trace mode
                        '--'] + self.benzene_config.target_cmd.split()
        
        if self.benzene_config.asan:
            fuzz_cmd_list.insert(fuzz_cmd_list.index('--'), '-asan')

        logging.info("trace() bfuzz (cmd : \"%s\")" % (subprocess.list2cmdline(fuzz_cmd_list)))

        stdin = subprocess.PIPE
        if self.benzene_config.stdin_filepath:
            logging.info('stdin mode enabled: \"%s\"' % (self.benzene_config.stdin_filepath))
            stdin = open(self.benzene_config.stdin_filepath, 'rb')

        # @TODO: unexpected results with subprocess.Popen() (https://github.com/grill66/Benzene/issues/17)
        # os.system(subprocess.list2cmdline(fuzz_cmd_list))
        proc_run = subprocess.Popen(fuzz_cmd_list, stdin=stdin, stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'))
        proc_run.wait()

        if proc_run.returncode != 0:
            logging.error("%s trace failed (bfuzz error)" % (self.name))
            server_proc.kill()
            return -1

        server_proc.wait()
        if self.benzene_config.stdin_filepath: stdin.close()

        return 0    

    def synthesize(self):
        if self.synthesized:
            return 0

        logging.info("session %s: synthesize predicates" % (self.name))

        if self.pred_manager is None:
            self.pred_manager = PredicateManager(self.target_img, vfg)
            
            if self.pred_manager.setup(self.corpus, self.trace_db_path, config_path=self.trace_config_path, corpus_range=self.corpus_range) < 0:
                self.synthesized = True                
                return -1

            with open(os.path.join(self.session_dir, 'maps'), 'r') as f:
               map_buf = f.read()
            memref_start = int(map_buf.split('\n')[0].split()[0].split('-')[0], base=16)
            memref_end = int(map_buf.split('\n')[-3].split()[0].split('-')[1], base=16)
            self.pred_manager.mem_ref_range = (memref_start, memref_end)

            logging.debug("idx2corpus: \n%s" % (str(self.pred_manager.idx2corpus)))

            # synthesize predicates per instruction
            for preds in self.pred_manager.instructions.values():
                for p in preds:
                    logging.debug("%s synthesis => offset 0x%x (%s)" % (self.name, p.offset, p.op_name()))
                    self.pred_manager.process_predicate(p)

            pred_cnt = 0
            for preds in self.pred_manager.instructions.values():
                for p in preds:
                    if p.pred_str == None:
                        continue

                    if p.node == None:
                        continue

                    pred_cnt += 1

            if pred_cnt == 0:
                logging.info("no predicates are synthesized for %s" % (self.name))
                self.synthesized = True
                return -1

        self.synthesized = True
        return 0

    def get_preds_from_non_crash(self, corpusid) -> List[BenzenePred]:
        selected: List[BenzenePred] = []
        try:
            idx = self.pred_manager.corpus2idx[corpusid]
        except KeyError:
            logging.warning('corpus id %d is not traced (because of result mismatch between fuzzing & tracing)' % (corpusid))
            return selected

        result_preds: List[BenzenePred] = []
        for preds in self.pred_manager.instructions.values():
            for p in preds:
                if p.pred_str == None or p.node == None or p.vector == None:
                    continue                
                result_preds.append(p)

        for p in result_preds:
            # we use the predicates `True`` in crash and `False` in non-crash
            if p.vector[INITIAL_CRASH_IDX] != True:
                # initial crash must be true on this predicate                          
                continue
            if p.vector[idx] != False: 
                continue
            selected.append(p)

        return selected

    def read_corpus(self):
        self.corpus: List[Tuple[int, int]] = []
        corpus = os.listdir(self.corpus_path)
        
        for filename in corpus:
            mutation_filepath = os.path.join(self.corpus_path, filename)
            
            with open(mutation_filepath, 'r') as f:
                mutation_json = json.load(f)

            corpus_id = mutation_json['corpus_id']
            crash = mutation_json['crash']

            self.corpus.append((corpus_id, crash, mutation_filepath))

        if self.corpus_range == None:
            corpus_list = [ t[0] for t in self.corpus ]
            self.corpus_range = ( min(corpus_list), max(corpus_list) )

    def get_mutation(self, corpus_id):
        for _id, crash, mut_filepath in self.corpus:
            if _id == corpus_id:
                with open(mut_filepath, 'r') as f:
                    mut_json = json.load(f)

                return mut_json['mutation']

        return None

    def merge_db(self):
        db_dir_path = os.path.join(self.session_dir, 'trace')
        self.trace_db_path = os.path.join(db_dir_path, 'trace.db')

        pri_db_path = os.path.join(db_dir_path, 'trace.0.db')

        conn = sqlite3.connect(pri_db_path)

        for db_name in os.listdir(db_dir_path):
            _ = db_name.split('.')

            if len(_) != 3:
                continue

            cur_prefix, cur_db_num, ext = _

            if 'trace' != cur_prefix:
                raise BenzeneError("prefix mismatch: `\"trace\" != \"%s\"`" % (cur_prefix))

            if cur_db_num == '0':
                continue

            db_path = os.path.join(db_dir_path, db_name)
            conn.execute("ATTACH '%s' as sub_db" % (db_path))

            conn.execute("BEGIN")
            
            conn.execute("INSERT INTO Corpus(CorpusId, Crash, Triage) SELECT CorpusId, Crash, Triage FROM sub_db.Corpus")
            conn.execute("INSERT INTO Traces SELECT * FROM sub_db.Traces")
            conn.execute("INSERT INTO UsedSeeds SELECT * FROM sub_db.UsedSeeds")

            conn.commit()
            conn.execute("detach database sub_db")

            os.remove(db_path)

        os.rename(pri_db_path, os.path.join(db_dir_path, 'trace.db'))        
