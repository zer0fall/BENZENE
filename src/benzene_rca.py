import pandas as pd
import sqlite3
import json
import logging

from dynvfg import *
from benzene_pred import *

from typing import List
from typing import Dict
from typing import Tuple

class PredicateManagerError(Exception):
    def __init__(self, msg):
        super().__init__(msg)

# initial crash's behavior vector
crash_vector : List[str] = []

# def cosine_distance(coor1, coor2) -> float:
#     v1 = np.array(coor1)
#     v2 = np.array(coor2)
#     d = np.dot(v1, v2) / (np.linalg.norm(v1) * np.linalg.norm(v2))
#     return 1 - d

def euclid_dist(coor1, coor2):
    d = 0

    for a1, a2 in zip(coor1, coor2):
        d += (a1 - a2) ** 2

    return d


class PredicateManager: # save predicate information corresponding to current run
    def __init__(self, img_name, vfg: DynVFG):
        self.conn = None
        self.img_name = img_name
        self.crash_vec: List[str] = None

        self.corpus2idx: Dict[int, int] = {}
        self.idx2corpus: Dict[int, int] = {}
        
        self.instructions : Dict[int, List[BenzenePred]] = {}

        self.vfg: DynVFG = vfg
        self.compress_done = False

        self.corpus_range: Tuple[int, int] = None

        self.exec_order: Dict[int, int] = {}
        self.mem_ref_range: Tuple[int, int] = None

    def pred_at(self, offset) -> List[BenzenePred]:
        return self.instructions[offset]


    def setup(self, corpus, trace_db_path: str, config_path: str, corpus_range: Tuple[int, int]=None):
        self.conn = sqlite3.connect(trace_db_path)
        cur = self.conn.cursor()

        # mapping table for actual CorpusId (used in fuzzing) with database's corpus idx
        if corpus_range:
            cur.execute('SELECT DISTINCT CorpusId FROM Traces WHERE CorpusId >= %d and CorpusId <= %d' % (corpus_range[0], corpus_range[1]))
            rows = cur.fetchall()
            self.corpus_range = corpus_range
        else:
            cur.execute('SELECT DISTINCT CorpusId FROM Traces')
            rows = cur.fetchall()

        row_cnt = 0
        for r in rows:
            corpus_id = r[0]
            # sqlite's Primary Key starts from 1, not 0
            # decrease the index value for setting the index to start from 0.
            
            if corpus_id in self.corpus2idx.keys():
                raise KeyError("corpusid %d already exists in dict" % (corpus_id))

            self.corpus2idx[corpus_id] = row_cnt
            self.idx2corpus[row_cnt] = corpus_id

            row_cnt += 1

        if self.read_config(config_path) < 0:
            return -1

        cur.close()

        # set crash vector
        self.crash_vec = [None] * len(self.corpus2idx)

        crash_exist = False
        non_crash_exist = False

        for corpus_id, crash, _ in corpus:
            try:
                idx = self.corpus2idx[corpus_id]
            except KeyError:
                # corpus_id does not exist in dict because corpus_id has no trace data (RUNNER_STATUS_CRASH_MISMATCH)
                logging.debug("corpus %d (crash: %d) has no trace data" % (corpus_id, crash))
                continue            

            try:
                if crash == 1:
                    self.crash_vec[idx] = True
                    crash_exist = True
                else:
                    self.crash_vec[idx] = False
                    non_crash_exist = True
            except IndexError:
                logging.fatal("corpus %d is out of range (id: %d, corpus_range : %s, len(crash_vec) : %d)" % (corpus_id, idx, str(self.corpus_range), len(self.crash_vec)))
                exit(-1)
        

        if crash_exist == False or non_crash_exist == False:
            logging.error("something went wrong during tracing. behavior not diverted (crash: %s, non-crash: %s)" % (str(crash_exist), str(non_crash_exist)))
            return -1

        # Create INDEX for performance boost
        logging.info("creating index... \"%s\"" % (trace_db_path))
        cur = self.conn.cursor()
        cur.execute("CREATE INDEX IF NOT EXISTS constants_offset_operand ON Traces(Offset, Operand)")
        cur.close()
        
        return 0


    def get_matrix(self, preds: List[BenzenePred]) -> pd.DataFrame:
        matrix = pd.DataFrame([p.repr_vector for p in preds], index=[p.img_name + "." + hex(p.offset) + ".%s" % (p.pred_str) for p in preds]).transpose()
        matrix = pd.concat( [ pd.DataFrame({"crash": self.crash_vec}), matrix ], axis=1)

        return matrix

    def get_rows(self, image, offset, op_name):
        cur = self.conn.cursor()
        
        if self.corpus_range != None:
            cur.execute("SELECT CorpusId, Value FROM Traces WHERE Image='%s' and Offset=%d and Operand='%s' and CorpusId >=%d and CorpusId <=%d" % (image, offset, op_name, self.corpus_range[0], self.corpus_range[1]))
        else:
            cur.execute("SELECT CorpusId, Value FROM Traces WHERE Image='%s' and Offset=%d and Operand='%s'" % (image, offset, op_name))
        
        rows = cur.fetchall()

        return rows

    def set_trace_rows(self, pred: BenzenePred) -> TraceRows:
        trace_rows : TraceRows = [[] for i in range(len(self.crash_vec))]
        
        # print("\t- fetching traced values from db...")
        sql_rows = self.get_rows(pred.img_name, pred.offset, pred.op_name())
        if not len(sql_rows):
            return None

        # print("\t- fetch done : %d items" % (len(rows)))

        # save trace values of each run
        # row[0] : CorpusId
        # row[1] : Value
        for (corpusid, value) in sql_rows:
            value = int.from_bytes(value, byteorder='little') # bytes to int

            trace_rows[ self.corpus2idx[corpusid] ].append(value)

        return trace_rows

    @property
    def initial_crash(self):
        return self.corpus_range[0]

    def process_predicate(self, pred: BenzenePred):
        rows = self.set_trace_rows(pred)
        
        if rows == None:
            logging.warning("no trace information at offset 0x%x (%s)" % (pred.offset, pred.op_name()))
            return

        pred.node = self.vfg.node_at(offset=pred.offset, img=pred.img_name)

        if pred.node == None:
            logging.warning("offset 0x%x has no data flow information." % (pred.offset))
            return
        try:
            edges = pred.node.get_edges(REG[pred.op_name()])
            if edges == None:
                # check if it's a clear instruction e.g., xor eax, eax
                disas = pred.node.disassemble()
                tokens = disas.split()
                if not ( tokens[0] in ['xor', 'pxor'] and tokens[1][:-1] == tokens[2] ):
                    logging.warning("DynNode (0x%x, 0x%x) has no %s operand." % (pred.node.addr, pred.offset, pred.op_name()))
                return            
        except KeyError:
            logging.warning("Operand (0x%s) does not exist in REG(Enum) (addr: 0x%x, offset: 0x%x)." % (pred.op_name(), pred.node.addr, pred.offset))
            return

        # if len(edges) == 0:
        #     logging.warning("There is no incoming edge (%s) (addr: 0x%x, offset: 0x%x)." % (pred.op_name(), pred.node.addr, pred.offset))
        #     return

        pred.synthesize(rows, self.crash_vec, self.corpus2idx[self.initial_crash], ptr_range=self.mem_ref_range)


    def read_config(self, config_path) -> int:
        if config_path is None:
            raise PredicateManagerError("config_path is not provided")

        with open(config_path, 'rb') as f:
            config = json.load(f)

        for inst_json in config['insts']:
            offset = inst_json['offset']
            img_name = inst_json['img_name']
            
            try:
                fn_name = self.vfg.node_at(offset=inst_json['offset'], img=self.img_name).fn_name
            except AttributeError:
                continue
            
            # sanitizer-related instructions are out-of-scope
            if 'asan' in fn_name or 'msan' in fn_name:
                continue

            preds: List[BenzenePred] = []
            
            exec_order = None

            for op_json in inst_json['ops']:
                # There are cases that a instruction has multiple operands.
                # We fix their execution order with preceeding one.
                if exec_order == None:
                    exec_order = op_json['exec_order']
                elif op_json['exec_order'] < exec_order:
                    exec_order = op_json['exec_order']

                self.exec_order[offset] = exec_order
                op_name = op_json['op_name']
                read_size = op_json['read_size']
                mut_type = op_json['mut_type']
                if op_json['dump_flag']:
                    try:
                        preds.append(BenzenePred(img_name, offset, REG[op_name], read_size, exec_order, mut_type))
                    except KeyError:
                        logging.warning("register %s is not defined (offset: 0x%x)." % (op_name, offset))
                        n = self.vfg.node_at(offset=offset, img=img_name)
                        if n != None:
                            logging.warning("\texpected : %s" % (str(n.get_dataflow_srcs())))

            if len(preds):
                self.instructions[offset] = preds

        return 0

    def get_exec_order(self, offset):
        return self.exec_order[offset]

    def drop_dups(self):
        if self.db == None:
            raise PredicateManagerError("drop_dups(): target db is not specified")
        
        conn = sqlite3.connect(self.db)
        
        cur = conn.cursor()

        if self.corpus_range:
            cur.execute("SELECT CorpusId, Value, Offset, Operand FROM UsedSeeds WHERE CorpusId >= %d and CorpusId <= %d" % (self.corpus_range[0], self.corpus_range[1]))
        else:
            cur.execute("SELECT CorpusId, Value, Offset, Operand FROM UsedSeeds")

        rows = cur.fetchall()

        data = []

        for corpus_id, val, offset, op in rows:
            val = int.from_bytes(val, byteorder='little')

            data.append((corpus_id, val, offset, op))


        df = pd.DataFrame(data=data, columns=['CorpusId', 'Value', 'Offset', 'Op'])

        idx = 0
        for i in df.duplicated(['Value', 'Offset', 'Op']):
            if i == True:
                # print("duplicated", df.loc[idx]['CorpusId'])
                cur.execute("DELETE FROM Corpus WHERE CorpusId = %d" % (df.loc[idx]['CorpusId']))
                conn.commit()

                cur.execute("DELETE FROM Traces WHERE CorpusId = %d" % (df.loc[idx]['CorpusId']))
                conn.commit()

                cur.execute("DELETE FROM UsedSeeds WHERE CorpusId = %d" % (df.loc[idx]['CorpusId']))
                conn.commit()        
            idx += 1

        conn.close()
