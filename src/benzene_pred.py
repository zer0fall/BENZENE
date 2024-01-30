from __future__ import annotations
import importlib
import pandas as pd
from enum import Enum
import numpy as np
import logging
from benzene_predclass import *

import sys
from dynvfg import *

from typing import List
from typing import Dict
from typing import Tuple

TraceRows = List[List[int]]

INITIAL_CRASH_IDX = 0

class BenzenePredError(Exception):
    def __init__(self):
        super().__init__('BenzenePred Error')

class BenzenePred:
    def __init__(self, img_name: str, offset: int, op: REG, read_size: int, order: int, mut_type):
        self.img_name: str = img_name
        self.op: REG = op
        self.offset: int = offset
        self.read_size: int = read_size
        self.exec_order: int = order
        self.pred_class = None 
        self.pred_str: str = None
        self.score: int = None
        self.vector: List[bool] = None
        self.hit_vector: List[int] = None
        self.mut_type = mut_type

        self.node: DynNode = None

        self.sub_preds: List[BenzenePred] = []
        self.is_toplevel: bool = True

        self.score: float = None

        self.repr_score: float = None
        self.repr_vector: List[bool] = None

    def op_name(self):
        return self.op.name

    def extract(self, vectors: List[Tuple[PredClassBase, bool, List[bool]]], crash_vec: List[bool], rows):
        # we leverage AURORA's predicate synthesis metric

        total_crash = 0
        total_non_crash = 0

        for elem in crash_vec:
            if elem == True:
                total_crash += 1
            else:
                total_non_crash += 1

        if total_crash == 0 or total_non_crash == 0:
            raise BenzenePredError("invalid total corpus count (total crash: %d, total non-crash: %d)" % (total_crash, total_non_crash))

        best_pred = None
        best_score = 0
        best_vector = None

        # iterate over candidate predicates.
        for pred_class, neg, pred_truth_vec in vectors:
            crash_hit = 0
            non_crash_hit = 0
            score = 0

            if len(crash_vec) != len(pred_truth_vec):
                raise BenzenePredError("Row size mismatch at offset 0x%x (crash vector : %d, current : %d)" % (self.offset, len(crash_vec), len(behavior_vec)))

            for idx, boolean in enumerate(pred_truth_vec):
                # print(elem, crash_vec[row_idx])
                
                if crash_vec[idx] == True:
                    if boolean == True:
                        crash_hit += 1
                    else: # crash occured when current predicate is False, which means it's not a crashing condition
                        logging.debug('crash but 0x%x.%s is false : (idx. %d) %s' 
                                                    % (self.offset, pred_class.get_verbose(neg=neg), idx, str(rows[idx])))
                        break
                elif crash_vec[idx] == False:
                    if boolean == False:
                        non_crash_hit += 1

            if idx != len(pred_truth_vec) - 1:
                continue # current pred_class is unavailable, skip it

            C_f = total_crash - crash_hit
            N_f = total_non_crash - non_crash_hit

            theta_hat = 0.5 * ( (C_f / total_crash) + (N_f / total_non_crash) )

            score = 2 * abs( theta_hat - 0.5 )
            
            if score > 1:
                raise BenzenePredError("%s's score is out of range : %f" % (pred_class.get_verbose(neg=neg), score))

            if score > best_score:
                best_score = score
                best_pred = pred_class.get_verbose(neg=neg)
                best_vector = pred_truth_vec
                self.pred_class = pred_class

        # select the best predicate for this instruction (and operand)
        if best_score != 0:
            self.pred_str = best_pred
            self.score = best_score
            self.vector = best_vector
        else:
            logging.debug("there is no best predicate (offset: 0x%x)" % (self.offset))

        logging.debug("offset (0x%x) : extracted predicate : %s" % (self.offset, self.pred_str))

    def make_pred_columns(self, rows, threshold=128, ptr_range=None):
        pred_columns = []

        uniq_values = set()

        if self.read_size == 8: # sizeof(void*)
            pred_columns.append(PredClassPtrExist(self.op_name(), ptr_range))
            pred_columns.append(PredClassConstExist(self.op_name(), ptr_range))

        # if self.is_ptr:    
        #     uniq_rows = [list(x) for x in set(tuple(x) for x in rows) if len(x) != 0]

        #     if len(uniq_rows) == 1: # There is only one unique behavior monitored, return empty.
        #         return []

        #     return pred_columns

        else: 
            # predicates for non-pointer data
            mins = set()
            maxs = set()

            uniq_rows = [list(x) for x in set(tuple(x) for x in rows) if len(x) != 0]

            if len(uniq_rows) == 1: # There is only one unique behavior monitored, return empty.
                return []

            for uniq_row in uniq_rows:
                mins.add(min(uniq_row))
                maxs.add(max(uniq_row))

                uniq_values.update(uniq_row)

            if len(uniq_values) == 0: # There is only one unique value monitored, return empty.    
                return []


            for a in mins:
                # if a == 0: # if v is 0, geq(x) is always true, skip it
                #     continue
                pred_columns.append(PredClassGEQ(self.op_name(), a))
                
            for a in maxs:
                pred_columns.append(PredClassLEQ(self.op_name(), a))

            if len(uniq_values) < threshold:
                for a in uniq_values:
                    pred_columns.append(PredClassExist(self.op_name(), a))

            return pred_columns


    def synthesize(self, rows: TraceRows, crash_vector, init_crash_idx, ptr_range=None):
        # check row count
        if len(crash_vector) != len(rows):
            raise BenzenePredError("row count mismatch (epsilon_c : %d, row count : %d)" % (len(crash_vector), len(rows)))
        
        init_row = rows[init_crash_idx]
        pred_classes = []
        uniq_values = set()
        is_ptr = False
 
        if self.read_size == 8:
            is_ptr = True
            for trace in init_row:
                if (trace < ptr_range[0] or trace > ptr_range[1]) and trace != 0x0:
                    is_ptr = False
                    break

        #     if is_ptr:
        #         uniq_rows = [list(x) for x in set(tuple(x) for x in rows) if len(x) != 0]

        #         if len(uniq_rows) == 1: # There is only one unique behavior monitored, return empty.
        #             pred_classes = []

        #         pred_classes.append(PredClassPtrExist(self.op_name(), ptr_range))
        #         pred_classes.append(PredClassConstExist(self.op_name(), ptr_range))


        if is_ptr == False: 
            # predicates for non-pointer data
            mins = set()
            maxs = set()

            uniq_rows = [list(x) for x in set(tuple(x) for x in rows) if len(x) != 0]

            if len(uniq_rows) == 1: # There is only one unique behavior monitored, return empty.
                pred_classes = []

            for uniq_row in uniq_rows:
                mins.add(min(uniq_row))
                maxs.add(max(uniq_row))

                uniq_values.update(uniq_row)

            if len(uniq_values) == 0: # There is only one unique value monitored, return empty.    
                pred_classes = []


            for a in mins:
                # if a == 0: # if v is 0, geq(x) is always true, skip it
                #     continue
                pred_classes.append(PredClassGEQ(self.op_name(), a))

            for a in maxs:
                pred_classes.append(PredClassLEQ(self.op_name(), a))

            if len(uniq_values) < 128:
                for a in uniq_values:
                    pred_classes.append(PredClassExist(self.op_name(), a))


        candidates = []

        if len(pred_classes) == 0:
            logging.debug("offset 0x%x (%s): no available pred class" % (self.offset, self.op_name()))
            return

        for pred_class in pred_classes:
            # create column vector
            behavior_vec = []

            # # check if initial crash satisfies current predicate
            # if not pred_class.operate(init_row):
            #     continue
            
            val_true_exist = False
            val_false_exist = False
            # create vector for each row in rows:
            for i, row in enumerate(rows):
                if pred_class.operate(row):
                    behavior_vec.append(True)
                    val_true_exist = True
                else:
                    # if crash_vector[i] == True: # Crash occurred but current predicate is False, implying that it's not a crashing condition.
                    #     # logging.debug('crash but 0x%x.%s is false : (idx. %d) %s' % (self.offset, pred_class.get_verbose(), i, str([hex(r) for r in row])))
                    #     logging.debug('crash but 0x%x.%s is false : (idx. %d)' % (self.offset, pred_class.get_verbose(), i))
                    #     valid = False
                    #     break

                    behavior_vec.append(False)
                    val_false_exist = True                      

            # if not valid:
            #     continue

            # this vector shows no diverted behavior, skip it.
            if not val_true_exist or not val_false_exist:
                logging.debug('predicate 0x%x.%s has no diversion (idx. %d)' % (self.offset, pred_class.get_verbose(), i))
                continue

            # append column to X
            candidates.append((pred_class, False, behavior_vec))
            # negation of pred class
            candidates.append((pred_class, True, [not elem for elem in behavior_vec]))

        if len(candidates) == 0:
            logging.debug("offset 0x%x (%s) : no synthesizable class" % (self.offset, self.op_name()))
            return

        self.extract(candidates, crash_vector, rows)
