import argparse
import subprocess
import os
from shutil import rmtree
import pandas as pd
import sqlite3
import pickle
from benzene_pred import *
from benzene_rca import *
from dynvfg import *
from benzene_config import *
from benzene_session import *
import multiprocessing as mp
from functools import partial
import logging
import json
import time
import re

from typing import List
from typing import Dict
from typing import Tuple

from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

pin_path = os.path.join(os.environ['PIN_ROOT'], 'pin')
drrun_path = os.path.join(os.environ['DR_BUILD'], 'bin64/drrun')
dr_path = os.path.join(os.environ['DR_BUILD'])
rr_path = os.path.join(os.environ['BENZENE_HOME'], 'rr-build/bin/rr')
os.environ['PATH'] = "%s:%s" % (os.path.join(os.environ['BENZENE_HOME'], 'tools'), os.environ['PATH'])

def get_cov_inx(prev_off, next_off):
    return ((prev_off & 0xFFFF) >> 1) ^ (next_off & 0xFFFF)

def run_backtracer(config: BenzeneConfig):
    rr_trace_path = os.path.join(config.outdir_path, 'rr-trace')
    origin_json_path = os.path.join(config.outdir_path, 'origins.json')

    # we basically include main executable as analysis target
    main_exe_path = os.path.realpath(config.target_cmd.split()[0])
    main_exe_name = os.path.basename(main_exe_path)
    backtracer_config = { "vfg_dir" : config.outdir_path, "modules" : [ main_exe_name ], "timeout": config.backtrace_timeout}

    if config.target_modules is not None:
        backtracer_config["modules"] += config.target_modules

    if config.asan:
        backtracer_config['asan_type'] = config.asan_type
        backtracer_config['asan_report_call'] = config.asan_report_addr - 0x5 # call instruction size is 0x5

    # make backtracer script's config file
    with open(os.path.join(config.outdir_path, 'backtracer.json'), 'w') as f:
        json.dump(backtracer_config, f)

    if not os.path.exists(rr_trace_path):
        print("[INFO] recording crashing execution for target function extraction")
        
        cmd_list = [rr_path, 'record', '-o', rr_trace_path] + config.target_cmd.split()
        logging.info('RR record cmd : \"%s\"' % (subprocess.list2cmdline(cmd_list)))
        
        # @TODO: handle STDIN-based inputs
        stdin = subprocess.PIPE
        if config.stdin_filepath:
            # print("Issue: fully-automated STDIN handling is under development.")
            # print("Please run this command in manual: \"%s\"" % (subprocess.list2cmdline(cmd_list)))
            # exit(0)
            stdin = open(config.stdin_filepath, 'rb')
            

        p = subprocess.Popen(cmd_list, stdin=stdin, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p.wait()

        if not os.path.exists(rr_trace_path):
            print("[FATAL] RR recording failed")
            return -1

    if not os.path.exists(origin_json_path):
        backtracer_path = os.path.join(os.environ['BENZENE_HOME'], 'src/backtracer/backtracer.py')
        source_cmd = '\n\npy out_dir=\'%s\'\nsource %s\n' % (config.outdir_path, backtracer_path)

        print("[INFO] extracting target functions (timeout: %d sec)" % (config.backtrace_timeout))
        p = subprocess.Popen([rr_path, 'replay', rr_trace_path], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # p = subprocess.Popen(['rr', 'replay', rr_trace_path], stdin=subprocess.PIPE)
        print("This step may take a while, please wait a minute...")

        p.communicate(input=bytes(source_cmd, 'utf-8'))
        p.wait()

        if p.returncode != 0:
            print("[FATAL] function extraction failed...")
            return -1
    else:
        print("[INFO] \"%s\" already exists, skip reverse backtracer" % (origin_json_path))

    return 0

def run_dynvfg(config: BenzeneConfig):
    dynvfg_path = os.path.join(os.environ['BENZENE_HOME'], 'tools' , 'dynvfg.so')

    if os.path.exists(os.path.join(config.outdir_path, 'vfg.json')):
        print("[INFO] \"%s\" already exists in \"%s\", Benzene skips the step." % ('vfg.json', config.outdir_path))
    
    else:
        cmd_list = [config.pin_path, '-t', dynvfg_path, '-out', config.outdir_path]

        if len(config.target_modules) != 0:
            for module_name in config.target_modules:
                cmd_list += ['-m', module_name]

        cmd_list += ['--']
        cmd_list += config.target_cmd.split()
        
        print("[INFO] Constructing dynamic value flow graph (cmd : \"{}\")".format(subprocess.list2cmdline(cmd_list)))
        
        stdin = subprocess.PIPE
        if config.stdin_filepath:
            stdin = open(config.stdin_filepath, 'rb')

        ret = subprocess.run(cmd_list,
                            stdin=stdin,
                            stdout=open(os.devnull, 'wb'),
                            stderr=open(os.devnull, 'wb'))

        if ret.returncode != 0:
            print("[FATAL] Something went wrong!")
            return -1

        if config.stdin_filepath: stdin.close()

    # get the result
    vfg.parse(config.outdir_path)

    # sanity checks 
    for module_name in config.target_modules:
        if module_name not in vfg.modules.keys():
            logging.fatal('module \"%s\" does not exists in the dynvfg result' % (module_name))
            raise BenzeneError('module \"%s\" does not exists in the dynvfg result' % (module_name))

    return 0


def check_ASLR():
    with open("/proc/sys/kernel/randomize_va_space", 'r') as f:
        if f.read()[0] != '0':
            print("It seems ASLR is enabled in this system... Please disable it :D")
            print('"echo 0 | sudo tee /proc/sys/kernel/randomize_va_space" would work!')
            return -1
    return 0


class Benzene:
    def __init__(self):
        self.config: BenzeneConfig = None

        self.corpus2idx: Dict[int, int] = {}
        self.idx2corpus: Dict[int, int] = {}

        self.session_tree: List[List[BenzeneFuzzSession]] = []

        # all the created sessions
        self.sessions: List[BenzeneFuzzSession] = []
        # sessions actually fuzzed
        self.fuzzed_sessions: List[BenzeneFuzzSession] = []

        self.total_run_cnt: int = 0
        self.init_crash_id: int = None # corpus-id of initial crash.
        self.crash_vec: List[int] = []
        self.cov_matrix = [List[List[int]]]
        self.resume = False
    
    def get_session(self, corpusid) -> BenzeneFuzzSession:
        for session in self.fuzzed_sessions:
            start = session.first_id()
            end = session.last_id()

            if corpusid >= start and corpusid <= end:
                return session

        return None
    
    def get_fuzz_target_functions(self, json_path: str):
        if vfg == None:
            raise BenzeneError("DynVFG is not initialized")

        logging.info('extracting fuzzing target using \"%s\"' % (json_path))
        
        with open(json_path, 'r') as f:
            backtracer_out = json.load(f)

        triage_offset = backtracer_out['triage'][0]
        backtrace_tree = backtracer_out['tree']
        logging.info("total depth of tree : %d" % (len(backtrace_tree)))

        fn_hashes: Dict[int, BenzeneFuzzSession] = {}

        # traverse each node in tree and extract target functions
        for depth, insts in enumerate(backtrace_tree):
            sessions_in_level: List[BenzeneFuzzSession] = []

            for inst_dict in insts:
                n = vfg.node_at(offset=inst_dict['offset'], img=inst_dict['img_name'])
                fn_hit_cnt = inst_dict['fn_hit']

                if n == None: continue
                if fn_hit_cnt == None: continue

                # get function at current offset from DynVFG
                fn = vfg.func_at(offset=n.fn_offset, img=n.img_name)

                if fn == None:
                    logging.warning("function for 0x%x (%s) not found" % (n.fn_offset, n.img_name))
                    continue

                # if fn.hit_cnt > fn_hit_avg:
                #     logging.info('%s\'s hit count is over the average : %f, skip it' % (fn.hit_cnt, fn_hit_avg))

                cur_hash = hash((fn.offset, fn_hit_cnt))

                if cur_hash not in fn_hashes.keys():
                    if fn_hit_cnt <= 0:
                        logging.warning("invalid session 0x%x(%s)'s function hit count: %d" % (fn.offset, fn.fn_name, fn_hit_cnt))
                        continue

                    # avoid fuzzing libc-related functions (such as `__libc_csu_init`)
                    if "libc" in fn.fn_name:
                        logging.info("skip libc related function 0x%x (%s)" % (fn.offset, fn.fn_name))
                        continue

                    # skip sanitizer-related functions
                    if "asan" in fn.fn_name or "msan" in fn.fn_name or 'sanitizer' in fn.fn_name:
                        logging.info("skip sanitizer related function 0x%x (%s)" % (fn.offset, fn.fn_name))
                        continue

                    if fn.fn_name in self.config.funcs_to_skip:
                        continue

                    session = BenzeneFuzzSession(self.config, fn.offset, n.img_name, fn_hit_cnt, triage_offset, fn_name=fn.fn_name, depth=depth)
                    
                    fn_hashes[cur_hash] = session
                    # session.insts.append(inst_dict)
                    sessions_in_level.append(session)
                    
                    # add newly created session to the list
                    self.sessions.append(session)

                # else:
                #     fn_hashes[cur_hash].insts.append(inst_dict)

            self.session_tree.append(sessions_in_level)

        if len(self.sessions) == 0:
            logging.fatal('finding target function failed (target function count == 0)')
            raise BenzeneError("`get_fuzz_target_functions` failed ( len(self.sessions) == 0 )")

    def fuzz(self):
        sessions_to_fuzz: List[BenzeneFuzzSession] = []

        if self.resume:
            for each_level in self.session_tree:
                for session in each_level:
                    result_json_path = os.path.join(session.session_dir, 'fuzz_result.json')
                    
                    if not os.path.exists(result_json_path): 
                        continue
                    
                    logging.info('session %s: reading fuzz result (json: \"%s\")' % (session.name, result_json_path))
                    
                    with open(result_json_path, 'r') as f:
                        session.fuzz_result = json.load(f)

                    do_append = True
                    for seed_offset, seed_result in session.fuzz_result['seeds'].items():
                        if seed_result['total_hit'] == 0:
                            logging.error('restored session %s got error' % (session.name))
                            logging.error("seed 0x%x is not selected" % (int(seed_offset)))
                            logging.error('check session\'s log : \"%s\"' % (os.path.join(session.session_dir, 'session.log')))
                            # logging.error('fuzz result : \n%s' % (json.dumps(self.fuzz_result, sort_keys=True, indent=4)))
                            do_append = False
                            break
                        
                    if do_append:
                        session.read_corpus()
                        self.fuzzed_sessions.append(session)
                        logging.info("\t%s", str(session.corpus_range))
                    continue
            
            print('[INFO] fuzzing result loaded (%d sessions)' % (len(self.fuzzed_sessions)))
            return
        
        for each_level in self.session_tree:
            for session in each_level:
                logging.info('fuzzing session %s (depth: %d)' % (session.name, session.depth))
                logging.info('\tsession\'s dir : \"%s\"' % (session.session_dir))

                if session.serialize_config() < 0:
                    logging.error("session %s serialize_config failed" % (session.name))
                    continue

                sessions_to_fuzz.append(session)

        # set corpus-id range for each session
        for session in sessions_to_fuzz:
            session.corpus_range = (self.total_run_cnt, self.total_run_cnt + session.auto_iter)
            self.total_run_cnt += session.last_id() - session.first_id() + 1

        if len(sessions_to_fuzz) == 0:
            logging.fatal('no function is identified for fuzzing (len(sessions_to_fuzz) == 0)')
            raise BenzeneError('target function extraction failed')

        print('[INFO] dryrun on %d functions' % (len(sessions_to_fuzz)))
        dryrun_success: List[BenzeneFuzzSession] = []

        while len(sessions_to_fuzz):
            if len(sessions_to_fuzz) < self.config.num_proc:
                num_proc = len(sessions_to_fuzz)
            else:
                num_proc = self.config.num_proc

            with mp.Pool(num_proc) as pool:
                dryrun_func = partial(BenzeneFuzzSession.dryrun, mode='fuzz')
                pool.map(dryrun_func, sessions_to_fuzz[:num_proc])

            # collect sessions which was successful in dryrun
            for session in sessions_to_fuzz[:num_proc]:
                # update current session's auto_iter size
                fuzz_config = session.read_config()

                if fuzz_config == None:
                    continue

                if len(fuzz_config['mutation_targets']) == 0:
                    logging.warning("session %s's mutation target size is 0, skip it" % (session.name))
                    continue

                dryrun_success.append(session)

            sessions_to_fuzz = sessions_to_fuzz[num_proc:]

        if len(dryrun_success) == 0:
            print("dryrun failed")
            logging.fatal("dryrun failed for all target functions")
            exit(-1)

        print('[INFO] **** start fuzzing ****')

        for session in dryrun_success:
            print('[INFO] fuzzing session %s' % (session.name))
            logging.info('fuzzing %s (corpus path: \"%s\")' % (session.name, session.corpus_path))

            if session.fuzz() < 0:
                logging.error("session %s fuzzing failed" % (session.name))
                continue            

            if session.parse_fuzz_result() == 0:
                # append successfully fuzzed session to the list
                self.fuzzed_sessions.append(session)

                logging.info('\tcorpus range: (%d, %d)' % (session.first_id(), session.last_id()))
                logging.info('\tresult: (crash %d, non_crash %d, false_crash: %d)' % (session.fuzz_result['crash'], session.fuzz_result['non_crash'], session.fuzz_result['false_crash']))

    def read_corpus(self):
        if len(self.corpus2idx) != 0 or len(self.idx2corpus) != 0:
            raise BenzeneError("corpus-to-idx table is already initialized")

        idx = 0
        for session in self.fuzzed_sessions:
            logging.info('initiating corpus of session %s' % (session.name))
            session.read_corpus()

            if self.init_crash_id == None:
                self.init_crash_id = session.first_id()

            for corpus_id, crash, _ in session.corpus:
                if self.corpus2idx.setdefault(corpus_id, idx) != idx:
                    raise KeyError("corpus %d already exists in corpus2idx (old: %d)" % (corpus_id, self.corpus2idx[corpus_id]))
                self.idx2corpus[idx] = corpus_id
                self.crash_vec.append(crash)
                idx += 1
        
        if len(self.corpus2idx) == 0 or len(self.corpus2idx) - len(self.fuzzed_sessions) == 0:
            logging.fatal("fuzzing failed, no behavior collected")
            logging.fatal("\t`len(corpus2idx)`: %d" % (len(self.corpus2idx)))
            logging.fatal("\t`len(fuzzed_sessions)`: %d" % (len(self.fuzzed_sessions)))
            # fuzzing failed: no behavior collected
            raise BenzeneError("corpus count is zero")

        if len(self.corpus2idx) != len(self.crash_vec):
            raise BenzeneError("length mismatch (corpus2idx: %d, crash_vec: %d)" % (len(self.corpus2idx), len(self.crash_vec)))
    
    # read and process coverage file
    def read_coverage(self):
        # matrix for edge coverage (row : corpus, column : edge)
        self.cov_matrix = [[] for i in range(len(self.corpus2idx))]

        for session in self.fuzzed_sessions:
            cov_dir_path = os.path.join(session.session_dir, 'cov')

            # collect cov file in coverage directory of each session
            for cov_file in os.listdir(cov_dir_path):
                f = open(os.path.join(cov_dir_path, cov_file), 'rb')
                cov_bin = f.read()
                
                corpus_id = int(cov_file.split('.')[1], 16)
                try:
                    idx = self.corpus2idx[corpus_id]
                except KeyError:
                    print("[FATAL] corpus id %d (session : %s) is out of range (len(corpus2idx): %d)" % (corpus_id, session.session_dir, len(self.corpus2idx)))
                    logging.fatal("corpus id %d (session : %s) is out of range (len(corpus2idx): %d)" % (corpus_id, session.session_dir, len(self.corpus2idx)))
                    logging.fatal("corpus2idx: \n%s", str(self.corpus2idx))
                    exit(-1)

                # convert 0xFFFF-size hitmap into list()
                try:
                    self.cov_matrix[idx] = list(cov_bin)
                except IndexError:
                    logging.error('%s: corpus %d out of range (corpus path: \"%s\")' % (session.name, corpus_id, session.corpus_path))
                    raise BenzeneError("corpus id %d is out of range (id: %d, len(corpus2idx): %d)" % (corpus_id, idx, len(self.corpus2idx)))

                f.close()

        
        # check it's validity
        for i in range(len(self.cov_matrix)):
            if self.cov_matrix[i] == []:
                raise BenzeneError("corpus %d's coverage data is empty (idx : %d)", (self.idx2corpus[i], i))

    def get_corpus_rank(self) -> List[Tuple[float, List[int]]]:
        init_crash_idx = self.corpus2idx[self.init_crash_id]
        cov_pickle_path = os.path.join(self.config.outdir_path, 'cov.pkl')

        if os.path.exists(cov_pickle_path):
            logging.info("cov matrix already exists")
            with open(cov_pickle_path, 'rb') as f:
                cov_matrix = pickle.load(f)
        else:
            self.read_coverage()
            cov_matrix = pd.DataFrame(self.cov_matrix)
            
            # [NOTICE] To avoid biases due to the non-crashing behaviors, 
            # we should only consider the edges that are executed by initial crash.
            init_cov = cov_matrix.iloc[init_crash_idx]

            remove_list = []
            for i in range(len(init_cov)):
                if init_cov[i] == 0:
                    remove_list.append(i)

            del self.cov_matrix
            
            cov_matrix = cov_matrix.drop(remove_list, axis=1)

            with open(cov_pickle_path, 'wb') as f:
                pickle.dump(cov_matrix, f)

        if len(cov_matrix.columns) == 0:
            raise BenzeneError("Coverage matrix has no columns")

        if len(self.crash_vec) != len(cov_matrix):
            raise BenzeneError("Row size mismatch (crash vector : %d, matrix : %d)" % (len(self.crash_vec), len(cov_matrix)))

        cm = StandardScaler().fit_transform(cov_matrix)

        if len(cov_matrix.columns) < 12:
            pca = PCA(n_components=len(cov_matrix.columns))
        else:
            pca = PCA(n_components=12)

        logging.info("fitting matrix (row size: %d)" % (len(cov_matrix)))
        pca.fit(cm)

        pc = pca.transform(cm) # princiapal components : coordinates for corpus

        distances = dict()

        # coordinate of initial crash on the reduced dimension.
        init_coor = pc[init_crash_idx]

        for idx in range(0, len(pc)):
            if self.crash_vec[idx] == True: # only non-crashes are our targets
                continue

            coor = pc[idx]
            distances[self.idx2corpus[idx]] = euclid_dist(coor, init_coor)

        sorted_d = {k: v for k, v in sorted(distances.items(), key=lambda item: item[1])}

        # non-crashes grouped by distance from initial crash.
        group_by_dist: Tuple[float, List[int]] = []
        
        # @sorted_d: corpus_id, distance
        for corpus_id, dist in sorted_d.items():
            try:
                if group_by_dist[-1][0] != dist:
                    group_by_dist.append((dist, [corpus_id]))
                else:
                    group_by_dist[-1][1].append(corpus_id)
            except IndexError:
                # it's a first push
                group_by_dist.append((dist, [corpus_id]))

        # prioritize the deeper one
        for _, indices in group_by_dist:
            indices.sort(reverse=False)

        # print(group_by_dist)

        ranked_corpus = []
        hashes = set()

        # resolve ties
        for dist, same_dist_corpus in group_by_dist:
            for corpus_id in same_dist_corpus:
                session = self.get_session(corpus_id)
                
                mutations = session.get_mutation(corpus_id)
                if mutations == None:
                    logging.warning("mutation for %d not found" % (corpus_id))
                
                hash_val = hash((dist, session.fn_offset, mutations[0]["offset"]))

                if hash_val in hashes:
                    continue

                hashes.add(hash_val)
                ranked_corpus.append((dist, corpus_id))

        return ranked_corpus

    # get the information of how it changed the behavior by mutation.
    def get_mutation(self, corpus_id):
        session = self.get_session(corpus_id)
        mutation = session.get_mutation(corpus_id)

        if mutation == None:
            return None

        return mutation

benzene = Benzene()

def init_options():
    parser = argparse.ArgumentParser(prog='benzene', description="BENZENE, an automated software crash analysis tool.")

    parser.add_argument('-o', '--out', metavar="<output-dir>", type=str, default='./benzene.out', help="output directory (default: ./benzene.out).")
    parser.add_argument('-c', '--cmd', metavar='<cmdline>', type=str, required=True, help='target executable\'s crashing commandline.')
    parser.add_argument('--proc', metavar='<#-of-processes>', default=1, type=int, help='The number of processes for crash exploration.')
    parser.add_argument('--asan', action='count', help='specify this option if target binary is ASAN enabled.')
    parser.add_argument('-t', '--timeout', metavar="<seconds>", default=600, type=int, help="timeout(sec) for extracting target function.")
    parser.add_argument('-m', '--module', metavar='<target-module>', type=str, nargs='*', default=[], help='target executable for root cause analysis (default: main executable).')
    parser.add_argument('--stdin', metavar='<filename>', type=str, help='stdin-based program input.')
    parser.add_argument('--skip', metavar='<func-name>', type=str, nargs='*', default=[], help='function list to skip analysis.')
    parser.add_argument('--pass-hang', action='count', help='assume hanged process as a non-crash. this option may be required for server-like program which does not terminate.')
    parser.add_argument('--debug', action='count', help='enable debugging mode logging.')

    args = parser.parse_args()

    args_dict = vars(args)
    config = BenzeneConfig()

    config.outdir_path = os.path.realpath(args_dict['out'])
    if config.outdir_path == None:
        # default output directory : ./out
        config.outdir_path = os.path.join(os.getcwd(), 'benzene.out')
    
    # create output directory if it doesn't exist
    if os.path.exists(config.outdir_path) == False:
        os.mkdir(config.outdir_path)

    config.backtrace_timeout = args_dict['timeout']
    config.num_proc = args_dict['proc']
    if config.num_proc == 1:
        print("[INFO] BENZENE runs in a single process mode. " 
            "For boosting the analysis, it's recommended to run BENZENE in a multi-process environment.")
    
    if args_dict['asan'] is not None: 
        config.asan = True

    if args_dict['pass_hang'] is not None:
        config.pass_hang = True

    for module_name in args_dict['module']:
        config.target_modules.append(module_name)

    for fn_name in args_dict['skip']:
        config.funcs_to_skip.append(fn_name)

    config.target_cmd = args_dict['cmd']
    if '<' in config.target_cmd.split():
        print("stdin redirection is detected in the provided command \"%s\"" % (config.target_cmd))
        print("please use \"--stdin\" option instead")
        exit(0)

    if args_dict['stdin'] != None:
        config.stdin_filepath = os.path.realpath(args_dict['stdin'])

    # check tools : Intel Pin and DynamoRIO
    if os.path.exists(pin_path) == False:
        print('It seems Intel Pin executable doesn\'t exist in \"%s\"' % (pin_path))
        print('check environment variable \"PIN_ROOT\"')
        return -1
    config.pin_path = pin_path

    if os.path.exists(drrun_path) == False:
        print('It seems \"drrun\" doesn\'t exist in \"%s\"' % (drrun_path))
        print('check environment variable \"DR_BUILD\"')
        return -1
    config.drrun_path = drrun_path

    # check STDIN
    stdin = subprocess.PIPE
    if config.stdin_filepath:
        stdin = open(config.stdin_filepath, 'rb')

    print("[INFO] first check if command \"%s\" makes crash" % (config.target_cmd))
    # parse ASAN-related metadata
    if config.asan == True:
        try:
            if os.environ['ASAN_OPTIONS'] != 'detect_leaks=0':
                print("ASAN's detect_leaks option not disabled. Please run \"export ASAN_OPTIONS=detect_leaks=0\"")
                exit(-1)
        except KeyError:
            print("ASAN's detect_leaks option not disabled. Please run \"export ASAN_OPTIONS=detect_leaks=0\"")
            exit(-1)

        p = subprocess.Popen(config.target_cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        asan_report_txt = ""
        asan_report_txt += str(p.stderr.read()) # read STDERR buffer to avoid blocking the process
        p.wait()

        asan_report_txt += str(p.stderr.read())

        # parse string like "heap-buffer-overflow on address 0x603000000900 at pc 0x555555c8d785"
        regex = re.compile(r'([^\s]*)\son\saddress\s0x[0-9abcdef]*\sat\spc\s(0x[0-9abcdef]*)')
        # regex = re.compile(r'on\saddress\s0x[0-9abcdef]*\sat\spc\s(0x[0-9abcdef]*)')

        match = regex.search(asan_report_txt)
        if match == None:
            print("ASAN report parsing failed")
            exit(-1)

        config.asan_type = match.group(1)
        config.asan_report_addr = int(match.group(2), 16)
    else:
        p = subprocess.Popen(config.target_cmd.split(), stdin=stdin, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        p.wait()
        
        if p.returncode != -11: # SIGSEGV's return code: -11
            print("target command \"%s\" does not crash, please re-check your commandline" % (config.target_cmd))
            exit(-1)

    print("[INFO] crash check done")

    if config.stdin_filepath: stdin.close()

    config.benzene_log_path = os.path.join(config.outdir_path, 'benzene.log')
    if args_dict['debug'] != None:
        logging.basicConfig(filename=config.benzene_log_path, filemode='w', level=logging.DEBUG)
    else:
        logging.basicConfig(filename=config.benzene_log_path, filemode='w', level=logging.INFO)

    benzene.config = config
    return 0


def run(max_rank=50, base_addr=0x555555554000):
    logging.info('commandline: %s' % (subprocess.list2cmdline(sys.argv)))
    logging.info('Benzene # of proc : %d' % (benzene.config.num_proc))
    before_binary_analysis = time.time()

    session_dirname = []
    for path in os.listdir(benzene.config.outdir_path):
        if "session.0x" in path:
            session_dirname.append(path)
    
    # clean up session data
    if len(session_dirname) != 0:
        print("[WARN] session data already exists in out_dir \"%s\"" % (benzene.config.outdir_path))
        print("Do you want to reset the directory and proceed? : [Y/n]")

        a = input()

        if a == 'Y' or a == 'y':
            # clean output directory
            for dirname in session_dirname:
                rmtree(os.path.join(benzene.config.outdir_path, dirname))

            if os.path.exists(os.path.join(benzene.config.outdir_path, 'cov.pkl')):
                os.remove(os.path.join(benzene.config.outdir_path, 'cov.pkl'))
        else:
            benzene.resume = True

    if check_ASLR() != 0:
        exit(-1)

    if run_dynvfg(benzene.config) != 0:
        exit(-1)

    if run_backtracer(benzene.config) != 0:
        logging.fatal('backtracer script failed')
        exit(-1)

    after_binary_analysis = time.time()
    benzene.config.pre_elapsed_time = after_binary_analysis - before_binary_analysis


    before_fuzz = time.time()

    benzene.get_fuzz_target_functions(os.path.join(benzene.config.outdir_path, 'origins.json'))
    logging.info('total session count : %d' % (len(benzene.sessions)))
    benzene.fuzz()
    after_fuzz = time.time()
    benzene.config.fuzz_elapsed_time = after_fuzz - before_fuzz

    before_rca = time.time()
    print('[INFO] read fuzzing results...')
    benzene.read_corpus()

    print("[INFO] calculating rank of collected non-crashing behaviors")
    ranked_corpus = benzene.get_corpus_rank() # (non-crashing) behavior ranking (no duplicates)

    logging.info("unique coverage non-crash count : %d" % (len(ranked_corpus)))

    logging.info("***** Non-Crash Rank *****")
    i = 0
    for dist, corpus_id in ranked_corpus:
        session = benzene.get_session(corpus_id)
        if session == None:
            raise BenzeneError("cannot retrieve session for corpus id %d" % (corpus_id))
        
        mutations = benzene.get_mutation(corpus_id)
        if len(mutations) == 0:
            logging.error("corpus %d (session: %s) has no mutation info" % (corpus_id, session.name))
            continue
        
        logging.info("\t#%d [dist: %f] non-crash %d (%s)" % (i, dist, corpus_id, session.name))
        for mutation in mutations:
            logging.info("\t\t 0x%x (%s) (hit: %d, addr: 0x%x): 0x%x->0x%x" \
                        %  (mutation['offset'], mutation['op_name'], mutation['hit_cnt'], \
                            mutation['offset']+0x555555554000, mutation['from'], mutation['to']))
        i = i + 1


    sessions_to_trace: List[BenzeneFuzzSession] = []
    trace_success: List[BenzeneFuzzSession] = []

    # maximum corpus rank: 50th
    if len(ranked_corpus) < max_rank:
        target_corpus = ranked_corpus
    else:
        target_corpus = ranked_corpus[:max_rank]

    ranked_corpus_info = []
    for dist, corpus_id in target_corpus:
        session = benzene.get_session(corpus_id)

        if session == None:
            raise BenzeneError("cannot retrieve session for corpus id %d" % (corpus_id))

        ranked_corpus_info.append((dist, session, corpus_id, benzene.get_mutation(corpus_id)))

        if os.path.exists(session.trace_db_path): # check if tracing on this session has been already done
            if not session in trace_success:
                trace_success.append(session)
            continue

        if not session in sessions_to_trace:
            sessions_to_trace.append(session)

    before_trace = time.time()

    print("[INFO] tracing %d functions" % (len(sessions_to_trace)))
    # run dryrun in parallel
    trace_dryrun_success: List[BenzeneFuzzSession] = []

    while len(sessions_to_trace):
        if len(sessions_to_trace) < benzene.config.num_proc:
            num_proc = len(sessions_to_trace)
        else:
            num_proc = benzene.config.num_proc

        with mp.Pool(num_proc) as pool:
            dryrun_func = partial(BenzeneFuzzSession.dryrun, mode='trace')
            pool.map(dryrun_func, sessions_to_trace[:num_proc])

        # check whether each session's dryrun was successful
        for session in sessions_to_trace[:num_proc]:
            trace_db_path = os.path.join(session.session_dir, 'trace')
            trace_db_path = os.path.join(trace_db_path, 'trace.0.db')
            
            # if it was successful, `trace.0.db` file should be created
            if not os.path.exists(trace_db_path):
                logging.error('session %s trace dryrun failed, skip it' % (session.name))
                continue
            
        # append successful sessions
        trace_dryrun_success += sessions_to_trace[:num_proc]

        sessions_to_trace = sessions_to_trace[num_proc:]

    for session in trace_dryrun_success:        
        print("[INFO] tracing %s" % (session.name))
        logging.info('tracing %s (trace-db: \"%s\")' % (session.name, session.trace_db_path))
        if session.trace() == 0: # trace success
            session.merge_db()
            trace_success.append(session)

    after_trace = time.time()
    benzene.config.trace_elapsed_time += after_trace - before_trace

    print("[INFO] synthesize predicates for %d functions" % (len(trace_success)))
    for session in trace_success:
        session.synthesize()


    print("[INFO] rank crashing conditions")
    corpus_hashes: Dict[int, List[int]] = {} # hash <- (session_offset, root_cause_predicate_offset)

    # rank predicates
    rank = []
    for non_crash_info in ranked_corpus_info:
        dist, session, corpus_id, mutations = non_crash_info

        if len(mutations) == 0:
            logging.error("corpus %d (session: %s) has no mutation info" % (corpus_id, session.name))
            continue

        if session.pred_manager == None:
            logging.error("session %s's pred_manager is NoneType" % (session.name))
            continue

        exec_order = session.pred_manager.get_exec_order(mutations[0]['offset'])

        logging.info("%s: non-crash %d" % (session.name, corpus_id))
        for mutation in mutations:
            logging.info("\t\t0x%x (%s) (hit: %d, addr: 0x%x): 0x%x->0x%x (exec: %d)" \
                        %  (mutation['offset'], mutation['op_name'], mutation['hit_cnt'], \
                            mutation['offset']+0x555555554000, mutation['from'], mutation['to'], exec_order))

        corpus_preds = session.get_preds_from_non_crash(corpus_id)
        logging.info("corpus preds count : %d" % (len(corpus_preds)))

        if len(corpus_preds) == 0:
            logging.info('no valid predicates, skip non-crash %d' % (corpus_id))
            continue

        corpus_preds.sort(key=lambda pred: pred.exec_order)

        root_cause_pred = None
        for p in corpus_preds:
            
            # if corpus_id == 1232:
            #     print("hayha p 0x%x:%s: %d" % ( p.offset, p.pred_str, p.exec_order) )
            
            if exec_order <= p.exec_order:
                root_cause_pred = p
                break

        if root_cause_pred == None:
            logging.warning("non-crash %d's crashing condition not found" % (corpus_id))
            continue

        corpus_hash = hash((session.fn_offset, root_cause_pred.offset))

        if corpus_hash in corpus_hashes.keys():
            logging.info('corpus %d is duplicate' % (corpus_id))
            corpus_hashes[corpus_hash].append(corpus_id)
            continue
        else:
            corpus_hashes[corpus_hash] = [corpus_id]
            rank.append((non_crash_info, root_cause_pred))

        logging.info("corpus %d's root cause predicate 0x%x.%s (addr: 0x%x)" \
                    % (corpus_id, root_cause_pred.offset, root_cause_pred.pred_str, 0x555555554000 + root_cause_pred.offset))
        for p in corpus_preds:
            logging.info("\t0x%x.%s (addr: 0x%x): %f (order: %d)" % (p.offset, p.pred_str, base_addr + p.offset, p.score, p.exec_order))

    after_rca = time.time()
    benzene.config.rca_elapsed_time = after_rca - before_rca - benzene.config.trace_elapsed_time

    logging.info("binary analysis elapsed time : %s" % (str(benzene.config.pre_elapsed_time)))
    logging.info("fuzzing elapsed time : %s" % (str(benzene.config.fuzz_elapsed_time)))
    logging.info("trace elapsed time : %s" % (str(benzene.config.trace_elapsed_time)))
    logging.info("rca elapsed time : %s" % (str(benzene.config.rca_elapsed_time)))



    # additionally log discovered non-crash information
    logging.info("***** Discovered Non-Crashes *****")
    for non_crash_info in ranked_corpus_info:
        dist, session, corpus_id, mutations = non_crash_info
        
        if len(mutations) == 0:
            logging.error("corpus %d (session: %s) has no mutation info" % (corpus_id, session.name))
            continue
        
        if session.pred_manager == None:
            logging.error("session %s's pred_manager is NoneType" % (session.name))
            continue

        exec_order = session.pred_manager.get_exec_order(mutations[0]['offset'])

        logging.info("%s: non-crash %d" % (session.name, corpus_id))
        for mutation in mutations:
            logging.info("\t\t0x%x (%s) (hit: %d, addr: 0x%x): 0x%x->0x%x (exec: %d)" \
                        %  (mutation['offset'], mutation['op_name'], mutation['hit_cnt'], \
                            mutation['offset']+0x555555554000, mutation['from'], mutation['to'], exec_order))


    # print root cause analysis result
    print("***** Root Cause Analysis Result *****")
    logging.info("***** Root Cause Analysis Result *****")
    print("#{:10s} | {:20s} | {:20s} | {:20s}".format('Rank', 'Module', 'Offset', 'Predicate'))
    print('-' * 90)
    for rank, _ in enumerate(rank):
        non_crash_info, root_cause = _
        dist, session, corpus_id, mutations = non_crash_info
        
        logging.info("[dist: %f] non-crash %d: 0x%x.%s (0x%x) (from session %s)" \
                    % (dist, corpus_id, root_cause.offset, root_cause.pred_str, root_cause.offset + base_addr, session.name))

        print("#{:10s} | {:20s} | {:20s} | {:20s}".format(str(rank + 1), root_cause.img_name, hex(root_cause.offset), root_cause.pred_str))



if __name__ == "__main__":

    if init_options() < 0:
        exit(-1)

    run()



