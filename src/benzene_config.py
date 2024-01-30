from typing import List

class BenzeneConfig:
    def __init__(self):
        self.outdir_path: str = None
        self.target_cmd: str = None
        self.num_proc: int = None
        self.backtrace_timeout: int = 600
        self.target_modules: List[str] = []
        self.funcs_to_skip: List[str] = []
        self.asan: bool = False
        self.asan_type: str = None
        self.asan_report_addr: str = None
        self.pass_hang: bool = False

        self.pin_path: str = None
        self.drrun_path: str = None
        self.stdin_filepath: str = None
        self.benzene_log_path: str = None

        self.pre_elapsed_time = 0
        self.fuzz_elapsed_time = 0
        self.trace_elapsed_time= 0
        self.rca_elapsed_time = 0
