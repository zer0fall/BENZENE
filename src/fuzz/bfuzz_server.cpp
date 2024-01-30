#include "bfuzz_server.h"
#include <algorithm>
#include <dirent.h>
#include <fstream>
#include "rapidjson/istreamwrapper.h"

#define FEEDBACK_PERIOD     15

#define MUTEX_LOCK()    mtx_.lock()
#define MUTEX_UNLOCK()  mtx_.unlock()

#define UPDATE_OP_INFO_ON_ERROR(mt_pick)   do { \
                                                MUTEX_LOCK(); \
                                                for (int i = 0; i < mt_pick.cnt; i++) { \
                                                    info = fuzz_ops_[mt_pick.picks[i]]; \
                                                    info->total_hit++; \
                                                    info->false_crash_cnt++; \
                                                } \
                                                MUTEX_UNLOCK(); \
                                            } while(0)
#define UPDATE_OP_INFO(mt_pick)    do { \
                                        MUTEX_LOCK(); \
                                        for (int i = 0; i < mt_pick.cnt; i++) { \
                                            info = fuzz_ops_[mt_pick.picks[i]]; \
                                            info->total_hit++; \
                                            if (pkt.status == PROC_STATUS_FALSE_CRASH || pkt.status == PROC_STATUS_HANG) \
                                                info->false_crash_cnt++; \
                                        } \
                                        MUTEX_UNLOCK(); \
                                    } while(0)

#define OPTSTR_CMP(in, opt_str) strncmp(in, opt_str, sizeof(opt_str))

static const char* status_text[] {
    "NONE",
    "INIT",
    "PARENT",
    "EXECUTE",
    "NON_CRASH",
    "CRASH",
    "FALSE_CRASH",
    "HANG",
    "DONE",
    "DUMP",
    "ERROR"
};

struct by_false_ratio { 
    bool operator()(mt_status_t* const &a, mt_status_t* const &b) const noexcept { 
        if (a->false_ratio == b->false_ratio) { // if ratio is same, prioritize smaller hit count.
            return a->total_hit < b->total_hit;
        }
        
        return a->false_ratio < b->false_ratio;
    }
};

struct by_pick_cnt { 
    bool operator()(mt_status_t* const &a, mt_status_t* const &b) const noexcept { 
        return a->total_hit < b->total_hit;
    }
};


BenzeneFuzzServer::BenzeneFuzzServer() {

}


int BenzeneFuzzServer::setup() {
    printf("[*] setup the server.\n");


    cntl_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    
    if (cntl_fd_ < 0) {
        perror("socket() failed");
        return -1;
    }

    cntl_addr_.sun_family = AF_UNIX;
    strncpy(cntl_addr_.sun_path, CNTL_SOCK_PATH, sizeof(CNTL_SOCK_PATH));
    
    // remove existing socket
    unlink(CNTL_SOCK_PATH);

    // setTimeout(cntl_fd_, 3);

    if (bind(cntl_fd_, (struct sockaddr *) &cntl_addr_, sizeof(cntl_addr_)) < 0) {
        perror("bind() failed");
        return -1;
    }
    
    /* set feedback period (default : one feedback per 15 runs) */
    feedback_period_ = FEEDBACK_PERIOD;

    printf("[+] config path : \"%s\"\n", config_path_);
    if (readConfigFromJSON(config_path_) < 0)
        return -1;
    
    if (fuzz_ops_.size() == 0) {
        printf("Error: there is no runtime seed to mutate.\n");
        return -1;
    }

    return 0;
}

int BenzeneFuzzServer::pickMutationTargets(mt_pick_t* packet) {
    // uint32_t picked_idx;
    uint32_t num_pick;          // the number of node picks
    uint32_t cur_num_pick = 0;  // the number of picked nodes so far
    uint32_t picked_cnt = 0;

    size_t feedback_cnt = 0;
    size_t num_nodes = fuzz_ops_.size();

    // initialize random number
    mangle_init();

    // if (num_nodes > MAX_SEED_OP_PICK_CNT) // selecting too many nodes is likely to cause false crash.
    //     num_pick = util_rndGet(1, MAX_SEED_OP_PICK_CNT);
    // else
    //     num_pick = util_rndGet(1, num_nodes);
    num_pick = 1;
    packet->cnt = num_pick;

    if ((util_rnd64() & 1)) { // feedback-driven mode with 50% chance
        feedback_cnt = util_rndGet(1, num_pick);
        
        MUTEX_LOCK();
        for (int i = 0; i < feedback_cnt; i++) {
            packet->picks[picked_cnt++] = feedback_table_[i]->idx;
        }
        MUTEX_UNLOCK();

        cur_num_pick += feedback_cnt;
    }
    
    /* randomly select fuzz target nodes */
    for (int i = cur_num_pick; i < num_pick; i++) {
        packet->picks[picked_cnt++] = mangle_get_index(num_nodes); // exclude already picked indices from feedback-driven selection.
    }

    return 0;
}


void BenzeneFuzzServer::handleCorpus(BenzeneFuzzMonitor* corpus) {
    status_pkt_t pkt;
    pid_t run_pid;

    proc_cmd_pkt_t cmd;
    mt_pick_t init_op_picks = {0, };
    
    proc_status_t corpus_result = PROC_STATUS_NONE;
    mt_status_t* info;

    if (corpus->recvStatus(&pkt) > 0) {
        printf("id - %d, pid %d, status : %s\n", pkt.id, pkt.pid, status_text[pkt.status]);
    }
    else {
        perror("recv");
        goto __controlRunner_exit;
    }

    run_pid = pkt.pid;

    /* check proc's status */
    if (pkt.status != PROC_STATUS_EXECUTE) {
        goto __controlRunner_exit;
    }
    
    /* proc successfully spawned */
    cmd.cmd = PROC_CMD_PICK_SEED;
    
    pickMutationTargets(&init_op_picks); /* pick fuzzing target operands */

    cmd.data.mt_pick = init_op_picks;

    /* send picked fuzzing target operands data to actual runenr */
    if (corpus->sendCommand(&cmd) < 0) {
        goto __controlRunner_exit;
    }
    
    if (corpus->recvStatus(&pkt) > 0) {
        corpus->handleRunnerStatus(&pkt);
        
        corpus_result = pkt.status;

        printf("id - %d, pid %d, status : %s\n", pkt.id, pkt.pid, status_text[pkt.status]);
        
        if (pkt.status == PROC_STATUS_ERROR) { 
            // internal mess during fuzzing, increase false crash count for the selected seeds.
            UPDATE_OP_INFO_ON_ERROR(init_op_picks);
            
            goto __controlRunner_exit;
        }

        /* update feedback table */
        mt_pick_t op_pick_actual_hits = {0, }; // operands which are actually hit during the program run
        
        if ( corpus->recvSeedHits(&op_pick_actual_hits) > 0 ) {
            if (op_pick_actual_hits.cnt == 0) {
                printf("Error: no hit?\n");
                exit(-1);
            }

            // UPDATE_OP_INFO(op_pick_actual_hits);
            MUTEX_LOCK(); 
            for (int i = 0; i < op_pick_actual_hits.cnt; i++) { 
                info = fuzz_ops_.at(op_pick_actual_hits.picks[i]); 
                info->total_hit++; 
                if (pkt.status == PROC_STATUS_FALSE_CRASH || pkt.status == PROC_STATUS_HANG) 
                    info->false_crash_cnt++; 
            } 
            MUTEX_UNLOCK();
            
        }
        else {
            printf("Error : there's no response for feedback data\n");
            perror("recv");
            corpus_result = PROC_STATUS_ERROR;
        }
        
        goto __controlRunner_exit;
    }
    else { 
        /* timed out, kill the child process */
        printf("kill(%d, SIGTERM)\n", pkt.pid);
        kill(pkt.pid, SIGTERM);

        // kill should work immediately
        corpus->setTimeout(2);

        /* try to catch PROC_STATUS_HANG */
        if (corpus->recvStatus(&pkt) > 0) {
            printf("id - %d, pid %d, status : %s\n", pkt.id, pkt.pid, status_text[pkt.status]);

            corpus->handleRunnerStatus(&pkt);

            corpus_result = pkt.status;

            mt_pick_t op_pick_actual_hits = {0, }; // operands which are actually hit during the program run

            if (corpus->recvSeedHits(&op_pick_actual_hits) > 0 ) {
                UPDATE_OP_INFO(op_pick_actual_hits);
            }
            else {
                printf("Error : there's no response for feedback data\n");
                perror("recv");
            }

            goto __controlRunner_exit;
        }
        else {
            printf("controlRunner(): something went wrong... kill process %d\n", run_pid);
            kill(run_pid, SIGKILL);

            // internal mess during fuzzing, increase false crash count for the selected seeds.
            UPDATE_OP_INFO_ON_ERROR(init_op_picks);
            
            corpus_result = PROC_STATUS_ERROR;
            goto __controlRunner_exit;
        }
    }

__controlRunner_exit:
    /* update current proc count */
    MUTEX_LOCK();

    if (corpus_result == PROC_STATUS_CRASH)
        crash_cnt_++;
    else if (corpus_result == PROC_STATUS_NON_CRASH)
        non_crash_cnt_++;

    alive_--;
    finished_++;
    MUTEX_UNLOCK();

    delete corpus;
}

void BenzeneFuzzServer::acceptCorpus(uint32_t run_iter) {
    int child_runner_fd = 0;
    struct sockaddr_un saddr;
    int addr_len = sizeof(struct sockaddr_un);

    while(true) {
        if (finished_ >= run_iter && alive_ == 0) {
            /* all iteration has been done, escape the loop */
            break;
        }

        child_runner_fd = accept(cntl_fd_, (struct sockaddr *)&saddr, (socklen_t*)&addr_len);

        if (child_runner_fd > 0) {
            // assignCorpusMonitor(child_runner_fd, saddr);
            /* new child proc just has been spawned, create corresponding BenzeneFuzzMonitor class */
            BenzeneFuzzMonitor* monitor = new BenzeneFuzzMonitor(child_runner_fd, saddr, this);

            monitor->setTimeout(timeout_);

            /* spawn control thread per each child process */
            std::thread th(&BenzeneFuzzServer::handleCorpus, this, monitor);
            th.detach();            
        }
        else { /* timed out */
            ;
        }
    }

    printf("[+] acceptCorpus() is returning\n");
}


void BenzeneFuzzServer::handleSpawnRequestFromFuzzer() {
    int corpus_fd = 0;
    struct sockaddr_un saddr;
    int addr_len = sizeof(struct sockaddr_un);

    sqlite3_stmt* stmt;
    int columns;

    printf("replay: handleSpawnRequestFromFuzzer (corpus cnt : %ld)\n", corpus_.size());

    size_t idx = 0;
    // request corpus info
    while(1) {
        if (finished_ >= corpus_.size()) {
            /* all iteration has been done, escape the loop */
            break;
        }

        if (!alive_) 
            continue;
        
        while (1) {
            corpus_fd = accept(cntl_fd_, (struct sockaddr *)&saddr, (socklen_t*)&addr_len);

            if (corpus_fd > 0) {
                mut_history_t* history = corpus_.at(idx++);
                // assignCorpusMonitor(child_runner_fd, saddr);
                /* new child proc just has been spawned, create corresponding BenzeneFuzzMonitor class */
                BenzeneFuzzMonitor* monitor = new BenzeneFuzzMonitor(corpus_fd, saddr, this);

                monitor->setTimeout(timeout_);

                /* spawn control thread per each child process */
                std::thread th(&BenzeneFuzzServer::handleMutation_replay, this, monitor, history);
                th.detach();
                break;
            }
            else { /* timed out */
                if (finished_ >= corpus_.size() && alive_ == 0) {
                    /* all iteration has been done, escape the loop */
                    break;
                }
            }
        }
    }

    printf("[+] handleSpawnRequestFromFuzzer() return\n");
}


void BenzeneFuzzServer::handleMutation_replay(BenzeneFuzzMonitor* corpus, mut_history_t* history) {
    status_pkt_t pkt;
    pid_t run_pid;

    proc_cmd_pkt_t cmd;
    
    proc_status_t corpus_result = PROC_STATUS_NONE;
    mt_status_t* info;

    if (corpus->recvStatus(&pkt) > 0) {
        printf("corpus_id - %d, pid %d, status : %s\n", history->corpus_id, pkt.pid, status_text[pkt.status]);
    }
    else {
        perror("handleMutation_replay(): recv");
        goto __handleCorpus_replay_exit;
    }

    run_pid = pkt.pid;

    /* check proc's status */
    if (pkt.status != PROC_STATUS_EXECUTE) {
        goto __handleCorpus_replay_exit;
    }
    
    /* proc successfully spawned */
    cmd.cmd = PROC_CMD_TRACE_SEED;
    
    // sendSeedForReplay(&history); /* pick fuzzing target operands */

    cmd.data.history = *history;

    /* send picked fuzzing target operands data to actual runenr */
    if (corpus->sendCommand(&cmd) < 0) {
        goto __handleCorpus_replay_exit;
    }
    
    if (corpus->recvStatus(&pkt) > 0) {
        corpus->handleRunnerStatus(&pkt);
        
        corpus_result = pkt.status;

        printf("corpus id - %d, pid %d, status : %s\n", history->corpus_id, pkt.pid, status_text[pkt.status]);
    }
    else { 
        /* timed out, kill the child process */
        printf("kill(%d, SIGTERM)\n", pkt.pid);
        kill(pkt.pid, SIGTERM);

        // kill should work immediately
        corpus->setTimeout(2);

        /* try to catch PROC_STATUS_HANG */
        if (corpus->recvStatus(&pkt) > 0) {
            printf("corpus id - %d, pid %d, status : %s\n", history->corpus_id, pkt.pid, status_text[pkt.status]);

            corpus->handleRunnerStatus(&pkt);

            goto __handleCorpus_replay_exit;
        }
        else {
            printf("controlRunner(): something went wrong... kill process %d\n", run_pid);
            kill(run_pid, SIGKILL);

            // internal mess during fuzzing, increase false crash count for the selected seeds.
            
            corpus_result = PROC_STATUS_ERROR;
            goto __handleCorpus_replay_exit;
        }
    }

__handleCorpus_replay_exit:
    /* update current proc count */
    MUTEX_LOCK();

    if (corpus_result == PROC_STATUS_CRASH)
        crash_cnt_++;
    else if (corpus_result == PROC_STATUS_NON_CRASH)
        non_crash_cnt_++;

    alive_--;
    finished_++;
    MUTEX_UNLOCK();

    delete corpus;
}


int BenzeneFuzzServer::run() {
    status_pkt_t    pkt;
    proc_cmd_pkt_t   cmd;
    pthread_t tid;
    int runner_fd;

    if (mode_ == BENZENE_MODE_TRACE) {
        return replay();
    }

    struct sockaddr_un saddr;
    int addr_len = sizeof(struct sockaddr_un);
    
    // run_slots_.reserve(max_run);

    /* initialize db slots */
    db_slots_.reserve(max_proc_);
    for (int i = 0; i < max_proc_; i++) {
        db_slots_[i] = 0;
    }

    spawned_ = 0;
    finished_ = 0;
    alive_ = 0;

    pkt = {0, 0, PROC_STATUS_NONE};

    printf("[*] Running... (max run : %d, run iteration : %d, corpus id : %d)\n", 
                                            max_proc_, iter_, init_id_);

    listen(cntl_fd_, max_proc_ + 1); // 

    /* wait proc initiation signal */
    runner_fd = accept(cntl_fd_, (struct sockaddr *)&saddr, (socklen_t*)&addr_len);

    // setTimeout(runner_fd, timeout_);
    setTimeout(cntl_fd_, 3);

    if (runner_fd < 0) {
        perror("accept error");
        return -1;
    }

    if (recv(runner_fd, &pkt, sizeof(pkt), 0) < 0) {
        perror("recv error");
        return -1;
    }

    if (pkt.status == PROC_STATUS_INIT) {
        printf("[*] proc initiated : %d\n", pkt.pid);

        /* send init id for trace dumping */
        cmd.cmd = PROC_CMD_INIT_ID;
        cmd.data.init_id = init_id_;
        sendCommand(runner_fd, &cmd);
    }
    else {
        printf("[-] Error : wrong response from proc : %d (%s)\n", pkt.status, status_text[pkt.status]);
        return -1;
    }


    /* Let's do the fuzz */

    uint32_t cur_total_run = 0;
    uint32_t cur_num_run = 0;
    uint32_t new_run = 0;
    uint32_t feedback_time = feedback_period_;

    std::thread accept_th(&BenzeneFuzzServer::acceptCorpus, this, iter_);

    uint32_t finished, alive;
    mt_status_t* tmp_info;

    while(true) {
        MUTEX_LOCK();
        finished = finished_;
        alive = alive_;
        MUTEX_UNLOCK();

        if (finished >= iter_ && alive == 0) { 
            /* all iteration has been done, escape the loop */
            break;
        }

        if (finished > feedback_time) {
            /* do feedback */
            MUTEX_LOCK();

            // calcuate false-crash ratio (%)
            for (size_t i = 0; i < fuzz_ops_.size(); i++) {
                tmp_info = fuzz_ops_[i];
                if (tmp_info->total_hit == 0)
                    tmp_info->false_ratio = 0;
                else
                    tmp_info->false_ratio = (float)tmp_info->false_crash_cnt / (float)tmp_info->total_hit;
            }
            
            if (feedback_mode_) {
                std::sort(feedback_table_.begin(), feedback_table_.end(), by_false_ratio());
                feedback_mode_--;
            }
            else {
                std::sort(feedback_table_.begin(), feedback_table_.end(), by_pick_cnt());
                feedback_mode_ = 3;
            }
            // sort feedback_table according to false crash ratio
            // std::sort(feedback_table_.begin(), feedback_table_.end(), by_false_ratio());
            
            feedback_time += feedback_period_;

            MUTEX_UNLOCK();
        }

        cur_total_run = finished + alive;

        if (cur_total_run < iter_ && alive < max_proc_) { 
            /* spawn new runners */
            
            new_run = max_proc_ - alive;

            if (cur_total_run + new_run > iter_)
                new_run = iter_ - cur_total_run;

            // printf("new run : %d !!, spawned : %d, alive : %d, finished : %d\n", new_run, spawned_, alive_, finished_);
            cmd.cmd = PROC_CMD_RUN;
            cmd.data.num_run = new_run;

            MUTEX_LOCK();
            spawned_ += new_run;
            alive_ += new_run;
            MUTEX_UNLOCK();
        
            // cmd = { PROC_CMD_RUN, 1};
            sendCommand(runner_fd, &cmd);
        }
        
        mtx_.unlock();

        sleep(0.5);
    }

    accept_th.join();
    printf("[+] acceptCorpus()'s exit confirmed...\n");

    /* whole exploration finished successfully, terminate proc client */
    cmd = { PROC_CMD_EXIT, 0 };

    if (sendCommand(runner_fd, &cmd) < 0) {
        perror("send failed");
    }

    printf("[+] waiting proc exit\n");

    /* wait for proc exit*/
    while(true) {
        if (recv(runner_fd, &pkt, sizeof(pkt), 0) > 0) {
            if (pkt.status == PROC_STATUS_DONE) {
                printf("[!] proc exit has been confirmed, finish the job!\n");
            }
            else {
                printf("Error : pid %d is left\n", pkt.pid);
            }
            break;
        }
        else {
            perror("recv\n");

        }    
    }

    printSummary(summary_path_);
    return 0;
}

mut_history_t* BenzeneFuzzServer::readMutation(const char* path) {
    mut_history_t* history = new mut_history_t;

    std::ifstream ifs(path);
    IStreamWrapper isw(ifs);
    
    Document mutation_json;
    mutation_json.ParseStream(isw);

    history->corpus_id = mutation_json["corpus_id"].GetUint();
    history->crash = mutation_json["crash"].GetUint();

    auto mut_arr = mutation_json["mutation"].GetArray();

    if (mut_arr.Size() == 0) {
        delete history;
        return nullptr;
    }

    for (size_t i = 0; i < mut_arr.Size(); i++) {
        json_val_t mut_json = mut_arr[i].GetObject();
        mutation_t* p_mut = &history->mutations[i];

        p_mut->offset = mut_json["offset"].GetUint();
        strncpy(p_mut->op_name, (const char*)mut_json["op_name"].GetString(), MAX_OP_NAME);
        p_mut->from = mut_json["from"].GetUint64();
        p_mut->to = mut_json["to"].GetUint64();
        p_mut->hit_cnt = mut_json["hit_cnt"].GetUint();
        p_mut->type = (mut_type_t)mut_json["mut_type"].GetUint();
    }

    return history;
}



int BenzeneFuzzServer::replay() {
    status_pkt_t    pkt;
    proc_cmd_pkt_t   cmd;
    pthread_t tid;
    int runner_fd;
    size_t corpus_size;
    struct sockaddr_un saddr;
    int addr_len = sizeof(struct sockaddr_un);
    
    printf("[+] replay & trace mode\n");
    printf("[+] corpus dir: \"%s\"\n", corpus_path_);

    DIR *dir;
    struct dirent *ent;
    if ((dir = opendir (corpus_path_)) != NULL) {
        /* print all the files and directories within directory */
        while ((ent = readdir (dir)) != NULL) {
            size_t name_len = strlen(ent->d_name);

            if (name_len < sizeof("0x0000.crash.json") - 1 || strncmp(&ent->d_name[name_len-5], ".json", 5))
                continue;

            std::string path = corpus_path_; 
            path += "/";
            path += ent->d_name;
            // printf("%s\n", path.c_str());

            mut_history_t* r = readMutation(path.c_str());
            if (!r) // empty mutation means it's a dryrun result. 
                continue;

            corpus_.push_back(readMutation(path.c_str()));
        }
        corpus_size = corpus_.size();
        closedir (dir);
    } else {
        /* could not open directory */
        perror ("");
        return BENZENE_ERROR;
    }

    if (corpus_size == 0) {
        printf("corpus_size is 0\n");
        return BENZENE_ERROR;
    }


    /* initialize db slots */
    db_slots_.reserve(max_proc_);
    for (int i = 0; i < max_proc_; i++) {
        db_slots_[i] = 0;
    }

    spawned_ = 0;
    finished_ = 0;
    alive_ = 0;

    pkt = {0, 0, PROC_STATUS_NONE};

    // printf("[*] Running... (max run : %d, run iteration : %ld, corpus id : %d)\n", 
    //                                         max_proc_, corpus_size, init_id_);

    listen(cntl_fd_, max_proc_ + 1); // 

    /* wait proc initiation signal */
    runner_fd = accept(cntl_fd_, (struct sockaddr *)&saddr, (socklen_t*)&addr_len);

    // setTimeout(runner_fd, timeout_);
    setTimeout(cntl_fd_, 3);

    if (runner_fd < 0) {
        perror("accept error");
        return BENZENE_ERROR;
    }

    if (recv(runner_fd, &pkt, sizeof(pkt), 0) < 0) {
        perror("recv error");
        return BENZENE_ERROR;
    }

    if (pkt.status == PROC_STATUS_INIT) {
        printf("[*] proc initiated : %d\n", pkt.pid);

        /* send init id for trace dumping */
        cmd.cmd = PROC_CMD_INIT_ID;
        cmd.data.init_id = init_id_;
        sendCommand(runner_fd, &cmd);
    }
    else {
        printf("[-] Error : wrong response from proc : %d (%s)\n", pkt.status, status_text[pkt.status]);
        return BENZENE_ERROR;
    }

    /* trace it */
    std::thread accept_th(&BenzeneFuzzServer::handleSpawnRequestFromFuzzer, this);
    
    uint32_t finished, alive;
    mt_status_t* tmp_info;

    uint32_t cur_total_run = 0;
    uint32_t cur_num_run = 0;
    uint32_t new_run = 0;

    while(true) {
        MUTEX_LOCK();
        finished = finished_;
        alive = alive_;
        MUTEX_UNLOCK();

        if (finished >= corpus_size && alive == 0) {
            printf("all done\n");
            /* all iteration has been done, escape the loop */
            break;
        }

        cur_total_run = finished + alive;

        if (cur_total_run < corpus_size && alive < max_proc_) { 
            /* spawn new runners */
            
            new_run = max_proc_ - alive;

            if (cur_total_run + new_run > corpus_size)
                new_run = corpus_size - cur_total_run;

            // printf("new run : %d !!, spawned : %d, alive : %d, finished : %d\n", new_run, spawned_, alive_, finished_);
            cmd.cmd = PROC_CMD_RUN;
            cmd.data.num_run = new_run;

            MUTEX_LOCK();
            spawned_ += new_run;
            alive_ += new_run;
            MUTEX_UNLOCK();
        
            // cmd = { PROC_CMD_RUN, 1};
            sendCommand(runner_fd, &cmd);
        }
        
        mtx_.unlock();

        sleep(0.5);
    }

    accept_th.join();
    printf("[+] acceptCorpus()'s exit confirmed...\n");

    /* whole exploration finished successfully, terminate proc client */
    cmd = { PROC_CMD_EXIT, 0 };

    if (sendCommand(runner_fd, &cmd) < 0) {
        perror("send failed");
    }

    printf("[+] waiting proc exit\n");

    /* wait for proc exit*/
    while(true) {
        if (recv(runner_fd, &pkt, sizeof(pkt), 0) > 0) {
            if (pkt.status == PROC_STATUS_DONE) {
                printf("[!] proc exit has been confirmed, finish the job!\n");
            }
            else {
                printf("Error : pid %d is left\n", pkt.pid);
            }
            break;
        }
        else {
            perror("recv\n");

        }    
    }

    printSummary(summary_path_);
    return BENZENE_SUCCESS;
}


int BenzeneFuzzServer::readConfigFromJSON(const char* filename) {
    benzene_config_t config;
    mt_status_t* mt_stat;
    FILE* fp;
    char* config_buf;

    fp = fopen(filename, "r");
    fseek(fp, 0, SEEK_END);
    size_t config_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (config_size == 0) {
        printf("config size is 0\n");
        return -1;
    }
    config_buf = (char*)malloc(config_size + 1);
    config_buf[config_size] = '\x00';

    if (fread(config_buf, 1, config_size, fp) != config_size) {
        printf("config size mismatch\n");
        fclose(fp);
        return -1;
    }
    fclose(fp);

    config.Parse(config_buf);

    fuzz_offset_    = config["fuzz_offset"].GetUint();
    hit_cnt_        = config["hit_cnt"].GetUint();

    // fix here config['mutation_targets']
    auto mts_json = config["mutation_targets"].GetArray();

    for (size_t i = 0; i < mts_json.Size(); i++) {
        auto mt_json = mts_json[i].GetObject();

        // create new `mt_status_t` to monitor the fuzzing process for each mutation target.
        mt_stat = new mt_status_t;
        mt_stat->addr       = mt_json["addr"].GetUint64();
        mt_stat->offset     = mt_json["offset"].GetUint();
        mt_stat->op_name    = mt_json["op_name"].GetString();
        mt_stat->idx        = fuzz_ops_.size();
        mt_stat->total_hit  = 0;
        mt_stat->false_crash_cnt = 0;
        fuzz_ops_.push_back(mt_stat);

        printf("0x%lx(%s)\n", mt_stat->offset, mt_stat->op_name.c_str());
        feedback_table_.push_back(mt_stat);
    }

    free(config_buf);
    return 0;
}

void BenzeneFuzzServer::initOptions(int argc, const char* argv[]) {
    const char* token;
    int i = 0;

    for (i = 1; i < argc; i++) {
        token = argv[i];

        if (OPTSTR_CMP(token, "--iter") == 0) {
            iter_ = atoi(argv[++i]);
        }
        else if (OPTSTR_CMP(token, "--proc") == 0) {
            max_proc_ = atoi(argv[++i]);
            if (max_proc_ == 0) {
                printf("invalid --proc option: 0\n");
                exit(-1);
            }
        }
        else if (OPTSTR_CMP(token, "--corpus_id") == 0) {
            init_id_ = atoi(argv[++i]);
        }
        else if (OPTSTR_CMP(token, "--config") == 0) {
            strncpy(config_path_, argv[++i], MAXIMUM_PATH);
        }
        else if (OPTSTR_CMP(token, "--timeout") == 0) {
            timeout_ = atoi(argv[++i]);
        }
        else if (OPTSTR_CMP(token, "--summary") == 0) {
            strncpy(summary_path_, argv[++i], MAXIMUM_PATH);
        }
        else if (OPTSTR_CMP(token, "--trace") == 0) {
            mode_ = BENZENE_MODE_TRACE;
            strncpy(corpus_path_, argv[++i], MAXIMUM_PATH);
        }
        else {
            printf("unrecognized option '%s'\n", token);
            exit(-1);
        }
    }

    if (iter_ == 0 && mode_ == BENZENE_MODE_FUZZ) {
        printf("fuzzing iteration count must be specified\n");
        exit(-1);
    }
    
    /* setup default values */
    if (max_proc_ == 0) 
        max_proc_ = 1;
    if (timeout_ == 0) 
        timeout_ = 5;
    if (summary_path_[0] == '\x00') {
        strncpy(summary_path_, "/dev/fd/0", MAXIMUM_PATH);
    }
    if (mode_ == BENZENE_MODE_NONE) {
        mode_ = BENZENE_MODE_FUZZ;
    }

}

void BenzeneFuzzServer::printSummary(const char* summary_path) {
    FILE* f;

    f = fopen(summary_path, "wb");

    fprintf(f, "fuzz_offset=0x%lx\n", fuzz_offset_);
    fprintf(f, "hit_cnt=%d\n", hit_cnt_);
    fprintf(f, "crash=%d\n", crash_cnt_);
    fprintf(f, "non_crash=%d\n", non_crash_cnt_);
    fprintf(f, "total_run=%d\n", finished_);

    uint32_t fuzz_total_run = 0;
    uint32_t fuzz_total_false_crashes = 0;

    for (size_t i = 0; i < feedback_table_.size(); i++) {
        mt_status_t* info = feedback_table_[i];

        fprintf(f, "seed=0x%lx,false_crash=%d,total_hit=%d,ratio=%f\n", 
                    info->offset, 
                    info->false_crash_cnt,
                    info->total_hit,
                    info->total_hit ? 
                                ((float)(info->false_crash_cnt * 100) / (float)info->total_hit) : 0.0);

        fuzz_total_run += info->total_hit;
        fuzz_total_false_crashes += info->false_crash_cnt;
    }

    fprintf(f, "fuzzing_success=%d\n", fuzz_total_run);
    fprintf(f, "false_crash_cnt=%d\n", fuzz_total_false_crashes);

    fclose(f);
}

int main (int argc, const char* argv[]) {

    BenzeneFuzzServer* server = new BenzeneFuzzServer();
    
    server->initOptions(argc, argv);

    if (server->setup() < 0)
        return -1;

    if (server->run() < 0)// id 0 (zero) for the given crash
        return -1; 

    return 0;
}