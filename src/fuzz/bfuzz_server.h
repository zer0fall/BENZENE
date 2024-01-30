#ifndef __BFUZZ_SERVER_H__
#define __BFUZZ_SERVER_H__

#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/shm.h> 

#include <stdio.h>
#include <string.h>
#include <vector>
#include <pthread.h>

#include <thread>
#include <mutex>
#include <assert.h>

#include "benzene_common.h"
#include "bfuzz_corpus.h"
#include "benzene_mutation.h"
#include "sqlite3.h"
#include <iostream>
#include <fstream>

#define CNTL_SOCK_PATH "/tmp/cntl_sock"
#define MAXIMUM_PATH 256

typedef struct {
    uint64_t        addr;
    uint64_t        offset;
    std::string     op_name;
    uint32_t        idx; /* index of op array */
    uint32_t        total_hit;
    uint32_t        false_crash_cnt;
    float           false_ratio;
} mt_status_t; // mutation target status

class BenzeneFuzzServer {
private:
    int cntl_fd_;
    struct sockaddr_un cntl_addr_;
    std::vector<mut_history_t*> corpus_;

    benzene_mode_t mode_ = BENZENE_MODE_NONE;
    std::mutex mtx_;
    
    uint32_t iter_ = 0;
    uint32_t init_id_ = 0;

    int timeout_ = 0;
    char config_path_[MAXIMUM_PATH];
    char summary_path_[MAXIMUM_PATH];
    char corpus_path_[MAXIMUM_PATH];

    uint32_t max_proc_ = 0;
    int32_t alive_;
    int32_t spawned_;
    int32_t finished_;

    uint32_t feedback_period_;

    std::vector<uint32_t> db_slots_;
    std::mutex slot_mtx_;

    std::vector<mt_status_t*> fuzz_ops_;
    std::vector<mt_status_t*> feedback_table_;

    uint32_t feedback_mode_ = 3;

    uint64_t fuzz_offset_ = 0;
    uint32_t hit_cnt_ = 0;

    uint32_t crash_cnt_ = 0;
    uint32_t non_crash_cnt_ = 0;
    
public:
    BenzeneFuzzServer();
    
    int setup();
    void initOptions(int argc, const char* argv[]);

    int run();
    int replay();

    int requestDBSlot() {
        slot_mtx_.lock();
        for (int i = 0; i < max_proc_; i++) {
            if (db_slots_[i] == 0) {
                db_slots_[i] = 1;
                slot_mtx_.unlock();
                return i;
            }
        }
        slot_mtx_.unlock();
        return -1;
    }

    void releaseDBSlot(int slot) {
        slot_mtx_.lock();

        assert(db_slots_[slot] == 1);

        db_slots_[slot] = 0;

        slot_mtx_.unlock();
    }

private:
    int readConfigFromJSON(const char* filename);

    int recvRunStatus(int fd, status_pkt_t* packet) {
        return recv(fd, packet, sizeof(status_pkt_t), 0);
    };

    int sendCommand(int fd, proc_cmd_pkt_t* packet) {
        return send(fd, packet, sizeof(proc_cmd_pkt_t), 0);
    };

    /* multi-threaded */
    void handleCorpus(BenzeneFuzzMonitor* corpus);
    void acceptCorpus(uint32_t run_iter);

    mut_history_t* readMutation(const char* path);
    void handleMutation_replay(BenzeneFuzzMonitor* control, mut_history_t* history);
    void handleSpawnRequestFromFuzzer();
    int sendSeedForReplay(mut_history_t* history);

    int setTimeout(int fd, int timeout) {
        struct timeval tv;
        tv.tv_sec = timeout;
        tv.tv_usec = 0;
        return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    }
    int pickMutationTargets(mt_pick_t* packet);

    void printSummary(const char* summary_path);
};



#endif