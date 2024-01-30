#ifndef __BFUZZ_CORPUS_H__
#define __BFUZZ_CORPUS_H__

#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <unistd.h>
#include "benzene_common.h"

class BenzeneFuzzMonitor {
private:
    int fd_;
    struct sockaddr_un client_addr_;
    void* master_;

public:
    BenzeneFuzzMonitor(int fd, struct sockaddr_un addr, void* master) : 
    fd_(fd),
    client_addr_(addr),
    master_(master)
    {};

    ~BenzeneFuzzMonitor() {
        close(fd_);
    }

    int sendCommand(proc_cmd_pkt_t* packet) {
        return send(fd_, packet, sizeof(proc_cmd_pkt_t), 0);
    };

    int sendFuzzOpPicks(mt_pick_t* packet) {
        return send(fd_, packet, sizeof(mt_pick_t), 0);
    }


    int recvStatus(status_pkt_t* packet) {
        return recv(fd_, packet, sizeof(status_pkt_t), 0);
    }

    /* get fuzzed operands during the program run from the client */
    int recvSeedHits(mt_pick_t* packet) {
        return recv(fd_, packet, sizeof(mt_pick_t), 0);
    }    

    int handleRunnerStatus(status_pkt_t* packet);

    int requestDBSlot();
    void releaseDBSlot(int slot);

    int setTimeout(int timeout) {
        struct timeval tv;
        tv.tv_sec = timeout;
        tv.tv_usec = 0;
        return setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    }
};



#endif