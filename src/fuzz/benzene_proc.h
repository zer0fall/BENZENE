#ifndef __BENZENE_PROC_H__
#define __BENZENE_PROC_H__

#include <sys/wait.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include "benzene_common.h"


typedef struct {
    int ipc_fd;
    pid_t pid;
    bool is_parent;
    bool init_done;

    struct sockaddr_un saddr;

    uint32_t total_run_cnt;
    uint32_t run_id;

    proc_status_t status;
} benzene_proc_t;

int initProc(benzene_proc_t* proc);
int exitProc(benzene_proc_t* proc);

inline void setStatus(benzene_proc_t* proc, proc_status_t status) {
    // printf("runid : %d\n", proc->run_id);
    proc->status = status;
}
inline proc_status_t getStatus(benzene_proc_t* proc) {
    return proc->status;
}
int notifyStatus(benzene_proc_t* proc);
int notifyStatus(benzene_proc_t* proc, proc_status_t status);
int notifyInit(benzene_proc_t* proc);

int sendDataToServer(benzene_proc_t* proc, const char* data, size_t len);
int recvDataFromServer(benzene_proc_t* proc, char* data, size_t len); 

int setupChild(benzene_proc_t* proc);
int spawnChild(benzene_proc_t* proc);

#endif