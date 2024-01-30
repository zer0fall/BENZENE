#include "benzene_proc.h"
#include "benzene_mutation.h"
#include "dr_api.h"


int initProc(benzene_proc_t* proc) {
    proc->is_parent = true;
    proc->run_id = 0;
    proc->total_run_cnt = 0;
    proc->pid = dr_get_process_id();

    DR_ASSERT(!proc->init_done); // prevent duplicate master creation

    proc_cmd_pkt_t cmd_pkt;

    proc->saddr.sun_family = AF_UNIX;
    strncpy(proc->saddr.sun_path, CNTL_SOCK_PATH, sizeof(CNTL_SOCK_PATH));
    
    proc->ipc_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (proc->ipc_fd < 0) {
        dr_fprintf(STDERR, "Error: socket() failed\n");
        return BENZENE_ERROR;
    }

    if (connect(proc->ipc_fd, (struct sockaddr*)&proc->saddr, sizeof(proc->saddr)) < 0) {
        dr_fprintf(STDERR, "Error: connect() failed\n");
        return BENZENE_ERROR;
    }

    if ( notifyInit(proc) < 0)
        return BENZENE_ERROR;    

    // set run count with initial id value
    recvDataFromServer(proc, (char*)&cmd_pkt, sizeof(proc_cmd_pkt_t));
    
    if (cmd_pkt.cmd != PROC_CMD_INIT_ID) {
        dr_fprintf(STDERR, "Error: wrong command received\n");
        return BENZENE_ERROR;
    }

    proc->total_run_cnt = cmd_pkt.data.init_id;

    /* prevent <defunct> processes */
    signal(SIGCHLD, SIG_IGN);

    /* craete process group for fuzzing */
    setsid();

    proc->init_done = true;
    return BENZENE_SUCCESS;
}

int exitProc(benzene_proc_t* proc) {
    if (proc->is_parent) {
        dr_fprintf(STDERR, "parent process exit!\n");

        /* kill all spawned child processes */
        signal(SIGTERM, SIG_IGN); /* kill except the current process */
        killpg(0, SIGTERM);
    }

    close(proc->ipc_fd);

    return BENZENE_SUCCESS;
}

int notifyStatus(benzene_proc_t* proc) {
    status_pkt_t pkt = { proc->run_id, proc->pid, proc->status };

    if (sendDataToServer(proc, (const char *)&pkt, sizeof(pkt)) < 0) {
        perror("send failed");
        return BENZENE_ERROR;
    }

    return BENZENE_SUCCESS;
}

int notifyStatus(benzene_proc_t* proc, proc_status_t status) {
    status_pkt_t pkt = { proc->run_id, proc->pid, status};

    if (sendDataToServer(proc, (const char *)&pkt, sizeof(pkt)) < 0) {
        perror("send failed");
        return BENZENE_ERROR;
    }

    return BENZENE_SUCCESS;
}

int notifyInit(benzene_proc_t* proc) {
    status_pkt_t pkt = { proc->run_id, proc->pid, PROC_STATUS_INIT };

    if (sendDataToServer(proc, (const char *)&pkt, sizeof(pkt)) < 0) {
        perror("send failed");
        fprintf(stderr, "notifyInit failed\n");
        return BENZENE_ERROR;
    }

    return BENZENE_SUCCESS;
}

int sendDataToServer(benzene_proc_t* proc, const char* data, size_t len) {
    return send(proc->ipc_fd, data, len, 0);
}
int recvDataFromServer(benzene_proc_t* proc, char* data, size_t len) {
    return recv(proc->ipc_fd, data, len, 0);
}

int setupChild(benzene_proc_t* proc) {
    if (proc->ipc_fd < 0) return BENZENE_ERROR;

    proc->is_parent = false;
    
    close(proc->ipc_fd);
    proc->ipc_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        
    /* newly connect to the server */
    if (connect(proc->ipc_fd , (struct sockaddr*)&proc->saddr, sizeof(proc->saddr)) < 0) {
        perror("connect()");
        return BENZENE_ERROR;
    }

    // get child process's pid
    proc->pid = dr_get_process_id(); 

    proc->run_id = proc->total_run_cnt;

    setStatus(proc, PROC_STATUS_EXECUTE);
    notifyStatus(proc);
    
    // set random state for each run
    mangle_init();

    return BENZENE_SUCCESS;
}

pid_t spawnChild(benzene_proc_t* proc){
    pid_t pid = fork();
    
    if (pid < 0) {
        return BENZENE_ERROR;
    }

    if (pid == 0) { // child (slave)
        if (setupChild(proc) < 0) {
            dr_exit_process(-1);
        }
    }
    else {  // master
        proc->total_run_cnt++;
    }

    return pid;
}