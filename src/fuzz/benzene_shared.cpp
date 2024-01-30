#include "benzene_shared.h"

#include <sys/shm.h>
#include <sys/ipc.h>
#include <sys/sem.h>

#include "dr_api.h"

int shm_id;
int sem_id;
bool sem_wait = false;

typedef struct {
    char* alloc_ptr;
    void* shm_mem;
} benzene_shm_t;

static benzene_shm_t* benzene_shm;
static size_t benzene_shm_size;

bool benzene_shm_set_write() {
    return dr_memory_protect(benzene_shm, benzene_shm_size, BENZENE_PROT_READ | BENZENE_PROT_WRITE);
}

bool benzene_shm_set_readonly() {
    return dr_memory_protect(benzene_shm, benzene_shm_size, BENZENE_PROT_READ);
}

bool setShmProt(uint prot) {
    return dr_memory_protect(benzene_shm, benzene_shm_size, prot);
}


/**
 * @brief allocate shared memory with `shm_size`
 * @param size_t shm_size 
 */
void* setupShm(size_t shm_size) {
    shm_id = shmget(BENZENE_SHM_KEY, shm_size, IPC_CREAT|0666);
    
    if(shm_id == -1){
        perror("shmget failed");
        return nullptr;
    }    

    benzene_shm = (benzene_shm_t*)shmat(shm_id, 0, IPC_CREAT|0666);

    if((int64_t)benzene_shm == -1){
        perror("shmgat failed");
        return nullptr;
    }

    /* 
     * Setup semaphore for feedback hitmap
     */
    semun_t su;
    sem_id = semget(BENZENE_SEM_KEY, SEM_NUM_SIZE, IPC_CREAT|0660);

    if (sem_id == -1) {
        perror("semget failed");
        return nullptr;
    }

    for (int i = 0; i < SEM_NUM_SIZE; i++) {
        su.val = 1;
        if(semctl(sem_id, i, SETVAL, su) == -1){
            perror("semctl failed\n");
            return nullptr;
        }    
    }

    benzene_shm_size = shm_size;
    benzene_shm->alloc_ptr = (char*)&benzene_shm->shm_mem;

    return benzene_shm;
}


int detachShm() {
    if (shmdt(benzene_shm) < 0) {
        perror("shmdt failed");
        return -1;
    }
    return BENZENE_SUCCESS;
}

int removeShm() {

    if( shmctl(shm_id, IPC_RMID, NULL) == -1){
        perror("shmctl failed\n");
        return -1;
    }    

    semun_t su;

    su.val = 1;
    if(semctl(sem_id, 0, IPC_RMID, su) == -1){
        perror("semctl 0 failed\n");
        return -1;
    }

    return BENZENE_SUCCESS;
}



void benzene_sem_wait(sem_num_t sem_num) {
    struct sembuf buf = {sem_num, -1, SEM_UNDO};
    // buf.sem_num=0;
    // buf.sem_op=-1;
    // buf.sem_flg=SEM_UNDO;

    if(semop(sem_id, &buf, 1) == -1){
        perror("semop failed");
        // fprintf(stderr, "semop failed : id (%d), num : %d\n", sem_id, sem_num);
        return;
    }

    sem_wait = true;
}

void benzene_sem_quit(sem_num_t sem_num){
    if (!sem_wait)
        return;

    struct sembuf buf = {sem_num, 1, SEM_UNDO};
    // buf.sem_num=0;
    // buf.sem_op=1;
    // buf.sem_flg=SEM_UNDO;

    if(semop(sem_id, &buf, 1) == -1){
        perror("semop failed");
        // fprintf(stderr, "semop failed : id (%d), num : %d\n", sem_id, sem_num);
        return;
    }
}

void* benzene_shm_malloc(size_t size) {
    void* result = benzene_shm->alloc_ptr;
    
    DR_ASSERT_MSG(size != 0, "alloc size is 0");
    
    if (benzene_shm->alloc_ptr + size >= ((char*)benzene_shm + benzene_shm_size))
        return nullptr; /* all shared memory is exhausted */

    benzene_shm->alloc_ptr += size;
    return result;
}