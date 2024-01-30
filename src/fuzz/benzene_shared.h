#ifndef __BENZENE_SHARED_H__
#define __BENZENE_SHARED_H__

#include <stdint.h>
#include <stdio.h>
#include "benzene_common.h"

#define SHM_READONLY  BENZENE_PROT_READ
#define SHM_WRITE     BENZENE_PROT_READ | BENZENE_PROT_WRITE

#define BENZENE_SHM_KEY 0xbe12e1e
#define BENZENE_SEM_KEY 0xabcd

typedef enum SEM_NUM {
    SEM_NUM_SHM = 0,
    SEM_NUM_RUN_CNT,
    SEM_NUM_SIZE /* the number of semaphores */
} sem_num_t;


typedef union semun {
    int  val;    /* Value for SETVAL */
    struct semid_ds *buf;    /* Buffer for IPC_STAT, IPC_SET */
    unsigned short  *array;  /* Array for GETALL, SETALL */
    struct seminfo  *__buf;  /* Buffer for IPC_INFO (Linux-specific) */
} semun_t;

bool benzene_shm_set_write();
bool benzene_shm_set_readonly(); 
bool setShmProt(uint prot);

void* setupShm(size_t shm_size);
int detachShm();
int removeShm();

void benzene_sem_wait(sem_num_t sem_num);
void benzene_sem_quit(sem_num_t sem_num);

void* benzene_shm_malloc(size_t size);

#endif