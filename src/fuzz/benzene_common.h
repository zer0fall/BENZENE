#ifndef __BENZENE_COMMON_H__
#define __BENZENE_COMMON_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdint.h>

#include "rapidjson/rapidjson.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

using namespace rapidjson;

typedef Value json_val_t;
typedef Document benzene_config_t;
typedef MemoryPoolAllocator<rapidjson::CrtAllocator> rapidjson_allocator_t;

#define CNTL_SOCK_PATH "/tmp/cntl_sock"
#define MAX_SEED_OP_PICK_CNT    2
#define MAX_OP_NAME 8
#define MAX_MUTATION_COUNT 6
#define UNIQUE_TRACE_THRESHOLD 128

typedef uint32_t benzene_mode_t;
#define BENZENE_SUCCESS         0x0
#define BENZENE_ERROR           -1

#define BENZENE_MODE_NONE       0x0
#define BENZENE_MODE_DRYRUN     0x1
#define BENZENE_MODE_FUZZ       0x2
#define BENZENE_MODE_TRACE      0x4

#define BENZENE_PROT_READ   0x1
#define BENZENE_PROT_WRITE  0x2

#define MAX_MODULE_NAME_LEN 64
#define MAXIMUM_MODULE_CNT 6

// @TODO: control shared memory in a dynamic way
#define MAXIMUM_SHM_SIZE 0x4000000
#define MAX_PROCESSES 20

#define SANITIZE_CONFIG(doc, key) do { DR_ASSERT_MSG(doc.HasMember(key) == true, "invalid configure"); } while(0);

enum PROC_STATUS {
    PROC_STATUS_NONE = 0,
    PROC_STATUS_INIT,
    PROC_STATUS_PARENT,
    PROC_STATUS_EXECUTE,
    PROC_STATUS_NON_CRASH,
    PROC_STATUS_CRASH,
    PROC_STATUS_FALSE_CRASH,
    PROC_STATUS_HANG,
    PROC_STATUS_DONE,
    PROC_STATUS_DUMP,
    PROC_STATUS_CRASH_MISMATCH,
    PROC_STATUS_ERROR
};

enum PROC_CMD {
    PROC_CMD_NONE = 0,
    PROC_CMD_RUN,
    PROC_CMD_EXIT,
    PROC_CMD_FEEDBACK,
    PROC_CMD_ASSIGN_SLOT,
    PROC_CMD_INIT_DB,
    PROC_CMD_PICK_SEED,
    PROC_CMD_INIT_ID,
    PROC_CMD_TRACE_SEED
};

typedef PROC_STATUS   proc_status_t;
typedef PROC_CMD      proc_cmd_t;

typedef struct _status_pkt_t {
    uint32_t        id;
    pid_t           pid;
    proc_status_t    status;
} status_pkt_t;

typedef struct _mt_pick_t {
    size_t      cnt;
    uint32_t    picks[MAX_SEED_OP_PICK_CNT];
} mt_pick_t;

// @TODO: extend to xmm/ymm/zmm registers
typedef u_int64_t trace_val_t;

struct trace_entry_t {
    trace_val_t val;
    uint32_t    hit_cnt; // optional
    trace_entry_t* prev;
    trace_entry_t* next;
};

// All the BenzeneOp should contain one of the `BENZENE_MT_TYPE` values.
typedef enum BENZENE_MT_TYPE { // BENZENE mutation types
    MUTATION_TYPE_NONE   = 0, // `MUTATION_TYPE_NONE` indicates that `BenzeneOp` is not a mutation target.
    MUTATION_TYPE_CONST  = 1,
    MUTATION_TYPE_PTR    = 2,
    MUTATION_TYPE_STR    = 4,
    MUTATION_TYPE_STRLEN = 8
} mut_type_t;

struct mutation_t {
    uint32_t    offset;
    char        op_name[MAX_OP_NAME];
    trace_val_t from;
    trace_val_t to;
    uint32_t    hit_cnt;
    mut_type_t  type; 
};

typedef struct {
    int corpus_id;
    bool crash;
    mutation_t mutations[MAX_MUTATION_COUNT];
} mut_history_t;

/* command packet from BenzeneFuzzServer */
typedef struct _proc_cmd_pkt_t {
    proc_cmd_t   cmd;
    union {
        uint32_t        num_run;
        uint32_t        db_num;
        uint32_t        db_cnt;
        uint32_t        init_id;
        mt_pick_t       mt_pick;
        mut_history_t   history;
    } data;
    /* other cmd */
} proc_cmd_pkt_t;

#endif