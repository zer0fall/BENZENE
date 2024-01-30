#include "bfuzz_corpus.h"
#include "bfuzz_server.h"

int BenzeneFuzzMonitor::handleRunnerStatus(status_pkt_t* packet) {
    mt_pick_t picked = {0, };

    switch(packet->status) {
        case PROC_STATUS_NON_CRASH:
        case PROC_STATUS_CRASH:
            break;
        case PROC_STATUS_FALSE_CRASH:
            break;
        case PROC_STATUS_HANG:
            printf("id - %d, pid %d, status : PROC_STATUS_HANG\n", packet->id, packet->pid);
            break;
        case PROC_STATUS_DUMP: {
            setTimeout(0); // disable timeout for secure DB dump

            /* send DB slots */
            proc_cmd_pkt_t cmd;
            int db_num = requestDBSlot();
            printf("id - %d, pid %d, status : PROC_STATUS_DUMP\n", packet->id, packet->pid);

            cmd.cmd = PROC_CMD_ASSIGN_SLOT;
            cmd.data.db_num = db_num;
            if (sendCommand(&cmd) < 0) {
                perror("send (DB assign)");
                return -1;
            }

            /* wait until dump is done */
            if (recvStatus(packet) > 0) {
                handleRunnerStatus(packet);
            }
            else {
                printf("Error : there's no response after dumping\n");
                assert(false);
                return -1;
            }

            releaseDBSlot(db_num);
            break;
        }
        case PROC_STATUS_CRASH_MISMATCH:
            // @TODO: handle crash mismatch
            break;
        default:
            printf("error! : status %d received!\n", packet->status);
            break;
    }

    return 0;
}

int BenzeneFuzzMonitor::requestDBSlot() {
    return reinterpret_cast<BenzeneFuzzServer*>(master_)->requestDBSlot();
}

void BenzeneFuzzMonitor::releaseDBSlot(int slot) {
    reinterpret_cast<BenzeneFuzzServer*>(master_)->releaseDBSlot(slot);
}