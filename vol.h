#ifndef __VOL_H__
#define __VOL_H__

#include "iscsi.h"
#include "scsi.h"
#include "misc.h"

#define PAGE_BUFFER_SIZE (4*1024)

struct page_buffer {
    struct list_element listelem;
    byte buf[PAGE_BUFFER_SIZE];
    uint32 offset;
    uint32 len;
}; // struct page_buffer

void page_dump_list(struct list *list, char *listname);

enum volume_type {
    VOLTYPE_NULL     = 0x00,
    VOLTYPE_STANDARD = 0x01,
};

enum volume_cmd_opcode {
    VOLUME_OP_READ  = 0x01,
    VOLUME_OP_WRITE = 0x11,
};

#define VOLCMD_RESULT_NULL    0x00
#define VOLCMD_RESULT_SUCCESS 0x01

enum volume_cmd_status {
    VOLCMD_STATUS_NULL,
    VOLCMD_STATUS_QUEUED,
    VOLCMD_STATUS_DOING,
    VOLCMD_STATUS_DONE,
    VOLCMD_STATUS_CANCELED,
};

struct volume_cmd {
    struct list_element listelem_conn; //< list element at connection thread
    struct list_element listelem_vol;  //< list element at volume thread

    struct volume *vol;
    enum volume_cmd_opcode opcode;     //< opcode
    uint8 opcode_scsi;
    uint64 lba;
    uint32 trans_len;

    struct list list_page;
    uint32 page_totallen;

    struct iscsi_conn *conn;
    int fd_ev;

    uint64 time_usec_start;
    uint64 time_usec_finish;

    pthread_mutex_t lock_status;
    enum volume_cmd_status status;

    pthread_cond_t *cond_cancel;

    uint8 result;

    void *data;
}; // struct volume_cmd


struct volume_ops {
    void *(*exec)(void *arg);
    int (*notify)(struct volume *vol);
    int (*sync_cache)(struct volume *vol, uint64 lba, uint32 len, int sync_nv, int immed);
/*
    int (*alloc_bufvec)(struct volume *vol,
			uint64 lba, uint32 len,
			struct buffer_vec **dsvec, uint32 *dsvec_cnt);
    int (*free_bufvec)(struct volume *vol,
		       struct buffer_vec *dsvec, uint32 dsvec_cnt);
*/
};


struct volume {
    struct list_element listelem;
    struct iscsi_target *target;
    
    struct list list_cmd;
    pthread_mutex_t lock_list_cmd;

    uint64 lun;
    uint64 capacity;
    uint32 sector_size;
    byte scsi_sn[SCSI_SN_MAXLEN];
    byte scsi_id[SCSI_ID_MAXLEN];

    char pathname[FILENAME_MAX];

    enum volume_type type;
    void *ext;

    struct volume_ops ops;

    pthread_t thread;

    pthread_mutex_t lock_reserve;
    union iscsi_sid reserve_sid;

    char pathname_iotrace[FILENAME_MAX];
    FILE *fp_iotrace;
}; // struct volume


#define LOCK_LIST_CMD(vol) do { pthread_mutex_lock(&(vol->lock_list_cmd)); } while (0)
#define UNLOCK_LIST_CMD(vol) do { pthread_mutex_unlock(&(vol->lock_list_cmd)); } while (0)

struct volume *vol_create(
    struct iscsi_target *target,
    uint64 lun,
    char *pathname,
    enum volume_type type,
    uint64 capacity,    // # of sectors per a volume
    uint32 sector_size, // bytes per a sector
    char *pathname_iotrace,      // NULL | pathname of IO-trace file
    void *options);
int vol_run(struct volume *vol);

int vol_enqueue_cmd(struct volume_cmd *cmd);
struct volume_cmd *vol_dequeue_cmd(struct volume *vol);
void vol_dump_cmd(struct volume_cmd *cmd);
int vol_alloc_buf(
    struct volume *vol,
    uint64 lba,
    uint32 trans_len,
    struct list *list_page,
    uint32 *page_totallen);
int vol_free_buf(
    struct volume *vol,
    struct list *list_page);

int vol_release(struct volume *vol, struct iscsi_conn *conn, int force);
int vol_reserve(struct volume *vol, struct iscsi_conn *conn);
int vol_is_reserved(struct volume *vol, struct iscsi_conn *conn);

int vol_send_cmd_completion(struct volume_cmd *volcmd, uint8 result);
int vol_cancel_cmd(struct volume_cmd *cmd);

inline void vol_record_start_time(
    struct volume *vol,
    struct volume_cmd *vol_cmd);
inline void vol_record_finish_time(
    struct volume *vol,
    struct volume_cmd *vol_cmd);
int vol_dump_iotrace(
    struct volume *vol,
    struct volume_cmd *vol_cmd);
void vol_init_volcmd(
    struct volume *vol,
    struct volume_cmd *volcmd,
    struct iscsi_conn *conn,
    struct scsi_cmd *scsicmd,
    struct list *list_page,
    uint32 page_totallen,
    void *data);

int vol_does_cache_wr(struct volume *vol);
int vol_does_cache_rd(struct volume *vol);
int vol_sync_cache(
    struct volume *vol,
    uint64 lba,
    uint32 len,
    int sync_nv,
    int immed);

#endif // __VOL_H__
