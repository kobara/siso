#include <pthread.h>
#include <errno.h>
#include <string.h> // memcpy
#include <sys/types.h> // fstat, open
#include <sys/stat.h>  // fstat, open
#include <unistd.h>    // fstat
#include <fcntl.h>     // open
#define FILE_OFFSET_BITS 64

#include "target.h"
#include "vol.h"
#include "volstd.h"
#include "iscsi.h"
#include "scsi.h"
#include "debug.h"
#include "connection.h"

static pthread_mutex_t PTHREAD_MUTEX_INIT = PTHREAD_MUTEX_INITIALIZER;

void vol_set_volcmd_status(struct volume_cmd *cmd, enum volume_cmd_status status);
enum volume_cmd_status vol_get_volcmd_status(struct volume_cmd *cmd);

#define LOCK_RESERVE(vol) pthread_mutex_lock(&((vol)->lock_reserve))
#define UNLOCK_RESERVE(vol) pthread_mutex_unlock(&((vol)->lock_reserve))

/**
 * Allocate page-buffer memory.
 * @param[in,out] vol            Volume
 * @param[in]     lba            Logical Block Address
 * @param[in]     trans_len      Transfer length (sectors)
 * @param[out]    list_page      List which is containing allocated page-buffer memory.
 * @param[out]    page_totallen  total length (in bytes) of page-buffer.
 * @return                       0 is success. otherwize, failure.
 */
int vol_alloc_buf(
    struct volume *vol,
    uint64 lba,
    uint32 trans_len,
    struct list *list_page,
    uint32 *page_totallen)
{
    uint64 lba_start, lba_end;
    uint32 idx;
    struct page_buffer *page;
    uint32 offset;
    uint32 page_cnt;

    ASSERT((vol != NULL), "vol == NULL\n");
    ASSERT((list_page != NULL), "list_page == NULL\n");
    ASSERT((page_totallen != NULL), "page_totallen == NULL\n");

    // round by page size
    // ToDo : replace these code to adapt changable sector-size.
    lba_start = lba & (~0x7);
    lba_end = lba + trans_len;
    if (lba_end % 8 > 0) {
	lba_end += (8 - (lba_end % 8));
    }
    log_dbg3("lba=%llu(0x%016llX), trans_len="U32_FMT"(0x%08lX)\n",
	    lba, lba, trans_len, trans_len);
    log_dbg3("lba_start=%llu(0x%016llX), lba_end=%llu(0x%016llX)\n",
	    lba_start, lba_start, lba_end, lba_end);

    page_cnt = (lba_end - lba_start) / 8;
    offset = (lba % 8) * 512;
    *page_totallen = trans_len * 512;

    ASSERT(((lba_end - lba_start) % 8 == 0),
	   "(lba_end(%llu) - lba_start(%llu)) % 8 (%llu) > 0\n",
	   lba_end, lba_start, (lba_end - lba_start) % 8);

    log_dbg3("page_cnt = "U32_FMT"\n", page_cnt);
    log_dbg3("offset="U32_FMT", *page_totallen="U32_FMT"\n", offset, *page_totallen);

    page = NULL;
    for (idx = 0; idx < page_cnt; idx++) {
	page = malloc_safe(sizeof(struct page_buffer));
	if (page == NULL) {
	    goto failure;
	}
	listelem_init(&(page->listelem), page);
	list_add_elem(list_page, &(page->listelem));
	if (idx == 0) {
	    page->offset = offset;
	    page->len = PAGE_BUFFER_SIZE - page->offset;
	    if (page->len > *page_totallen) {
		page->len = *page_totallen;
	    }
	} else {
	    page->offset = 0;
	    page->len = PAGE_BUFFER_SIZE;
	    if (PAGE_BUFFER_SIZE * (idx + 1) - offset > *page_totallen) {
		page->len = ((*page_totallen + offset) % PAGE_BUFFER_SIZE);
	    }
	}
	log_dbg3("idx="U32_FMT", page->{offset="U32_FMT", len="U32_FMT"}\n",
		idx, page->offset, page->len);
    }
    ASSERT((page_cnt == list_page->len),
	   "page_cnt("U32_FMT") != list_page->len("U32_FMT")\n",
	   page_cnt, list_page->len);
    return 0;

failure:
    ASSERT((0), "NOT IMPLEMENTED YET!\n");
    return -1;
} // vol_alloc_buf


/**
 * Free page-buffer memory.
 */
int vol_free_buf(
    struct volume *vol,
    struct list *list_page)
{
    struct page_buffer *page;

    log_dbg3("list_page->len = "U32_FMT"\n", list_page->len);
    if (list_is_empty(list_page)) {
	return 0;
    }

    while (1) {
	page = (struct page_buffer *)list_unlist_head_elem(list_page);
	if (page == NULL) {
	    break;
	}
	log_dbg3("page->{len="U32_FMT", offset="U32_FMT"}\n", page->len, page->offset);
	free_safe(page, sizeof(struct page_buffer));
    }
    ASSERT((list_page->head == NULL), "list_page->head(%p) != NULL\n", list_page->head);
    ASSERT((list_page->len == 0), "list_page->len("U32_FMT") > 0\n", list_page->len);

    return 0;
} //vol_free_buf
    

/**
 * Dump volume-thread command.
 */
void vol_dump_cmd(struct volume_cmd *cmd)
{
    log_dbg3("cmd->opcode = 0x%02X\n", cmd->opcode);
    log_dbg3("cmd->lba = %llu(0x%016llX)\n", cmd->lba, cmd->lba);
    log_dbg3("cmd->trans_len = "U32_FMT"(0x%08lX)\n", cmd->trans_len, cmd->trans_len);
    log_dbg3("cmd->conn = %p\n", cmd->conn);
    log_dbg3("cmd->data = %p\n", cmd->data);
    log_dbg3("cmd->fd_ev = %d\n", cmd->fd_ev);

    page_dump_list(&(cmd->list_page), "cmd->list_page");
    log_dbg3("cmd->page_totallen = "U32_FMT"\n", cmd->page_totallen);
    log_dbg3("cmd->result = 0x%02X\n", cmd->result);
    return;
} // vol_dump_cmd


/**
 * Create volume-thread.
 */
struct volume *vol_create(
    struct iscsi_target *target,
    uint64 lun,
    char *pathname,
    enum volume_type type,
    uint64 capacity,    // # of sectors per a volume
    uint32 sector_size, // bytes per a sector
    char *pathname_iotrace, // NULL | pathname of IO-trace file
    void *options)
{
    struct volume *vol = NULL;
    int rv = 0;

    ASSERT((options == NULL), "options != NULL\n"); // NOT SUPPORTED YET

    vol = malloc_safe(sizeof(struct volume));
    if (vol == NULL) {
	log_err("Unable to allocate memory ("U32_FMT" bytes)\n",
		sizeof(struct volume));
	goto failure;
    }
    listelem_init(&(vol->listelem), vol);

    vol->target = target;
    vol->lun = lun;
    vol->type = type;
    vol->capacity = capacity;
    vol->sector_size = sector_size;
    vol->reserve_sid.id64 = 0; // not reserved
    vol->fp_iotrace = NULL;

    vol->lock_list_cmd = PTHREAD_MUTEX_INIT;
    vol->lock_reserve = PTHREAD_MUTEX_INIT;
    pthread_mutex_init(&(vol->lock_list_cmd), NULL);
    pthread_mutex_init(&(vol->lock_reserve), NULL);
    list_init(&(vol->list_cmd));

    strncpy(vol->pathname, pathname, sizeof(vol->pathname));
    if (vol->pathname[sizeof(vol->pathname)-1] != '\0') {
	log_err("Pathname \"%s\" is too long.\n", pathname);
	goto failure;
    }

    if (pathname_iotrace != NULL) {
	strncpy(vol->pathname_iotrace, pathname_iotrace, sizeof(vol->pathname_iotrace));
	if (vol->pathname_iotrace[sizeof(vol->pathname_iotrace)-1] != '\0') {
	    log_err("IO-trace pathname \"%s\" is too long.\n", pathname_iotrace);
	    goto failure;
	}
	vol->fp_iotrace = fopen(vol->pathname_iotrace, "w");
	if (vol->fp_iotrace == NULL) {
	    log_err("Unable to open IO-trace file \"%s\" (errno=%s).",
		    vol->pathname_iotrace, errno);
	    goto failure;
	}
    }

    switch (vol->type) {
    case VOLTYPE_STANDARD:
	rv = volstd_init(vol, options);
	break;
    default:
	ASSERT(0, "NOT SUPPORTED YET\n");
	goto failure;
    }
    log_dbg3("rv=%d\n", rv);
    if (rv) {
	goto failure;
    }

    return vol;

failure:
    if (vol != NULL) {
	if (memcmp(&(vol->lock_list_cmd), &PTHREAD_MUTEX_INIT, sizeof(pthread_mutex_t))) {
	    pthread_mutex_destroy(&(vol->lock_list_cmd));
	}
	if (memcmp(&(vol->lock_reserve), &PTHREAD_MUTEX_INIT, sizeof(pthread_mutex_t))) {
	    pthread_mutex_destroy(&(vol->lock_reserve));
	}
	if (vol->fp_iotrace != NULL) {
	    fclose(vol->fp_iotrace);
	}
	free_safe(vol, sizeof(struct volume));
    }
    return NULL;
} // vol_create


int vol_run(struct volume *vol)
{
    int rv = 0;
    int err;

    rv = pthread_create(&(vol->thread), NULL, vol->ops.exec, vol);
    err = errno;
    if (rv) {
	log_err("Unable to create volume thread (LUN=%llu).\n",
		vol->lun);
	rv = -err;
	goto failure;
    }
    log_dbg3("launched thread (LUN=%llu)\n", vol->lun);

    return 0;

failure:
    return rv;
} // vol_run


/**
 * Check volume reservation
 */
int vol_is_reserved(struct volume *vol, struct iscsi_conn *conn)
{
    int rv;

    if (vol == NULL) {
	return -ENOENT;
    }

    LOCK_RESERVE(vol);
    {
	if (!vol->reserve_sid.id64 ||
	    vol->reserve_sid.id64 == conn->sid.id64) {
	    rv = 0;
	} else {
	    rv = -EBUSY;
	}
    }
    UNLOCK_RESERVE(vol);

    return rv;
} // vol_is_reserved


/**
 * Release volume reservation.
 */
int vol_release(struct volume *vol, struct iscsi_conn *conn, int force)
{
    int rv;
    if (vol == NULL) {
	return -ENOENT;
    }

    LOCK_RESERVE(vol);
    {
	if (force || vol->reserve_sid.id64 == conn->sid.id64) {
	    log_dbg1("Released reservation. (force=%d, reserved:0x%016llX, requested:0x%016llX).\n",
		     force, vol->reserve_sid.id64, conn->sid.id64);
	    vol->reserve_sid.id64 = 0;
	    rv = 0;
	} else {
	    log_info("Cannot release reservation. (reserved:0x%016llX, requested:0x%016llX).\n",
		     vol->reserve_sid.id64, conn->sid.id64);
	    rv = -EBUSY;
	}
    }
    UNLOCK_RESERVE(vol);

    return rv;
} // vol_release


/**
 * Reserve volume.
 */
int vol_reserve(struct volume *vol, struct iscsi_conn *conn)
{
    int rv;

    LOCK_RESERVE(vol);
    {
	if (vol->reserve_sid.id64 &&
	    vol->reserve_sid.id64 != conn->sid.id64) {
	    // Reservation conflict
	    log_info("Reservation conflict occured (reserved:0x%016llX, requested:0x%016llX).\n",
		     vol->reserve_sid.id64, conn->sid.id64);
	    rv = -EBUSY;
	} else {
	    log_dbg1("Reserved (0x%016llX).\n", conn->sid.id64);
	    vol->reserve_sid.id64 = conn->sid.id64;
	    rv = 0;
	}
    }
    UNLOCK_RESERVE(vol);

    return rv;
} // vol_reserve


#define LOCK_VOLCMD_STATUS(cmd) do { pthread_mutex_lock(&(cmd->lock_status)); } while (0)
#define UNLOCK_VOLCMD_STATUS(cmd) do { pthread_mutex_unlock(&(cmd->lock_status)); } while (0)

void vol_set_volcmd_status(
struct volume_cmd *cmd,
enum volume_cmd_status status)
{
    LOCK_VOLCMD_STATUS(cmd);
    {
	cmd->status = status;
    }
    UNLOCK_VOLCMD_STATUS(cmd);
    return;
} // vol_set_volcmd_status


enum volume_cmd_status vol_get_volcmd_status(struct volume_cmd *cmd)
{
    enum volume_cmd_status status;

    LOCK_VOLCMD_STATUS(cmd);
    {
	status = cmd->status;
    }
    UNLOCK_VOLCMD_STATUS(cmd);

    return status;
} // vol_get_volcmd_status


int vol_cancel_cmd(struct volume_cmd *cmd)
{
    struct volume *vol = cmd->vol;
    enum volume_cmd_status status;

    LOCK_LIST_CMD(vol);
    {
	status = vol_get_volcmd_status(cmd);

	log_dbg1("status=%d\n", status);

	switch (status) {
	case VOLCMD_STATUS_QUEUED:
	    ASSERT((list_is_elem_listed(&(vol->list_cmd),
					&(cmd->listelem_vol))),
		   "! list_is_elem_listed(&(vol->list_cmd), &(cmd->listelem_vol))\n");
	    // Delist the command from command queue
	    list_unlist_elem(&(vol->list_cmd), &(cmd->listelem_vol));
	    // Change command status to "cannceled".
	    vol_set_volcmd_status(cmd, VOLCMD_STATUS_CANCELED);
	    break;
	case VOLCMD_STATUS_DOING:
	    ASSERT((!list_is_elem_listed(&(vol->list_cmd),
					 &(cmd->listelem_vol))),
		   "list_is_elem_listed(&(vol->list_cmd), &(cmd->listelem_vol))\n");
	    // Change command status to "cannceled".
	    vol_set_volcmd_status(cmd, VOLCMD_STATUS_CANCELED);
	    // wait for IO completion
	    pthread_cond_t cond_cancel;
	    cmd->cond_cancel = &cond_cancel;
	    pthread_cond_init(cmd->cond_cancel, NULL);
	    pthread_cond_wait(cmd->cond_cancel, &(vol->lock_list_cmd));
	    pthread_cond_destroy(cmd->cond_cancel);
	    log_dbg1("Received canceled I/O completion.\n");
	    break;
	case VOLCMD_STATUS_NULL:
	case VOLCMD_STATUS_CANCELED:
	case VOLCMD_STATUS_DONE:
	    break;
	default:
	    ASSERT((0), "status=%d\n", status);
	    break;
	}
    }
    UNLOCK_LIST_CMD(vol);

    return 0;
} // vol_cancel_cmd


int vol_enqueue_cmd(struct volume_cmd *cmd)
{
    struct volume *vol = NULL;

    vol = cmd->vol;

    ASSERT(vol != NULL, "vol == NULL\n");
    ASSERT(vol->type == VOLTYPE_STANDARD,
	   "vol->type(%d) != VOLTYPE_STANDARD(%d)\n",
	   vol->type, VOLTYPE_STANDARD);

    // enqueue and notify
    listelem_init(&(cmd->listelem_vol), cmd);
    log_dbg3("lock\n");
    LOCK_LIST_CMD(vol);
    {
	// Change command status to "queued".
	vol_set_volcmd_status(cmd, VOLCMD_STATUS_QUEUED);
	// Enqueue command.
	list_add_elem(&(vol->list_cmd), &(cmd->listelem_vol));

	vol->ops.notify(vol);

	log_dbg3("vol->list_cmd.len="U32_FMT"\n", vol->list_cmd.len);
	log_dbg3("sent signal.\n");
    }
    UNLOCK_LIST_CMD(vol);
    log_dbg3("unlock\n");

    return 0;
} // vol_enqueue_cmd


inline void vol_record_start_time(struct volume *vol, struct volume_cmd *vol_cmd)
{
    vol_cmd->time_usec_start = get_time_in_usec();
    return;
} // vol_record_start_time


inline void vol_record_finish_time(struct volume *vol, struct volume_cmd *vol_cmd)
{
    vol_cmd->time_usec_finish = get_time_in_usec();
    return;
} // vol_record_finish_time



/**
 * Flush IO-trace.
 */
int vol_flush_iotrace(struct volume *vol)
{
    if (vol->fp_iotrace == NULL) {
	return 0;
    }
    fflush(vol->fp_iotrace);
    return 0;
} // vol_flush_iotrace


/**
 * Dump IO-trace.
 */
int vol_dump_iotrace(struct volume *vol, struct volume_cmd *vol_cmd)
{
    if (vol->fp_iotrace == NULL) {
	return 0;
    }
    fprintf(vol->fp_iotrace,
	    "0x%016lX, %lu, %lu, 0x%02X, %lu, "U32_FMT"\n",
	    vol_cmd->conn->sid.id64,
	    vol_cmd->time_usec_start,
	    vol_cmd->time_usec_finish,
	    vol_cmd->opcode_scsi,
	    vol_cmd->lba,
	    vol_cmd->trans_len);
    return 0;
} //vol_dump_iotrace


/**
 * Send I/O command completion to iSCSI connection thread.
 * @param[in,out] volcmd   Volume command
 * @param[in]     result   Command result
 */
int vol_send_cmd_completion(struct volume_cmd *volcmd, uint8 result)
{
    struct volume *vol = volcmd->vol;
    int rv;

    LOCK_LIST_CMD(vol);
    {
	enum volume_cmd_status status;
	status = vol_get_volcmd_status(volcmd);

	switch (status) {
	case VOLCMD_STATUS_DOING:
	    vol_set_volcmd_status(volcmd, VOLCMD_STATUS_DONE);
	    rv = iscsi_volcmd_send_completion(volcmd, result);
	    break;
	case VOLCMD_STATUS_CANCELED:
	    log_wrn("IO is canceled (SCSI opcode=0x%02X, LBA=%llu, trans_len="U32_FMT")\n",
		    volcmd->opcode_scsi, volcmd->lba, volcmd->trans_len);
	    pthread_cond_signal(volcmd->cond_cancel);
	    break;
	case VOLCMD_STATUS_NULL:
	case VOLCMD_STATUS_QUEUED:
	case VOLCMD_STATUS_DONE:
	default:
	    ASSERT((0), "status=%d\n", status);
	    break;
	}
    }
    UNLOCK_LIST_CMD(vol);

    return rv;
} // vol_send_cmd_completion


struct volume_cmd *vol_dequeue_cmd(struct volume *vol)
{
    struct volume_cmd *volcmd = NULL;

    volcmd = (struct volume_cmd *)list_unlist_head_elem(&(vol->list_cmd));
    if (volcmd != NULL) {
	ASSERT((volcmd->status == VOLCMD_STATUS_QUEUED),
	       "volcmd->status != VOLCMD_STATUS_QUEUED\n");

	// Change command status to "cannceled".
	vol_set_volcmd_status(volcmd, VOLCMD_STATUS_DOING);

	page_dump_list(&(volcmd->list_page), "volcmd->list_page");
    }

    return volcmd;
} // vol_dequeue_cmd


inline void page_dump_list(struct list *list, char *listname)
{
    struct page_buffer *page;

    struct page_buffer *page_pre;

    ASSERT((list != NULL), "list == NULL\n");
    if (list_is_empty(list)) {
	log_dbg3("list \"%s\" has no elements.\n", listname);
    } else {
	log_dbg3("list \"%s\" has "U32_FMT" elements.\n", listname, list->len);
	page_pre = NULL;
	do_each_list_elem (struct page_buffer *, list, page, listelem) {
	    log_dbg3("&(page->listelem)=%p\n", &(page->listelem));
	    log_dbg3("page->listelem.next=%p\n", page->listelem.next);
	    log_dbg3("page->listelem.prev=%p\n", page->listelem.prev);
	    ASSERT((page_pre != page), "page_pre == page");
	    log_dbg3("page=%p\n", page);
	    log_dbg3("  buf=%p\n", page->buf);
	    log_dbg3("  offset="U32_FMT"\n", page->offset);
	    log_dbg3("  len="U32_FMT"\n", page->len);
	    page_pre = page;
	} while_each_list_elem (struct page_buffer *, list, page, listelem);
    }
    return;
} // page_dump_list


void vol_init_volcmd(
    struct volume *vol,
    struct volume_cmd *volcmd,
    struct iscsi_conn *conn,
    struct scsi_cmd *scsicmd,
    struct list *list_page,
    uint32 page_totallen,
    void *data)
{
    switch (scsicmd->opcode) {
    case SCSI_OP_WRITE_10:
	volcmd->opcode = VOLUME_OP_WRITE;
	break;
    case SCSI_OP_READ_10:
	volcmd->opcode = VOLUME_OP_READ;
	break;
    default:
	ASSERT((0), "scsicmd->opcode = 0x%02X\n", scsicmd->opcode);
	break;
    }
    listelem_init(&(volcmd->listelem_conn), volcmd);
    listelem_init(&(volcmd->listelem_vol), volcmd);

    volcmd->vol = vol;
    volcmd->conn = conn;
    volcmd->fd_ev = conn->fd_ev;
    volcmd->result = VOLCMD_RESULT_NULL;

    pthread_mutex_init(&(volcmd->lock_status), NULL);
    volcmd->status = VOLCMD_STATUS_NULL;

    volcmd->opcode_scsi = scsicmd->opcode;
    volcmd->lba = scsicmd->lba;
    volcmd->trans_len = scsicmd->trans_len;

    list_init(&(volcmd->list_page));
    if (list_page != NULL) {
	(volcmd->list_page) = *list_page;
    }
    volcmd->page_totallen = page_totallen;
    volcmd->data = data;

#if defined __DEBUG
    page_dump_list(&(volcmd->list_page), "volcmd->list_page");
#endif

    return;
} // vol_init_volcmd


int vol_does_cache_wr(struct volume *vol)
{
    // tempolary implementation.
    return 1;
} // vol_does_cache_wr


int vol_does_cache_rd(struct volume *vol)
{
    // tempolary implementation.
    return 0;
} // vol_does_cache_rd


int vol_sync_cache(struct volume *vol, uint64 lba, uint32 len, int sync_nv, int immed)
{
    return vol->ops.sync_cache(vol, lba, len, sync_nv, immed);
} // vol_sync_cache
