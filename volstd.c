#include <pthread.h>
#include <errno.h>
#include <string.h> // memcpy
#include <sys/types.h> // open, llseek
#include <fcntl.h>     // open
#include <sys/stat.h>  // open
#include <unistd.h>    // llseek

#include "volstd.h"
#include "vol.h"
#include "iscsi.h"
#include "scsi.h"
#include "connection.h"

struct volume_standard {
    struct volume *vol;
    pthread_cond_t cond_cmdq;

    int fd; // file descriptor
}; // volume_standard


static pthread_cond_t PTHREAD_COND_INIT = PTHREAD_COND_INITIALIZER;

void *volstd_exec(void *arg);
int volstd_notify(struct volume *vol);
int volstd_alloc_bufvec(struct volume *vol, uint64 lba, uint32 len, struct buffer_vec **dsvec, uint32 *dsvec_cnt);
int volstd_free_bufvec(struct volume *vol, struct buffer_vec *dsvec, uint32 dsvec_cnt);

static int exec_read(struct volume_standard *volstd, struct volume_cmd *cmd);
static int exec_write(struct volume_standard *volstd, struct volume_cmd *cmd);

int volstd_sync_cache(
    struct volume *vol,
    uint64 lba,
    uint32 len,
    int sync_nv,
    int immed)
{
    // not implemented yet
    return 0;
} // volstd_sync_cache


int volstd_init(struct volume *vol, void *options)
{
    struct volume_standard *volstd = NULL;
    int rv = 0;
    int err = 0;

    vol->ops.notify = &volstd_notify;
    vol->ops.exec = &volstd_exec;
    vol->ops.sync_cache = &volstd_sync_cache;

    volstd = malloc_safe(sizeof(struct volume_standard));
    if (volstd == NULL) {
	log_err("Unable to allocate memory ("U32_FMT" bytes).\n",
		sizeof(struct volume_standard));
	rv = -ENOMEM;
	goto failure;
    }
    volstd->cond_cmdq = PTHREAD_COND_INIT;

    volstd->fd = 0;

    ASSERT((vol->ext == NULL), "vol->ext(%p) != NULL\n", vol->ext);
    vol->ext = volstd;

    volstd->vol = vol;
    
    pthread_cond_init(&(volstd->cond_cmdq), NULL);

    log_dbg3("Open/Create file \"%s\"\n", vol->pathname);
    volstd->fd = open(vol->pathname,
		      O_CREAT|O_SYNC|O_RDWR,
		      S_IRUSR | S_IWUSR);
//    volstd->fd = open(vol->pathname, O_CREAT|O_RDWR);
    err = errno;
    log_dbg3("volstd->fd=%d, errno=%d\n", volstd->fd, err);
    if (volstd->fd == -1) {
	log_err("Unable to open file \"%s\" (errno=%d)\n",
		vol->pathname, err);
	rv = err;
	goto failure;
    }

    return 0;

failure:
    if (volstd != NULL) {
	if (memcmp(&(volstd->cond_cmdq), &PTHREAD_COND_INIT, sizeof(pthread_cond_t))) {
	    pthread_cond_destroy(&(volstd->cond_cmdq));
	}
	if (volstd->fd) {
	    close(volstd->fd);
	}
	free_safe(volstd, sizeof(struct volume_standard));
	volstd = NULL;
    }
     return rv;
} // volstd_init


int volstd_notify(struct volume *vol)
{
    ASSERT((vol != NULL), "vol == NULL\n");
    
    struct volume_standard *volstd;
    volstd = (struct volume_standard *)vol->ext;

    pthread_cond_signal(&(volstd->cond_cmdq));

    return 0;
} // volstd_notify


void *volstd_exec(void *arg)
{
    struct volume *vol;
    struct volume_standard *volstd;
    struct volume_cmd *cmd = NULL;
    
    vol = (struct volume *)arg;

    ASSERT(vol != NULL, "vol == NULL\n");
    ASSERT(vol->type == VOLTYPE_STANDARD,
	   "vol->type(%d) != VOLTYPE_STANDARD(%d)\n",
	   vol->type, VOLTYPE_STANDARD);
    volstd = (struct volume_standard *)vol->ext;

    log_dbg3("lock\n");
    LOCK_LIST_CMD(vol);
    {
loop:
	cmd = vol_dequeue_cmd(vol);
	log_dbg3("cmd=%p\n", cmd);
	if (cmd == NULL) {
	    log_dbg3("sleep...\n");
	    // wait for enqueue notification
	    pthread_cond_wait(&(volstd->cond_cmdq), &(vol->lock_list_cmd));
	    // dequeue
	    log_dbg3("wakeup.\n");
	    goto loop;
	}
    }
    UNLOCK_LIST_CMD(vol);
    log_dbg3("unlock\n");

#ifdef __DEBUG
    vol_dump_cmd(cmd);
#endif // __DEBUG

    int rv = 0;

    vol_record_start_time(vol, cmd);

    switch (cmd->opcode) {
    case VOLUME_OP_READ:
	rv = exec_read(volstd, cmd);
	break;
    case VOLUME_OP_WRITE:
	rv = exec_write(volstd, cmd);
	break;
    default:
	ASSERT(0, "NOT IMPLEMENTED YET\n");
	abort();
    }

    vol_record_finish_time(vol, cmd);

    vol_dump_iotrace(vol, cmd);

    if (rv) {
	goto failure;
    }

    rv = vol_send_cmd_completion(cmd, VOLCMD_RESULT_SUCCESS);
    if (rv) {
	goto failure;
    }

    goto loop;

failure:
    return NULL;
} // volstd_exec


int volstd_alloc_bufvec(struct volume *vol, uint64 lba, uint32 len, struct buffer_vec **dsvec, uint32 *dsvec_cnt)
{
    int rv = 0;

    *dsvec = NULL;
    *dsvec_cnt = 1;

    *dsvec = malloc_safe(sizeof(struct buffer_vec));
    if (*dsvec == NULL) {
	rv = -ENOMEM;
	log_err("Unable to allocate memory ("U32_FMT" bytes).\n",
		sizeof(struct buffer_vec));
	goto failure;
    }

    (*dsvec)->buflen = len * vol->sector_size;
    (*dsvec)->buf = malloc_safe((*dsvec)->buflen);
    if ((*dsvec)->buf == NULL) {
	rv = -ENOMEM;
	log_err("Unable to allocate memory ("U32_FMT" bytes).\n",
		(*dsvec)->buflen);
	goto failure;
    }
    (*dsvec)->offset = 0;
    (*dsvec)->len = (*dsvec)->buflen;

    return 0;

failure:
    if (*dsvec != NULL) {
	if ((*dsvec)->buf != NULL) {
	    free_safe((*dsvec)->buf, (*dsvec)->buflen);
	}
	free_safe(*dsvec, sizeof(struct buffer_vec));
    }
    *dsvec = NULL;
    *dsvec_cnt = 0;
    return rv;
} // volstd_alloc_bufvec


int volstd_free_bufvec(struct volume *vol, struct buffer_vec *dsvec, uint32 dsvec_cnt)
{
    return 0;
} // volstd_free_bufvec


int exec_write(struct volume_standard *volstd, struct volume_cmd *cmd)
{
    struct volume *vol;
    ssize_t wrlen;
    int err;
    int rv;
    uint64 offset;
    loff_t off;
    struct page_buffer *page;
    struct iovecs iovs;

    ASSERT((volstd != NULL), "volstd == NULL\n");
    ASSERT((cmd != NULL), "cmd == NULL\n");
    ASSERT((!list_is_empty(&(cmd->list_page))), "cmd->list_page is empry.\n");

    vol = volstd->vol;

    ASSERT((cmd->trans_len * vol->sector_size == cmd->page_totallen),
	   "cmd->trans_len("U32_FMT") * vol->sector_size("U32_FMT") != cmd->page_totallen("U32_FMT")\n",
	   cmd->trans_len, vol->sector_size, cmd->page_totallen);

    offset = (cmd->lba * vol->sector_size);
    log_dbg3("offset=%llu(0x%016llX)\n", offset, offset);

    off = llseek(volstd->fd, offset, SEEK_SET);
    if (off == -1) {
	rv = -1;
	goto failure;
    }

    iovec_init(&iovs);
    do_each_list_elem(struct page_buffer *, &(cmd->list_page), page, listelem) {
	iovec_add(&iovs, &(page->buf[page->offset]), page->len);
    } while_each_list_elem(struct page_buffer *, &(cmd->list_page), page, listelem);

retry:
    wrlen = writev(volstd->fd, iovs.vec, iovs.cnt);
    err = errno;

    log_dbg3("iovs.cnt=%d, iovs.len=%ld\n", iovs.cnt, iovs.len);
    log_dbg3("wrlen=%d, errno=%d\n", wrlen, err);

    if (wrlen == -1) {
	if (err == EINTR) {
	    log_dbg3("inturrupted.\n");
	    goto retry;
	}
	log_err("Unable to write. (errno=%d)\n", err);
	rv = -err;
	goto failure;
    }

    // Rewind a vector-IO buffer.
    iovec_rewind(&iovs, wrlen);
    if (iovs.len > 0) {
	log_dbg3("Continue to write these data (iovs.len(%ld) > 0).\n)",
		iovs.len);
	goto retry;
    }

#ifdef __DEBUG
    log_dbg3("cmd->lba=%llu(0x%016llX), cmd->trans_len="U32_FMT"(0x%08lX)\n",
	    cmd->lba, cmd->lba, cmd->trans_len, cmd->trans_len);
//    print_hex(cmd->dsvec[0].buf, cmd->dsvec[0].buflen);
#endif    

    return 0;

failure:
    return rv;
} // exec_write


int exec_read(struct volume_standard *volstd, struct volume_cmd *cmd)
{
    struct volume *vol;
    ssize_t rdlen;
    int err;
    int rv;
    uint64 offset;
    loff_t off;
    struct page_buffer *page;
    struct iovecs iovs;

    ASSERT((volstd != NULL), "volstd == NULL\n");
    ASSERT((cmd != NULL), "cmd == NULL\n");

    vol = volstd->vol;

    rv = vol_alloc_buf(vol, cmd->lba, cmd->trans_len,
		       &(cmd->list_page), &(cmd->page_totallen));
    if (rv) {
	goto failure;
    }

    ASSERT((cmd->trans_len * vol->sector_size == cmd->page_totallen),
	   "cmd->trans_len("U32_FMT") * vol->sector_size("U32_FMT") != cmd->page_totallen("U32_FMT")\n",
	   cmd->trans_len, vol->sector_size, cmd->page_totallen);

    offset = (cmd->lba * vol->sector_size);
    log_dbg3("offset=%llu(0x%016llX)\n", offset, offset);

    off = llseek(volstd->fd, offset, SEEK_SET);
    if (off == -1) {
	rv = -1;
	goto failure;
    }

    iovec_init(&iovs);
    
    page_dump_list(&(cmd->list_page), "cmd->list_page");

    do_each_list_elem(struct page_buffer *, &(cmd->list_page), page, listelem) {
	iovec_add(&iovs, &(page->buf[page->offset]), page->len);
    } while_each_list_elem(struct page_buffer *, &(cmd->list_page), page, listelem);

retry:
    rdlen = readv(volstd->fd, iovs.vec, iovs.cnt);
    err = errno;

    log_dbg3("iovs.cnt=%d, iovs.len=%ld\n", iovs.cnt, iovs.len);
    log_dbg3("rdlen=%d, errno=%d\n", rdlen, err);

    if (rdlen == -1) {
	if (err == EINTR) {
	    log_dbg3("inturrupted.\n");
	    goto retry;
	}
	log_err("Unable to read. (errno=%d)\n", err);
	rv = -err;
	goto failure;
    }
    // Rewind a vector-IO buffer.
    iovec_rewind(&iovs, rdlen);

    if (iovs.len > 0 && !(rdlen == 0 && err == 0)) {
	log_dbg3("Continue to read data (iovs.len(%ld) > 0).\n)",
		iovs.len);
	goto retry;
    }

#ifdef __DEBUG
    log_dbg3("cmd->lba=%llu(0x%016llX), cmd->trans_len="U32_FMT"(0x%08lX)\n",
	    cmd->lba, cmd->lba, cmd->trans_len, cmd->trans_len);
//    print_hex(cmd->dsvec[0].buf, cmd->dsvec[0].buflen);
#endif    

    return 0;

failure:
    return rv;
} // exec_read
