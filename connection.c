/*
 * SISO : Simple iSCSI Storage
 * 
 * iSCSI connection thread.
 *
 * Copyright(C) 2012 Makoto KOBARA <makoto.kobara _at_ gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <string.h> // memset
#include <netdb.h>
#include <sys/epoll.h>   // epoll_*
#include <sys/eventfd.h> // eventfd
#include <unistd.h> // fcntl
#include <fcntl.h>  // fcntl
#include <stdarg.h> // va_start, va_end
#include <assert.h>
#include "connection.h"
#include "iscsi.h"
#include "target.h"
#include "misc.h"
#include "scsi.h"
#include "vol.h"
#include "login.h"
#include "siso.h"

static void *connection_main(void *arg);

static int iscsi_exec_rx(struct iscsi_conn *conn);
static int iscsi_exec_tx(struct iscsi_conn *conn);
static int iscsi_exec_notify(struct iscsi_conn *conn);
static int connection_handle_rx(struct iscsi_conn *conn, struct iscsi_pdu *pdu);

static int exec_text_req(struct iscsi_conn *conn, struct iscsi_pdu *pdu);
static int pack_sendtargets(struct iscsi_conn *conn, struct iscsi_pdu *pdu_rsp);

static int exec_logout_req(struct iscsi_conn *conn, struct iscsi_pdu *pdu);
static int exec_scsidata_out(struct iscsi_conn *conn, struct iscsi_pdu *pdu);
static int exec_nop_out(struct iscsi_conn *conn, struct iscsi_pdu *pdu);

static struct iscsi_pdu *create_text_rsp(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req);
static struct iscsi_pdu *create_logout_rsp(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req);
static struct iscsi_pdu *create_nop_in(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req);

static struct iscsi_conn *create_connection(
    struct siso_info *siso,
    int fd,
    struct sockaddr_storage *cli_addr,
    socklen_t cli_addr_len);

struct iscsi_conn *iscsi_conn_create_and_launch(
    struct siso_info *siso,
    int fd,
    struct sockaddr_storage *cli_addr,
    socklen_t cli_addr_len)
{
    int ret;

    struct iscsi_conn *conn;

    conn = create_connection(siso, fd, cli_addr, cli_addr_len);
    if (conn == NULL) {
	log_err("Unable to create iSCSI connection.\n");
	return NULL;
    }

    ret = pthread_create(&(conn->thread), NULL, connection_main, conn);
    if (ret < 0) {
	log_err("Unable to create server_main. (%d).\n", errno);
	return NULL;
    }

    return conn;
// ToDo error handling
} // iscsi_conn_create_and_launch


int iscsi_close_connection(struct iscsi_conn *conn)
{
    ASSERT((conn->siso != NULL), "conn->siso == NULL\n"); 

    int rv = 0;
    struct siso_info *siso = NULL;

    siso = conn->siso;

    log_dbg1("conn->session=%p\n", conn->session);
    log_dbg1("conn->target=%p\n", conn->target);

    if (conn->session != NULL) {
	// This connection is already attached session.
	// so remove connection by target.
	ASSERT((conn->target != NULL), "conn->target == NULL\n");
	rv = iscsi_unbind_connection(conn);
//	siso_attach_connection(siso, conn);
    } else {
	// This connection is not attached session yet,
	// so remove connection directory.
	ASSERT((conn->target == NULL), "conn->target != NULL\n");
    }
    conn->stage = ISCSI_STAGE_FINISH;

    return rv;
} // iscsi_close_connection


int iscsi_destroy_connection(struct iscsi_conn *conn)
{
    ASSERT((conn->stage == ISCSI_STAGE_FINISH),
	   "conn->stage != ISCSI_STAGE_FINISH\n");

    struct iscsi_target *target = NULL;
    struct siso_info *siso = NULL;

    target = conn->target;
    siso = conn->siso;

    if (conn->fd_sock) {
	close(conn->fd_sock);
	conn->fd_sock = 0;
    }
    if (conn->fd_ep) {
	close(conn->fd_ep);
	conn->fd_ep = 0;
    }

    // detach from connection list.
    siso_detach_connection(siso, conn);

//    log_dbg3("target->list_conn.len = "U32_FMT"\n", target->list_conn.len);

    free(conn);

    return 0;
} // iscsi_destroy_connection 


static int iscsi_add_pdu_to_iovec(struct iscsi_conn *conn, struct iscsi_pdu *pdu)
{
    int i;
    uint32 padlen;

    ASSERT((conn->iov_tx.len == 0), "conn->iov_tx.len("U32_FMT") > 0\n", conn->iov_tx.len);

    iovec_init(&(conn->iov_tx));
    iovec_add(&(conn->iov_tx), &(pdu->bhs), ISCSI_PDU_BHSLEN);
    for (i = 0; i < pdu->dsvec_cnt; i++) {
	ASSERT((pdu->dsvec[i].offset + pdu->dsvec[i].len <= pdu->dsvec[i].buflen),
	       "pdu->dsvec["U32_FMT"].offset("U32_FMT") + pdu->dsvec["U32_FMT"].len("U32_FMT") <= pdu->dsvec["U32_FMT"].buflen("U32_FMT")\n",
	       i, pdu->dsvec[i].offset,
	       i, pdu->dsvec[i].len,
	       i, pdu->dsvec[i].buflen);
	iovec_add(&(conn->iov_tx),
		  pdu->dsvec[i].buf + pdu->dsvec[i].offset,
		  pdu->dsvec[i].len);
    }

    if (pdu->dslen % 4 > 0) {
	padlen = 4 - (pdu->dslen % 4);
	iovec_add(&(conn->iov_tx), conn->dspad_tx, padlen);
    }
    return 0;
} // iscsi_add_pdu_to_iovec


int iscsi_enqueue_and_tx_pdu(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu)
{
    int rv;

    // pack iSCSI PDU parameters to BHS buffer.
    iscsi_set_sn(conn, pdu);
    iscsi_pack_pdu(conn, pdu);

    log_dbg3("Enqueue PDU to TX queue.\n");

#ifdef __DEBUG
    iscsi_dump_pdu(conn, pdu);
    iscsi_dump_pdu_in_hex(conn, pdu);
#endif


    // Add PDU to TX queue(list),
    // and to IOVec if this PDU is head of TX queue.
    if (list_is_empty(&(conn->list_pdu_tx))) {
	iscsi_add_pdu_to_iovec(conn, pdu);
    }
    list_add_elem(&(conn->list_pdu_tx), &(pdu->listelem_rxtx));

    log_dbg3("Add PDU to TX queue (opcode=0x%02X, ITT=0x%08lX, conn->list_pdu_tx.len="U32_FMT").\n",
	    pdu->opcode, pdu->itt, conn->list_pdu_tx.len);

    rv = iscsi_exec_tx(conn);
    log_dbg3("rv = %d\n", rv);
    if (rv == -1) {
	log_dbg3("rv == -1\n");
	goto failure;
    }

    return 0;
failure:
    return -1;
} // iscsi_enqueue_and_tx_pdu


static int iscsi_exec_tx(struct iscsi_conn *conn)
{
    struct iscsi_pdu *pdu = NULL;
    struct epoll_event *ev = NULL;
    int txlen = 0;
    int err = 0;
    int rv = 0;

    ASSERT(conn->iov_tx.cnt > 0, "conn->iov_tx.cnt == 0\n");
    ASSERT(conn->iov_tx.len > 0, "conn->iov_tx.len == 0\n");

    ev = &(conn->event[EVENT_SOCKET]);
    pdu = (struct iscsi_pdu *)list_ref_head_elem(&(conn->list_pdu_tx));
    ASSERT((pdu != NULL), "pdu == NULL\n");

next:
    log_dbg3("send PDU (opcode=0x%02X, ITT=0x%08lX\n",
	    pdu->opcode, pdu->itt);

#ifdef __DEBUG
    int idx;
    iscsi_dump_pdu(conn, pdu);
    iscsi_dump_pdu_in_hex(conn, pdu);
    log_dbg3("conn->iov_tx.{cnt="U32_FMT", len="U32_FMT"}\n",
	    conn->iov_tx.cnt, conn->iov_tx.len);
    for (idx = 0; idx < conn->iov_tx.cnt; idx++) {
	log_dbg3("conn->iov_tx.vec[%d].base=%p\n", idx, conn->iov_tx.vec[idx].iov_base);
	log_dbg3("conn->iov_tx.vec[%d].len=%d\n", idx, conn->iov_tx.vec[idx].iov_len);
    }
#endif

    // Send and error handling
    txlen = writev(conn->fd_sock, conn->iov_tx.vec, conn->iov_tx.cnt);
    err = errno;
    log_dbg3("txlen=%d, err=%d\n", txlen, err);
    if (txlen == -1) {
	if (err == EINTR) {
	    log_dbg3("Inturrupted.\n");
	    goto next;
	} else if (err == EAGAIN || err == EWOULDBLOCK) {
	    // non-blocking "writev" is blocked, so wait.
	    log_dbg3("non-blocking \"writev\" is blocked\n");
	    if (!(ev->events & EPOLLOUT)) {
		// start event-polling
		ev->events |= EPOLLOUT;
		rv = epoll_ctl(conn->fd_ep, EPOLL_CTL_MOD, conn->fd_sock, ev);
		if (rv) {
		    err = errno;
		    log_err("Unable to epoll_ctl (err=%d).\n", err);
		    goto failure;
		}
	    }
	    return conn->iov_tx.len;
	} else {
	    log_err("Unable to write (%d, %d).\n", txlen, err);
	    return -err;
	}
    }

    // Rewind a vector-IO buffer.
    iovec_rewind(&(conn->iov_tx), txlen);
    if (conn->iov_tx.len > 0) {
	// Continue to send this PDU
	log_dbg3("Continue to send this PDU (conn->iov_tx.len(%ld) > 0).\n",
		conn->iov_tx.len);
	goto next;
    }

    list_unlist_elem(&(conn->list_pdu_tx), &(pdu->listelem_rxtx));
    log_dbg3("Completed to send this PDU (opode=0x%02X, ITT=0x%08lX)\n",
	    pdu->opcode, pdu->itt);

    log_dbg3("pdu->opcode=0x%02X, pdu->Sbit=%d\n", pdu->opcode, pdu->Sbit);
    if (pdu->opcode != ISCSI_OP_R2T &&
	pdu->opcode != ISCSI_OP_SCSI_DATA_OUT &&
	!(pdu->opcode == ISCSI_OP_SCSI_DATA_IN && !pdu->Sbit)) {
	log_dbg3("Remove task\n");
	iscsi_remove_task(conn, pdu->task);
    } else {
	log_dbg3("Do not remove task\n");
    }
    pdu = NULL;

    if (conn->stage == ISCSI_STAGE_CLOSE) {
	log_dbg1("conn->stage == ISCSI_STAGE_CLOSE\n");
	iscsi_close_connection(conn);
//	conn->stage = ISCSI_STAGE_FINISH;
	goto succeed;
    }

    if (! list_is_empty(&(conn->list_pdu_tx))) {
	// Continue to send next PDU (TX queue is using)
	pdu = (struct iscsi_pdu *)list_ref_head_elem(&(conn->list_pdu_tx));
	iscsi_add_pdu_to_iovec(conn, pdu);
	log_dbg3("Continue to send next PDU (conn->list_pdu_tx.len="U32_FMT").\n",
		conn->list_pdu_tx.len);
	goto next;
    }

    // Complete to send all PDUs (TX queue is empty)
    ASSERT(conn->list_pdu_tx.len == 0, "conn->list_pdu_tx.len("U32_FMT") > 0\n", conn->list_pdu_tx.len);
    if (ev->events & EPOLLOUT) {
	// stop event-polling
	ev->events &= (~EPOLLOUT);
	rv = epoll_ctl(conn->fd_ep, EPOLL_CTL_MOD, conn->fd_sock, ev);
	if (rv) {
	    err = errno;
	    log_err("Unable to epoll_ctl (err=%d).\n", err);
	    goto failure;
	}
    }
    log_dbg3("Complete to send all of PDUs.\n");

succeed:
    return 0;

failure:
    return -1;
} // iscsi_exec_tx


int iscsi_cancel_all_volcmd(struct iscsi_conn *conn)
{
    struct volume_cmd *volcmd = NULL;

    LOCK_LIST_VOLCMD(conn);
    {
	while (1) {
	    volcmd = (struct volume_cmd *)list_unlist_head_elem(&(conn->list_volcmd));
	    if (volcmd == NULL) {
		break;
	    }
	    vol_cancel_cmd(volcmd);
	}
    }
    UNLOCK_LIST_VOLCMD(conn);
    return 0;
}  // iscsi_cancel_all_volcmd

int iscsi_volcmd_send_completion(struct volume_cmd *volcmd, uint8 result)
{
    struct iscsi_conn *conn;

    ASSERT((volcmd != NULL), "volcmd == NULL\n");

    conn = volcmd->conn;

    LOCK_LIST_VOLCMD(conn);
    {
	volcmd->result = result;
#ifdef __DEBUG
	vol_dump_cmd(volcmd);
#endif
    }
    UNLOCK_LIST_VOLCMD(conn);
    
    log_dbg3("Send event to iSCSI connection thread.\n");
    unsigned long val;
    val = 1;
    write(conn->fd_ev, &val, sizeof(val));

    return 0;
} // iscsi_volcmd_send_completion


struct volume_cmd *iscsi_volcmd_completion(struct iscsi_conn *conn)
{
    struct volume_cmd *volcmd = NULL;
    struct volume_cmd *volcmd_comp = NULL;

    volcmd_comp = NULL;

    LOCK_LIST_VOLCMD(conn);
    {
	log_dbg3("conn->list_volcmd.len = %d\n", conn->list_volcmd.len);

	if (! list_is_empty(&(conn->list_volcmd)) ) {
	    do_each_list_elem(struct volume_cmd *, &(conn->list_volcmd), volcmd, listelem_conn) {
		log_dbg3("volcmd->result = 0x%02X\n", volcmd->result);
		if (volcmd->result != VOLCMD_RESULT_NULL) {
		    volcmd_comp = volcmd;
		    break;
		}
	    } while_each_list_elem(struct volume_cmd *, &(conn->list_volcmd), volcmd, listelem_conn);
	    
	    log_dbg3("volcmd_comp = %p\n", volcmd_comp);
	    if (volcmd_comp != NULL) {
		list_unlist_elem(&(conn->list_volcmd), &(volcmd->listelem_conn));
	    }
	}
    }
    UNLOCK_LIST_VOLCMD(conn);

    return volcmd_comp;
} // iscsi_volcmd_completion


int iscsi_free_volcmd(struct iscsi_conn *conn, struct volume_cmd *volcmd)
{
    free_safe(volcmd, sizeof(struct volume_cmd));
    return 0;
} // iscsi_free_volcmd


static int iscsi_exec_notify(struct iscsi_conn *conn)
{
    struct volume_cmd *volcmd;
    unsigned long val = 0;
    int err = 0;
    int rv;
    struct iscsi_pdu *pdu_req;

retry:
    rv = read(conn->fd_ev, &val, sizeof(val));
    err = errno;
    log_dbg3("rv=%d, err=%d\n", rv, err);
    if (rv == -1) {
	if (err == EINTR) {
	    goto retry;
	}
	rv = -err;
	goto failure;
    }

    while (1) {
	volcmd = iscsi_volcmd_completion(conn);

	log_dbg3("volcmd = %p\n", volcmd);

	if (volcmd == NULL) {
	    break;
	}
	vol_dump_cmd(volcmd);
	pdu_req = (struct iscsi_pdu *)volcmd->data;
	ASSERT((pdu_req != NULL), "pdu_req == NULL");
	ASSERT((pdu_req->opcode == ISCSI_OP_SCSI_CMD),
	       "pdu_req->opcode(0x%02X) != ISCSI_OP_SCSI_CMD(0x%02X)\n",
	       pdu_req->opcode, ISCSI_OP_SCSI_CMD);
	iscsi_dump_pdu(conn, pdu_req);
	    
	rv = iscsi_exec_scsi_cmd_completion(conn, pdu_req, volcmd);

	iscsi_free_volcmd(conn, volcmd);
	
	if (rv) {
	    ASSERT((0), "NOT IMPLEMENTED YET!\n");
	}
    }
    log_dbg3("There are no completed disk-IO commands.");

    return 0;

failure:
    return rv;
} // iscsi_exec_notify


static int iscsi_exec_rx(struct iscsi_conn *conn)
{
    uint32 idx;
    int err;
    int rxlen;
    struct iscsi_pdu *pdu = NULL;
    int rv;

retry:
    // Initialize
    if (conn->state_rx == SOCKIO_BHS_INIT) {

	log_dbg3("Create iSCSI PDU.\n");

	pdu = conn->pdu_rx = iscsi_create_pdu(conn);
	if (pdu == NULL) {
	    return -1;
	}
	log_dbg3("pdu->bhs=%p\n", &(pdu->bhs));
	iovec_init(&(conn->iov_rx));
	iovec_add(&(conn->iov_rx), &(pdu->bhs), ISCSI_PDU_BHSLEN);
	conn->state_rx = SOCKIO_BHS_RXTX;
    } else {
	log_dbg3("Use iSCSI PDU.\n");
	pdu = conn->pdu_rx;
    }
    ASSERT(conn->pdu_rx != NULL, "conn->pdu_rx == NULL\n");
    ASSERT(pdu != NULL, "pdu == NULL\n");

    // Receive and error handling
    rxlen = readv(conn->fd_sock, conn->iov_rx.vec, conn->iov_rx.cnt);
    err = errno;

    log_dbg3("conn->iov_rx.cnt=%d, conn->iov_rx.len=%ld\n",
	    conn->iov_rx.cnt, conn->iov_rx.len);
    log_dbg3("rxlen=%d, errno=%d\n",
	    rxlen, err);

    if (rxlen == 0) {
	log_dbg3("non-blocking \"readv\" is blocked\n");
	return conn->iov_rx.len;
    } else if (rxlen == -1) {
	if (err == EAGAIN || err == EWOULDBLOCK) {
	    // non-blocking "readv" is blocked, so wait.
	    log_dbg3("non-blocking \"readv\" is blocked\n");
	    rv = conn->iov_rx.len;
	    goto done;
	} else if (err == EINTR) {
	    log_dbg3("inturrupted.\n");
	    goto retry;
	}
	log_err("Unable to read (%d, %d).\n", rxlen, err);
	rv = -err;
	goto failure;
    }

    // Rewind a vector-IO buffer.
    iovec_rewind(&(conn->iov_rx), rxlen);
    if (conn->iov_rx.len > 0) {
	log_dbg3("conn->iov_rx.len(%ld) > 0\n", conn->iov_rx.len);
	goto retry;
    }

    struct iscsi_task *task;

    switch (conn->state_rx) {
    case SOCKIO_BHS_NULL:
	ASSERT(0, "conn->state_rx = SOCKIO_BHS_NULL\n");
	break;
    case SOCKIO_BHS_INIT:
	ASSERT(0, "conn->state_rx = SOCKIO_BHS_INIT\n");
	break;
    case SOCKIO_BHS_RXTX:
	log_dbg3("conn->state_rx = SOCKIO_BHS_RXTX\n");
	ASSERT(conn->iov_rx.cnt == 0,
	       "conn->iov_rx.cnt(%d) > 0\n", conn->iov_rx.cnt);

	iscsi_dump_pdu_in_hex(conn, pdu);
	iscsi_unpack_pdu(conn, pdu);
	log_dbg3("Received PDU's BHS (opcode=0x%02X, ITT=0x%08X, DSlen="U32_FMT").\n",
		pdu->opcode, pdu->itt, pdu->dslen);
	iscsi_dump_pdu(conn, pdu);

	task = iscsi_search_task(conn, pdu->itt);
	if (task == NULL) {
	    log_dbg3("Not found an iSCSI task(ITT=0x%08X), so create new one\n",
		    pdu->itt);
	    task = iscsi_create_task(conn, pdu->itt);
	    task->vol = pdu->vol;
	} else {
	    log_dbg3("Found an iSCSI task(ITT=0x%08X)\n",
		    pdu->itt);
	}
	log_dbg3("Add the PDU(opcode=0x%02X) to the task(ITT=0x%08X).\n",
		pdu->opcode, pdu->itt);
	iscsi_add_pdu_to_task(conn, task, pdu);

	if (pdu->opcode != ISCSI_OP_SCSI_DATA_OUT) {
	    conn->expcmdsn = pdu->cmdsn + (pdu->Ibit ? 0 : 1);
	}

	log_dbg3("init\n");
	iovec_init(&(conn->iov_rx));
	conn->state_rx = SOCKIO_AHS_INIT;
	// Do not break here
    case SOCKIO_AHS_INIT:
	log_dbg3("conn->state_rx = SOCKIO_AHS_INIT\n");
	conn->state_rx = SOCKIO_DS_INIT;
	// Do not break here
    case SOCKIO_DS_INIT:
	log_dbg3("conn->state_rx = SOCKIO_DS_INIT\n");
	log_dbg3("dslen="U32_FMT"(0x%08lX)\n", pdu->dslen, pdu->dslen);

	if (pdu->opcode == ISCSI_OP_SCSI_CMD &&
	    pdu->cmd.opcode == SCSI_OP_WRITE_10) {
	    uint32 page_cnt = 0;
	    uint32 page_totallen = 0;

	    rv = vol_alloc_buf(pdu->vol, pdu->cmd.lba, pdu->cmd.trans_len,
			       &(pdu->task->list_page), &(pdu->task->page_totallen));
	    pdu->task->page_filled = 0;
	    log_dbg3("page_cnt="U32_FMT", page_totallen="U32_FMT"\n",
		    page_cnt, page_totallen);
	}
	if (pdu->dslen > 0) {
	    log_dbg3("pdu->task->list_page.len = "U32_FMT"\n", pdu->task->list_page.len);
	    if (list_is_empty(&(pdu->task->list_page))) {
		// TEMPOLARY IMPLEMENTATION
		byte *dsbuf = NULL;
		dsbuf = iscsi_alloc_dsbuf(conn, pdu->dslen);
		// ToDo: rethink this buffer allocation method
		if (dsbuf == NULL) {
		    rv = -ENOMEM;
		    goto failure;
		}

		pdu->dsvec[0].buf = dsbuf;
		pdu->dsvec[0].buflen = pdu->dslen;
		pdu->dsvec[0].offset = 0;
		pdu->dsvec[0].len = pdu->dslen;
		pdu->dsvec[0].page = NULL;
		pdu->dsvec_cnt = 1;

	    uint32 idx;
	    log_dbg3("pdu->dsvec_cnt="U32_FMT"\n", pdu->dsvec_cnt);
	    for (idx = 0; idx < pdu->dsvec_cnt; idx++) {
 		log_dbg3("pdu->dsvec["U32_FMT"].buf=%p\n", idx, pdu->dsvec[idx].buf);
 		log_dbg3("pdu->dsvec["U32_FMT"].buflen="U32_FMT"\n", idx, pdu->dsvec[idx].buflen);
		log_dbg3("pdu->dsvec["U32_FMT"].len="U32_FMT"\n", idx, pdu->dsvec[idx].len);
 		log_dbg3("pdu->dsvec["U32_FMT"].offset="U32_FMT"\n", idx, pdu->dsvec[idx].offset);
 		log_dbg3("pdu->dsvec["U32_FMT"].page=%p\n", idx, pdu->dsvec[idx].page);
	    }

	    } else {
		uint32 remain = pdu->dslen;
		uint32 gap = pdu->task->page_filled;
		struct page_buffer *page;

#ifdef __DEBUG
		if (pdu->opcode == ISCSI_OP_SCSI_DATA_OUT) {
		    log_dbg3("pdu->bufoffset="U32_FMT"(0x%08lX), gap="U32_FMT"(0x%08lX)\n",
			    pdu->bufoffset, pdu->bufoffset,
			    gap, gap);
		    ASSERT(pdu->bufoffset == gap,
			   "pdu->bufoffset("U32_FMT") != gap("U32_FMT")\n",
			   pdu->bufoffset, gap);
		}
#endif
		idx = 0;
		do_each_list_elem (struct page_buffer *, &(pdu->task->list_page), page, listelem) {
		    log_dbg3("idx="U32_FMT", page->len="U32_FMT", gap="U32_FMT", remain="U32_FMT"\n",
			    idx, page->len, gap, remain);
		    if (gap > page->len) {
			gap -= page->len;
		    } else {
			pdu->dsvec[idx].buf = &(page->buf[page->offset + gap]);
			pdu->dsvec[idx].page = page;
			log_dbg3("page->len - gap = "U32_FMT", remain="U32_FMT"\n",
				page->len - gap, remain);
			if (page->len - gap < remain) {
			    pdu->dsvec[idx].buflen = page->len - gap;
			    pdu->dsvec[idx].len = pdu->dsvec[idx].buflen;
			    pdu->dsvec[idx].offset = 0;
			    log_dbg3("pdu->dsvec["U32_FMT"].buflen="U32_FMT"\n", idx, pdu->dsvec[idx].buflen);
			    log_dbg3("pdu->dsvec["U32_FMT"].len="U32_FMT"\n", idx, pdu->dsvec[idx].len);
			    log_dbg3("pdu->dsvec["U32_FMT"].offset="U32_FMT"\n", idx, pdu->dsvec[idx].offset);
			    remain -= (page->len - gap);
			    gap = 0;
			    idx++;
			} else {
			    pdu->dsvec[idx].buflen = remain;
			    pdu->dsvec[idx].len = pdu->dsvec[idx].buflen;
			    pdu->dsvec[idx].offset = 0;
			    log_dbg3("pdu->dsvec["U32_FMT"].buflen="U32_FMT"\n", idx, pdu->dsvec[idx].buflen);
			    log_dbg3("pdu->dsvec["U32_FMT"].len="U32_FMT"\n", idx, pdu->dsvec[idx].len);
			    log_dbg3("pdu->dsvec["U32_FMT"].offset="U32_FMT"\n", idx, pdu->dsvec[idx].offset);
			    remain = 0;
			    gap = 0;
			    idx++;
			    break;
			}
		    }
		} while_each_list_elem (struct page_buffer *, &(pdu->task->list_page), page, listelem);
		pdu->dsvec_cnt = idx;
		log_dbg3("BEFORE: pdu->task->page_filled="U32_FMT"\n", pdu->task->page_filled);
		pdu->task->page_filled += pdu->dslen;
		log_dbg3("AFTER:  pdu->task->page_filled="U32_FMT"\n", pdu->task->page_filled);
	    }

	    for (idx = 0; idx < pdu->dsvec_cnt; idx++) {
		iovec_add(&(conn->iov_rx),
			  pdu->dsvec[idx].buf + pdu->dsvec[idx].offset,
			  pdu->dsvec[idx].len);
	    }

	    if (pdu->dslen % 4 > 0) {
		uint32 padlen;
		padlen = 4 - (pdu->dslen % 4);
		iovec_add(&(conn->iov_rx), conn->dspad_rx, padlen);
	    }
	    conn->state_rx = SOCKIO_AHS_DS_RXTX;

	    uint32 idx;
	    log_dbg3("pdu->dsvec_cnt="U32_FMT"\n", pdu->dsvec_cnt);
	    for (idx = 0; idx < pdu->dsvec_cnt; idx++) {
 		log_dbg3("pdu->dsvec["U32_FMT"].buf=%p\n", idx, pdu->dsvec[idx].buf);
 		log_dbg3("pdu->dsvec["U32_FMT"].buflen="U32_FMT"\n", idx, pdu->dsvec[idx].buflen);
		log_dbg3("pdu->dsvec["U32_FMT"].len="U32_FMT"\n", idx, pdu->dsvec[idx].len);
 		log_dbg3("pdu->dsvec["U32_FMT"].offset="U32_FMT"\n", idx, pdu->dsvec[idx].offset);
 		log_dbg3("pdu->dsvec["U32_FMT"].page=%p\n", idx, pdu->dsvec[idx].page);
	    }

	    goto retry;
	}
	break;
    case SOCKIO_AHS_DS_RXTX:
	log_dbg3("conn->state_rx = SOCKIO_AHS_DS_RXTX\n");
	iscsi_dump_pdu_in_hex(conn, pdu);
	break;
    default:
	ASSERT(0, "Detected Unknown socket IO status\n");
	abort();
    }

    ASSERT((conn->iov_rx.len == 0),
	   "conn->iov_rx.len("U32_FMT") > 0\n",
	   conn->iov_rx.len);

    rv = connection_handle_rx(conn, pdu);
    conn->state_rx = SOCKIO_BHS_INIT;
    if (rv == -1) {
	goto failure;
    }

    goto retry;

done:
    return rv;
failure:
    return rv;
} // iscsi_exec_rx


static int connection_handle_rx(struct iscsi_conn *conn, struct iscsi_pdu *pdu)
{
    int rv;

    ASSERT(sizeof(struct iscsi_bhs_nop_out) == ISCSI_PDU_BHSLEN,
	   "sizeof(struct iscsi_bhs_nop_out)(%d) != ISCSI_PDU_BHSLEN\n",
	   sizeof(struct iscsi_bhs_nop_out));
    ASSERT(sizeof(struct iscsi_bhs_scsi_cmd) == ISCSI_PDU_BHSLEN,
	   "sizeof(struct iscsi_bhs_scsi_cmd)(%d) != ISCSI_PDU_BHSLEN\n",
	   sizeof(struct iscsi_bhs_scsi_cmd));
    ASSERT(sizeof(struct iscsi_bhs_taskmng_req) == ISCSI_PDU_BHSLEN,
	   "sizeof(struct iscsi_bhs_taskmng_req)(%d) != ISCSI_PDU_BHSLEN\n",
	   sizeof(struct iscsi_bhs_taskmng_req));
    ASSERT(sizeof(struct iscsi_bhs_login_req) == ISCSI_PDU_BHSLEN,
	   "sizeof(struct iscsi_bhs_login_req)(%d) != ISCSI_PDU_BHSLEN\n",
	   sizeof(struct iscsi_bhs_login_req));
    ASSERT(sizeof(struct iscsi_bhs_text_req) == ISCSI_PDU_BHSLEN,
	   "sizeof(struct iscsi_bhs_text_req)(%d) != ISCSI_PDU_BHSLEN\n",
	   sizeof(struct iscsi_bhs_text_req));
    ASSERT(sizeof(struct iscsi_bhs_scsidata_out) == ISCSI_PDU_BHSLEN,
	   "sizeof(struct iscsi_bhs_scsidata_out)(%d) != ISCSI_PDU_BHSLEN\n",
	   sizeof(struct iscsi_bhs_scsidata_out));
    ASSERT(sizeof(struct iscsi_bhs_logout_req) == ISCSI_PDU_BHSLEN,
	   "sizeof(struct iscsi_bhs_logout_req)(%d) != ISCSI_PDU_BHSLEN\n",
	   sizeof(struct iscsi_bhs_logout_req));
    ASSERT(sizeof(struct iscsi_bhs_login_rsp) == ISCSI_PDU_BHSLEN,
	   "sizeof(struct iscsi_bhs_login_rsp)(%d) != ISCSI_PDU_BHSLEN\n",
	   sizeof(struct iscsi_bhs_login_rsp));
    ASSERT(sizeof(struct iscsi_bhs_text_rsp) == ISCSI_PDU_BHSLEN,
	   "sizeof(struct iscsi_bhs_text_rsp)(%d) != ISCSI_PDU_BHSLEN\n",
	   sizeof(struct iscsi_bhs_text_rsp));
    ASSERT(sizeof(struct iscsi_bhs_scsidata_in) == ISCSI_PDU_BHSLEN,
	   "sizeof(struct iscsi_bhs_scsidata_in)(%d) != ISCSI_PDU_BHSLEN\n",
	   sizeof(struct iscsi_bhs_scsidata_in));
    ASSERT(sizeof(struct iscsi_bhs_logout_rsp) == ISCSI_PDU_BHSLEN,
	   "sizeof(struct iscsi_bhs_logout_rsp)(%d) != ISCSI_PDU_BHSLEN\n",
	   sizeof(struct iscsi_bhs_logout_rsp));
    ASSERT(sizeof(struct iscsi_bhs_scsi_rsp) == ISCSI_PDU_BHSLEN,
	   "sizeof(struct iscsi_bhs_scsi_rsp)(%d) != ISCSI_PDU_BHSLEN\n",
	   sizeof(struct iscsi_bhs_scsi_rsp));
 
    iscsi_dump_pdu(conn, pdu);

    rv = 0;
    log_dbg1("pdu->opcpde=%u\n", pdu->opcode);
    switch (pdu->opcode) {
    case ISCSI_OP_NOP_OUT:
	rv = exec_nop_out(conn, pdu);
	break;
    case ISCSI_OP_SCSI_CMD:
	rv = iscsi_exec_scsi_cmd(conn, pdu);
	break;
    case ISCSI_OP_TASK_MGT_REQ:
	ASSERT(0, "Not Implemented Yet!\n");
	break;
    case ISCSI_OP_LOGIN_REQ:
	rv = exec_login_req(conn, pdu);
	break;
    case ISCSI_OP_TEXT_REQ:
	rv = exec_text_req(conn, pdu);
	break;
    case ISCSI_OP_SCSI_DATA_OUT:
	rv = exec_scsidata_out(conn, pdu);
	break;
    case ISCSI_OP_LOGOUT_REQ:
	rv = exec_logout_req(conn, pdu);
	break;
    case ISCSI_OP_SNACK:
	ASSERT((0), "NOT IMPLEMENTED YET\n");
	break;
    case ISCSI_OP_NOP_IN:
    case ISCSI_OP_SCSI_RSP:
    case ISCSI_OP_TASK_MGT_RSP:
    case ISCSI_OP_LOGIN_RSP:
    case ISCSI_OP_TEXT_RSP:
    case ISCSI_OP_SCSI_DATA_IN:
    case ISCSI_OP_LOGOUT_RSP:
    case ISCSI_OP_R2T:
    case ISCSI_OP_ASYNC_MSG:
    case ISCSI_OP_REJECT:
	ASSERT(0, "Not Implemented Yet!\n");
	break;
    default:
	// ToDo: implement error handling.
	ASSERT(0, "Unknown opcode (0x%02X)\n", pdu->opcode);
	break;
    }
    log_dbg3("rv = %d\n", rv);
    return rv;
} // connection_handle_rx


static void *connection_main(void *arg)
{
    int err, rv;
    enum event_iotype iotype;
    struct epoll_event event;
    struct iscsi_conn *conn;

    conn = (struct iscsi_conn *)arg;

    while (conn->stage != ISCSI_STAGE_FINISH) {
	log_dbg3("wait with epoll_wait\n");
	rv = epoll_wait(conn->fd_ep, &event, 1, -1);
	err = errno;

	log_dbg3("Returned from epoll_wait (rv=%d, errno=%d).\n", rv, err);
	log_dbg3("event.events = 0x%02X (EPOLLIN=0x%02X, EPOLLOUT=0x%02X, EPOLLRDHUP=0x%02X)\n",
		event.events, EPOLLIN, EPOLLOUT, EPOLLRDHUP);
	
	if (rv == -1) {
	    // ToDo : Implement error handling
	    log_err("Unable to wait epoll events (%d).\n", err);
	    break;
	} else if (rv == 0) {
	    log_dbg3("Timeout.\n");
	    continue;
	}
	
	if (event.events & EPOLLRDHUP) {
	    log_info("Connection is closed (or shutdowned by peer).\n");
	    break;
	}
	if (event.events & EPOLLERR || event.events & EPOLLHUP) {
	    log_err("Detected error event at epoll_wait.\n");
	    break;
	}

	iotype = (enum event_iotype)(event.data.u64);
	switch (iotype) {
	case EVENT_SOCKET:
	    log_dbg3("EVENT_SOCKET\n");
	    if (event.events & EPOLLIN) {
		rv = iscsi_exec_rx(conn);
	    }
	    if (event.events & EPOLLOUT) {
		rv = iscsi_exec_tx(conn);
	    }
	    break;
	case EVENT_DISKRW:
	    log_dbg3("EVENT_DISKRW\n");
	    ASSERT(0, "NOT IMPLEMENTED YET");
	    break;
	case EVENT_EVENT:
	    log_dbg3("EVENT_EVENT\n");
	    ASSERT((event.events & EPOLLIN),
		   "!(event.events & EPOLLIN)");
	    rv = iscsi_exec_notify(conn);
	    break;
	default:
	    ASSERT((0), "iotype=%d\n", iotype);
	}
    }

    if (conn->stage != ISCSI_STAGE_FINISH) {
	log_dbg1("conn->stage(%d) != ISCSI_STAGE_FINISH\n", conn->stage);
	iscsi_close_connection(conn);
    }

    log_info("Close an iSCSI connection.\n");
    iscsi_destroy_connection(conn);

    return NULL;
} // connection_main


static int exec_nop_out(struct iscsi_conn *conn, struct iscsi_pdu *pdu)
{
    struct iscsi_pdu *pdu_rsp;
    int rv;

    pdu_rsp = create_nop_in(conn, pdu);
    if (pdu_rsp == NULL) {
	return -1;
    }

    rv = iscsi_add_pdu_to_task(conn, pdu->task, pdu_rsp);
    if (rv) {
	return -1;
    }
    
    rv = iscsi_enqueue_and_tx_pdu(conn, pdu_rsp);
    if (rv) {
	return -1;
    }
    return 0;
} //exec_nop_out


static int exec_logout_req(struct iscsi_conn *conn, struct iscsi_pdu *pdu)
{
    struct iscsi_pdu *pdu_rsp;
    int rv;
    
    pdu_rsp = create_logout_rsp(conn, pdu);
    if (pdu_rsp == NULL) {
	goto failure;
    }

    rv = iscsi_add_pdu_to_task(conn, pdu->task, pdu_rsp);
    if (rv) {
	goto failure;
    }

    conn->stage = ISCSI_STAGE_CLOSE;
    
    rv = iscsi_enqueue_and_tx_pdu(conn, pdu_rsp);
    if (rv) {
	goto failure;
    }

#if 0
    rv = iscsi_close_connection(conn);
    if (rv) {
	goto failure;
    }
#endif

    // ToDo: Stop receiving PDU.

    return 0;
failure:
    return -1;
} // exec_logout_req


static int exec_text_req(struct iscsi_conn *conn, struct iscsi_pdu *pdu)
{
    struct iscsi_pdu *pdu_rsp;
    int rv;
    char *sendtargets;

    ASSERT(pdu->dsvec_cnt <= 1,
	   "pdu->dsvec_cnt("U32_FMT") <= 1\n", pdu->dsvec_cnt);
    if (pdu->dsvec_cnt == 1) {
	ASSERT(pdu->dsvec[0].len == pdu->dslen,
	       "pdu->dsvec[0].len("U32_FMT") != pdu->dslen("U32_FMT")\n",
	       pdu->dsvec[0].len, pdu->dslen);
	ASSERT(pdu->dsvec[0].len == pdu->dsvec[0].buflen,
	       "pdu->dsvec[0].len("U32_FMT") != pdu->dsvec[0].buflen("U32_FMT")\n",
	       pdu->dsvec[0].len, pdu->dsvec[0].buflen);
	ASSERT(pdu->dsvec[0].offset == 0,
	       "pdu->dsvec[0].offset("U32_FMT") > 0\n",
	       pdu->dsvec[0].offset);
    }

    if (pdu->dsvec_cnt > 0) {
	sendtargets = seek_value((char *)pdu->dsvec[0].buf, pdu->dsvec[0].len,
				 "SendTargets");
    }
    log_dbg3("SendTargets = %s\n", sendtargets);

    pdu_rsp = create_text_rsp(conn, pdu);
    if (pdu_rsp == NULL) {
	return -1;
    }

    if (sendtargets != NULL) {
	rv = pack_sendtargets(conn, pdu_rsp);
	if (rv) {
	    goto failure;
	}
    } else {
	ASSERT((0), "NOT IMPLEMENTED YET!\n");
    }

    rv = iscsi_add_pdu_to_task(conn, pdu->task, pdu_rsp);
    if (rv) {
	// ToDo : Implement error handling
	log_err("Error, not implemented yet!\n");
	abort();
    }

    rv = iscsi_enqueue_and_tx_pdu(conn, pdu_rsp);
    if (rv) {
	return -1;
    }

    return 0;

failure:
    return -1;
} // exec_text_req


static struct iscsi_pdu *create_nop_in(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req)
{
    struct iscsi_pdu *pdu_rsp;

    pdu_rsp = iscsi_create_pdu(conn);
    if (pdu_rsp == NULL) {
	return NULL;
    }

    pdu_rsp->opcode = ISCSI_OP_NOP_IN;
    pdu_rsp->Fbit = 1;
    pdu_rsp->dslen = 0;
    pdu_rsp->ahslen = 0;
    pdu_rsp->itt = pdu_req->itt;
    pdu_rsp->ttt = pdu_req->ttt;

    return pdu_rsp;
} // create_nop_in


/**
 * 
 */
static struct iscsi_pdu *create_logout_rsp(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req)
{
    struct iscsi_pdu *pdu_rsp;

    pdu_rsp = iscsi_create_pdu(conn);
    if (pdu_rsp == NULL) {
	return NULL;
    }

    pdu_rsp->opcode = ISCSI_OP_LOGOUT_RSP;
    pdu_rsp->Fbit = 1;
    pdu_rsp->response = ISCSI_LOGOUT_SUCCESS;
    pdu_rsp->dslen = 0;
    pdu_rsp->ahslen = 0;
    pdu_rsp->itt = pdu_req->itt;

    pdu_rsp->time2wait   = 0;
    pdu_rsp->time2retain = 0;

    return pdu_rsp;
} // create_logout_rsp


/**
 * Create a Text Response PDU.
 */
static struct iscsi_pdu *create_text_rsp(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req)
{
    struct iscsi_pdu *pdu_rsp;

    pdu_rsp = iscsi_create_pdu(conn);
    if (pdu_rsp == NULL) {
	return NULL;
    }

    pdu_rsp->opcode = ISCSI_OP_TEXT_RSP;
    pdu_rsp->Fbit = 1;
    pdu_rsp->Cbit = 0;
    pdu_rsp->dslen = 0;
    pdu_rsp->ahslen = 0;
    pdu_rsp->itt = pdu_req->itt;
    pdu_rsp->ttt = 0xFFFFFFFF;
    pdu_req->task->ttt = 0xFFFFFFFF;

    return pdu_rsp;
} // create_text_rsp


/**
 * Process a SCSI Data-Out PDU.
 *
 * @param[in,out] conn  iSCSI connection
 * @param[in]     pdu   SCSI Data Out PDU
 * @retval        0     succeed
 * @retval        -1    failure
 */
int exec_scsidata_out(struct iscsi_conn *conn, struct iscsi_pdu *pdu)
{
    ASSERT((pdu != NULL), "pdu == NULL\n");

    struct iscsi_task *task = NULL;
    struct iscsi_pdu *pdu_req;
    uint rv;

    task = pdu->task;
    ASSERT((task != NULL), "task == NULL\n");

    // PDU pdu_req must be SCSI-Command PDU,
    // and SCSI Command must be Write 10 CDB.
    pdu_req = (struct iscsi_pdu *)list_ref_head_elem(&(task->list_pdu));
    ASSERT((pdu_req != NULL), "pdu_req == NULL\n");
    ASSERT(((pdu_req->opcode == ISCSI_OP_SCSI_CMD) &&
	    (pdu_req->cmd.opcode == SCSI_OP_WRITE_10)),
	   "pdu_req->opcode(0x%02X) != ISCSI_OP_SCSI_CMD || pdu_req->cmd.opcode != SCSI_OP_WRITE_10\n",
	   pdu_req->opcode, pdu_req->cmd.opcode);

    log_dbg3("pdu->bufoffset="U32_FMT"(0x%08lX), task->page_filled="U32_FMT"(0x%08lX)\n",
	    pdu->bufoffset, pdu->bufoffset,
	    task->page_filled, task->page_filled);
    ASSERT(pdu->bufoffset + pdu->dslen == task->page_filled,
	   "pdu->bufoffset("U32_FMT"(0x%08lX)) + pdu->dslen("U32_FMT"(0x%08lX)) != task->page_filled("U32_FMT"(0x%08lX))\n",
	   pdu->bufoffset, pdu->bufoffset,
	   pdu->dslen, pdu->dslen,
	   task->page_filled, task->page_filled);

    log_dbg3("task->page_filled("U32_FMT"(0x%08lX)), task->page_totallen("U32_FMT"(0x%08lX))\n",
	    task->page_filled, task->page_filled,
	    task->page_totallen, task->page_totallen);

    // If received all data, execute SCSI write operation.
    if (task->page_filled == task->page_totallen) {
	log_dbg3("Write\n");
	rv = iscsi_exec_scsi_cmd(conn, pdu_req);
	if (rv) {
	    goto failure;
	}
    } else {
    }

    return 0;
failure:
    return -1;
} // exec_scsidata_out


static struct iscsi_conn *create_connection(
    struct siso_info *siso,
    int fd,
    struct sockaddr_storage *cli_addr,
    socklen_t cli_addr_len)
{
    int rv;
    int err;

    struct iscsi_conn *conn = NULL;

    conn = malloc(sizeof(struct iscsi_conn));
    if (conn == NULL) {
	log_err("Unable to allocate memory for iSCSI connection (%d bytes).\n",
		sizeof(struct iscsi_conn));
	goto failure;
    }

    conn->cli_addr = *cli_addr;
    conn->cli_addr_len = cli_addr_len;

    conn->target = NULL;
    conn->siso = siso;
    conn->fd_ep = 0;
    conn->fd_ev = 0;
    conn->fd_sock = 0;

    conn->stage = ISCSI_STAGE_START;
    conn->chap_a = ISCSI_CHAP_ALGORITHM_NULL;
    conn->chap_i = 0;
    conn->sid.id64 = 0;

    list_init(&(conn->list_volcmd));
    pthread_mutex_init(&(conn->lock_list_volcmd), NULL);

    conn->fd_ep = epoll_create(8);
    if (conn->fd_ep == -1) {
	log_err("Unable to create epoll descriptor.\n");
	goto failure;
    }
    conn->fd_ev = eventfd(0, 0);
    if (conn->fd_ev == -1) {
	log_err("Unable to create event descriptor.\n");
	goto failure;
    }
    conn->fd_sock = fd;
    set_non_blocking(conn->fd_sock);

    log_dbg3("conn->fd_ep=%d, conn->fd_sock=%d\n",
	    conn->fd_ep, conn->fd_sock);

    conn->pdus = 0;

    list_init(&(conn->list_task));

    conn->statsn = 1;
    conn->expcmdsn = 0;
    conn->ttt = 0;

    conn->session = ISCSI_SESSION_NULL;

    conn->error_recovery_level = DEFAULT_ERROR_RECOVERY_LEVEL;
    conn->initial_r2t = DEFAULT_INITIAL_R2T;
    conn->immediate_data = DEFAULT_IMMEDIATE_DATA;
    conn->max_burst_length = DEFAULT_MAX_BURST_LENGTH;
    conn->first_burst_length = DEFAULT_FIRST_BURST_LENGTH;
    conn->max_connections = DEFAULT_MAX_CONNECTIONS;
    conn->data_pdu_in_order = DEFAULT_DATA_PDU_IN_ORDER;
    conn->max_outstanding_r2t = DEFAULT_MAX_OUTSTANDING_R2T;
    conn->default_time2wait = DEFAULT_DEFAULT_TIME2WAIT;
    conn->default_time2retain = DEFAULT_DEFAULT_TIME2RETAIN;
    conn->header_digest = DEFAULT_HEADER_DIGEST;
    conn->data_digest = DEFAULT_DATA_DIGEST;

#define DEFAULT_MAX_XMIT_DATA_LEN 0x2000 // 8KiB

    conn->max_xmit_data_len = DEFAULT_MAX_XMIT_DATA_LEN;

    memset((void *)&(conn->dspad_tx), 0x0, 4);
    memset((void *)&(conn->dspad_rx), 0x0, 4);

    memset((void *)&conn->event[EVENT_SOCKET],
	   0x0,
	   sizeof(conn->event[EVENT_SOCKET]));
    memset((void *)&conn->event[EVENT_DISKRW],
	   0x0,
	   sizeof(conn->event[EVENT_DISKRW]));
    memset((void *)&conn->event[EVENT_EVENT],
	   0x0,
	   sizeof(conn->event[EVENT_EVENT]));
    conn->event[EVENT_SOCKET].data.u64 = EVENT_SOCKET;
    conn->event[EVENT_DISKRW].data.u64 = EVENT_DISKRW;
    conn->event[EVENT_EVENT].data.u64 = EVENT_EVENT;
    log_dbg3("conn->fd_ep=%d, conn->fd_sock=%d, conn->fd_ev=%d\n",
	    conn->fd_ep, conn->fd_sock, conn->fd_ev);

    conn->event[EVENT_SOCKET].events = EPOLLIN | EPOLLRDHUP | EPOLLET;
    rv = epoll_ctl(conn->fd_ep,
		    EPOLL_CTL_ADD,
		    conn->fd_sock,
		    &(conn->event[EVENT_SOCKET]));
    err = errno;
    if (rv == -1) {
	log_err("Unable to add conn->fd_sock to epoll context (errno=%d).\n",
		err);
	goto failure;
    }

    conn->event[EVENT_EVENT].events = EPOLLIN | EPOLLRDHUP | EPOLLET;
    rv = epoll_ctl(conn->fd_ep,
		    EPOLL_CTL_ADD,
		    conn->fd_ev,
		    &(conn->event[EVENT_EVENT]));
    err = errno;
    if (rv == -1) {
	log_err("Unable to add conn->fd_rv to epoll context (errno=%d).\n",
		err);
	goto failure;
    }

    conn->state_rx = SOCKIO_BHS_INIT;

    listelem_init(&(conn->listelem_siso), conn);
    listelem_init(&(conn->listelem_session), conn);

    return conn;

failure:
    if (conn != NULL) {
	if (conn->fd_ep > 0) {
	    close(conn->fd_ep);
	}
	if (conn->fd_ev > 0) {
	    close(conn->fd_ev);
	}
	free_safe(conn, sizeof(struct iscsi_conn));
	conn = NULL;
    }
    return NULL;
} // create_connection

#if 0
    list_add_elem(&(target->list_conn), &(conn->listelem));
    log_dbg3("Initialized the connection. ("U32_FMT" connections available)\n",
	    target->list_conn.len);
#endif


static int pack_sendtargets(struct iscsi_conn *conn, struct iscsi_pdu *pdu_rsp)
{
    ASSERT((conn->siso != NULL), "conn->siso == NULL\n");

    uint32 dsbuflen;
    byte *dsbuf;
    uint32 idx;
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(struct sockaddr_storage);
    int err;
    char addr[NI_MAXHOST];
    int len = 0;
    struct siso_info *siso = conn->siso;

    dsbuflen = ISCSI_PDU_DSLEN_MAX;
    dsbuf = iscsi_alloc_dsbuf(conn, dsbuflen);
    if (dsbuf == NULL) {
	goto failure;
    }
    log_dbg1("dsbuf=%p\n", dsbuf);
    idx = pdu_rsp->dsvec_cnt;
    pdu_rsp->dsvec[idx].buf = dsbuf;
    pdu_rsp->dsvec[idx].buflen = dsbuflen;
    pdu_rsp->dsvec[idx].offset = 0;
    pdu_rsp->dsvec[idx].len = 0;
    pdu_rsp->dsvec[idx].page = NULL;
    pdu_rsp->dslen = 0;
    pdu_rsp->dsvec_cnt++;

    memset(dsbuf, 0x0, dsbuflen);
    
    if (getsockname(conn->fd_sock, (struct sockaddr *)&ss, &slen)) {
	err = errno;
	// ToDo : implement error handling
	log_err("Unable to get socket name with \"getsockname\" (errno="U32_FMT")\n", err);
	abort();
    }
    log_dbg3("NI_MAXHOST=%d\n", NI_MAXHOST);
    if (getnameinfo((struct sockaddr *)&ss, slen, addr, sizeof(addr), NULL, 0, NI_NUMERICHOST)) {
	err = errno;
	// ToDo : implement error handling
	log_err("Unable to get socket name with \"getnameinfo\" (errno="U32_FMT")\n", err);
	abort();
    }

    ASSERT((!list_is_empty(&(siso->list_target))),
	   "list_is_empty(&(siso->list_target))\n");

    struct iscsi_target *target;
    do_each_list_elem(struct iscsi_target *, &(siso->list_target), target, listelem) {
	len = pack_kv(dsbuf, dsbuflen, "TargetName", target->name);
	log_dbg1("target->name=%s\n", target->name);
	log_dbg3("dsbuflen = "U32_FMT", len="U32_FMT"\n", dsbuflen, len);
	dsbuf += len;
	dsbuflen -= len;
	log_dbg3("dsbuflen = "U32_FMT", len="U32_FMT"\n", dsbuflen, len);
	ASSERT((dsbuflen > 0), "dsbuflen <= 0\n");
    } while_each_list_elem(struct iscsi_target *, &(siso->list_target), target, listelem);

    if (ss.ss_family == AF_INET) {
	// IPv4
	len = pack_kv(dsbuf, dsbuflen, "TargetAddress", "%s:%u,1", addr, conn->siso->port);
    } else {
	// IPv6
	struct sockaddr_in6 *saddr_in6 = (struct sockaddr_in6 *)&ss;
	if (is_ipv4_mapped_ipv6_addr(saddr_in6)) {
	    len = pack_kv(dsbuf, dsbuflen, "TargetAddress", "%u.%u.%u.%u:%u,1",
			  saddr_in6->sin6_addr.s6_addr[12],
			  saddr_in6->sin6_addr.s6_addr[13],
			  saddr_in6->sin6_addr.s6_addr[14],
			  saddr_in6->sin6_addr.s6_addr[15],
			  conn->siso->port);
	} else {
	    len = pack_kv(dsbuf, dsbuflen, "TargetAddress", "[%s]:%u,1", addr, conn->siso->port);
	}
    }
    dsbuf += len;
    dsbuflen -= len;
    log_dbg3("dsbuflen = "U32_FMT", len="U32_FMT"\n", dsbuflen, len);
    ASSERT((dsbuflen > 0), "dsbuflen <= 0\n");

    pdu_rsp->dsvec[0].len = pdu_rsp->dsvec[0].buflen - dsbuflen;
    pdu_rsp->dslen = pdu_rsp->dsvec[0].len;

    return 0;
failure:
    return -1;
}
