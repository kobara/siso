/*
 * SISO : Simple iSCSI Storage
 * 
 * basic iSCSI protocol data-structures and handlers.
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


#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include "target.h"
#include "iscsi.h"
#include "misc.h"
#include "vol.h"

#define HEADER_CHECKER 0xAA
#define FOOTER_CHECKER 0xCC

static struct volume *lookup_volume(struct iscsi_conn *conn, uint64 lun);

uint32 iscsi_alloc_buf(
    struct iscsi_conn *conn,
    uint32 len,
    struct buffer_vec **bufvec);

/*********************************************************************
 * PUBLIC FUNCTIONS
 *********************************************************************/
 /**
  * Allocate DS(DataSegment) memory
  */
byte *iscsi_alloc_dsbuf(struct iscsi_conn *conn, uint32 dslen)
{
    byte *ds;

    ds = malloc_safe(dslen);
    if (ds == NULL) {
	log_err("Unable to allocate memory (dslen="U32_FMT").\n", dslen);
	return NULL;
    }

    conn->dslen_total += dslen;
    log_dbg3("Allocated memory (conn->dslen_total="U32_FMT").\n",
	    conn->dslen_total);

    return ds;
} // iscsi_alloc_dsbuf


 /**
  * Free DS(DataSegment) memory
  */
int iscsi_free_dsbuf(struct iscsi_conn *conn, byte *ds, uint32 dslen)
{
    free_safe(ds, dslen);

    conn->dslen_total -= dslen;

    log_dbg3("Free memory (conn->dslen_total="U32_FMT").\n",
	    conn->dslen_total);

    return 0;
} // iscsi_free_dsbuf


/*
 * add PDU to task.
 */
int iscsi_add_pdu_to_task(struct iscsi_conn *conn, struct iscsi_task *task, struct iscsi_pdu *pdu)
{
    pdu->task = task;

    list_add_elem(&(task->list_pdu), &(pdu->listelem_task));

    log_dbg3("-----\n");
    log_dbg3("Add PDU (pdu->{opcode=0x%02X, itt=0x%08lX}, task->list_pdu.len="U32_FMT").\n",
	    pdu->opcode, pdu->itt, task->list_pdu.len);
    do_each_list_elem(struct iscsi_pdu *, &(task->list_pdu), pdu, listelem_task) {
	log_dbg3("&(pdu->listelem_task) = %p\n", &(pdu->listelem_task));
	log_dbg3("pdu->listelem_task.next = %p\n", pdu->listelem_task.next);
	log_dbg3("pdu->listelem_task.prev = %p\n", pdu->listelem_task.prev);
	log_dbg3("pdu->listelem_task.body = %p\n", pdu->listelem_task.body);
	ASSERT((pdu->listelem_task.next != NULL), "pdu->listelem_task.next == NULL\n");
	ASSERT((pdu->listelem_task.prev != NULL), "pdu->listelem_task.prev == NULL\n");
	iscsi_dump_pdu(conn, pdu);
    } while_each_list_elem(struct iscsi_pdu *, &(task->list_pdu), pdu, listelem_task);

    log_dbg3("-----\n");

    return 0;
} // iscsi_add_pdu_to_task


/*
 * Search an iSCSI command from command list at the iSCSI connection.
 */
struct iscsi_task *iscsi_search_task(struct iscsi_conn *conn, uint32 itt)
{
    struct iscsi_task *task, *task_found;

    task_found = NULL;

    if (list_is_empty(&(conn->list_task))) {
	log_dbg3("Not found the task (itt=0x%08lX)\n", itt);
    } else {
	ASSERT((conn->list_task.head != NULL), "conn->list_task.head == NULL\n");
	do_each_list_elem(struct iscsi_task *, &(conn->list_task), task, listelem) {
	    log_dbg3("task->itt="U32_FMT"(0x%08lX)\n", itt, itt);
	    if (task->itt == itt) {
		log_dbg3("Found the task (itt="U32_FMT"(0x%08lX))\n", itt, itt);
		task_found = task;
		break;
	    }
	} while_each_list_elem(struct iscsi_task *, &(conn->list_task), task, listelem);
	log_dbg3("Not found the task (itt=0x%08lX)\n", itt);
    }

    return task_found;
} // iscsi_search_task


/**
 * Set ResponsePDU's sequence numbers (e.g. StatSN,ExpCmdSN,MaxCmdSN)
 *
 * @param[in]      conn    an iSCSI connection
 * @param[in,out]  pdu     a response PDU
 */
void iscsi_set_sn(struct iscsi_conn *conn, struct iscsi_pdu *pdu)
{
    // ToDo: Change MaxCmdSN

    switch (pdu->opcode) {
    // Requests
    case ISCSI_OP_NOP_OUT:
    case ISCSI_OP_TASK_MGT_REQ:
    case ISCSI_OP_SCSI_CMD:
    case ISCSI_OP_LOGIN_REQ:
    case ISCSI_OP_SCSI_DATA_OUT:
    case ISCSI_OP_LOGOUT_REQ:
    case ISCSI_OP_SNACK:
	// This PDU is request PDU.
	ASSERT(0, "pdu->opcode=0x%02X\n", pdu->opcode);
	break;
    // Responses
    case ISCSI_OP_NOP_IN:
    case ISCSI_OP_SCSI_RSP:
    case ISCSI_OP_LOGIN_RSP:
    case ISCSI_OP_TEXT_RSP:
    case ISCSI_OP_LOGOUT_RSP:
	pdu->statsn = conn->statsn++;
	pdu->expcmdsn = conn->expcmdsn;
	pdu->maxcmdsn = conn->expcmdsn + 1;
	break;
    case ISCSI_OP_SCSI_DATA_IN:
	if (pdu->Fbit) {
	    // If this PDU is a final PDU in the sequence,
	    // increment StatSN.
	    pdu->statsn = conn->statsn++;
	} else {
	    // Not, hold StatSN.
	    pdu->statsn = conn->statsn;
	}
	pdu->expcmdsn = conn->expcmdsn;
	pdu->maxcmdsn = conn->expcmdsn + 1;
	break;
    case ISCSI_OP_R2T:
	pdu->statsn = conn->statsn;
	pdu->expcmdsn = conn->expcmdsn;
	pdu->maxcmdsn = conn->expcmdsn + 1;
	break;
    case ISCSI_OP_TASK_MGT_RSP:
    case ISCSI_OP_ASYNC_MSG:
    case ISCSI_OP_REJECT:
	ASSERT(0, "!NOT IMPLEMENTED YET!\n");
	break;
    }
    return;
} // iscsi_set_sn


/**
 * pack PDU parameters to BHS buffer.
 *
 * @param[in]      conn    an iSCSI connection
 * @param[in,out]  pdu     a response PDU
 */
void iscsi_pack_pdu(struct iscsi_conn *conn, struct iscsi_pdu *pdu)
{
    struct iscsi_bhs_scsi_rsp *bhs_srsp;
    struct iscsi_bhs_login_rsp *bhs_lirsp;
    struct iscsi_bhs_text_rsp *bhs_txtrsp;
    struct iscsi_bhs_logout_rsp *bhs_lorsp;
    struct iscsi_bhs_scsidata_in *bhs_sdin;
    struct iscsi_bhs_nop_in *bhs_nopin;
    struct iscsi_bhs_r2t *bhs_r2t;

    memset(&(pdu->bhs), 0x0, ISCSI_PDU_BHSLEN);

    pdu->bhs.opcode = pdu->opcode;
    pdu->bhs.itt = cpu_to_be32(pdu->itt);

    switch (pdu->opcode) {
    case ISCSI_OP_NOP_OUT:
    case ISCSI_OP_TASK_MGT_REQ:
    case ISCSI_OP_SCSI_CMD:
    case ISCSI_OP_LOGIN_REQ:
    case ISCSI_OP_SCSI_DATA_OUT:
    case ISCSI_OP_LOGOUT_REQ:
    case ISCSI_OP_SNACK:
	ASSERT(0, "!NOT IMPLEMENTED YET! (pdu->opcode=0x%02X)\n", pdu->opcode);
	break;
    case ISCSI_OP_NOP_IN:
	bhs_nopin = (struct iscsi_bhs_nop_in *)&(pdu->bhs);
	bhs_nopin->Fbit = ISCSI_MASK_FBIT;
	bhs_nopin->len = cpu_to_be32(pdu->dslen) | (pdu->ahslen / 4);
	bhs_nopin->ttt = cpu_to_be32(pdu->ttt);
	bhs_nopin->statsn = cpu_to_be32(pdu->statsn);
	bhs_nopin->expcmdsn = cpu_to_be32(pdu->expcmdsn);
	bhs_nopin->maxcmdsn = cpu_to_be32(pdu->maxcmdsn);
	break;
    case ISCSI_OP_SCSI_RSP:
	bhs_srsp = (struct iscsi_bhs_scsi_rsp *)&(pdu->bhs);
	bhs_srsp->flags |= ISCSI_MASK_FBIT;
	bhs_srsp->flags |= (pdu->obit ? ISCSI_MASK_SOBIT : 0x0);
	bhs_srsp->flags |= (pdu->ubit ? ISCSI_MASK_SUBIT : 0x0);
	bhs_srsp->flags |= (pdu->Obit ? ISCSI_MASK_BOBIT : 0x0);
	bhs_srsp->flags |= (pdu->Ubit ? ISCSI_MASK_BUBIT : 0x0);
	bhs_srsp->response = pdu->response;
	bhs_srsp->status = pdu->status;
	bhs_srsp->len = cpu_to_be32(pdu->dslen) | (pdu->ahslen / 4);
	bhs_srsp->snack = cpu_to_be32(pdu->snack);
	bhs_srsp->statsn = cpu_to_be32(pdu->statsn);
	bhs_srsp->expcmdsn = cpu_to_be32(pdu->expcmdsn);
	bhs_srsp->maxcmdsn = cpu_to_be32(pdu->maxcmdsn);
	bhs_srsp->expdatasn = cpu_to_be32(pdu->expdatasn);
	bhs_srsp->brrcount = cpu_to_be32(pdu->brrcount);
	bhs_srsp->rcount = cpu_to_be32(pdu->rcount);
	break;
    case ISCSI_OP_TASK_MGT_RSP:
	ASSERT(0, "!NOT IMPLEMENTED YET! (pdu->opcode=0x%02X)\n", pdu->opcode);
	break;
    case ISCSI_OP_LOGIN_RSP:
	bhs_lirsp = (struct iscsi_bhs_login_rsp *)&(pdu->bhs);
	bhs_lirsp->flags |= (pdu->Tbit ? ISCSI_MASK_TBIT : 0x0);
	bhs_lirsp->flags |= (pdu->Cbit ? ISCSI_MASK_CBIT : 0x0);
	bhs_lirsp->flags |= (pdu->csg << 2);
	bhs_lirsp->flags |= (pdu->nsg);
	bhs_lirsp->vmax = pdu->vmax;
	bhs_lirsp->vact = pdu->vact;
	bhs_lirsp->len = cpu_to_be32(pdu->dslen) | (pdu->ahslen / 4);
	bhs_lirsp->sid = pdu->sid;
	bhs_lirsp->statsn = cpu_to_be32(pdu->statsn);
	bhs_lirsp->expcmdsn = cpu_to_be32(pdu->expcmdsn);
	bhs_lirsp->maxcmdsn = cpu_to_be32(pdu->maxcmdsn);
	bhs_lirsp->sclass = pdu->sclass;
	bhs_lirsp->sdetail = pdu->sdetail;
	break;
    case ISCSI_OP_TEXT_RSP:
	bhs_txtrsp = (struct iscsi_bhs_text_rsp *)&(pdu->bhs);
	bhs_txtrsp->flags |= (pdu->Fbit ? ISCSI_MASK_FBIT : 0x0);
	bhs_txtrsp->flags |= (pdu->Cbit ? ISCSI_MASK_CBIT : 0x0);
	bhs_txtrsp->lun = cpu_to_be64(pdu->lun);
	bhs_txtrsp->len = cpu_to_be32(pdu->dslen) | (pdu->ahslen / 4);
	bhs_txtrsp->ttt = cpu_to_be32(pdu->ttt);
	bhs_txtrsp->statsn = cpu_to_be32(pdu->statsn);
	bhs_txtrsp->expcmdsn = cpu_to_be32(pdu->expcmdsn);
	bhs_txtrsp->maxcmdsn = cpu_to_be32(pdu->maxcmdsn);
	break;
    case ISCSI_OP_SCSI_DATA_IN:
	bhs_sdin = (struct iscsi_bhs_scsidata_in *)&(pdu->bhs);
	bhs_sdin->flags |= (pdu->Fbit ? ISCSI_MASK_FBIT : 0x0);
	bhs_sdin->flags |= (pdu->Abit ? ISCSI_MASK_ABIT : 0x0);
	bhs_sdin->flags |= (pdu->Obit ? ISCSI_MASK_OBIT : 0x0);
	bhs_sdin->flags |= (pdu->Ubit ? ISCSI_MASK_UBIT : 0x0);
	bhs_sdin->flags |= (pdu->Sbit ? ISCSI_MASK_SBIT : 0x0);
	bhs_sdin->len = cpu_to_be32(pdu->dslen) | (pdu->ahslen / 4);
	bhs_sdin->lun = cpu_to_be64(pdu->lun);
	bhs_sdin->itt = cpu_to_be32(pdu->itt);
	bhs_sdin->ttt = cpu_to_be32(pdu->ttt);
	bhs_sdin->statsn = cpu_to_be32(pdu->statsn);
	bhs_sdin->expcmdsn = cpu_to_be32(pdu->expcmdsn);
	bhs_sdin->maxcmdsn = cpu_to_be32(pdu->maxcmdsn);
	bhs_sdin->datasn = cpu_to_be32(pdu->datasn);
	bhs_sdin->bufoffset = cpu_to_be32(pdu->bufoffset);
	bhs_sdin->rcount = cpu_to_be32(pdu->rcount);
	break;
    case ISCSI_OP_LOGOUT_RSP:
	bhs_lorsp = (struct iscsi_bhs_logout_rsp *)&(pdu->bhs);
	bhs_lorsp->Fbit |= (pdu->Fbit ? ISCSI_MASK_FBIT : 0x0);
	bhs_lorsp->response = pdu->response;
	bhs_lorsp->len = cpu_to_be32(pdu->dslen) | (pdu->ahslen / 4);
	bhs_lorsp->itt = cpu_to_be32(pdu->itt);
	bhs_lorsp->statsn = cpu_to_be32(pdu->statsn);
	bhs_lorsp->expcmdsn = cpu_to_be32(pdu->expcmdsn);
	bhs_lorsp->maxcmdsn = cpu_to_be32(pdu->maxcmdsn);
	bhs_lorsp->time2wait = cpu_to_be16(pdu->time2wait);
	bhs_lorsp->time2retain = cpu_to_be16(pdu->time2retain);
	break;
    case ISCSI_OP_R2T:
	bhs_r2t = (struct iscsi_bhs_r2t *)&(pdu->bhs);
	bhs_r2t->Fbit |= (pdu->Fbit ? ISCSI_MASK_FBIT : 0x0);
	bhs_r2t->len = cpu_to_be32(pdu->dslen) | (pdu->ahslen / 4);
	bhs_r2t->lun = cpu_to_be64(pdu->lun);
	bhs_r2t->itt = cpu_to_be32(pdu->itt);
	bhs_r2t->ttt = cpu_to_be32(pdu->ttt);
	bhs_r2t->statsn = cpu_to_be32(pdu->statsn);
	bhs_r2t->expcmdsn = cpu_to_be32(pdu->expcmdsn);
	bhs_r2t->maxcmdsn = cpu_to_be32(pdu->maxcmdsn);
	bhs_r2t->r2tsn = cpu_to_be32(pdu->r2tsn);
	bhs_r2t->bufoffset = cpu_to_be32(pdu->bufoffset);
	bhs_r2t->ddtlen = cpu_to_be32(pdu->ddtlen);
	break;
    case ISCSI_OP_ASYNC_MSG:
    case ISCSI_OP_REJECT:
	ASSERT(0, "!NOT IMPLEMENTED YET! (pdu->opcode=0x%02X)\n", pdu->opcode);
	break;
    }
    return;
} // iscsi_pack_pdu


/**
 * get PDU parameters from BHS.
 *
 * @param[in]      conn    an iSCSI connection
 * @param[in,out]  pdu     a response PDU
 */
void iscsi_unpack_pdu(struct iscsi_conn *conn, struct iscsi_pdu *pdu)
{
#if __BYTE_ORDER == __BIG_ENDIAN
#error "Not supported yet"
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    pdu->Ibit = (pdu->bhs.opcode & ISCSI_MASK_IBIT) > 0 ? 1 : 0;
    pdu->opcode = pdu->bhs.opcode & ISCSI_MASK_OPCODE;
    pdu->vol = NULL;

    struct iscsi_bhs_nop_out *bhs_nout;
    struct iscsi_bhs_taskmng_req *bhs_tmr;
    struct iscsi_bhs_scsi_cmd *bhs_scmd;
    struct iscsi_bhs_login_req *bhs_lireq;
    struct iscsi_bhs_text_req *bhs_txtreq;
    struct iscsi_bhs_scsidata_out *bhs_sdout;
    struct iscsi_bhs_scsidata_in *bhs_sdin;
    struct iscsi_bhs_logout_req *bhs_loreq;
    struct iscsi_bhs_logout_rsp *bhs_lores;
    struct iscsi_bhs_login_rsp *bhs_lirsp;
    struct iscsi_bhs_text_rsp *bhs_txtrsp;

    // Requests.
    switch (pdu->opcode) {
    case ISCSI_OP_NOP_OUT:
	bhs_nout = (struct iscsi_bhs_nop_out *)&(pdu->bhs);
	pdu->Fbit = (bhs_nout->Fbit & ISCSI_MASK_FBIT) > 0 ? 1 : 0; // always "1"
	pdu->ahslen = (bhs_nout->len & 0xFF) * 4;        // AHS length
	pdu->dslen = be32_to_cpu(bhs_nout->len & ~0xFF); // DS length
	pdu->lun = scsi_unpack_lun(be64_to_cpu(bhs_nout->lun));
	pdu->itt = be32_to_cpu(bhs_nout->itt);
	pdu->ttt = be32_to_cpu(bhs_nout->ttt);
	pdu->cmdsn = be32_to_cpu(bhs_nout->cmdsn);
	pdu->expstatsn = be32_to_cpu(bhs_nout->expstatsn);
	break;
    case ISCSI_OP_TASK_MGT_REQ:
	bhs_tmr = (struct iscsi_bhs_taskmng_req *)&(pdu->bhs);
	pdu->Fbit = (bhs_tmr->flags & ISCSI_MASK_FBIT) > 0 ? 1 : 0; // always "1"
	pdu->func = bhs_tmr->flags & ISCSI_MASK_FUNCTION;
	pdu->ahslen = (bhs_tmr->len & 0xFF) * 4;        // AHS length
	pdu->dslen = be32_to_cpu(bhs_tmr->len & ~0xFF); // DS length
	pdu->lun = scsi_unpack_lun(be64_to_cpu(bhs_tmr->lun));
	pdu->itt = be32_to_cpu(bhs_tmr->itt);
	pdu->rtt = be32_to_cpu(bhs_tmr->rtt);
	pdu->cmdsn = be32_to_cpu(bhs_tmr->cmdsn);
	pdu->expstatsn = be32_to_cpu(bhs_tmr->expstatsn);
	pdu->refcmdsn = be32_to_cpu(bhs_tmr->refcmdsn);
	pdu->expdatasn = be32_to_cpu(bhs_tmr->expdatasn);
	break;
    case ISCSI_OP_SCSI_CMD:
	bhs_scmd = (struct iscsi_bhs_scsi_cmd *)&(pdu->bhs);
	pdu->Fbit = (bhs_scmd->flags & ISCSI_MASK_FBIT) > 0 ? 1 : 0;
	pdu->Rbit = (bhs_scmd->flags & ISCSI_MASK_RBIT) > 0 ? 1 : 0;
	pdu->Wbit = (bhs_scmd->flags & ISCSI_MASK_WBIT) > 0 ? 1 : 0;
   	pdu->attr = bhs_scmd->flags & ISCSI_MASK_ATTR;
	pdu->ahslen = (bhs_scmd->len & 0xFF) * 4;        // AHS length
	pdu->dslen = be32_to_cpu(bhs_scmd->len & ~0xFF); // DS length
	pdu->lun = scsi_unpack_lun(be64_to_cpu(bhs_scmd->lun));
	pdu->itt = be32_to_cpu(bhs_scmd->itt);
	pdu->expdtlen = be32_to_cpu(bhs_scmd->expdtlen);
	pdu->cmdsn = be32_to_cpu(bhs_scmd->cmdsn);
	pdu->expstatsn = be32_to_cpu(bhs_scmd->expstatsn);
	// scsi command
	pdu->vol = lookup_volume(conn, pdu->lun);
	scsi_unpack_cdb(conn, pdu, &(pdu->cmd));
	break;
    case ISCSI_OP_LOGIN_REQ:
	bhs_lireq = (struct iscsi_bhs_login_req *)&(pdu->bhs);
	pdu->Tbit = (bhs_lireq->flags & ISCSI_MASK_TBIT) > 0 ? 1 : 0;;
	pdu->Cbit = (bhs_lireq->flags & ISCSI_MASK_CBIT) > 0 ? 1 : 0;;
	pdu->csg = (bhs_lireq->flags & ISCSI_MASK_CSG) >> 2;
	pdu->nsg = bhs_lireq->flags & ISCSI_MASK_NSG;
	pdu->vmax = bhs_lireq->vmax;
	pdu->vmin = bhs_lireq->vmin;
	pdu->ahslen = (bhs_lireq->len & 0xFF) * 4;        // AHS length
	pdu->dslen = be32_to_cpu(bhs_lireq->len & ~0xFF); // DS length
	log_dbg1("isid=0x%016llX\n", bhs_lireq->sid.id64);
	log_dbg1("isid=0x%016llX\n", be64_to_cpu(bhs_lireq->sid.id64));
//	pdu->sid.id64 = be64_to_cpu(bhs_lireq->sid.id64);
	pdu->sid.id64 = bhs_lireq->sid.id64;
	pdu->itt = be32_to_cpu(bhs_lireq->itt);
	pdu->cid = be16_to_cpu(bhs_lireq->cid);
	pdu->cmdsn = be32_to_cpu(bhs_lireq->cmdsn);
	pdu->expstatsn = be32_to_cpu(bhs_lireq->expstatsn);
	break;
    case ISCSI_OP_TEXT_REQ:
	bhs_txtreq = (struct iscsi_bhs_text_req *)&(pdu->bhs);
	pdu->Fbit = (bhs_txtreq->flags & ISCSI_MASK_FBIT) > 0 ? 1 : 0;;
	pdu->Cbit = (bhs_txtreq->flags & ISCSI_MASK_CBIT) > 0 ? 1 : 0;;
	pdu->ahslen = (bhs_txtreq->len & 0xFF) * 4;        // AHS length
	pdu->dslen = be32_to_cpu(bhs_txtreq->len & ~0xFF); // DS length
	pdu->lun = scsi_unpack_lun(be64_to_cpu(bhs_txtreq->lun));
	pdu->itt = be32_to_cpu(bhs_txtreq->itt);
	pdu->ttt = be32_to_cpu(bhs_txtreq->ttt);
	pdu->cmdsn = be32_to_cpu(bhs_txtreq->cmdsn);
	pdu->expstatsn = be32_to_cpu(bhs_txtreq->expstatsn);
	break;
    case ISCSI_OP_SCSI_DATA_OUT:
	bhs_sdout = (struct iscsi_bhs_scsidata_out *)&(pdu->bhs);
	pdu->Fbit = (bhs_sdout->Fbit & ISCSI_MASK_FBIT) > 0 ? 1 : 0;;
	pdu->ahslen = (bhs_sdout->len & 0xFF) * 4;        // AHS length
	pdu->dslen = be32_to_cpu(bhs_sdout->len & ~0xFF); // DS length
	pdu->lun = scsi_unpack_lun(be64_to_cpu(bhs_sdout->lun));
	pdu->itt = be32_to_cpu(bhs_sdout->itt);
	pdu->ttt = be32_to_cpu(bhs_sdout->ttt);
	pdu->expstatsn = be32_to_cpu(bhs_sdout->expstatsn);
	pdu->datasn = be32_to_cpu(bhs_sdout->datasn);
	pdu->bufoffset = be32_to_cpu(bhs_sdout->bufoffset);
	break;
    case ISCSI_OP_LOGOUT_REQ:
	bhs_loreq = (struct iscsi_bhs_logout_req *)&(pdu->bhs);
	pdu->Fbit = (bhs_loreq->flags & ISCSI_MASK_FBIT) > 0 ? 1 : 0;;
	pdu->reason = bhs_loreq->flags & ISCSI_MASK_REASONCODE;
	pdu->ahslen = (bhs_loreq->len & 0xFF) * 4;        // AHS length
	pdu->dslen = be32_to_cpu(bhs_loreq->len & ~0xFF); // DS length
	pdu->itt = be32_to_cpu(bhs_loreq->itt);
	pdu->cid = be16_to_cpu(bhs_loreq->cid);
	pdu->cmdsn = be32_to_cpu(bhs_loreq->cmdsn);
	pdu->expstatsn = be32_to_cpu(bhs_loreq->expstatsn);
	conn->expcmdsn = pdu->cmdsn + (pdu->Ibit ? 0 : 1);
	break;
    case ISCSI_OP_SNACK:
    case ISCSI_OP_NOP_IN:
	ASSERT(0, "NOT IMPLEMENTED YET!\n");
    // Responses
    case ISCSI_OP_SCSI_RSP:
    case ISCSI_OP_TASK_MGT_RSP:
	ASSERT(0, "NOT IMPLEMENTED YET!\n");
    case ISCSI_OP_LOGIN_RSP:
	bhs_lirsp = (struct iscsi_bhs_login_rsp *)&(pdu->bhs);
	pdu->Tbit = (bhs_lirsp->flags & ISCSI_MASK_TBIT) > 0 ? 1 : 0;;
	pdu->Cbit = (bhs_lirsp->flags & ISCSI_MASK_CBIT) > 0 ? 1 : 0;;
	pdu->csg = (bhs_lirsp->flags & ISCSI_MASK_CSG) >> 2;
	pdu->nsg = bhs_lirsp->flags & ISCSI_MASK_NSG;
	pdu->vmax = bhs_lirsp->vmax;
	pdu->vact = bhs_lirsp->vact;
	pdu->ahslen = (bhs_lirsp->len & 0xFF) * 4;        // AHS length
	pdu->dslen = be32_to_cpu(bhs_lirsp->len & ~0xFF); // DS length
	pdu->sid = bhs_lirsp->sid;
	pdu->itt = be32_to_cpu(bhs_lirsp->itt);
	pdu->statsn = be32_to_cpu(bhs_lirsp->statsn);
	pdu->expcmdsn = be32_to_cpu(bhs_lirsp->expcmdsn);
	pdu->maxcmdsn = be32_to_cpu(bhs_lirsp->maxcmdsn);
	pdu->sclass = bhs_lirsp->sclass;
	pdu->sdetail = bhs_lirsp->sdetail;
	break;
    case ISCSI_OP_TEXT_RSP:
	bhs_txtrsp = (struct iscsi_bhs_text_rsp *)&(pdu->bhs);
	pdu->Fbit = (bhs_txtrsp->flags & ISCSI_MASK_FBIT) > 0 ? 1 : 0;;
	pdu->Cbit = (bhs_txtrsp->flags & ISCSI_MASK_CBIT) > 0 ? 1 : 0;;
	pdu->ahslen = (bhs_txtrsp->len & 0xFF) * 4;        // AHS length
	pdu->dslen = be32_to_cpu(bhs_txtrsp->len & ~0xFF); // DS length
	pdu->lun = scsi_unpack_lun(be64_to_cpu(bhs_txtrsp->lun));
	pdu->itt = be32_to_cpu(bhs_txtrsp->itt);
	pdu->ttt = be32_to_cpu(bhs_txtrsp->ttt);
	pdu->statsn = be32_to_cpu(bhs_txtrsp->statsn);
	pdu->expcmdsn = be32_to_cpu(bhs_txtrsp->expcmdsn);
	pdu->maxcmdsn = be32_to_cpu(bhs_txtrsp->maxcmdsn);
	break;
    case ISCSI_OP_SCSI_DATA_IN:
#define ISCSI_MASK_ABIT 0x40
#define ISCSI_MASK_OBIT 0x04
#define ISCSI_MASK_UBIT 0x02
#define ISCSI_MASK_SBIT 0x01
	bhs_sdin = (struct iscsi_bhs_scsidata_in *)&(pdu->bhs);
	pdu->Fbit = (bhs_sdin->flags & ISCSI_MASK_FBIT) > 0 ? 1 : 0;;
	pdu->Abit = (bhs_sdin->flags & ISCSI_MASK_ABIT) > 0 ? 1 : 0;;
	pdu->Obit = (bhs_sdin->flags & ISCSI_MASK_OBIT) > 0 ? 1 : 0;;
	pdu->Ubit = (bhs_sdin->flags & ISCSI_MASK_UBIT) > 0 ? 1 : 0;;
	pdu->Sbit = (bhs_sdin->flags & ISCSI_MASK_SBIT) > 0 ? 1 : 0;;
	pdu->status = bhs_sdin->status;
	pdu->ahslen = (bhs_sdin->len & 0xFF) * 4;        // AHS length
	pdu->dslen = be32_to_cpu(bhs_sdin->len & ~0xFF); // DS length
	pdu->lun = scsi_unpack_lun(be64_to_cpu(bhs_sdin->lun));
	pdu->itt = be32_to_cpu(bhs_sdin->itt);
	pdu->ttt = be32_to_cpu(bhs_sdin->ttt);
	pdu->statsn = be32_to_cpu(bhs_sdin->statsn);
	pdu->expcmdsn = be32_to_cpu(bhs_sdin->expcmdsn);
	pdu->maxcmdsn = be32_to_cpu(bhs_sdin->maxcmdsn);
	pdu->datasn = be32_to_cpu(bhs_sdin->datasn);
	pdu->bufoffset = be32_to_cpu(bhs_sdin->bufoffset);
	pdu->rcount = be32_to_cpu(bhs_sdin->rcount);
	break;
    case ISCSI_OP_LOGOUT_RSP:
	bhs_lores = (struct iscsi_bhs_logout_rsp *)&(pdu->bhs);
	pdu->Fbit = (bhs_lores->Fbit & ISCSI_MASK_FBIT) > 0 ? 1 : 0;;
	pdu->response = bhs_lores->response;
	pdu->ahslen = (bhs_lores->len & 0xFF) * 4;        // AHS length
	pdu->dslen = be32_to_cpu(bhs_lores->len & ~0xFF); // DS length
	pdu->itt = be32_to_cpu(bhs_lores->itt);
	pdu->statsn = be32_to_cpu(bhs_lores->statsn);
	pdu->expcmdsn = be32_to_cpu(bhs_lores->expcmdsn);
	pdu->maxcmdsn = be32_to_cpu(bhs_lores->maxcmdsn);
	pdu->time2wait = be16_to_cpu(bhs_lores->time2wait);
	pdu->time2retain = be16_to_cpu(bhs_lores->time2retain);
	break;
    case ISCSI_OP_R2T:
    case ISCSI_OP_ASYNC_MSG:
    case ISCSI_OP_REJECT:
	ASSERT(0, "NOT IMPLEMENTED YET!\n");
	break;
    }
#else
#error "Deteted unknown endian."
#endif
    return;
} // iscsi_unpack_pdu


void iscsi_dump_pdu(struct iscsi_conn *conn, struct iscsi_pdu *pdu)
{
    switch (pdu->opcode) {
    case ISCSI_OP_NOP_OUT:
	log_dbg2("NOP-Out (0x%02X)\n", pdu->opcode);
	log_dbg2("  Ibit = %u\n", pdu->Ibit);
	log_dbg2("  Fbit = %u\n", pdu->Fbit);
	log_dbg2("  ahslen = "U32_FMT"(0x%08lX)\n", pdu->ahslen, pdu->ahslen);
	log_dbg2("  dslen = "U32_FMT"(0x%08lX)\n", pdu->dslen, pdu->dslen);
	log_dbg2("  lun = %llu(0x%016llX)\n", pdu->lun, pdu->lun);
	log_dbg2("  itt = "U32_FMT"(0x%08lX)\n", pdu->itt, pdu->itt);
	log_dbg2("  ttt = "U32_FMT"(0x%08lX)\n", pdu->ttt, pdu->ttt);
	log_dbg2("  cmdsn = "U32_FMT"(0x%08lX)\n", pdu->cmdsn, pdu->cmdsn);
	log_dbg2("  expstatsn = "U32_FMT"(0x%08lX)\n", pdu->expstatsn, pdu->expstatsn);
	break;
    case ISCSI_OP_TASK_MGT_REQ:
	log_dbg2("Task Management Function Request (0x%02X)\n", pdu->opcode);
	ASSERT((0), "NOT IMPLEMENTED YET (pdu->opcode = 0x%02X)\n", pdu->opcode);
	break;
    case ISCSI_OP_SCSI_CMD:
	log_dbg2("SCSI Command Request (0x%02X)\n", pdu->opcode);
	log_dbg2("  Fbit = %u\n", pdu->Fbit);
	log_dbg2("  Rbit = %u\n", pdu->Rbit);
	log_dbg2("  Wbit = %u\n", pdu->Wbit);
	log_dbg2("  ATTR = 0x%X\n", pdu->attr);
	log_dbg2("  ahslen = "U32_FMT"(0x%08lX)\n", pdu->ahslen, pdu->ahslen);
	log_dbg2("  dslen = "U32_FMT"(0x%08lX)\n", pdu->dslen, pdu->dslen);
	log_dbg2("  lun = %llu(0x%016llX)\n", pdu->lun, pdu->lun);
	log_dbg2("  itt = "U32_FMT"(0x%08lX)\n", pdu->itt, pdu->itt);
	log_dbg2("  expdtlen = "U32_FMT"(0x%08lX)\n", pdu->expdtlen, pdu->expdtlen);
	log_dbg2("  cmdsn = "U32_FMT"(0x%08lX)\n", pdu->cmdsn, pdu->cmdsn);
	log_dbg2("  expstatsn = "U32_FMT"(0x%08lX)\n", pdu->expstatsn, pdu->expstatsn);
	scsi_dump_cdb(conn, &(pdu->cmd));
	break;
    case ISCSI_OP_LOGIN_REQ:
	log_dbg2("Login Request (0x%02X)\n", pdu->opcode);
	log_dbg2("  Ibit = %u\n", pdu->Ibit);
	log_dbg2("  Tbit = %u\n", pdu->Tbit);
	log_dbg2("  Cbit = %u\n", pdu->Cbit);
	log_dbg2("  csg = %u\n", pdu->csg);
	log_dbg2("  nsg = %u\n", pdu->nsg);
	log_dbg2("  vmax = %u\n", pdu->vmax);
	log_dbg2("  vmin = %u\n", pdu->vmin);
	log_dbg2("  ahslen = "U32_FMT"(0x%08lX)\n", pdu->ahslen, pdu->ahslen);
	log_dbg2("  dslen = "U32_FMT"(0x%08lX)\n", pdu->dslen, pdu->dslen);
	log_dbg2("  itt = "U32_FMT"(0x%08lX)\n", pdu->itt, pdu->itt);
	log_dbg2("  cid = 0x%04X\n", pdu->cid);
	log_dbg2("  sid = 0x%016X\n", pdu->sid.id64);
	log_dbg2("    isid = 0x%02X%02X%02X%02X%02X%02X\n",
		 pdu->sid.id.isid[0], pdu->sid.id.isid[1], pdu->sid.id.isid[2],
		 pdu->sid.id.isid[3], pdu->sid.id.isid[4], pdu->sid.id.isid[5]);
	log_dbg2("    tsih = 0x%02X%02X\n",
		 pdu->sid.id.tsih[0], pdu->sid.id.tsih[1]);
 	log_dbg2("  cmdsn = "U32_FMT"(0x%08lX)\n", pdu->cmdsn, pdu->cmdsn);
	log_dbg2("  expstatsn = "U32_FMT"(0x%08lX)\n", pdu->expstatsn, pdu->expstatsn);
	break;
    case ISCSI_OP_TEXT_REQ:
	log_dbg2("Text Request (0x%02X)\n", pdu->opcode);
	log_dbg2("  Ibit = %u\n", pdu->Ibit);
	log_dbg2("  Fbit = %u\n", pdu->Fbit);
	log_dbg2("  Cbit = %u\n", pdu->Cbit);
	log_dbg2("  ahslen = "U32_FMT"(0x%08lX)\n", pdu->ahslen, pdu->ahslen);
	log_dbg2("  dslen = "U32_FMT"(0x%08lX)\n", pdu->dslen, pdu->dslen);
	log_dbg2("  lun = %llu(0x%016llX)\n", pdu->lun, pdu->lun);
	log_dbg2("  itt = "U32_FMT"(0x%08lX)\n", pdu->itt, pdu->itt);
	log_dbg2("  ttt = "U32_FMT"(0x%08lX)\n", pdu->ttt, pdu->ttt);
	log_dbg2("  cmdsn = "U32_FMT"(0x%08lX)\n", pdu->cmdsn, pdu->cmdsn);
	log_dbg2("  expstatsn = "U32_FMT"(0x%08lX)\n", pdu->expstatsn, pdu->expstatsn);
	break;
    case ISCSI_OP_SCSI_DATA_OUT:
	log_dbg2("SCSI Data-Out (0x%02X)\n", pdu->opcode);
	log_dbg2("  Fbit = %u\n", pdu->Fbit);
	log_dbg2("  ahslen = "U32_FMT"(0x%08lX)\n", pdu->ahslen, pdu->ahslen);
	log_dbg2("  dslen = "U32_FMT"(0x%08lX)\n", pdu->dslen, pdu->dslen);
	log_dbg2("  lun = %llu(0x%016llX)\n", pdu->lun, pdu->lun);
	log_dbg2("  itt = "U32_FMT"(0x%08lX)\n", pdu->itt, pdu->itt);
	log_dbg2("  ttt = "U32_FMT"(0x%08lX)\n", pdu->ttt, pdu->ttt);
	log_dbg2("  expstatsn = "U32_FMT"(0x%08lX)\n", pdu->expstatsn, pdu->expstatsn);
	log_dbg2("  datasn = "U32_FMT"(0x%08lX)\n", pdu->datasn, pdu->datasn);
	log_dbg2("  bufoffset = "U32_FMT"(0x%08lX)\n", pdu->bufoffset, pdu->bufoffset);
	break;
    case ISCSI_OP_LOGOUT_REQ:
	log_dbg2("Logout Request (0x%02X)\n", pdu->opcode);
	log_dbg2("  Ibit = %u\n", pdu->Ibit);
	log_dbg2("  Fbit = %u\n", pdu->Fbit);
	log_dbg2("  reason = %u\n", pdu->reason);
	log_dbg2("  ahslen = "U32_FMT"(0x%08lX)\n", pdu->ahslen, pdu->ahslen);
	log_dbg2("  dslen = "U32_FMT"(0x%08lX)\n", pdu->dslen, pdu->dslen);
	log_dbg2("  itt = "U32_FMT"(0x%08lX)\n", pdu->itt, pdu->itt);
	log_dbg2("  cid = %u(0x%04lX)\n", pdu->cid, pdu->cid);
	log_dbg2("  cmdsn = "U32_FMT"(0x%08lX)\n", pdu->cmdsn, pdu->cmdsn);
	log_dbg2("  expstatsn = "U32_FMT"(0x%08lX)\n", pdu->expstatsn, pdu->expstatsn);
	break;
    case ISCSI_OP_SNACK:
	ASSERT((0), "NOT IMPLEMENTED YET (pdu->opcode = 0x%02X)\n", pdu->opcode);
	break;
    case ISCSI_OP_NOP_IN:
	log_dbg2("NOP-In (0x%02X)\n", pdu->opcode);
	log_dbg2("  Fbit = %u\n", pdu->Fbit);
	log_dbg2("  ahslen = "U32_FMT"(0x%08lX)\n", pdu->ahslen, pdu->ahslen);
	log_dbg2("  dslen = "U32_FMT"(0x%08lX)\n", pdu->dslen, pdu->dslen);
	log_dbg2("  lun = %llu(0x%016llX)\n", pdu->lun, pdu->lun);
	log_dbg2("  itt = "U32_FMT"(0x%08lX)\n", pdu->itt, pdu->itt);
	log_dbg2("  ttt = "U32_FMT"(0x%08lX)\n", pdu->ttt, pdu->itt);
	log_dbg2("  statsn = "U32_FMT"(0x%08lX)\n", pdu->statsn, pdu->statsn);
	log_dbg2("  expcmdsn = "U32_FMT"(0x%08lX)\n", pdu->expcmdsn, pdu->expcmdsn);
	log_dbg2("  maxcmdsn = "U32_FMT"(0x%08lX)\n", pdu->maxcmdsn, pdu->maxcmdsn);
	break;
	break;
    case ISCSI_OP_SCSI_RSP:
	log_dbg2("SCSI Response (0x%02X)\n", pdu->opcode);
	log_dbg2("  Fbit = %u\n", pdu->Fbit);
	log_dbg2("  obit = %u\n", pdu->obit);
	log_dbg2("  ubit = %u\n", pdu->ubit);
	log_dbg2("  Obit = %u\n", pdu->Obit);
	log_dbg2("  Ubit = %u\n", pdu->Ubit);
	log_dbg2("  response = %u(0x%02X)\n", pdu->response, pdu->response);
	log_dbg2("  status = %u(0x%02X)\n", pdu->status, pdu->status);
	log_dbg2("  ahslen = "U32_FMT"(0x%08lX)\n", pdu->ahslen, pdu->ahslen);
	log_dbg2("  dslen = "U32_FMT"(0x%08lX)\n", pdu->dslen, pdu->dslen);
	log_dbg2("  itt = "U32_FMT"(0x%08lX)\n", pdu->itt, pdu->itt);
	log_dbg2("  snack = "U32_FMT"(0x%08lX)\n", pdu->snack, pdu->snack);
	log_dbg2("  statsn = "U32_FMT"(0x%08lX)\n", pdu->statsn, pdu->statsn);
	log_dbg2("  expcmdsn = "U32_FMT"(0x%08lX)\n", pdu->expcmdsn, pdu->expcmdsn);
	log_dbg2("  maxcmdsn = "U32_FMT"(0x%08lX)\n", pdu->maxcmdsn, pdu->maxcmdsn);
	log_dbg2("  expdatasn = "U32_FMT"(0x%08lX)\n", pdu->expdatasn, pdu->expdatasn);
	log_dbg2("  brrcount = "U32_FMT"(0x%08lX)\n", pdu->brrcount, pdu->brrcount);
	log_dbg2("  rcount = "U32_FMT"(0x%08lX)\n", pdu->rcount, pdu->rcount);
	break;
    case ISCSI_OP_TASK_MGT_RSP:
	ASSERT((0), "NOT IMPLEMENTED YET (pdu->opcode = 0x%02X)\n", pdu->opcode);
	break;
    case ISCSI_OP_LOGIN_RSP:
	log_dbg2("Login Response (0x%02X)\n", pdu->opcode);
	log_dbg2("  Tbit = %u\n", pdu->Tbit);
	log_dbg2("  Cbit = %u\n", pdu->Cbit);
	log_dbg2("  csg = %u\n", pdu->csg);
	log_dbg2("  nsg = %u\n", pdu->nsg);
	log_dbg2("  vmax = %u\n", pdu->vmax);
	log_dbg2("  vmin = %u\n", pdu->vmin);
	log_dbg2("  ahslen = "U32_FMT"(0x%08lX)\n", pdu->ahslen, pdu->ahslen);
	log_dbg2("  dslen = "U32_FMT"(0x%08lX)\n", pdu->dslen, pdu->dslen);
	log_dbg2("  itt = "U32_FMT"(0x%08lX)\n", pdu->itt, pdu->itt);
	log_dbg2("  sid = 0x%016X\n", pdu->sid.id64);
	log_dbg2("  statsn = "U32_FMT"(0x%08lX)\n", pdu->statsn, pdu->statsn);
	log_dbg2("  expcmdsn = "U32_FMT"(0x%08lX)\n", pdu->expcmdsn, pdu->expcmdsn);
	log_dbg2("  maxcmdsn = "U32_FMT"(0x%08lX)\n", pdu->maxcmdsn, pdu->maxcmdsn);
	log_dbg2("  sclass = %u(0x%02X)\n", pdu->sclass, pdu->sclass);
	log_dbg2("  sdetail = %u(0x%02X)\n", pdu->sdetail, pdu->sdetail);
	break;
    case ISCSI_OP_TEXT_RSP:
	log_dbg2("Text Response (0x%02X)\n", pdu->opcode);
	log_dbg2("  Fbit = %u\n", pdu->Tbit);
	log_dbg2("  Cbit = %u\n", pdu->Cbit);
	log_dbg2("  ahslen = "U32_FMT"(0x%08lX)\n", pdu->ahslen, pdu->ahslen);
	log_dbg2("  dslen = "U32_FMT"(0x%08lX)\n", pdu->dslen, pdu->dslen);
	log_dbg2("  lun = %llu(0x%016llX)\n", pdu->lun, pdu->lun);
	log_dbg2("  itt = "U32_FMT"(0x%08lX)\n", pdu->itt, pdu->itt);
	log_dbg2("  ttt = "U32_FMT"(0x%08lX)\n", pdu->ttt, pdu->ttt);
	log_dbg2("  statsn = "U32_FMT"(0x%08lX)\n", pdu->statsn, pdu->statsn);
	log_dbg2("  expcmdsn = "U32_FMT"(0x%08lX)\n", pdu->expcmdsn, pdu->expcmdsn);
	log_dbg2("  maxcmdsn = "U32_FMT"(0x%08lX)\n", pdu->maxcmdsn, pdu->maxcmdsn);
	break;
    case ISCSI_OP_SCSI_DATA_IN:
	log_dbg2("SCSI Data-In (0x%02X)\n", pdu->opcode);
	log_dbg2("  Fbit = %u\n", pdu->Fbit);
	log_dbg2("  Abit = %u\n", pdu->Abit);
	log_dbg2("  Obit = %u\n", pdu->Obit);
	log_dbg2("  Ubit = %u\n", pdu->Ubit);
	log_dbg2("  Sbit = %u\n", pdu->Sbit);
	log_dbg2("  ahslen = "U32_FMT"(0x%08lX)\n", pdu->ahslen, pdu->ahslen);
	log_dbg2("  dslen = "U32_FMT"(0x%08lX)\n", pdu->dslen, pdu->dslen);
	log_dbg2("  lun = %llu(0x%016llX)\n", pdu->lun, pdu->lun);
	log_dbg2("  itt = "U32_FMT"(0x%08lX)\n", pdu->itt, pdu->itt);
	log_dbg2("  ttt = "U32_FMT"(0x%08lX)\n", pdu->ttt, pdu->ttt);
	log_dbg2("  statsn = "U32_FMT"(0x%08lX)\n", pdu->statsn, pdu->statsn);
	log_dbg2("  expcmdsn = "U32_FMT"(0x%08lX)\n", pdu->expcmdsn, pdu->expcmdsn);
	log_dbg2("  maxcmdsn = "U32_FMT"(0x%08lX)\n", pdu->maxcmdsn, pdu->maxcmdsn);
	log_dbg2("  datasn = "U32_FMT"(0x%08lX)\n", pdu->datasn, pdu->datasn);
	log_dbg2("  bufoffset = "U32_FMT"(0x%08lX)\n", pdu->bufoffset, pdu->bufoffset);
	log_dbg2("  rcount = "U32_FMT"(0x%08lX)\n", pdu->rcount, pdu->rcount);
	break;
    case ISCSI_OP_LOGOUT_RSP:
	log_dbg2("Logout Response (0x%02X)\n", pdu->opcode);
	log_dbg2("  Fbit = %u\n", pdu->Fbit);
	log_dbg2("  response = %u(0x%02X)\n", pdu->response, pdu->response);
	log_dbg2("  ahslen = "U32_FMT"(0x%08lX)\n", pdu->ahslen, pdu->ahslen);
	log_dbg2("  dslen = "U32_FMT"(0x%08lX)\n", pdu->dslen, pdu->dslen);
	log_dbg2("  itt = "U32_FMT"(0x%08lX)\n", pdu->itt, pdu->itt);
	log_dbg2("  statsn = "U32_FMT"(0x%08lX)\n", pdu->statsn, pdu->statsn);
	log_dbg2("  expcmdsn = "U32_FMT"(0x%08lX)\n", pdu->expcmdsn, pdu->expcmdsn);
	log_dbg2("  maxcmdsn = "U32_FMT"(0x%08lX)\n", pdu->maxcmdsn, pdu->maxcmdsn);
	log_dbg2("  time2wait = %u(0x%04X)\n", pdu->time2wait, pdu->time2wait);
	log_dbg2("  time2retain = %u(0x%04X)\n", pdu->time2retain, pdu->time2retain);
	break;
    case ISCSI_OP_R2T:
	log_dbg2("Ready To Transfer (0x%02X)\n", pdu->opcode);
	log_dbg2("  Fbit = %u\n", pdu->Fbit);
	log_dbg2("  ahslen = "U32_FMT"(0x%08lX)\n", pdu->ahslen, pdu->ahslen);
	log_dbg2("  dslen = "U32_FMT"(0x%08lX)\n", pdu->dslen, pdu->dslen);
	log_dbg2("  lun = %llu(0x%016llX)\n", pdu->lun, pdu->lun);
	log_dbg2("  itt = "U32_FMT"(0x%08lX)\n", pdu->itt, pdu->itt);
	log_dbg2("  ttt = "U32_FMT"(0x%08lX)\n", pdu->ttt, pdu->ttt);
	log_dbg2("  statsn = "U32_FMT"(0x%08lX)\n", pdu->statsn, pdu->statsn);
	log_dbg2("  expcmdsn = "U32_FMT"(0x%08lX)\n", pdu->expcmdsn, pdu->expcmdsn);
	log_dbg2("  maxcmdsn = "U32_FMT"(0x%08lX)\n", pdu->maxcmdsn, pdu->maxcmdsn);
	log_dbg2("  r2tsn = "U32_FMT"(0x%08lX)\n", pdu->r2tsn, pdu->r2tsn);
	log_dbg2("  bufoffset = "U32_FMT"(0x%08lX)\n", pdu->bufoffset, pdu->bufoffset);
	log_dbg2("  ddtlen = "U32_FMT"(0x%08lX)\n", pdu->ddtlen, pdu->ddtlen);
	break;
    case ISCSI_OP_ASYNC_MSG:
    case ISCSI_OP_REJECT:
    default:
	ASSERT((0), "NOT IMPLEMENTED YET (pdu->opcode = 0x%02X)\n", pdu->opcode);
	break;
    }
    return;
} // iscsi_dump_pdu


void iscsi_dump_pdu_in_hex(struct iscsi_conn *conn, struct iscsi_pdu *pdu)
{
    uint32 i;

    if (logger_getlv() < LOGLV_DBG2) {
	return;
    }

    printf("&(pdu->bhs)=%p, ISCSI_PDU_BHSLEN=%d\n",
	   &(pdu->bhs), ISCSI_PDU_BHSLEN);
    print_hex((char *)&(pdu->bhs), ISCSI_PDU_BHSLEN);

    printf("pdu->dsvec_cnt=%d\n", pdu->dsvec_cnt);
    if (pdu->dsvec_cnt == 0) {
	return;
    }

    if (pdu->opcode == ISCSI_OP_LOGIN_RSP) {
	if (logger_is_dbg3()) {
	    for (i = 0; i < pdu->dsvec_cnt; i++) {
		log_dbg3("pdu->dsvec["U32_FMT"].{buf=%p, buflen="U32_FMT", offset="U32_FMT", len="U32_FMT"}\n",
			 i, pdu->dsvec[i].buf, pdu->dsvec[i].buflen, pdu->dsvec[i].offset, pdu->dsvec[i].len);
		print_hex((char *)(pdu->dsvec[i].buf + pdu->dsvec[i].offset), pdu->dsvec[i].len);
	    }
	}
    }

    return;
} // iscsi_dump_pdu_in_hex


/**
 * Create iSCSI task
 * This function doesn't create iSCSI PDUs.
 */
struct iscsi_task *iscsi_create_task(struct iscsi_conn *conn, uint32 itt)
{
    struct iscsi_task *task;

    task = malloc_safe(sizeof(struct iscsi_task));
    if (task == NULL) {
	log_err("Unable to allocate memory (struct iscsi_task).\n");
    }

    // initialize
    task->conn = conn;

    task->itt = itt;

    list_init(&(task->list_pdu));

    list_init(&(task->list_page));
    task->page_totallen = 0;
    task->page_filled = 0;

    task->vol = NULL;
    
    task->ttt = 0xFFFFFFFF;
    task->datasn = 0;

    task->laptime.scsi_opcode = 0x00;

    listelem_init(&(task->listelem), task);
    list_add_elem(&(conn->list_task), &(task->listelem));
    
    log_dbg3("Created iSCSI task (itt=0x%08lX, conn->list_task.len="U32_FMT").\n",
	    task->itt, conn->list_task.len);
    return task;
} // iscsi_create_task


/**
 * Remove iSCSI task
 *   This function removes PDUs which are included the task.
 */
int iscsi_remove_task(struct iscsi_conn *conn, struct iscsi_task *task)
{
    struct iscsi_pdu *pdu;

    log_dbg3("Remove iSCSI task (task->list_pdu.len="U32_FMT", conn->list_task.len="U32_FMT", conn->pdus="U32_FMT").\n",
	    task->list_pdu.len, conn->list_task.len, conn->pdus);
    ASSERT((conn->list_task.len > 0), "conn->list_task.len == 0\n");

    list_unlist_elem(&(conn->list_task), &(task->listelem));

    // Removes PDUs which are included the task.
    if (list_is_empty(&(task->list_pdu))) {
	log_dbg3("task->list_pdu is empty\n");
    } else {
	log_dbg3("task->list_pdu is NOT empty\n");
	while (1) {
	    pdu = (struct iscsi_pdu *)list_unlist_head_elem(&(task->list_pdu));
	    if (pdu == NULL) {
		break;
	    }
	    iscsi_dump_pdu(conn, pdu);
	    iscsi_remove_pdu(conn, pdu);
	}
    }
    ASSERT(task->list_pdu.head == NULL, "task->list_pdu.head(%p) != NULL\n", task->list_pdu.head);
    ASSERT(task->list_pdu.len == 0, "task->list_pdu.len("U32_FMT") > 0\n", task->list_pdu.len);

    if (! list_is_empty(&(task->list_page))) {
	int rv;
	rv = vol_free_buf(task->vol, &(task->list_page));
	ASSERT((!rv), "rv\n");
    }
    free_safe(task, sizeof(struct iscsi_task));

    log_dbg3("Remove iSCSI task (conn->task_cnt="U32_FMT", conn->pdus="U32_FMT").\n",
	    conn->list_task.len, conn->pdus);

    return 0;
} // iscsi_remove_task


/**
 * Create an iSCSI PDU
 */
struct iscsi_pdu *iscsi_create_pdu(struct iscsi_conn *conn)
{
    struct iscsi_pdu *pdu;

    pdu = malloc_safe(sizeof(struct iscsi_pdu));
    if (pdu == NULL) {
	log_err("Unable allocate PDU.\n");
	return NULL;
    }

    pdu->Sbit = 0;
    
    pdu->ahsbuf = NULL;
    pdu->ahsbuflen = 0;

    pdu->dsvec_cnt = 0;
    pdu->dsvec_offset = 0;
    pdu->dsvec_len = 0;

    pdu->task = NULL;
    pdu->conn = conn;

    listelem_init(&(pdu->listelem_conn), pdu);
    listelem_init(&(pdu->listelem_task), pdu);
    listelem_init(&(pdu->listelem_rxtx), pdu);

    conn->pdus++;

    log_dbg3("Created iSCSI PDU (conn->pdus="U32_FMT").\n", conn->pdus);

    return pdu;
} // iscsi_create_pdu


/**
 * Destroy an iSCSI PDU
 */
void iscsi_remove_pdu(struct iscsi_conn *conn, struct iscsi_pdu *pdu)
{
    uint32 i;

    log_dbg3("Remove PDU (opcode=0x%02X, ITT=0x%08lX\n",
	    pdu->opcode, pdu->itt);

    for (i = 0; i < pdu->dsvec_cnt; i++) {
	ASSERT(pdu->dsvec[i].buf != NULL,
	       "pdu->dsvec["U32_FMT"].buf == NULL\n");
	log_dbg3("pdu->dsvec["U32_FMT"].{buf=%p, buflen="U32_FMT", offset="U32_FMT", len="U32_FMT", page=%p}\n",
		i,
		pdu->dsvec[i].buf,
		pdu->dsvec[i].buflen, 
		pdu->dsvec[i].offset,
		pdu->dsvec[i].len,
		pdu->dsvec[i].page);
	if (pdu->dsvec[i].page == NULL) {
	    log_dbg3("pdu->dsvec["U32_FMT"].page == NULL\n", i);
	    iscsi_free_dsbuf(conn, pdu->dsvec[i].buf, pdu->dsvec[i].buflen);
	} else {
	    log_dbg3("pdu->dsvec["U32_FMT"].page(%p) != NULL\n", i, pdu->dsvec[i].page);
	    if (pdu->task != NULL) {
		ASSERT((pdu->task->list_page.len > 0),
		       "pdu->task->list_page.len == 0\n");
		ASSERT((pdu->task->list_page.head != NULL),
		       "pdu->task->list_page.head == NULL\n");
	    }
	}
    }
    log_dbg3("Free an iSCSI PDU (pdu->{opcode=0x%02X, itt=0x%08lX}, conn->pdus="U32_FMT").\n",
	    pdu->opcode, pdu->itt, conn->pdus-1);

    free_safe(pdu, sizeof(struct iscsi_pdu));

    conn->pdus--;

    return;
} // iscsi_remove_pdu


/*********************************************************************
 * PRIVATE FUNCTIONS
 *********************************************************************/
/**
 * Lookup volume object by LUN
 * 
 * @param[in] conn   An iSCSI connection
 * @param[in] lun    LUN (logical unit number)
 * @return           An volume object.
 */
static struct volume *lookup_volume(struct iscsi_conn *conn, uint64 lun)
{
    struct volume *vol;

    if (list_is_empty(&(conn->target->list_vol))) {
	log_dbg3("no volues.\n");
	return NULL;
    }

    do_each_list_elem(struct volume *, &(conn->target->list_vol), vol, listelem) {
	log_dbg3("vol->lun=%llu, lun=%llu\n", vol->lun, lun);
	if (vol->lun == lun) {
	    return vol;
	}
    } while_each_list_elem(struct volume *, &(conn->target->list_vol), vol, listelem);
 
   return NULL;
} // lookup_volume
