#include <string.h> // memset
#include <errno.h>  // 

#include "iscsi.h"
#include "misc.h"
#include "debug.h"
#include "scsi.h"
#include "vol.h"
#include "target.h"

#define SCSI_EVPD_MASK 0x01 // Inquiry
#define SCSI_CMDT_MASK 0x02 // Inquiry

#define SCSI_RDPROTECT_MASK    0xE0
#define SCSI_WRPROTECT_MASK    0xE0
#define SCSI_VRPROTECT_MASK    0xE0
#define SCSI_DPO_MASK          0x08
#define SCSI_VERF10_DPO_MASK   0x10
#define SCSI_BYTECHECK_MASK    0x02
#define SCSI_FUA_NV_MASK       0x02
#define SCSI_GROUP_NUMBER_MASK 0x1F
#define SCSI_SERVICE_ACTION_MASK 0x1F
#define SCSI_SYNC_NV_MASK 0x04
#define SCSI_IMMED_MASK   0x02

#define INQUIRY_VERSION_SPC2 0x04
#define INQUIRY_TRMTSK   0x40 // terminate task management functions
#define INQUIRY_NORMACA  0x20 // normal ACA supported
#define INQUIRY_HISUP    0x10 // hierarchical addressing mode support
#define INQUIRY_FORMAT   0x02 // response data format : SPC-2/3/4
#define INQUIRY_CMDQUE   0x02 // supports the command queueing in SAM-4

#define PAGECODE_SUPPORTED_PAGES 0x00 // supported vital product data pages
#define PAGECODE_UNIT_SERIAL_NUM 0x80 // unit serial number
#define PAGECODE_DEVICE_ID       0x83 // device identification



#define ISCSI_STATUS_GOOD                 0x00
#define ISCSI_STATUS_CHECK_CONDITION      0x02
#define ISCSI_STATUS_BUSY                 0x08
#define ISCSI_STATUS_RESERVATION_CONFLICT 0x18
#define ISCSI_STATUS_TASK_SET_FULL        0x28
#define ISCSI_STATUS_ACA_ACTIVE           0x30
#define ISCSI_STATUS_TASK_ABORTED         0x40

#define ISCSI_RESPONSE_COMPLETE           0x00
#define ISCSI_RESPONSE_TARGET_FAILURE     0x01


static int exec_report_luns(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd);
static int exec_inquiry(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd);
static int exec_read_capacity(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd);
static int exec_read(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd);
static int exec_write(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd);
static int exec_mode_sense_6(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd);
static int exec_test_unit_ready(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd);
static int exec_verify(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd);
static int exec_servact_in(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd);
static int exec_reserve(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd);
static int exec_release(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd);
static int exec_sync_cache(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd);

static int create_and_send_scsidata_in_by_page(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct list *list_page,
    uint32 page_totallen);
static int create_and_send_scsidata_in(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    byte *dsbuf,
    uint32 dsbuflen,
    uint32 dslen);
static struct iscsi_pdu *create_scsi_data_in(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req);
static int create_and_send_scsi_rsp(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    uint8 response,
    uint8 status,
    uint8 sense_key,
    uint8 asc,
    uint8 ascq);
static int create_and_send_r2t(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    uint32 bufoffset,
    uint32 ddtlen);

static int enqueue_volcmd(
    struct iscsi_conn *conn,
    struct volume *vol,
    struct scsi_cmd *scsicmd,
    struct list *list_page,
    uint32 page_totallen,
    void *data);

/*********************************************************************
 * PUBLIC FUNCTIONS
 *********************************************************************/
/**
 * Execute SCSI command completion.
 * @param[in,out] conn             An iSCSI connection thread.
 * @param[in]     pdu_req          An iSCSI PDU.
 * @param[in]     cmd              A SCSI command.
 * @retval        0                success
 * @retval        "negative value" failure
 */
int iscsi_exec_scsi_cmd_completion(
struct iscsi_conn *conn,
struct iscsi_pdu *pdu_req,
struct volume_cmd *cmd)
{
    int rv;

    // ToDo: renew
    switch (cmd->opcode) {
    case VOLUME_OP_READ:
	rv = create_and_send_scsidata_in_by_page(conn,
						 pdu_req,
						 &(cmd->list_page),
						 cmd->page_totallen);
	break;
    case VOLUME_OP_WRITE:
	rv = create_and_send_scsi_rsp(conn, pdu_req,
				      ISCSI_RESPONSE_COMPLETE, ISCSI_STATUS_GOOD,
				      SCSI_SENSE_KEY_NO_SENSE,
				      0x00, 0x00);
	break;
    default:
	ASSERT((0),
	       "Detected an illegal opcode (cmd->opcode=0x%02X).\n",
	       cmd->opcode);
    }
    if (rv) {
	goto failure;
    }

    return 0;

failure:
    return -1;
} // iscsi_exec_scsi_cmd_completion


/**
 * Check LU reservation.
 * @param[in,out] conn             An iSCSI connection thread.
 * @param[in]     pdu              An iSCSI PDU.
 * @retval        0                success
 * @retval        "negative value" failure
 */
static int check_lu_reservation(struct iscsi_conn *conn, struct iscsi_pdu *pdu)
{
    struct volume *vol = pdu->vol;
    int rv;

    rv = vol_is_reserved(vol, conn);
    if (rv == -ENOENT) {
	return 0;
    } else if (rv == -EBUSY) {
	switch (pdu->cmd.opcode) {
	case SCSI_OP_INQUIRY:
	case SCSI_OP_RELEASE_6:
	case SCSI_OP_REPORT_LUNS:
	case SCSI_OP_REQUEST_SENSE:
	case SCSI_OP_READ_CAPACITY:
	    break;
	case SCSI_OP_SERVICE_ACTION_IN_16:
	    if (pdu->cmd.service_action == SCSI_SERV_ACT_IN_READ_CAPACITY_16) {
		break;
	    }
	    // fall through
	default:
	    rv = create_and_send_scsi_rsp(conn, pdu,
					  ISCSI_RESPONSE_COMPLETE,
					  ISCSI_STATUS_RESERVATION_CONFLICT,
					  SCSI_SENSE_KEY_NO_SENSE,
					  0x00, 0x00);
	    if (rv) {
		return -1;
	    }
	    return 1;
	    break;
	}
    }
    return 0;
} // check_lu_reservation


/**
 * Execute SCSI Command PDU
 * @param[in,out] conn             An iSCSI connection thread.
 * @param[in]     pdu              An iSCSI PDU.
 * @retval        0                success
 * @retval        "negative value" failure
 */
int iscsi_exec_scsi_cmd(struct iscsi_conn *conn, struct iscsi_pdu *pdu)
{
    int rv;

    rv = check_lu_reservation(conn, pdu);
    if (rv == -1) {
	return -1;
    } else if (rv == 1) {
	return 0;
    }

    switch (pdu->cmd.opcode) {
    case SCSI_OP_REPORT_LUNS:
	rv = exec_report_luns(conn, pdu, &(pdu->cmd));
	break;
    case SCSI_OP_INQUIRY:
	rv = exec_inquiry(conn, pdu, &(pdu->cmd));
	break;
    case SCSI_OP_READ_CAPACITY:
	rv = exec_read_capacity(conn, pdu, &(pdu->cmd));
	break;
//    case SCSI_OP_READ_6:
    case SCSI_OP_READ_10:
//    case SCSI_OP_READ_16:
	rv = exec_read(conn, pdu, &(pdu->cmd));
	break;
    case SCSI_OP_WRITE_10:
	rv = exec_write(conn, pdu, &(pdu->cmd));
	break;
    case SCSI_OP_MODE_SENSE_6:
	rv = exec_mode_sense_6(conn, pdu, &(pdu->cmd));
	break;
    case SCSI_OP_TEST_UNIT_READY:
	rv = exec_test_unit_ready(conn, pdu, &(pdu->cmd));
	break;
// case SCSI_OP_VERIFY_6:
    case SCSI_OP_VERIFY_10:
// case SCSI_OP_VERIFY_16:
	rv = exec_verify(conn, pdu, &(pdu->cmd));
	break;
    case SCSI_OP_SERVICE_ACTION_IN_16:
	rv = exec_servact_in(conn, pdu, &(pdu->cmd));
	break;
    case SCSI_OP_RESERVE_6:
	rv = exec_reserve(conn, pdu, &(pdu->cmd));
	break;
    case SCSI_OP_RELEASE_6:
	rv = exec_release(conn, pdu, &(pdu->cmd));
	break;
    case SCSI_OP_SYNC_CACHE_10:
	rv = exec_sync_cache(conn, pdu, &(pdu->cmd));
	break;
    default:
	log_err("SCSI Opcode 0x%02X is not supported yet.\n", pdu->cmd.opcode);
	rv = create_and_send_scsi_rsp(conn, pdu, ISCSI_RESPONSE_COMPLETE,
				      ISCSI_STATUS_CHECK_CONDITION,
				      SCSI_SENSE_KEY_ILLEGAL_REQUEST,
				      0x20, 0x00);
	break;
    }

    log_dbg3("rv = %d\n", rv);
    return rv;
} // iscsi_exec_scsi_cmd


/*********************************************************************
 * PRIVATE FUNCTIONS
 *********************************************************************/
/**
 * Execute Read command.
 * @param[in,out] conn             An iSCSI connection thread.
 * @param[in]     pdu_req          An iSCSI PDU.
 * @param[in]     cmd              A SCSI command.
 * @retval        0                success
 * @retval        "negative value" failure
 */
static int exec_read(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd)
{
    struct volume *vol = pdu_req->vol;
    int rv = 0;

    log_dbg3("vol = %p\n", vol);
    if (vol == NULL) {
	goto sense_key;
    }

    // allocate buffer vector
    log_dbg3("cmd->lba=%llu(0x%016llX)\n", cmd->lba, cmd->lba);
    log_dbg3("cmd->trans_len="U32_FMT"(0x%08lX)\n", cmd->trans_len, cmd->trans_len);

    ASSERT((pdu_req->task != NULL), "pdu_req->task == NULL\n");

    rv = enqueue_volcmd(conn, vol, cmd, NULL, 0, pdu_req);
    if (rv) {
	goto failure;
    }

    return 0;

sense_key:
    ASSERT(0, "NOT IMPLEMENTED YET\n");
    return 0;

failure:
    return -1;
} // exec_read


/**
 * Execute Write command.
 * @param[in,out] conn             An iSCSI connection thread.
 * @param[in]     pdu_req          An iSCSI PDU.
 * @param[in]     cmd              A SCSI command.
 * @retval        0                success
 * @retval        "negative value" failure
 */
static int exec_write(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd)
{
    struct volume *vol = pdu_req->vol;
    struct iscsi_task *task = NULL;
    int rv = 0;

    log_dbg3("vol = %p\n", vol);
    if (vol == NULL) {
	goto sense_key;
    }

    task = pdu_req->task;

    log_dbg3("task->page_filled("U32_FMT"(0x%08lX)), pdu_req->expdtlen("U32_FMT"(0x%08lX))\n",
	    task->page_filled, task->page_filled,
	    pdu_req->expdtlen, pdu_req->expdtlen);

    if (task->page_filled < pdu_req->expdtlen) {
	ASSERT((task->page_totallen == pdu_req->expdtlen),
	       "task->page_totallen("U32_FMT"(0x%08lX)) != pdu_req->expdtlen("U32_FMT"(0x%08lX))\n",
	       task->page_totallen, task->page_totallen,
	       pdu_req->expdtlen, pdu_req->expdtlen);
	log_dbg3("Send R2T\n");
	rv = create_and_send_r2t(conn, pdu_req,
				 task->page_filled,
				 pdu_req->expdtlen - task->page_filled);
	return rv;
    }

    // allocate buffer vector
    log_dbg3("cmd->lba=%llu(0x%016llX)\n", cmd->lba, cmd->lba);
    log_dbg3("cmd->trans_len="U32_FMT"(0x%08lX)\n", cmd->trans_len, cmd->trans_len);

    page_dump_list(&(task->list_page), "task->list_page");
    log_dbg3("task->page_totallen = "U32_FMT"\n", task->page_totallen);
    
    // build volcmd

    rv = enqueue_volcmd(conn, vol, cmd,
			&(task->list_page), task->page_totallen,
			pdu_req);
    if (rv) {
	goto failure;
    }

    return 0;

sense_key:
    ASSERT(0, "NOT IMPLEMENTED YET\n");
    return 0;

failure:
    return -1;
} // exec_write


/**
 * Execute ServiceActionIn command.
 * @param[in,out] conn             An iSCSI connection thread.
 * @param[in]     pdu_req          An iSCSI PDU.
 * @param[in]     cmd              A SCSI command.
 * @retval        0                success
 * @retval        "negative value" failure
 */
static int exec_servact_in(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd)
{
    struct volume *vol = pdu_req->vol;
    uint32 dsbuflen;
    byte *dsbuf;
    int rv;

    switch (cmd->service_action) {
    case SCSI_SERV_ACT_IN_READ_CAPACITY_16:
	break;
    default:
	// NOT SUPPORTED YET
	goto sense_key;
    }

    dsbuflen = 12;

    if (cmd->pmi) {
	log_err("PMI=1 is not supported yet.\n");
	abort();
    }

    dsbuf = iscsi_alloc_dsbuf(conn, dsbuflen);
    if (dsbuf == NULL) {
	goto failure;
    }
    memset(dsbuf, 0x0, dsbuflen);

    *(uint64 *)(&dsbuf[0]) = cpu_to_be64(vol->capacity - 1);
    *(uint32 *)(&dsbuf[8]) = cpu_to_be32(vol->sector_size);

    ASSERT(dsbuf != NULL, "dsbuf == NULL");
    ASSERT(dsbuflen > 0, "dsbuflen == 0");

    // ToDo : check pdu->expdtlen == cmd->alloc_len
    rv = create_and_send_scsidata_in(conn, pdu_req, dsbuf, dsbuflen, dsbuflen);
    return rv;

sense_key:
    // ToDo : send sense key
    ASSERT((0), "NOT IMPLEMENTED YET!\n");
    return 0;

failure:
    return -1;
} // exec_read_capacity


/**
 * Execute ReadCapacity command.
 * @param[in,out] conn             An iSCSI connection thread.
 * @param[in]     pdu_req          An iSCSI PDU.
 * @param[in]     cmd              A SCSI command.
 * @retval        0                success
 * @retval        "negative value" failure
 */
static int exec_read_capacity(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd)
{
    struct volume *vol = pdu_req->vol;
    uint32 dsbuflen;
    byte *dsbuf;
    int rv;

    dsbuflen = 8;

    if (cmd->pmi) {
	log_err("PMI=1 is not supported yet.\n");
	goto sense_key;
    }

    dsbuf = iscsi_alloc_dsbuf(conn, dsbuflen);
    if (dsbuf == NULL) {
	goto failure;
    }
    memset(dsbuf, 0x0, dsbuflen);

    *(uint32 *)(&dsbuf[0]) = (vol->capacity >> 32) ?
	0xFFFFFFFF : cpu_to_be32(vol->capacity - 1);
    *(uint32 *)(&dsbuf[4]) = cpu_to_be32(vol->sector_size);

    ASSERT(dsbuf != NULL, "dsbuf == NULL");
    ASSERT(dsbuflen > 0, "dsbuflen == 0");

    // ToDo : check pdu->expdtlen == cmd->alloc_len
    rv = create_and_send_scsidata_in(conn, pdu_req, dsbuf, dsbuflen, dsbuflen);
    return rv;

sense_key:
    // ToDo : send sense key
    ASSERT((0), "NOT IMPLEMENTED YET!\n");
    return 0;
failure:
    return -1;
} // exec_read_capacity


/**
 * Execute Inquiry command.
 * @param[in,out] conn             An iSCSI connection thread.
 * @param[in]     pdu_req          An iSCSI PDU.
 * @param[in]     cmd              A SCSI command.
 * @retval        0                success
 * @retval        "negative value" failure
 */
static int exec_inquiry(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd)
{
    byte *dsbuf = NULL;
    uint32 dsbuflen = 0;
    int rv = 0;
    struct volume *vol;

    vol = pdu_req->vol;

    log_dbg3("cmd->cmdt=%u, cmd->evpd=%u, cmd->page_code=0x%02X\n",
	    cmd->cmdt, cmd->evpd, cmd->page_code);

    if ((cmd->cmdt && cmd->evpd) || (!cmd->evpd && cmd->page_code)) {
	log_err("Detected an illegal INQUIRY command (CMDT=%u, EVPD=%u, page_code=0x%02X).\n",
		cmd->cmdt, cmd->evpd, cmd->page_code);
	// ToDo  : implement error handling code
	abort();
    }

    if ((!cmd->cmdt) && (!cmd->evpd)) {
	dsbuflen = 36;
	dsbuf = iscsi_alloc_dsbuf(conn, dsbuflen);
	if (dsbuf == NULL) {
	    goto failure;
	}
	memset(dsbuf, 0x00, dsbuflen);
	dsbuf[2] = INQUIRY_VERSION_SPC2; // version
	dsbuf[3] = INQUIRY_TRMTSK | INQUIRY_HISUP | INQUIRY_FORMAT; // flags
	dsbuf[4] = (dsbuflen-5);         // allocation length
	dsbuf[5] = 0x00;                 // flags
	dsbuf[6] = 0x00;                 // flags
	dsbuf[7] = INQUIRY_CMDQUE;
	memset(&dsbuf[8], ' ', 8);
	memcpy(&dsbuf[8], SCSI_VENDOR_ID,
	       min(sizeof(SCSI_VENDOR_ID), SCSI_VENDOR_ID_MAXLEN));
	memset(&dsbuf[16], ' ', 16);
	memcpy(&dsbuf[16], SCSI_PRODUCT_ID,
	       min(sizeof(SCSI_PRODUCT_ID), SCSI_PRODUCT_ID_MAXLEN));
	memset(&dsbuf[32], ' ', 4);
	memcpy(&dsbuf[32], SCSI_PRODUCT_REV,
	       min(sizeof(SCSI_PRODUCT_REV), SCSI_PRODUCT_REV_MAXLEN));
    } else if (cmd->evpd) {
	switch (cmd->page_code) {
	case PAGECODE_SUPPORTED_PAGES:
	    dsbuflen = (4 + 3); // header + page length (# of VDP parameters)
	    dsbuf = iscsi_alloc_dsbuf(conn, dsbuflen);
	    if (dsbuf == NULL) {
		goto failure;
	    }
	    memset(dsbuf, 0x00, dsbuflen);
	    dsbuf[0] = 0x00; // peripheral qualifier and device type
	    dsbuf[1] = PAGECODE_SUPPORTED_PAGES; // page code
	    dsbuf[2] = 0x00;                     // page length (MSB)
	    dsbuf[3] = 0x03;                     // page length (LSB)
	    dsbuf[4] = PAGECODE_SUPPORTED_PAGES; // VPD parameters (1)
	    dsbuf[5] = PAGECODE_UNIT_SERIAL_NUM; // VPD parameters (2)
	    dsbuf[6] = PAGECODE_DEVICE_ID;       // VPD parameters (3)
	    break;
	case PAGECODE_UNIT_SERIAL_NUM:
	    dsbuflen = 4 + SCSI_SN_MAXLEN; // header + SCSI serial number length
	    dsbuf = iscsi_alloc_dsbuf(conn, dsbuflen);
	    if (dsbuf == NULL) {
		goto failure;
	    }
	    memset(dsbuf, 0x00, dsbuflen);
	    dsbuf[0] = 0x00; // peripheral qualifier and device type
	    dsbuf[1] = PAGECODE_UNIT_SERIAL_NUM; // page code
	    dsbuf[2] = 0x00;                     // page length (MSB)
	    dsbuf[3] = SCSI_SN_MAXLEN;              // page length (LSB)
	    memcpy(&dsbuf[4], vol->scsi_sn, SCSI_SN_MAXLEN);
	    break;
	case PAGECODE_DEVICE_ID:
	    dsbuflen = (4 + 4 + SCSI_VENDOR_ID_MAXLEN + SCSI_ID_MAXLEN);
	    dsbuf = iscsi_alloc_dsbuf(conn, dsbuflen);
	    if (dsbuf == NULL) {
		goto failure;
	    }
	    memset(dsbuf, 0x00, dsbuflen);
	    dsbuf[0] = 0x00; // peripheral qualifier and device type
	    dsbuf[1] = PAGECODE_DEVICE_ID;       // page code
	    dsbuf[2] = 0x00;                     // page length (MSB)
	    dsbuf[3] = 4 + SCSI_VENDOR_ID_MAXLEN + SCSI_ID_MAXLEN; // page length (LSB)
	    dsbuf[4] = 0x01;
	    dsbuf[5] = 0x01;
	    dsbuf[6] = 0x00;
	    dsbuf[7] = SCSI_VENDOR_ID_MAXLEN + SCSI_ID_MAXLEN;
	    memcpy(&dsbuf[8], SCSI_VENDOR_ID, SCSI_VENDOR_ID_MAXLEN);
	    memcpy(&dsbuf[8+SCSI_VENDOR_ID_MAXLEN],
		   vol->scsi_id,
		   SCSI_ID_MAXLEN);
	    break;
	default:
	    log_err("INQUIRY / Page code 0x%02X is not supported yet.\n",
		    cmd->page_code);
	    goto sense_key;
	}
    }

    ASSERT(dsbuf != NULL, "dsbuf == NULL");
    ASSERT(dsbuflen > 0, "dsbuflen == 0");

    // ToDo : check pdu->expdtlen == cmd->alloc_len
    uint32 dslen = min(dsbuflen, cmd->alloc_len);
    log_dbg3("dslen = "U32_FMT"\n", dslen);
    rv = create_and_send_scsidata_in(conn, pdu_req, dsbuf, dsbuflen, dslen);
    log_dbg3("rv = %d\n", rv);
    return rv;

sense_key:
    rv = create_and_send_scsi_rsp(conn, pdu_req,
				  ISCSI_RESPONSE_COMPLETE,
				  ISCSI_STATUS_CHECK_CONDITION,
				  SCSI_SENSE_KEY_ILLEGAL_REQUEST,
				  0x24, 0x00);
    return rv;
failure:
    return -1;
} // exec_inquiry


/**
 * Execute TestUnitReady command.
 * @param[in,out] conn             An iSCSI connection thread.
 * @param[in]     pdu_req          An iSCSI PDU.
 * @param[in]     cmd              A SCSI command.
 * @retval        0                success
 * @retval        "negative value" failure
 */
static int exec_test_unit_ready(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd)
{
    int rv;
    rv = create_and_send_scsi_rsp(conn, pdu_req,
				  ISCSI_RESPONSE_COMPLETE, ISCSI_STATUS_GOOD,
				  SCSI_SENSE_KEY_NO_SENSE,
				  0x00, 0x00);
    return rv;
} // exec_test_unit_ready


/**
 * Execute SynchronizedCache command.
 * @param[in,out] conn             An iSCSI connection thread.
 * @param[in]     pdu_req          An iSCSI PDU.
 * @param[in]     cmd              A SCSI command.
 * @retval        0                success
 * @retval        "negative value" failure
 */
static int exec_sync_cache(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd)
{
    int rv;

    rv = vol_sync_cache(pdu_req->vol,
			cmd->lba, cmd->lblocks,
			cmd->sync_nv, cmd->immed);
    if (rv) {
	goto failure;
    }
    rv = create_and_send_scsi_rsp(conn, pdu_req,
				  ISCSI_RESPONSE_COMPLETE, ISCSI_STATUS_GOOD,
				  SCSI_SENSE_KEY_NO_SENSE,
				  0x00, 0x00);
    return rv;

failure:
    rv = create_and_send_scsi_rsp(conn, pdu_req,
				  ISCSI_RESPONSE_COMPLETE, ISCSI_STATUS_CHECK_CONDITION,
				  SCSI_SENSE_KEY_MEDIUM_ERROR,
				  0x03, 0x00);
    return rv;
} // exec_sync_cache


/**
 * Execute Verify command.
 * @param[in,out] conn             An iSCSI connection thread.
 * @param[in]     pdu_req          An iSCSI PDU.
 * @param[in]     cmd              A SCSI command.
 * @retval        0                success
 * @retval        "negative value" failure
 */
static int exec_verify(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd)
{
    int rv;
    rv = create_and_send_scsi_rsp(conn, pdu_req,
				  ISCSI_RESPONSE_COMPLETE, ISCSI_STATUS_GOOD,
				  SCSI_SENSE_KEY_NO_SENSE,
				  0x00, 0x00);
    return rv;
} // exec_test_unit_ready


static uint32 pack_disconn_reconn_page(
    struct iscsi_conn *conn, byte *buf, uint32 buflen);
static uint32 pack_iec_page(
    struct iscsi_conn *conn, byte *buf, uint32 buflen);
static uint32 pack_ctrl_m_page(
    struct iscsi_conn *conn, byte *buf, uint32 buflen);
static uint32 pack_caching_page(
    struct iscsi_conn *conn, byte *buf, uint32 buflen,
    int cache_rw,
    int cache_rd);


/**
 * Execute ModeSense(6) command.
 * @param[in,out] conn             An iSCSI connection thread.
 * @param[in]     pdu_req          An iSCSI PDU.
 * @param[in]     cmd              A SCSI command.
 * @retval        0                success
 * @retval        "negative value" failure
 */
static int exec_mode_sense_6(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd)
{
    struct volume *vol = pdu_req->vol;
    byte *dsbuf;
    uint32 dsbuflen = 1024;
    uint32 dslen = 0;
    int rv;

    log_dbg3("\n");

    if (pdu_req->vol) {
//	if (LUReadonly(cmnd->lun))
//		data[2] = 0x80;
    }

    dsbuf = iscsi_alloc_dsbuf(conn, dsbuflen);
    if (dsbuf == NULL) {
	goto failure;
    }
    memset(dsbuf, 0x0, dsbuflen);

    if (cmd->dbd) {
	// disable block descriptor
	// header / block descriptor length
	dsbuf[3] = 0x00;
	dslen = 4;
    } else {
	// enable block descriptor
	// header / block descriptor length
	dsbuf[3] = 0x08; 

	// block descriptor (short-LBA mode parameter block descriptor)
	// block descriptor / number of logical blocks
	*(uint32 *)(&dsbuf[4]) = (vol->capacity >> 32) ?
	    0xFFFFFFFF : cpu_to_be32(vol->capacity - 1);
	// block destriptor / logical block length
	*(uint32 *)(&dsbuf[8]) = cpu_to_be32(vol->sector_size);

	dslen = 12;
    }

    log_dbg3("cmd->page_code=%u(0x%02X)\n", cmd->page_code, cmd->page_code);

    // pages
    switch (cmd->page_code) {
    case 0x02:
	// Disconnect-Reconnect
	dslen += pack_disconn_reconn_page(conn,
					  &dsbuf[dslen],
					  dsbuflen - dslen);
	break;
    case 0x08:
	// Caching mode
	dslen += pack_caching_page(conn,
				   &dsbuf[dslen],
				   dsbuflen - dslen,
				   vol_does_cache_wr(pdu_req->vol),
				   vol_does_cache_rd(pdu_req->vol));
	break;
    case 0x0A:
	// 
	dslen += pack_ctrl_m_page(conn,
				  &dsbuf[dslen],
				  dsbuflen - dslen);
	break;
    case 0x1C:
	// Informational Exceptions Control
//	ASSERT((cmd->subpage_code == 0x00),
//	       "cmd->subpage_code(0x%02X) != 0x00\n",
//	       cmd->subpage_code);
	dslen += pack_iec_page(conn,
			       &dsbuf[dslen],
			       dsbuflen - dslen);
	break;
    case 0x3F:
	// Returl All Mode Pages
	dslen += pack_disconn_reconn_page(conn,
					  &dsbuf[dslen],
					  dsbuflen - dslen);
	dslen += pack_caching_page(conn,
				   &dsbuf[dslen],
				   dsbuflen - dslen,
				   vol_does_cache_wr(pdu_req->vol),
				   vol_does_cache_rd(pdu_req->vol));
	dslen += pack_ctrl_m_page(conn,
				  &dsbuf[dslen],
				  dsbuflen - dslen);
	dslen += pack_iec_page(conn,
			       &dsbuf[dslen],
			       dsbuflen - dslen);
	break;
    default:
	// NOT IMPLEMENTED YET
	goto sense_key;
    }
    dsbuf[0] = dslen - 1;
    
    // ToDo : check pdu->expdtlen == cmd->alloc_len
    rv = create_and_send_scsidata_in(conn, pdu_req, dsbuf, dsbuflen, dslen);
    return rv;

sense_key:
    // ToDo : send sense key
    ASSERT((0), "NOT IMPLEMENTED YET!\n");
    return 0;

failure:
    return -1;
} // exec_mode_sense_6


/**
 * Pack Mode Sense - Disconnect-Reconnect page.
 **/
static uint32 pack_disconn_reconn_page(
struct iscsi_conn *conn, byte *buf, uint32 buflen)
{
    // Disconnect-Reconnect
    byte page[] = {0x02, 0x0E, 0x80, 0x80,
		   0x00, 0x0A, 0x00, 0x00,
		   0x00, 0x00, 0x00, 0x00,
		   0x00, 0x00, 0x00, 0x00};
    ASSERT((buflen >= sizeof(page)),
	   "buflen("U32_FMT") < sizeof(page)("U32_FMT" bytes)\n",
	   buflen, sizeof(page));
    memcpy(buf, page, sizeof(page));
    return sizeof(page);
} // pack_disconn_reconn_page


static uint32 pack_caching_page(
    struct iscsi_conn *conn, byte *buf, uint32 buflen,
    int cache_rw,
    int cache_rd)
{
    byte page[] = {0x08, 0x12, 0x10, 0x00,
		   0xFF, 0xFF, 0x00, 0x00,
		   0xFF, 0xff, 0xFF, 0xFF,
		   0x80, 0x14, 0x00, 0x00,
		   0x00, 0x00, 0x00, 0x00};
    ASSERT((buflen >= sizeof(page)),
	   "buflen("U32_FMT") < sizeof(page)("U32_FMT" bytes)\n",
	   buflen, sizeof(page));

    memcpy(buf, page, sizeof(page));
    if (cache_rw) {
	// Enable write-back cache
	buf[2] |= 0x04; // WCE bit
    }
    if (!cache_rd) {
	// Disable read cache
	buf[2] |= 0x01;
    }
    return sizeof(page);
} // pack_caching_page


static uint32 pack_ctrl_m_page(
struct iscsi_conn *conn, byte *buf, uint32 buflen)
{
    // 
    byte page[] = {0x0A, 0x0A, 0x02, 0x00,
		   0x00, 0x00, 0x00, 0x00,
		   0x00, 0x00, 0x02, 0x4B};
    ASSERT((buflen >= sizeof(page)),
	   "buflen("U32_FMT") < sizeof(page)("U32_FMT" bytes)\n",
	   buflen, sizeof(page));
    memcpy(buf, page, sizeof(page));
    return sizeof(page);
} // pack_ctrl_m_page


/**
 * Pack Mode Sense - Informational Exceptions Control page.
 **/
static uint32 pack_iec_page(
struct iscsi_conn *conn, byte *buf, uint32 buflen)
{
    // Informational Exceptions Control
    byte page[] = {0x1C, 0x0A, 0x08, 0x00,
		   0x00, 0x00, 0x00, 0x00,
		   0x00, 0x00, 0x00, 0x00};
    ASSERT((buflen >= sizeof(page)),
	   "buflen("U32_FMT") < sizeof(page)("U32_FMT" bytes)\n",
	   buflen, sizeof(page));
    memcpy(buf, page, sizeof(page));
    return sizeof(page);
} // pack_iec_page


/**
 * Execute Reserve command.
 * @param[in,out] conn             An iSCSI connection thread.
 * @param[in]     pdu_req          An iSCSI PDU.
 * @param[in]     cmd              A SCSI command.
 * @retval        0                success
 * @retval        "negative value" failure
 */
static int exec_reserve(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd)
{
    ASSERT((conn != NULL), "conn == NULL\n");
    ASSERT((pdu_req != NULL), "pdu_req == NULL\n");
    ASSERT((cmd != NULL), "cmd == NULL\n");

    int rv;

    rv = vol_reserve(pdu_req->vol, conn);
    if (!rv) {
	rv = create_and_send_scsi_rsp(conn, pdu_req,
				      ISCSI_RESPONSE_COMPLETE, ISCSI_STATUS_GOOD,
				      SCSI_SENSE_KEY_NO_SENSE,
				      0x00, 0x00);
    } else if (rv == -ENOENT) {
	rv = create_and_send_scsi_rsp(conn, pdu_req,
				      ISCSI_RESPONSE_COMPLETE,
				      ISCSI_STATUS_CHECK_CONDITION,
				      SCSI_SENSE_KEY_ILLEGAL_REQUEST,
				      0x25, 0x00);
    } else if (rv == -EBUSY) {
	rv = create_and_send_scsi_rsp(conn, pdu_req,
				      ISCSI_RESPONSE_COMPLETE,
				      ISCSI_STATUS_RESERVATION_CONFLICT,
				      SCSI_SENSE_KEY_NO_SENSE,
				      0x00, 0x00);
    } else {
	ASSERT((0), "rv=%d\n", rv);
    }
    return rv;
} // exec_reserve


/**
 * Execute Release command.
 * @param[in,out] conn             An iSCSI connection thread.
 * @param[in]     pdu_req          An iSCSI PDU.
 * @param[in]     cmd              A SCSI command.
 * @retval        0                success
 * @retval        "negative value" failure
 */
static int exec_release(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd)
{
    ASSERT((conn != NULL), "conn == NULL\n");
    ASSERT((pdu_req != NULL), "pdu_req == NULL\n");
    ASSERT((cmd != NULL), "cmd == NULL\n");

    int rv;

    rv = vol_release(pdu_req->vol, conn, 0);
    if (!rv) {
	rv = create_and_send_scsi_rsp(conn, pdu_req,
				      ISCSI_RESPONSE_COMPLETE, ISCSI_STATUS_GOOD,
				      SCSI_SENSE_KEY_NO_SENSE,
				      0x00, 0x00);
    } else if (rv == -ENOENT) {
	rv = create_and_send_scsi_rsp(conn, pdu_req,
				      ISCSI_RESPONSE_COMPLETE,
				      ISCSI_STATUS_CHECK_CONDITION,
				      SCSI_SENSE_KEY_ILLEGAL_REQUEST,
				      0x25, 0x00);
    } else if (rv == -EBUSY) {
	rv = create_and_send_scsi_rsp(conn, pdu_req,
				      ISCSI_RESPONSE_COMPLETE,
				      ISCSI_STATUS_RESERVATION_CONFLICT,
				      SCSI_SENSE_KEY_NO_SENSE,
				      0x00, 0x00);
    } else {
	ASSERT((0), "rv=%d\n", rv);
    }

    return rv;
} // exec_release


/**
 * Execute ReportLUNs command.
 * @param[in,out] conn             An iSCSI connection thread.
 * @param[in]     pdu_req          An iSCSI PDU.
 * @param[in]     cmd              A SCSI command.
 * @retval        0                success
 * @retval        "negative value" failure
 */
static int exec_report_luns(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct scsi_cmd *cmd)
{
    struct iscsi_target *target;
    int dsbuflen;
    byte *dsbuf;
    uint32 lun_list_len;
    uint32 remain;
    byte *p;
    struct volume *vol;
    int rv;

    ASSERT((conn != NULL), "conn == NULL\n");
    ASSERT((pdu_req != NULL), "pdu_req == NULL\n");
    ASSERT((cmd != NULL), "cmd == NULL\n");

    target = conn->target;
    rv = 0;

    if (cmd->alloc_len < 16) {
	// ToDo
	//   send ScsiResponse(ILLEGAL_REQUEST, 0x24, 0x0)
	ASSERT(0, "Not implemented yet\n");
	goto sense_key;
    }

    log_dbg3("conn->target->list_vol.len=%llu\n", conn->target->list_vol.len);
    lun_list_len = conn->target->list_vol.len * 8;
    log_dbg3("cmd->alloc_len="U32_FMT", lun_list_len="U32_FMT"\n",
	    cmd->alloc_len, lun_list_len);

    dsbuflen = min(cmd->alloc_len, lun_list_len + 8);
    log_dbg3("dsbuflen="U32_FMT"\n", dsbuflen);
    if (dsbuflen < 16) {
	goto sense_key;
    }

    dsbuf = iscsi_alloc_dsbuf(conn, dsbuflen);
    if (dsbuf == NULL) {
	goto failure;
    }
    memset(dsbuf, 0x0, dsbuflen);

    // pack to SCSI Data-In buffer
    // 1) LUN list length
    p = dsbuf;
    remain = dsbuflen;
    *((uint32 *)p) = cpu_to_be32(lun_list_len);
    p += sizeof(uint32);
    remain -= sizeof(uint32);
    // 2) Reserved
    p += sizeof(uint32);
    remain -= sizeof(uint32);
    // 3) LUN list
    do_each_list_elem(struct volume *, &(target->list_vol), vol, listelem) {
	log_dbg3("vol->lun=%llu, remain="U32_FMT"\n", vol->lun, remain);
	if (remain == 0) {
	    break;
	}
	ASSERT((vol->lun <= SCSI_LUN_MAX), "vol->lun > SCSI_LUN_MAX");
	*((uint64 *)p) = cpu_to_be64(scsi_pack_lun(vol->lun));
//	uint16 lun_16 = (uint16)vol->lun;
//	 = cpu_to_be16(lun_16 | ((vol->lun > 0xFF) ? (0x01 << 14) : 0));
	log_dbg1("*(uint64 *)p = %u\n", *((uint64 *)p));
	p += sizeof(uint64);
	remain -= sizeof(uint64);
    } while_each_list_elem(struct volume *, &(target->list_vol), vol, listelem);

    // ToDo : check pdu->expdtlen == cmd->alloc_len
    rv = create_and_send_scsidata_in(conn, pdu_req, dsbuf, dsbuflen, dsbuflen);
    return rv;
sense_key:
    // ToDo : send sense key
    ASSERT((0), "NOT IMPLEMENTED YET!\n");
    return 0;
failure:
    return -1;
} // exec_report_luns


static int create_and_send_r2t(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    uint32 bufoffset,
    uint32 ddtlen)
{
    struct iscsi_task *task = NULL;
    struct iscsi_pdu *pdu_rsp = NULL;
    int rv;

    ASSERT(pdu_req->opcode == ISCSI_OP_SCSI_CMD,
	   "pdu_req->opcode(0x%02X) != ISCSI_OP_SCSI_CMD(0x%02X)\n",
	   pdu_req->opcode, ISCSI_OP_SCSI_CMD);
    ASSERT(pdu_req->cmd.opcode == SCSI_OP_WRITE_10,
	   "pdu_req->cmd.opcode(0x%02X) != ISCSI_OP_WRITE_10(0x%02X)\n",
	   pdu_req->cmd.opcode, SCSI_OP_WRITE_10);

    log_dbg3("bufoffset="U32_FMT"(0x%08lX), ddtlen="U32_FMT"(0x%08lX)\n",
	    bufoffset, bufoffset,
	    ddtlen, ddtlen);

    task = pdu_req->task;

    pdu_rsp = iscsi_create_pdu(conn);
    if (pdu_rsp == NULL) {
	goto failure;
    }
    pdu_rsp->opcode = ISCSI_OP_R2T;
    pdu_rsp->Fbit = 1;
    pdu_rsp->ahslen = 0;
    pdu_rsp->dslen = 0;
    pdu_rsp->itt = pdu_req->itt;
    pdu_rsp->ttt = conn->ttt;
    task->ttt = conn->ttt;
    conn->ttt++;

    pdu_rsp->r2tsn = 0;
    pdu_rsp->bufoffset = bufoffset;
    pdu_rsp->ddtlen = ddtlen;

    pdu_rsp->dsvec_cnt = 0;
    pdu_rsp->dslen = 0;

    // add PDU to task and send
    rv = iscsi_add_pdu_to_task(conn, pdu_req->task, pdu_rsp);
    if (rv) {
	goto failure;
    }
    rv = iscsi_enqueue_and_tx_pdu(conn, pdu_rsp);
    if (rv) {
	goto failure;
    }

    return rv;

failure:
    if (pdu_rsp != NULL) {
	free_safe(pdu_rsp, sizeof(pdu_rsp));
	pdu_rsp = NULL;
    }
    return -1;
} // create_and_send_r2t


static int create_and_send_scsi_rsp(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    uint8 response,
    uint8 status,
    uint8 sense_key,
    uint8 asc,
    uint8 ascq)
{
    struct iscsi_pdu *pdu_rsp = NULL;
    byte *dsbuf = NULL;
    int rv;

    ASSERT(pdu_req->opcode == ISCSI_OP_SCSI_CMD,
	   "pdu_req->opcode(0x%02X) != ISCSI_OP_SCSI_CMD(0x%02X)\n",
	   pdu_req->opcode, ISCSI_OP_SCSI_CMD);

    log_dbg3("response=%u(0x%02X), status=%u(0x%02X), sense_key=%u(0x%02X), asc=%u(0x%02X), ascq=%u(0x%02X)\n",
	     response, response,
	     status, status,
	     sense_key, sense_key,
	     asc, asc,
	     ascq, ascq);

    pdu_rsp = iscsi_create_pdu(conn);
    if (pdu_rsp == NULL) {
	goto failure;
    }
    pdu_rsp->opcode = ISCSI_OP_SCSI_RSP;
    pdu_rsp->Fbit = 1;
    pdu_rsp->ubit = 0;
    pdu_rsp->obit = 0;
    pdu_rsp->Ubit = 0;
    pdu_rsp->Obit = 0;
    pdu_rsp->response = response;
    pdu_rsp->status = status;
    pdu_rsp->ahslen = 0;
    pdu_rsp->dslen = 0;
    pdu_rsp->itt = pdu_req->itt;
    pdu_rsp->snack = 0;
    pdu_rsp->expdatasn = 0;
    pdu_rsp->brrcount = 0;
    pdu_rsp->rcount = 0;
    pdu_rsp->dsvec_cnt = 0;

    switch (status) {
    case ISCSI_STATUS_GOOD:
    case ISCSI_STATUS_RESERVATION_CONFLICT:
	if (pdu_req->Rbit) {
	    // Residual underflow occured.
	    pdu_rsp->Ubit = 1;
	    pdu_rsp->rcount = pdu_req->expdtlen;
	}
	break;
    case ISCSI_STATUS_CHECK_CONDITION:
#define SCSI_SENSE_BUF_SIZE 20
	dsbuf = iscsi_alloc_dsbuf(conn, SCSI_SENSE_BUF_SIZE);
	if (dsbuf == NULL) {
	    goto failure;
	}
	memset(dsbuf, 0x00, SCSI_SENSE_BUF_SIZE);
	dsbuf[1] = (SCSI_SENSE_BUF_SIZE - 2); // Sense Length
	dsbuf[2] = 0xF0; // Valid
	dsbuf[4] = sense_key;
	dsbuf[9] = 0x06; // Additional Sense Length
	dsbuf[14] = asc;
	dsbuf[15] = ascq;
	pdu_rsp->dsvec[0].buf = dsbuf;
	pdu_rsp->dsvec[0].buflen = SCSI_SENSE_BUF_SIZE;
	pdu_rsp->dsvec[0].len = SCSI_SENSE_BUF_SIZE;
	pdu_rsp->dsvec[0].offset = 0;
	pdu_rsp->dsvec[0].page = NULL;
	pdu_rsp->dsvec_cnt = 1;
	pdu_rsp->dsvec_len = SCSI_SENSE_BUF_SIZE;
	pdu_rsp->dsvec_offset = 0;
	pdu_rsp->dslen = SCSI_SENSE_BUF_SIZE;
	if (pdu_req->Wbit){
	    pdu_rsp->Ubit = 1;
	    pdu_rsp->rcount = pdu_req->expdtlen;
	}
	break;
    default:
	ASSERT((0), "NOT SUPPORTED YET (status=0x%02X)!\n", status);
    }

    // add PDU to task and send
    rv = iscsi_add_pdu_to_task(conn, pdu_req->task, pdu_rsp);
    if (rv) {
	goto failure;
    }
    rv = iscsi_enqueue_and_tx_pdu(conn, pdu_rsp);
    if (rv) {
	goto failure;
    }

    return rv;

failure:
    if (pdu_rsp != NULL) {
	if (dsbuf != NULL) {
	    free_safe(dsbuf, SCSI_SENSE_BUF_SIZE);
	    dsbuf = NULL;
	}
	free_safe(pdu_rsp, sizeof(pdu_rsp));
	pdu_rsp = NULL;
    }
    return -1;
} // create_and_send_scsi_rsp


static int create_and_send_scsidata_in_by_page(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct list *list_page,
    uint32 page_totallen)
{
    struct iscsi_pdu *pdu_rsp = NULL;
    struct page_buffer *page;
    uint32 idx;
    int rv;
    uint32 dslen;
    uint32 datasn;
    uint32 bufoffset;
    uint32 len, offset;
    int overflow;

    log_dbg3("list_page->len="U32_FMT", page_totallen="U32_FMT"\n",
	    list_page->len, page_totallen);

    if (list_page->len > IOV_MAX) {
	goto failure;
    }

    dslen = 0;
    idx = 0;
    bufoffset = 0;
    datasn = 0;

    ASSERT((page_totallen == pdu_req->cmd.trans_len * 512),
	   "page_totallen != pdu_req->cmd.trans_len * 512\n");
    ASSERT((page_totallen == pdu_req->expdtlen),
	   "page_totallen != pdu_req->expdtlen\n");

    overflow = 0;

    do_each_list_elem (struct page_buffer *, list_page, page, listelem) {
	len = page->len;
	offset = page->offset;
	while (1) {
	    log_dbg3("len="U32_FMT"(0x%08lX), offset="U32_FMT"(0x%08lX), idx="U32_FMT", datasn="U32_FMT", pdu_rsp=%p\n",
		    len, len, offset, offset, idx, datasn, pdu_rsp);
	    if (pdu_rsp == NULL) {
		pdu_rsp = create_scsi_data_in(conn, pdu_req);
		if (pdu_rsp == NULL) {
		    goto failure;
		}
		idx = 0;
		pdu_rsp->datasn = datasn;
		pdu_rsp->bufoffset = bufoffset;
		pdu_rsp->rcount = 0;
		pdu_rsp->dslen = 0;
		pdu_rsp->Fbit = 0;
		pdu_rsp->Sbit = 0;
		datasn++;
	    }
	    pdu_rsp->dsvec[idx].buf = page->buf;
	    pdu_rsp->dsvec[idx].buflen = PAGE_BUFFER_SIZE;
	    pdu_rsp->dsvec[idx].offset = offset;
	    pdu_rsp->dsvec[idx].page = page;
	    pdu_rsp->dsvec_cnt++;

	    if (page_totallen > pdu_req->expdtlen &&
		(bufoffset + len >= pdu_req->expdtlen)) {
		// Residual overflow.
		pdu_rsp->dsvec[idx].len = (pdu_req->expdtlen - bufoffset);
		pdu_rsp->dslen += pdu_rsp->dsvec[idx].len;
		pdu_rsp->rcount = (page_totallen - pdu_req->expdtlen);
		bufoffset += pdu_rsp->dsvec[idx].len;
		len -= pdu_rsp->dsvec[idx].len;
		offset += pdu_rsp->dsvec[idx].len;
		pdu_rsp->Obit = 1;
		overflow = 1;
		log_dbg3("Residual overflow occured (itt="U32_FMT"(0x%08lX), datasn="U32_FMT"(0x%08lX), "U32_FMT"(0x%08lX) bytes).\n",
			pdu_rsp->itt, pdu_rsp->itt,
			pdu_rsp->datasn, pdu_rsp->datasn,
			pdu_rsp->rcount, pdu_rsp->rcount);
		log_dbg3("  pdu_rsp->dsvec["U32_FMT"].len="U32_FMT"(0x%08lX)\n",
			idx, pdu_rsp->dsvec[idx].len, pdu_rsp->dsvec[idx].len);
		log_dbg3("  pdu_rsp->dsvec["U32_FMT"].offset="U32_FMT"(0x%08lX)\n",
			idx, pdu_rsp->dsvec[idx].offset, pdu_rsp->dsvec[idx].offset);
		log_dbg3("  pdu_rsp->dslen="U32_FMT"(0x%08lX)\n", pdu_rsp->dslen, pdu_rsp->dslen);
		log_dbg3("  bufoffset="U32_FMT"(0x%08lX)\n", bufoffset, bufoffset);
		log_dbg3("  len="U32_FMT"(0x%08lX)\n", len, len);
		log_dbg3("  offset="U32_FMT"(0x%08lX)\n", offset, offset);
		break;
	    }
	    if ((pdu_rsp->dslen + len) > conn->max_xmit_data_len) {
		// Split the page buffer into two(or more) SCSI Data-In PDU.
		pdu_rsp->dsvec[idx].len = (conn->max_xmit_data_len - pdu_rsp->dslen);
		pdu_rsp->dslen = conn->max_xmit_data_len;
		bufoffset += pdu_rsp->dsvec[idx].len;
		len -= pdu_rsp->dsvec[idx].len;
		offset += pdu_rsp->dsvec[idx].len;
		log_dbg3("Split the page into two (or more) SCSI Data-In PDU.\n");
		log_dbg3("  pdu_rsp->dsvec["U32_FMT"].len="U32_FMT"(0x%08lX)\n",
			idx, pdu_rsp->dsvec[idx].len, pdu_rsp->dsvec[idx].len);
		log_dbg3("  pdu_rsp->dsvec["U32_FMT"].offset="U32_FMT"(0x%08lX)\n",
			idx, pdu_rsp->dsvec[idx].offset, pdu_rsp->dsvec[idx].offset);
		log_dbg3("  pdu_rsp->dslen="U32_FMT"(0x%08lX)\n", pdu_rsp->dslen, pdu_rsp->dslen);
		log_dbg3("  bufoffset="U32_FMT"(0x%08lX)\n", bufoffset, bufoffset);
		log_dbg3("  len="U32_FMT"(0x%08lX)\n", len, len);
		log_dbg3("  offset="U32_FMT"(0x%08lX)\n", offset, offset);
		// add PDU to task and send
		rv = iscsi_add_pdu_to_task(conn, pdu_req->task, pdu_rsp);
		if (rv) {
		    goto failure;
		}
		rv = iscsi_enqueue_and_tx_pdu(conn, pdu_rsp);
		if (rv) {
		    goto failure;
		}
		pdu_rsp = NULL;
	    } else { // (pdu_rsp->dslen + len) <= conn->max_xmit_data_len
		// Concatinate next page buffer into single SCSI Data-In PDU.
		pdu_rsp->dsvec[idx].offset = offset;
		pdu_rsp->dsvec[idx].len = len;
		pdu_rsp->dslen += len;
		bufoffset += len;
		len -= len;
		offset += len;
		log_dbg3("Concatinate next page into single SCSI Data-In PDU.\n");
		log_dbg3("  pdu_rsp->dsvec["U32_FMT"].len="U32_FMT"(0x%08lX)\n",
			idx, pdu_rsp->dsvec[idx].len, pdu_rsp->dsvec[idx].len);
		log_dbg3("  pdu_rsp->dslen="U32_FMT"(0x%08lX)\n", pdu_rsp->dslen, pdu_rsp->dslen);
		log_dbg3("  pdu_rsp->dsvec["U32_FMT"].offset="U32_FMT"(0x%08lX)\n",
			idx, pdu_rsp->dsvec[idx].offset, pdu_rsp->dsvec[idx].offset);
		log_dbg3("  bufoffset="U32_FMT"(0x%08lX)\n", bufoffset, bufoffset);
		log_dbg3("  len="U32_FMT"(0x%08lX)\n", len, len);
		log_dbg3("  offset="U32_FMT"(0x%08lX)\n", offset, offset);
		idx++;
		break;
	    }
	}
	if (overflow) {
	    break;
	}
    } while_each_list_elem (struct page_buffer *, list_page, page, listelem);


    ASSERT((pdu_rsp != NULL), "pdu_rsp == NULL");
    ASSERT((page_totallen == bufoffset),
	   "page_totallen("U32_FMT"(0x%08lX)) != bufoffset("U32_FMT"(0x%08lX))\n",
	   page_totallen, page_totallen, bufoffset, bufoffset);

    // Check and send last PDU.
    pdu_rsp->Fbit = 1;
    pdu_rsp->Sbit = 1;
    pdu_rsp->status = ISCSI_STATUS_GOOD;
    log_dbg3("page_totallen="U32_FMT"(0x%08lX), pdu_req->expdtlen="U32_FMT"\n", 
	    page_totallen, page_totallen,
	    pdu_req->expdtlen, pdu_req->expdtlen);

    if (page_totallen < pdu_req->expdtlen) {
	// Residual underflow occured.
	pdu_rsp->Ubit = 1;
	pdu_rsp->rcount = pdu_req->expdtlen - page_totallen;
	log_dbg3("Residual underflow occured (itt="U32_FMT"(0x%08lX), datasn="U32_FMT"(0x%08lX), "U32_FMT"(0x%08lX) bytes).\n",
		pdu_rsp->itt, pdu_rsp->itt,
		pdu_rsp->datasn, pdu_rsp->datasn,
		pdu_rsp->rcount, pdu_rsp->rcount);
    }

    pdu_req->task->list_page = *list_page;
    pdu_req->task->page_totallen = page_totallen;

    rv = iscsi_add_pdu_to_task(conn, pdu_req->task, pdu_rsp);
    if (rv) {
	goto failure;
    }
    rv = iscsi_enqueue_and_tx_pdu(conn, pdu_rsp);
    if (rv) {
	goto failure;
    }

    return 0;

failure:
    return -1;
} // create_and_send_scsidata_in_by_page


/**
 * Create and send a SCSI Data-In PDU.
 * @param[in,out] conn       An iSCSI connection thread.
 * @param[in]     pdu_req    An iSCSI PDU.
 * @param[in]     dsbuf      A data segment buffer.
 * @param[in]     dsbuflen   Length of a data segment buffer (in bytes).
 * @param[in]     dslen      Active length of a data segment buffer (in bytes).
 * @retval        0                success
 * @retval        "negative value" failure
 */
static int create_and_send_scsidata_in(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    byte *dsbuf,
    uint32 dsbuflen,
    uint32 dslen)
{
    struct iscsi_pdu *pdu_rsp;
    int rv;

    pdu_rsp = create_scsi_data_in(conn, pdu_req);
    if (pdu_rsp == NULL) {
	goto failure;
    }

    pdu_rsp->dsvec[0].buf = dsbuf;
    pdu_rsp->dsvec[0].buflen = dsbuflen;
    pdu_rsp->dsvec[0].len = dslen;
    pdu_rsp->dsvec[0].offset = 0;
    pdu_rsp->dsvec[0].page = 0;
    pdu_rsp->dsvec_cnt = 1;
    pdu_rsp->dsvec_len = dslen;
    
    pdu_rsp->dslen = dslen;

    // check residual underflow
    log_dbg3("pdu_req->expdtlen="U32_FMT"(0x%08lX), pdu_rsp->dslen="U32_FMT"(0x%08lX)\n",
	    pdu_req->expdtlen, pdu_req->expdtlen,
	    pdu_rsp->dslen, pdu_rsp->dslen);
    if (pdu_rsp->dslen < pdu_req->expdtlen) {
	// residual underflow
	pdu_rsp->Ubit = 1;
	pdu_rsp->rcount = pdu_req->expdtlen - pdu_rsp->dslen;
    } else if (pdu_rsp->dslen > pdu_req->expdtlen) {
	pdu_rsp->Obit = 1;
	pdu_rsp->rcount = pdu_rsp->dslen - pdu_req->expdtlen;
	pdu_rsp->dslen = pdu_req->expdtlen;
	pdu_rsp->dsvec[0].len = pdu_rsp->dslen;
	pdu_rsp->dsvec_len = pdu_rsp->dslen;
    }

    // add PDU to task and send
    rv = iscsi_add_pdu_to_task(conn, pdu_req->task, pdu_rsp);
    if (rv) {
	goto failure;
    }
    rv = iscsi_enqueue_and_tx_pdu(conn, pdu_rsp);
    if (rv) {
	goto failure;
    }

    return 0;

failure:
    return -1;
} // create_and_send_scsidata_in


/**
 * Create a SCSI Data-In PDU.
 * @param[in,out] conn       An iSCSI connection thread.
 * @param[in]     pdu_req    An iSCSI PDU.
 * @return                   SCSI Data-In PDU (NULL:failure)
 */
static struct iscsi_pdu *create_scsi_data_in(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req)
{
    struct iscsi_pdu *pdu_rsp = NULL;

    ASSERT(pdu_req->opcode == ISCSI_OP_SCSI_CMD,
	   "pdu_req->opcode(0x%02X) != ISCSI_OP_SCSI_CMD(0x%02X)\n",
	   pdu_req->opcode, ISCSI_OP_SCSI_CMD);

    pdu_rsp = iscsi_create_pdu(conn);
    if (pdu_rsp == NULL) {
	return NULL;
    }
    pdu_rsp->opcode = ISCSI_OP_SCSI_DATA_IN;
    pdu_rsp->Fbit = 1;
    pdu_rsp->Abit = 0;
    pdu_rsp->Obit = 0;
    pdu_rsp->Ubit = 0;
    pdu_rsp->Sbit = 1;
    pdu_rsp->status = ISCSI_STATUS_GOOD;
    pdu_rsp->ahslen = 0;
    pdu_rsp->dslen = 0;
    pdu_rsp->lun = 0;
    pdu_rsp->itt = pdu_req->itt;
    pdu_rsp->ttt = 0xFFFFFFFF;
    pdu_req->task->ttt = 0xFFFFFFFF;

    pdu_rsp->datasn = 0;
    pdu_rsp->bufoffset = 0;
    pdu_rsp->brrcount = 0;
    pdu_rsp->rcount=0;

    return pdu_rsp;
} // create_scsi_data_in

#ifndef __packed
#define __packed __attribute__ ((packed))
#endif

// TestUnitReady
struct scsi_cdb_test_unit_ready {
    uint8 opcode; // 0x00
    uint8 reserved[4];
    uint8 control;
} __packed; // struct scsi_cdb_test_unit_ready

#define SCSI_READ_CAPACITY_PMI_MASK 0x01

// ReadCapacity(10)
struct scsi_cdb_read_capacity {
    uint8 opcode;
    uint8 reserved1;
    uint32 lba_32;
    uint8 reserved2[2];
    uint8 pmi; // PMI flag
    uint8 control;
    uint8 reserved3[6];
} __packed; // struct scsi_cdb_read_capacity

// Read(10) command (SBC-3)
struct scsi_cdb_read_10 {
    uint8 opcode;
    uint8 flags;         // RDPROTECT, DPO, FUA, FUA_NV
    uint32 lba_32;
    uint8 grp_num;       // group number
    uint16 trans_len_16; // transfer length
    uint8 control;
} __packed; // struct scsi_cdb_read_10

// WRITE(10) command (SBC-3)
struct scsi_cdb_write_10 {
    uint8 opcode;        // 0x2A
    uint8 flags;         // WRPROTECT, DPO, FUA, FUA_NV
    uint32 lba_32;
    uint8 grp_num;       // group number
    uint16 trans_len_16; // transfer length
    uint8 control;
} __packed;

// Report LUNs command
struct scsi_cdb_report_luns {
    uint8 opcode;
    uint8 reserved1;
    uint8 select_report;
    uint8 reserved2[3];
    uint32 alloc_len_32;
    uint8 reserved3;
    uint8 control;
} __packed; // struct scsi_cdb_report_lun

// Inquiry command
struct scsi_cdb_inquiry {
    uint8 opcode;
    uint8 flag;
    uint8 page_code;
    uint16 alloc_len_16;
    uint8 control;
    uint8 reserved[10];
} __packed; // struct scsi_cdb_inquiry

// Mode Sense (6) command
struct scsi_cdb_mode_sense_6 {
    uint8 opcode;
    uint8 dbd;
    uint8 flags;
    uint8 subpage_code;
    uint8 alloc_len_8;
    uint8 control;
} __packed; // struct scsi_cdb_mode_sense_6

// Verify (10) command
struct scsi_cdb_verify_10 {
    uint8 opcode; // 0x2F
    uint8 flags; // VRPROTECT, DPO, BYTCHK
    uint32 lba_32;
    uint8 grp_num;   // group number
    uint16 verf_len_16; // verification length
    uint8 control;
} __packed;

// Service Action In (16) command
struct scsi_cdb_service_action_in_16 {
    uint8 opcode;
    uint8 service_action;
    uint8 reserved[14];
} __packed;

// Service Action In (16) / Read Capacity (16) commandx
#define SCSI_READ_CAPACITY_16_PMI_MASK 0x01
struct scsi_cdb_read_capacity_16 {
    uint8 opcode;
    uint8 service_action;
    uint64 lba_64;
    uint32 alloc_len_32;
    uint8 pmi; // PMI flag
    uint8 control;
} __packed;

// Reserve (6)
struct scsi_cdb_reserve_6 {
    uint8 opcode;
    uint8 reserved[4];
    uint8 control;
} __packed;

// Release (6)
struct scsi_cdb_release_6 {
    uint8 opcode;
    uint8 reserved[4];
    uint8 control;
} __packed;

// SynchronizeCache(10)
struct scsi_cdb_sync_cache_10 {
    uint8 opcode;
    uint8 flags; // SYNC_NV, IMMED
    uint32 lba_32;
    uint8 grp_num; // group number
    uint16 lblocks; // number of logical blocks
    uint8 control;
} __packed;

#define SCSI_MDSENSE6_DBD_MASK 0x08      //< ModeSense(6) DBD mask
#define SCSI_MDSENSE6_PC_MASK  0xC0      //< ModeSense(6) PC mask
#define SCSI_MDSENSE6_PAGECODE_MASK 0x3F //< ModeSense(6) pagecode mask

/**
 * Enqueue volume command into volume thread.
 * @param[in,out] conn             An iSCSI connection thread.
 * @param[in]     cmd              A SCSI command.
 * @retval        0                success
 * @retval        "negative value" failure
 */
int scsi_dump_cdb(struct iscsi_conn *conn, struct scsi_cmd *cmd)
{
    log_dbg3("cmd->opcode = 0x%02X\n", cmd->opcode);
    switch (cmd->opcode) {
    case SCSI_OP_TEST_UNIT_READY:
	log_dbg2("Test Unit Ready (0x%02X)\n", cmd->opcode);
	log_dbg2("  control = 0x%02X\n", cmd->control);
	break;
    case SCSI_OP_REPORT_LUNS:
	log_dbg2("Report LUNs (0x%02X)\n", cmd->opcode);
	log_dbg2("  select report = "U32_FMT"\n", cmd->select_report);
	log_dbg2("  allocation length = "U32_FMT"(0x%04lX)\n", (uint32)cmd->alloc_len, (uint32)cmd->alloc_len);
	log_dbg2("  control = 0x%02X\n", cmd->control);
	break;
    case SCSI_OP_INQUIRY:
	log_dbg2("Inquiry (0x%02X)\n", cmd->opcode);
	log_dbg2("  EVPD = %u\n", cmd->evpd);
	log_dbg2("  page code = %u(0x%02X)\n", cmd->page_code, cmd->page_code);
	log_dbg2("  allocation length = %u(0x%02X)\n", (uint16)cmd->alloc_len, (uint16)cmd->alloc_len);
	log_dbg2("  control = 0x%02X\n", cmd->control);
	break;
    case SCSI_OP_READ_CAPACITY:
	log_dbg2("Read Capacity (0x%02X)\n", cmd->opcode);
	log_dbg2("  LBA = "U32_FMT"(0x%08lX)\n", (uint32)cmd->lba, (uint32)cmd->lba);
	log_dbg2("  PMI = %u\n", cmd->pmi);
	log_dbg2("  control = 0x%02X\n", cmd->control);
	break;
    case SCSI_OP_READ_10:
	log_dbg2("Read(10) (0x%02X)\n", cmd->opcode);
	log_dbg2("  LBA = "U32_FMT"(0x%08lX)\n", (uint32)cmd->lba, (uint32)cmd->lba);
	log_dbg2("  transfer length = %u(0x%04X)\n", (uint16)cmd->trans_len, (uint16)cmd->trans_len);
	log_dbg2("  read protect = 0x%02X\n", cmd->rdprotect);
	log_dbg2("  DPO = %u\n", cmd->dpo);
	log_dbg2("  FUA_NV = %u\n", cmd->fua_nv);
	log_dbg2("  group number = 0x%02X\n", cmd->grp_num);
	log_dbg2("  control = 0x%02X\n", cmd->control);
	break;
    case SCSI_OP_WRITE_10:
	log_dbg2("Write(10) (0x%02X)\n", cmd->opcode);
	log_dbg2("  LBA = "U32_FMT"(0x%08lX)\n", (uint32)cmd->lba, (uint32)cmd->lba);
	log_dbg2("  transfer length = %u(0x%04X)\n", (uint16)cmd->trans_len, (uint16)cmd->trans_len);
	log_dbg2("  write protect = 0x%02X\n", cmd->wrprotect);
	log_dbg2("  DPO = %u\n", cmd->dpo);
	log_dbg2("  FUA_NV = %u\n", cmd->fua_nv);
	log_dbg2("  group number = 0x%02X\n", cmd->grp_num);
	log_dbg2("  control = 0x%02X\n", cmd->control);
	break;
    case SCSI_OP_MODE_SENSE_6:
	log_dbg2("Mode Sense (6) (0x%02X)\n", cmd->opcode);
	log_dbg2("  DBD = %u\n", cmd->dbd);
	log_dbg2("  PC = %u\n", cmd->pc);
	log_dbg2("  page code = %u(0x%02X)\n", cmd->page_code, cmd->page_code);
	log_dbg2("  subpage code = %u(0x%02X)\n", cmd->subpage_code, cmd->subpage_code);
	log_dbg2("  allocation length = "U32_FMT"(0x%02lX)\n", (uint8)cmd->alloc_len, (uint8)cmd->alloc_len);
	log_dbg2("  control = 0x%02X\n", cmd->control);
	break;
    case SCSI_OP_VERIFY_10:
	log_dbg2("Verify (6) (0x%02X)\n", cmd->opcode);
	log_dbg2("  verify protect = 0x%02X\n", cmd->vrprotect);
	log_dbg2("  DPO = %u\n", cmd->dpo);
	log_dbg2("  byte check = %u\n", cmd->byte_check);
	log_dbg2("  LBA = "U32_FMT"(0x%08lX)\n", (uint32)cmd->lba, (uint32)cmd->lba);
	log_dbg2("  group number = 0x%02X\n", cmd->grp_num);
	log_dbg2("  verify length = %u(0x%04X)\n", (uint16)cmd->verf_len, (uint16)cmd->verf_len);
	log_dbg2("  control = 0x%02X\n", cmd->control);
	break;
    case SCSI_OP_SERVICE_ACTION_IN_16:
	switch (cmd->service_action) {
	case SCSI_SERV_ACT_IN_READ_CAPACITY_16:
	    log_dbg2("Read Capacity (16) (0x%02X/0x%02X)\n", cmd->opcode, cmd->service_action);
	    log_dbg2("  LBA = %llu(0x%016llX)\n", cmd->lba, cmd->lba);
	    log_dbg2("  allocation length = "U32_FMT"(0x%08lX)\n", cmd->alloc_len, cmd->alloc_len);
	    log_dbg2("  PMI = %u\n", cmd->pmi);
	    log_dbg2("  control = 0x%02X\n", cmd->control);
	    break;
	case SCSI_SERV_ACT_IN_READ_LONG_16:
	    log_dbg2("Read Long (16) (0x%02X/0x%02X)\n", cmd->opcode, cmd->service_action);
	    ASSERT((0), "Read Long (16) IS NOT SUPPORTED YET\n");
	default:
	    ASSERT((0), "NOT IMPLEMENTED YET (0x%02X/0x%02X)\n",
		   cmd->opcode, cmd->service_action);
	    break;
	}
	break;
    case SCSI_OP_RESERVE_6:
	log_dbg2("Researve (6) (0x%02X)\n", cmd->opcode);
	log_dbg2("  control = 0x%02X\n", cmd->control);
	break;
    case SCSI_OP_RELEASE_6:
	log_dbg2("Release (6) (0x%02X)\n", cmd->opcode);
	log_dbg2("  control = 0x%02X\n", cmd->control);
	break;
    case SCSI_OP_SYNC_CACHE_10:
	log_dbg2("Synchronize Cache (10) (0x%02X)\n", cmd->opcode);
	log_dbg2("  SYNC_NV = %u\n", cmd->sync_nv);
	log_dbg2("  IMMED = %u\n", cmd->immed);
	log_dbg2("  LBA = "U32_FMT"(0x%08lX)\n", (uint32)cmd->lba, (uint32)cmd->lba);
	log_dbg2("  group number = 0x%02X\n", cmd->grp_num);
	log_dbg2("  number of logical blocks = %u(0x%04X)\n", (uint16)cmd->lblocks, (uint16)cmd->lblocks);
	log_dbg2("  control = 0x%02X\n", cmd->control);
	break;
    case SCSI_OP_SERVICE_ACTION_OUT_16:
    default:
	log_dbg2("SCSI Opcode 0x%02X is not supported yet.\n", cmd->opcode);
//	ASSERT(0, "NOT IMPLEMENTED YET (cmd->opcode = 0x%02X)\n", cmd->opcode);
	break;
    }
    return 0;
} // scsi_dump_cdb


/**
 * Enqueue volume command into volume thread.
 * @param[in,out] conn             An iSCSI connection thread.
 * @param[in]     pdu              An iSCSI PDU.
 * @param[in]     cmd              A SCSI command.
 * @retval        0                success
 * @retval        "negative value" failure
 */
int scsi_unpack_cdb(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu,
    struct scsi_cmd *cmd)
{
    struct scsi_cdb *cdb;
    struct iscsi_bhs_scsi_cmd *bhs;
    struct scsi_cdb_report_luns *cdb_rep_luns;
    struct scsi_cdb_inquiry *cdb_inq;
    struct scsi_cdb_test_unit_ready *cdb_tst;
    struct scsi_cdb_read_capacity *cdb_rd_cap;
    struct scsi_cdb_read_10 *cdb_rd_10;
    struct scsi_cdb_write_10 *cdb_wr_10;
    struct scsi_cdb_verify_10 *cdb_verf_10;
    struct scsi_cdb_mode_sense_6 *cdb_mdsense_6;
    struct scsi_cdb_service_action_in_16 *cdb_servact_in_16;
    struct scsi_cdb_read_capacity_16 *cdb_rd_cap_16;
    struct scsi_cdb_reserve_6 *cdb_rsv_6;
    struct scsi_cdb_release_6 *cdb_rls_6;
    struct scsi_cdb_sync_cache_10 *cdb_sync_10;

    bhs = (struct iscsi_bhs_scsi_cmd *)&(pdu->bhs);
    cdb = &(bhs->cdb);
    
    cmd->opcode = cdb->opcode;
    log_dbg3("Unpack CDB(opcode=0x%02X).\n", cmd->opcode);

#if __BYTE_ORDER == __BIG_ENDIAN
#error "Not supported yet"
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    switch (cmd->opcode) {
    case SCSI_OP_TEST_UNIT_READY:
	cdb_tst = (struct scsi_cdb_test_unit_ready *)cdb;
	cmd->control = cdb_tst->control;
	break;
    case SCSI_OP_REPORT_LUNS:
	cdb_rep_luns = (struct scsi_cdb_report_luns *)cdb;
	cmd->select_report = cdb_rep_luns->select_report;
	cmd->alloc_len     = (uint32)be32_to_cpu(cdb_rep_luns->alloc_len_32);
	cmd->control       = cdb_rep_luns->control;
	break;
    case SCSI_OP_INQUIRY:
	cdb_inq = (struct scsi_cdb_inquiry *)cdb;
	cmd->evpd          = cdb_inq->flag & SCSI_EVPD_MASK;
	cmd->cmdt          = cdb_inq->flag & SCSI_CMDT_MASK;
	cmd->page_code     = cdb_inq->page_code;
	cmd->alloc_len     = (uint32)be16_to_cpu(cdb_inq->alloc_len_16);
	cmd->control       = cdb_inq->control;
	break;
    case SCSI_OP_READ_CAPACITY:
	cdb_rd_cap = (struct scsi_cdb_read_capacity *)cdb;
	cmd->lba = (uint64)be32_to_cpu(cdb_rd_cap->lba_32);
	cmd->pmi = ((cdb_rd_cap->pmi & SCSI_READ_CAPACITY_PMI_MASK) ? 1 : 0);
	cmd->control = cdb_rd_cap->control;
	break;
    case SCSI_OP_READ_10:
	cdb_rd_10 = (struct scsi_cdb_read_10 *)cdb;
	cmd->lba = (uint64)be32_to_cpu(cdb_rd_10->lba_32);
	cmd->rdprotect = (cdb_rd_10->flags & SCSI_RDPROTECT_MASK) >> 5;
	cmd->dpo = (cdb_rd_10->flags & SCSI_DPO_MASK ? 1 : 0);
	cmd->fua_nv = (cdb_rd_10->flags & SCSI_FUA_NV_MASK ? 1 : 0);
	cmd->grp_num = (cdb_rd_10->grp_num & SCSI_GROUP_NUMBER_MASK);
	cmd->trans_len = (uint32)be16_to_cpu(cdb_rd_10->trans_len_16);
	cmd->control = cdb_rd_10->control;
	break;
    case SCSI_OP_WRITE_10:
	cdb_wr_10 = (struct scsi_cdb_write_10 *)cdb;
	cmd->lba = (uint64)be32_to_cpu(cdb_wr_10->lba_32);
	cmd->wrprotect = (cdb_wr_10->flags & SCSI_WRPROTECT_MASK) >> 5;
	cmd->dpo = (cdb_wr_10->flags & SCSI_DPO_MASK ? 1 : 0);
	cmd->fua_nv = (cdb_wr_10->flags & SCSI_FUA_NV_MASK ? 1 : 0);
	cmd->grp_num = (cdb_wr_10->grp_num & SCSI_GROUP_NUMBER_MASK);
	cmd->trans_len = (uint32)be16_to_cpu(cdb_wr_10->trans_len_16);
	cmd->control = cdb_wr_10->control;
	break;
    case SCSI_OP_MODE_SENSE_6:
	cdb_mdsense_6 = (struct scsi_cdb_mode_sense_6 *)cdb;
	cmd->dbd = (cdb_mdsense_6->dbd & SCSI_MDSENSE6_DBD_MASK) ? 1 : 0;
	cmd->pc  = (cdb_mdsense_6->flags & SCSI_MDSENSE6_PC_MASK) >> 6;
	cmd->page_code = (cdb_mdsense_6->flags & SCSI_MDSENSE6_PAGECODE_MASK);
	cmd->subpage_code = cdb_mdsense_6->subpage_code;
	cmd->alloc_len = (uint32)cdb_mdsense_6->alloc_len_8;
	cmd->control = cdb_mdsense_6->control;
	break;
    case SCSI_OP_VERIFY_10:
	cdb_verf_10 = (struct scsi_cdb_verify_10 *)cdb;
	cmd->rdprotect = (cdb_verf_10->flags & SCSI_VRPROTECT_MASK) >> 5;
	cmd->dpo = (cdb_verf_10->flags & SCSI_VERF10_DPO_MASK ? 1 : 0);
	cmd->byte_check = (cdb_verf_10->flags & SCSI_BYTECHECK_MASK ? 1 : 0);
	cmd->lba = (uint64)be32_to_cpu(cdb_verf_10->lba_32);
	cmd->grp_num = (cdb_verf_10->grp_num & SCSI_GROUP_NUMBER_MASK);
	cmd->verf_len = (uint32)be16_to_cpu(cdb_verf_10->verf_len_16);
	cmd->control = cdb_verf_10->control;
	break;
    case SCSI_OP_SYNC_CACHE_10:
	cdb_sync_10 = (struct scsi_cdb_sync_cache_10 *)cdb;
	cmd->sync_nv = (cdb_sync_10->flags & SCSI_SYNC_NV_MASK ? 1 : 0);
	cmd->immed = (cdb_sync_10->flags & SCSI_IMMED_MASK ? 1 : 0);
	cmd->lba = (uint64)be32_to_cpu(cdb_sync_10->lba_32);
	cmd->grp_num = (cdb_sync_10->grp_num & SCSI_GROUP_NUMBER_MASK);
	cmd->lblocks = (uint32)be16_to_cpu(cdb_sync_10->lblocks);
	break;
    case SCSI_OP_SERVICE_ACTION_IN_16:
	cdb_servact_in_16 = (struct scsi_cdb_service_action_in_16 *)cdb;
	cmd->service_action = (cdb_servact_in_16->service_action & SCSI_SERVICE_ACTION_MASK);
	switch (cmd->service_action) {
	case SCSI_SERV_ACT_IN_READ_CAPACITY_16:
	    cdb_rd_cap_16 = (struct scsi_cdb_read_capacity_16 *)cdb;
	    cmd->lba = (uint64)be64_to_cpu(cdb_rd_cap_16->lba_64);
	    cmd->alloc_len = (uint32)be32_to_cpu(cdb_rd_cap_16->alloc_len_32);
	    cmd->pmi = ((cdb_rd_cap_16->pmi & SCSI_READ_CAPACITY_16_PMI_MASK) ? 1 : 0);
	    cmd->control = cdb_rd_cap_16->control;
	    break;
	default:
	    ASSERT((0), "NOT IMPLEMENTED YET (0x%02X/0x%02X)\n",
		   cmd->opcode, cmd->service_action);
	    break;
	}
	break;
    case SCSI_OP_RESERVE_6:
	cdb_rsv_6 = (struct scsi_cdb_reserve_6 *)cdb;
	cmd->control = cdb_rsv_6->control;
	break;
    case SCSI_OP_RELEASE_6:
	cdb_rls_6 = (struct scsi_cdb_release_6 *)cdb;
	cmd->control = cdb_rls_6->control;
	break;
    default:
	log_err("SCSI Opcode 0x%02X is not supported yet.\n", cmd->opcode);
//	ASSERT((0), "NOT IMPLEMENTED YET (0x%02X)\n", cmd->opcode);
	break;
    }
#else
#error "Deteted unknown endian."
#endif
    return 0;
} // scsi_unpack_cdb



/**
 * Enqueue volume command into volume thread.
 * @param[in,out] conn             An iSCSI connection thread.
 * @param[in,out] vol              A volume thread.
 * @param[in]     scsicmd          A SCSI command.
 * @param[in]     list_page        List of page-buffers.
 * @param[in]     page_totallen    Total length (in bytes) of page-buffers.
 * @param[in]     data             Data which is stored within volume command.
 * @retval        0                success
 * @retval        "negative value" failure
 */
static int enqueue_volcmd(
    struct iscsi_conn *conn,
    struct volume *vol,
    struct scsi_cmd *scsicmd,
    struct list *list_page,
    uint32 page_totallen,
    void *data)
{
    struct volume_cmd *volcmd = NULL;
    int rv;

    // create volume command and initialize
    volcmd = malloc_safe(sizeof(struct volume_cmd));
    if (volcmd == NULL) {
	log_err("Unable to allocate volume command ("U32_FMT").\n",
		sizeof(struct volume_cmd));
	goto failure;
    }
    vol_init_volcmd(vol, volcmd, conn, scsicmd, list_page, page_totallen, data);

    // enqueue the command into volume thread's queue.
    rv = vol_enqueue_cmd(volcmd);
    if (rv) {
	goto failure;
    }

    LOCK_LIST_VOLCMD(conn);
    {
	list_add_elem(&(conn->list_volcmd), &(volcmd->listelem_conn));
    }
    UNLOCK_LIST_VOLCMD(conn);

    return 0;

failure:
    return -1;
} // create_volcmd


/**
 * Unpack LUN (single-level LUN structure)
 *   @param[in] lun      LUN (single-leve LUN structure, see SAM-2)
 *   @return             LUN (number, from 0x0000 to 0x3FFF)
 */
uint16 scsi_unpack_lun(uint64 lun)
{
    ASSERT(((lun << 16) == 0),
	   "lun=0x%016llX\n", lun);

    uint16 lun_16;

    lun_16 = (uint16)((lun >> 48) & SCSI_LUN_MAX);

    return lun_16;
} // scsi_unpack_lun


/**
 * Pack LUN
 *   @param[in] lun      LUN (number, from 0x0000 to 0x3FFF)
 *   @return             LUN (single-leve LUN structure, see SAM-2)
 */
uint64 scsi_pack_lun(uint16 lun)
{
    ASSERT(((lun <= SCSI_LUN_MAX)),
	   "lun(0x%04X) > SCSI_LUN_MAX(0x%04X)\n",
	   lun, SCSI_LUN_MAX);

    uint64 lun_64;

    lun_64 = ((((uint64)lun) << 48) | ((lun > 0xFF) ? (((uint64)1) << 62) : 0));

    return lun_64;
} // scsi_pack_lun
