#ifndef __SCSI_H__
#define __SCSI_H__

#include "misc.h"
#include "iscsi.h"

struct iscsi_conn;
struct iscsi_pdu;

#define SCSI_ID_MAXLEN 16
#define SCSI_SN_MAXLEN 32 // < 255

#define SCSI_PRODUCT_ID_MAXLEN    16
#define SCSI_VENDOR_ID_MAXLEN     8
#define SCSI_PRODUCT_REV_MAXLEN   4


#define SCSI_LUN_MAX 0x3FFF
// Operation Codes
#define SCSI_OP_TEST_UNIT_READY  0x00 // Test Unit Ready
#define SCSI_OP_REQUEST_SENSE    0x03
#define SCSI_OP_INQUIRY          0x12
#define SCSI_OP_RESERVE_6        0x16 // Reserve (6)
#define SCSI_OP_RELEASE_6        0x17 // Release (6)
#define SCSI_OP_MODE_SENSE_6     0x1A // Mode Sense(6)
#define SCSI_OP_READ_CAPACITY    0x25
#define SCSI_OP_READ_10          0x28 // Read (10)
#define SCSI_OP_WRITE_10         0x2A // Write (10)
#define SCSI_OP_VERIFY_10        0x2F // Verify (10)
#define SCSI_OP_SYNC_CACHE_10    0x35 // Synchronize Cache (10)
#define SCSI_OP_REPORT_LUNS      0xA0

#define SCSI_OP_SERVICE_ACTION_IN_16  0x9E // Service Action In (16)
#define SCSI_OP_SERVICE_ACTION_OUT_16 0x9F // Service Action Out (16)
// Service Action codes
#define SCSI_SERV_ACT_IN_READ_CAPACITY_16 0x10 // Read Capacity (16)
#define SCSI_SERV_ACT_IN_READ_LONG_16     0x11 // Read Long (16)
#define SCSI_SERV_ACT_OUT_READ_LONG_16    0x11 // Write Long (16)

// Sense Keys
#define SCSI_SENSE_KEY_NO_SENSE            0x00
#define SCSI_SENSE_KEY_RECOVERED_ERROR     0x01
#define SCSI_SENSE_KEY_NOT_READY           0x02
#define SCSI_SENSE_KEY_MEDIUM_ERROR        0x03
#define SCSI_SENSE_KEY_HARDWARE_ERROR      0x04
#define SCSI_SENSE_KEY_ILLEGAL_REQUEST     0x05
#define SCSI_SENSE_KEY_UNIT_ATTENTION      0x06
#define SCSI_SENSE_KEY_DATA_PROTECT        0x07
#define SCSI_SENSE_KEY_BLANK_CHECK         0x08
#define SCSI_SENSE_KEY_COPY_ABORTED        0x0a
#define SCSI_SENSE_KEY_ABORTED_COMMAND     0x0b
#define SCSI_SENSE_KEY_VOLUME_OVERFLOW     0x0d
#define SCSI_SENSE_KEY_MISCOMPARE          0x0e

struct scsi_cdb {
    uint8 opcode;
    uint8 reserved[15];
}; // struct scsi_cdb


struct scsi_cmd {
    uint8 opcode;
    uint8 select_report; // ReportLUNs
    uint8 evpd;          // Inquiry
    uint8 cmdt;          // Inquiry
    uint8 page_code;     // Inquiry, ModeSense(6)
    uint32 alloc_len;    // ReportLUNs, Inquiry, ModeSense(6)
    uint8 control;
    uint64 lba;          // ReadCapacity, Read(10), Write(10), Verify(10),SyncCache(10)
    uint8 rdprotect;     // RDPROTECT : Read(10)
    uint8 wrprotect;     // WRPROTECT : Write(10)
    uint8 vrprotect;     // VRPROTECT : Verify(10)
    uint8 dpo;           // DPO : Read(10), Verify(10)
    uint8 byte_check;    // Verify(10)
    uint8 fua_nv;        // FUA_NV : Read(10)
    uint32 trans_len;    // Read(10), Write(10)
    uint32 verf_len;     // Verify(10)
    uint32 lblocks;      // SyncCache(10)
    uint8 grp_num;       // group number : Read(10)
    uint8 pmi;           // PMI: ReadCapacity, ReadCapacity(16)
    uint8 dbd;           // DBD : ModeSense(6)
    uint8 pc;            // PC : ModeSense(6)
    uint8 subpage_code;  // SubPage Code : ModeSense(6)

    uint8 service_action; // ReadCapacity(16)
    uint8 immed;          // immediate : SyncCache(10)
    uint8 sync_nv;        // synchronize non-volatile caches : SyncCache(10)
}; // struct scsi_cmd


struct volume_cmd;

int scsi_dump_cdb(
    struct iscsi_conn *conn,
    struct scsi_cmd *cmd);
int scsi_unpack_cdb(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu,
    struct scsi_cmd *cmd);

int iscsi_exec_scsi_cmd(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu);
int iscsi_exec_scsi_cmd_completion(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct volume_cmd *cmd);
uint64 scsi_pack_lun(uint16 lun);
uint16 scsi_unpack_lun(uint64 lun);


#endif // __SCSI_H__
