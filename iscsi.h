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


#ifndef __ISCSI_H__
#define __ISCSI_H__

#include <byteswap.h>
#include <endian.h>
#include <sys/epoll.h>
#include <pthread.h>
#include "misc.h"
#include "scsi.h"

struct iscsi_target;
struct volume_cmd;
struct volume;

#ifndef __packed
#define __packed __attribute__ ((packed))
#endif

#define __DEBUG

#define SCSI_VENDOR_ID       "HUCKLE"
#define SCSI_PRODUCT_ID      "VIRTUAL-DISK"
#define SCSI_PRODUCT_REV     "0.0"

#define ISCSI_PORT                      3260

#define CONFFILE_BUFFER_MAX (64*1024)

#define ISCSI_NAME_MAXLEN 223
#define ISCSI_NAME_MAXBUFLEN (ISCSI_NAME_MAXLEN + 1)

#define ISCSI_NSG_SECURITY     0x00 // Next Stage
#define ISCSI_NSG_OPERATIONAL  0x01 // Next Stage
#define ISCSI_NSG_FULL_FEATURE 0x03 // Next Stage
#define ISCSI_CSG_SECURITY     0x00 // Current Stage
#define ISCSI_CSG_OPERATIONAL  0x01 // Current Stage
#define ISCSI_CSG_FULL_FEATURE 0x03 // Current Stage

#define ISCSI_VERSION            0x00
#define ISCSI_PDU_DSLEN_MAX (64*1024)

#define ISCSI_PDU_BHSLEN                48
// initiator to target
#define ISCSI_OP_NOP_OUT                0x00
#define ISCSI_OP_SCSI_CMD               0x01
#define ISCSI_OP_TASK_MGT_REQ           0x02
#define ISCSI_OP_LOGIN_REQ              0x03
#define ISCSI_OP_TEXT_REQ               0x04
#define ISCSI_OP_SCSI_DATA_OUT          0x05
#define ISCSI_OP_LOGOUT_REQ             0x06
#define ISCSI_OP_SNACK                  0x10
// target to initiator
#define ISCSI_OP_NOP_IN                 0x20
#define ISCSI_OP_SCSI_RSP               0x21
#define ISCSI_OP_TASK_MGT_RSP           0x22
#define ISCSI_OP_LOGIN_RSP              0x23
#define ISCSI_OP_TEXT_RSP               0x24
#define ISCSI_OP_SCSI_DATA_IN           0x25
#define ISCSI_OP_LOGOUT_RSP             0x26
#define ISCSI_OP_R2T                    0x31
#define ISCSI_OP_ASYNC_MSG              0x32
#define ISCSI_OP_REJECT                 0x3F

#define ISCSI_MASK_RETRY     0x80
#define ISCSI_MASK_IBIT 0x40
#define ISCSI_MASK_OPCODE    0x3F

#define ISCSI_MASK_FBIT 0x80
#define ISCSI_MASK_ABIT 0x40 // SCSI Data-In
#define ISCSI_MASK_OBIT 0x04 // SCSI Data-In
#define ISCSI_MASK_UBIT 0x02 // SCSI Data-In
#define ISCSI_MASK_SBIT 0x01 // SCSI Data-In
#define ISCSI_MASK_FUNCTION  0x7F

#define ISCSI_MASK_SOBIT 0x10 // scsires
#define ISCSI_MASK_SUBIT 0x08 // scsires
#define ISCSI_MASK_BOBIT 0x04 // scsires
#define ISCSI_MASK_BUBIT 0x02 // scsires

#define ISCSI_MASK_RBIT 0x40
#define ISCSI_MASK_WBIT 0x20
#define ISCSI_MASK_ATTR 0x07
#define ISCSI_MASK_TBIT 0x80 // loginreq, loginrsp
#define ISCSI_MASK_CBIT 0x40 // loginreq, loginrsp
#define ISCSI_MASK_CSG  0x0C // loginreq, loginrsp
#define ISCSI_MASK_NSG  0x03 // loginreq, loginrsp

// Login Response / Status Classes
#define ISCSI_SCLASS_SUCCESS		0x00
#define ISCSI_SCLASS_REDIRECT		0x01
#define ISCSI_SCLASS_INITIATOR_ERR	0x02
#define ISCSI_SCLASS_TARGET_ERR		0x03

// Login Response / Status Details
// Class-0 (Success)
#define ISCSI_SDETAIL_ACCEPT		0x00

// Class-1 (Redirection)
#define ISCSI_SDETAIL_TGT_MOVED_TEMP	0x01
#define ISCSI_SDETAIL_TGT_MOVED_PERM	0x02

// Class-2 (Initiator Error)
#define ISCSI_SDETAIL_INIT_ERR		0x00
#define ISCSI_SDETAIL_AUTH_FAILED	0x01
#define ISCSI_SDETAIL_TGT_FORBIDDEN	0x02
#define ISCSI_SDETAIL_TGT_NOT_FOUND	0x03
#define ISCSI_SDETAIL_TGT_REMOVED	0x04
#define ISCSI_SDETAIL_NO_VERSION	0x05
#define ISCSI_SDETAIL_TOO_MANY_CONN	0x06
#define ISCSI_SDETAIL_MISSING_FIELDS	0x07
#define ISCSI_SDETAIL_CONN_ADD_FAILED	0x08
#define ISCSI_SDETAIL_INV_SESSION_TYPE	0x09
#define ISCSI_SDETAIL_SESSION_NOT_FOUND	0x0A
#define ISCSI_SDETAIL_INV_REQ_TYPE	0x0B

// Class-3 (Target Error)
#define ISCSI_SDETAIL_TARGET_ERROR	0x00
#define ISCSI_SDETAIL_SVC_UNAVAILABLE	0x01
#define ISCSI_SDETAIL_NO_RESOURCES	0x02

// Logout Request Reason Code Mask
#define ISCSI_MASK_REASONCODE 0x7F


#define ISCSI_LOGOUT_SUCCESS        0x0
#define ISCSI_LOGOUT_CID_NOT_FOUND  0x1
#define ISCSI_LOGOUT_CONN_RECOVERY  0x2
#define ISCSI_LOGOUT_CLEANUP_FAILED 0x3

enum iscsi_sockio_state {
    SOCKIO_BHS_NULL = 0x00,
    SOCKIO_BHS_INIT = 0x10,
    SOCKIO_BHS_RXTX = 0x11,
    SOCKIO_AHS_INIT,
    SOCKIO_DS_INIT,
    SOCKIO_AHS_DS_RXTX,
    SOCKIO_DONE = 0xFF,
}; // enum iscsi_sockio_state

#define SESSION_MAX 32
#define CONNECTION_MAX 32

enum event_iotype {
    EVENT_SOCKET = 1,
    EVENT_DISKRW = 2,
    EVENT_EVENT = 3,
    EVENT_TOTAL  = 4
}; // enum event_iotype


enum iscsi_auth_method {
    ISCSI_AUTH_NULL = 0x00,
    ISCSI_AUTH_NONE = 0x01,
    ISCSI_AUTH_CHAP = 0x02,
    ISCSI_AUTH_UNKNOWN = 0xFF,
}; // enum iscsi_auth_method

enum iscsi_session_type {
    ISCSI_SESSION_NULL = 0x00,
    ISCSI_SESSION_DISCOVERY = 0x01,
    ISCSI_SESSION_NORMAL = 0x02,
    ISCSI_SESSION_UNKNOWN = 0xFF
}; // enum iscsi_session_type


// iSCSI session ID
union iscsi_sid {
//#if __BYTE_ORDER == __BIG_ENDIAN
    struct {
	uint8 isid[6];
	uint8 tsih[2];
    } id;
/*
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    struct {
	uint8 tsih[2];
	uint8 isid[6];
    } id;
#endif
*/
    uint64 id64;
} __packed;

enum iscsi_stage {
    ISCSI_STAGE_START                   = 0x00,
//    ISCSI_STAGE_SECURITY                = 0x10,
//    ISCSI_STAGE_SECURITY_NONE           = 0x11,
    ISCSI_STAGE_SECURITY_CHAP_START = 0x1A,
    ISCSI_STAGE_SECURITY_CHAP_CHALLENGE  = 0x1B,
//    ISCSI_STAGE_SECURITY_CHAP_RESPONSE  = 0x1C,
    ISCSI_STAGE_OPERATIONAL             = 0x20,
    ISCSI_STAGE_FULL_FEATURE            = 0x30,
    ISCSI_STAGE_CLOSE                   = 0xFE,
    ISCSI_STAGE_FINISH                  = 0xFF
};

enum iscsi_chap_algorithm {
    ISCSI_CHAP_ALGORITHM_NULL = 0x00,
    ISCSI_CHAP_ALGORITHM_MD5 = 0x05,
    ISCSI_CHAP_ALGORITHM_SHA1 = 0x07,
    ISCSI_CHAP_ALGORITHM_UNKNOWN = 0xFF
};

// iSCSI connection
struct iscsi_conn {
    struct list_element listelem_siso;    // connection list
    struct list_element listelem_session; // connection list

    struct siso_info *siso;
    struct iscsi_target *target;            // iscsi target
    pthread_t thread;

    struct sockaddr_storage cli_addr; // client address
    socklen_t cli_addr_len;    // client address length

    enum iscsi_stage stage;

    enum iscsi_chap_algorithm chap_a;
    uint8 chap_i;
#define ISCSI_CHAP_CHALLENGE_MAXLEN 1024
#define ISCSI_CHAP_CHALLENGE_LEN 16

    uint8 chap_c_num[ISCSI_CHAP_CHALLENGE_MAXLEN];
    uint32 chap_c_len;
    char chap_c_str[ISCSI_CHAP_CHALLENGE_MAXLEN * 2 + 2 + 1];
    uint8 chap_r_exp_num[DIGEST_LEN_SHA1];        // DIGEST_LEN_MD5 < DIGEST_LEN_SHA1
    char chap_r_exp_str[DIGEST_LEN_SHA1 * 2 + 2 + 1]; // DIGEST_LEN_MD5 < DIGEST_LEN_SHA1

    struct list list_volcmd;
    
//    struct volume_cmd *list_volcmd;
//    uint32 list_volcmd->len;

    pthread_mutex_t lock_list_volcmd;

#define DEFAULT_ERROR_RECOVERY_LEVEL	0
#define DEFAULT_INITIAL_R2T		1
#define DEFAULT_IMMEDIATE_DATA		1
#define DEFAULT_MAX_BURST_LENGTH	(256*1024)
#define DEFAULT_FIRST_BURST_LENGTH	(64*1024)
#define DEFAULT_MAX_CONNECTIONS		1
#define DEFAULT_DATA_PDU_IN_ORDER	1
#define DEFAULT_DATA_SEQUENCE_IN_ORDER	1
#define DEFAULT_MAX_OUTSTANDING_R2T	1
#define DEFAULT_DEFAULT_TIME2WAIT   2
#define DEFAULT_DEFAULT_TIME2RETAIN 20
#define DEFAULT_HEADER_DIGEST DIGEST_NONE
#define DEFAULT_DATA_DIGEST DIGEST_NONE

#define DIGEST_NONE   0x01
#define DIGEST_CRC32C 0x02
#define DIGEST_ALL    (DIGEST_NONE | DIGEST_CRC32C)


    uint32 error_recovery_level;
    uint32 initial_r2t;
    uint32 immediate_data;
    uint32 max_burst_length;
    uint32 first_burst_length;
    uint32 max_connections;
    uint32 data_pdu_in_order;
    uint32 data_sequence_in_order;
    uint32 max_outstanding_r2t;
    uint32 default_time2wait;
    uint32 default_time2retain;
    uint32 header_digest;
    uint32 data_digest;

    uint32 max_xmit_data_len;

    union iscsi_sid sid;
    enum iscsi_session_type session_type;
    char initiator_name[ISCSI_NAME_MAXBUFLEN];

    uint32 statsn;
    uint32 expcmdsn;
//    uint32 maxcmdsn;
//    uint32 cmdsn;
    uint32 ttt;

//    uint32 expcmdsn;
//    uint32 maxcmdsn;

    enum iscsi_sockio_state state_rx;           // rx state
    enum iscsi_sockio_state state_tx;           // tx state

    struct iovecs iov_rx; // RX vector IO buffer
    struct iovecs iov_tx; // TX vector IO buffer

    byte dspad_tx[4];
    byte dspad_rx[4];

    struct iscsi_session *session;  // owning iSCSI session
    uint16 cid;                     // connection ID

    struct list list_task;

    uint32 pdus;
    uint32 dslen_total;
    uint32 ahslen_total;


    struct iscsi_pdu *pdu_rx;
    struct list list_pdu_tx;

//    struct iscsi_pdu *pdu_rx;              // rx PDU queue
//    uint32 pdus_rx;                         // always 1
//    struct iscsi_pdu *pduq_tx;              // tx PDU queue
//    uint32 pdus_tx;                         // <= 0

    struct epoll_event event[EVENT_TOTAL];
    int fd_ep;                              // epoll fd
    int fd_ev;                              // event epoll
    int fd_sock;                            // socket fd

    uint32 stat_sn;
    uint32 exp_stat_sn;
    uint32 itt;
}; // struct iscsi_conn

#define SECTOR_SIZE_DEFAULT 512
#define CAPACITY_DEFAULT (1024*1024*1024 / SECTOR_SIZE_DEFAULT)



// 10.18.  NOP-Out
struct iscsi_bhs_nop_out {
    uint8 opcode; // 0x00
    uint8 Fbit; // always 1
    uint16 reserved1;
    uint32 len; // AHS(1byte) and DS(3bytes)
    uint64 lun;
    uint32 itt;
    uint32 ttt;
    uint32 cmdsn;
    uint32 expstatsn;
    uint64 reserved2[2];
} __packed;

// 10.19.  NOP-In
struct iscsi_bhs_nop_in {
    uint8 opcode; // 0x20
    uint8 Fbit; // always 1
    uint16 reserved1;
    uint32 len; // AHS(1byte) and DS(3bytes)
    uint64 lun;
    uint32 itt;
    uint32 ttt;
    uint32 statsn;
    uint32 expcmdsn;
    uint32 maxcmdsn;
    uint32 reserved2[3];
} __packed;

// 10.3. SCSI Command
struct iscsi_bhs_scsi_cmd {
    uint8 opcode;
    uint8 flags; // Fbit,Rbit,Wbit,ATTR
    uint16 reserved;
    uint32 len; // AHS(1byte) and DS(3bytes)
    uint64 lun;
    uint32 itt;
    uint32 expdtlen; // Expected Data Transfer Length
    uint32 cmdsn;
    uint32 expstatsn;
    struct scsi_cdb cdb;
} __packed;


// 10.4.  SCSI Response
struct iscsi_bhs_scsi_rsp {
    uint8 opcode;
    uint8 flags; // Fbit(always 1), obit, ubit, Obit, Ubit
    uint8 response;
    uint8 status;
    uint32 len; // AHS(1byte) and DS(3bytes)
    uint32 reserved[2];
    uint32 itt;
    uint32 snack;
    uint32 statsn;
    uint32 expcmdsn;
    uint32 maxcmdsn;
    uint32 expdatasn;
    uint32 brrcount; // Bidirectional Read Residual Count
    uint32 rcount;   // Residual Count
} __packed;


// 10.5.  Task Management Function Request
struct iscsi_bhs_taskmng_req {
    uint8 opcode;
    uint8 flags; // Fbit(always 1) and function
    uint16 reserved1;
    uint32 len; // AHS(1byte) and DS(3bytes)
    uint64 lun;
    uint32 itt;
    uint32 rtt; // Referenced Task Tag
    uint32 cmdsn;
    uint32 expstatsn;
    uint32 refcmdsn;
    uint32 expdatasn;
    uint64 reserved2;
} __packed;

// 10.6.  Task management Function Response
struct iscsi_bhs_taskmng_rsp {
    uint8 opcode; // 0x22
    uint8 Fbit;   // always 1
    uint8 response;
    uint8 reserved1;
    uint32 len; // AHS(1byte) and DS(3bytes)
    uint32 reserved2[2];
    uint32 itt;
    uint32 reserved3;
    uint32 statsn;
    uint32 expcmdsn;
    uint32 maxcmdsn;
    uint32 reserved4[3];
} __packed;


// 10.7.  SCSI Data-Out
struct iscsi_bhs_scsidata_out {
    uint8 opcode; // 0x05
    uint8 Fbit;
    uint16 reserved1;
    uint32 len; // AHS(1byte) and DS(3bytes)
    uint64 lun;
    uint32 itt;
    uint32 ttt;
    uint32 reserved2;
    uint32 expstatsn;
    uint32 reserved3;
    uint32 datasn;
    uint32 bufoffset;
    uint32 reserevd;
} __packed;


// 10.7.  SCSI_Data-In
struct iscsi_bhs_scsidata_in {
    uint8 opcode; // 0x25
    uint8 flags;  // Fbit, Abit, Obit, Ubit, Sbit
    uint8 reserved1;
    uint8 status;
    uint32 len; // AHS(1byte) and DS(3bytes)
    uint64 lun;
    uint32 itt;
    uint32 ttt;
    uint32 statsn;
    uint32 expcmdsn;
    uint32 maxcmdsn;
    uint32 datasn;
    uint32 bufoffset; // buffer offset
    uint32 rcount;  // residual count
} __packed;


// 10.8.  Ready To Transfer
struct iscsi_bhs_r2t {
    uint8 opcode; // 0x31
    uint8 Fbit;   // always 1
    uint16 reserved;
    uint32 len; // AHS(1byte) and DS(3bytes)
    uint64 lun;
    uint32 itt;
    uint32 ttt;
    uint32 statsn;
    uint32 expcmdsn;
    uint32 maxcmdsn;
    uint32 r2tsn;
    uint32 bufoffset;
    uint32 ddtlen; // Desired Data Transfer Length
} __packed;


// 10.9.  Asynchronous Message


// 10.10.  Text Request
struct iscsi_bhs_text_req {
    uint8 opcode; // 0x04
    uint8 flags;  // Fbit and Cbit
    uint16 reserved1;
    uint32 len; // AHS(1byte) and DS(3bytes)
    uint64 lun;
    uint32 itt;
    uint32 ttt;
    uint32 cmdsn;
    uint32 expstatsn;
    uint32 reserved2[4];
} __packed;


// 10.11.  Text Response
struct iscsi_bhs_text_rsp {
    uint8 opcode;  // 0x24
    uint8 flags;   // Fbit and Cbit
    uint16 reserved1;
    uint32 len;    // AHS(1byte) and DS(3bytes)
    uint64 lun;
    uint32 itt;
    uint32 ttt;
    uint32 statsn;
    uint32 expcmdsn;
    uint32 maxcmdsn;
    uint32 reserved2[3];
} __packed;


// 10.12.  Login Request
struct iscsi_bhs_login_req {
    uint8 opcode; // 0x03
    uint8 flags;  // Tbit, Cbit, CSG, NSG
    uint8 vmax;   // version max
    uint8 vmin;   // version min
    uint32 len;   // AHS(1byte) and DS(3bytes)
    union iscsi_sid sid; // ISID(6bytes) and TSIH(2bytes)
    uint32 itt;
    uint16 cid;
    uint16 reserved1;
    uint32 cmdsn;
    uint32 expstatsn;
    uint64 reserved2[2];
} __packed;


// 10.13.  Login Response
struct iscsi_bhs_login_rsp {
    uint8 opcode; // 0x23
    uint8 flags; // Tbit, Cbit, CSG, NSG
    uint8 vmax;  // Version-max
    uint8 vact;  // Version-active
    uint32 len; // AHS(1byte) and DS(3bytes)
    union iscsi_sid sid; // ISID(6bytes) and TSIH(2bytes)
    uint32 itt;
    uint32 reserved1;
    uint32 statsn;
    uint32 expcmdsn;
    uint32 maxcmdsn;
    uint8 sclass; // Status-Class
    uint8 sdetail; // Status-Detail
    uint16 reserved;
    uint64 reserved2;
} __packed;


// 10.14.  Logout Request
struct iscsi_bhs_logout_req {
    uint8 opcode; // 0x06
    uint8 flags; // Fbit(always 1) and Reason Code
    uint16 reserved1;
    uint32 len; // AHS(1byte) and DS(3bytes)
    uint64 reserved2;
    uint32 itt;
    uint16 cid;
    uint16 reserved3;
    uint32 cmdsn;
    uint32 expstatsn;
    uint64 reserved4[2];
} __packed;


// 10.15.  Logout Response
struct iscsi_bhs_logout_rsp {
    uint8 opcode; // 0x26
    uint8 Fbit; // always 1
    uint8 response;
    uint8 reserved1;
    uint32 len; // AHS(1byte) and DS(3bytes)
    uint64 reserved2;
    uint32 itt;
    uint32 reserved3;
    uint32 statsn;
    uint32 expcmdsn;
    uint32 maxcmdsn;
    uint32 reserved4;
    uint16 time2wait;
    uint16 time2retain;
    uint32 reserved;
} __packed;

// iSCSI status code (see. RFC3720 "10.4.2.  Status")
#define ISCSI_STATUS_GOOD                 0x00
#define ISCSI_STATUS_CHECK_CONDITION      0x02
#define ISCSI_STATUS_BUSY                 0x08
#define ISCSI_STATUS_RESERVATION_CONFLICT 0x18
#define ISCSI_STATUS_TASK_SET_FULL        0x28
#define ISCSI_STATUS_ACA_ACTIVE           0x30
#define ISCSI_STATUS_TASK_ABORTED         0x40

// ref: 10.2.1. Basic Header Segment (BHS)
struct iscsi_bhs {
    // 0-3
    uint8 opcode;   // final bit operation code
    uint8 spec1[3]; // opecode-specific fields
    // 4-7
#if 0
    struct {
	uint32 ahslen : 8; // ahs length
	uint32 dslen : 24; // data segment length
    } len;
#else
    uint32 len;
#endif
    // 8-15
    uint32 lun[2];  // lun or opecode-specific fields
    // 16-19
    uint32 itt;     // initiator task tag
    // 20-23
    uint32 ttt;     // target task tag
    // 24-27
    uint32 sn;      // sequence number
    // 28-31
    uint32 exp_sn;  // expected sequence number
    // 32-35
    uint32 max_sn;  // max sequence number
    // 36-48
    uint32 spec2;   // opecode-specific fields
}; // struct iscsi_bhs


struct buffer_vec {
    byte *buf;
    uint32 buflen;
    uint32 offset;
    uint32 len;
    struct page_buffer *page;
}; // struct buffer_vec


struct databuf_vec {
}; // struct databuf_vec

struct iscsi_pdu {
    struct iscsi_conn *conn;
    struct iscsi_task *task;        // iSCSI command

    struct volume *vol;

    struct list_element listelem_conn; // chain in iSCSI connection
    struct list_element listelem_task; // chain in iSCSI task
    struct list_element listelem_rxtx; // chain in RX/TX queue

    struct iscsi_bhs bhs;           // BHS

    byte *ahsbuf;                      // AHS buffer
    uint32 ahsbuflen;


#define DATASEGMENT_VECTOR_MAX (DEFAULT_MAX_BURST_LENGTH / PAGE_BUFFER_SIZE)
    struct buffer_vec dsvec[IOV_MAX];
    uint32 dsvec_cnt;
    uint32 dsvec_len;
    uint32 dsvec_offset;

//    byte *dsbuf;                       // DS buffer
//    uint32 dsbuflen;

    uint8 opcode;
    uint8 Ibit;                     // immediate bit
    uint32 ahslen;                  // AHS buffer length
    uint32 dslen;                   // DS buffer length
    uint32 itt;
    uint32 ttt; // nopout

    uint8 status; // : SCSIData-In, scsirsp

    uint64 lun; // only support single-level LUN structure
    uint8 Fbit; // final bit : taskmngreq, scsicmd, textreq/res, r2t
    uint8 func; // taskmngreq
    uint32 rtt; // taskmngreq
    uint8 Rbit; // scsicmd
    uint8 Wbit; // scsicmd
    uint8 attr; // scsicmd
    uint32 expdtlen;  // Expected Data Transfer Length : scsicmd
    uint32 cmdsn;     // Command SN: nopout, taskmngreq, scsicmd, loginreq
    uint32 expstatsn; // Expected Stat SN: nopout, taskmngreq, scsicmd, loginreq
    uint32 refcmdsn;  // Ref Command SN: taskmngreq
    uint32 expdatasn; // Expected Data SN : taskmngreq, scsirsp
    uint32 r2tsn;     // Ready To Transfer SN : r2t
    uint8 Tbit; // Transit bit : loginreq/res
    uint8 Cbit; // Continue bit : loginreq/res, textreq/res
    uint8 csg; // Current Stage : loginreq
    uint8 nsg; // Next Stage : loginreq
    uint8 vmax; // Version-max : loginreq, loginrsp
    uint8 vmin; // Version-min : loginreq
    uint8 vact; // Version-active : loginrsp
    union iscsi_sid sid; // session ID : loginreq
    uint16 cid; // loginreq, logoutreq
    uint8 sclass; // Status-Class : loginrsp
    uint8 sdetail; // Status-Detail : loginrsp

    uint8 Abit; // scsidata-in
    uint8 Obit; // scsidata-in
    uint8 Ubit; // scsidata-in, scsirsp
    uint8 Sbit; // scsidata-in, scsirsp
    uint8 obit; // scsirsp
    uint8 ubit; // scsirsp
    uint32 snack; // scsirsp
    uint32 brrcount; // scsirsp
    
    uint32 statsn; // scsidata-in
    uint32 expcmdsn; // scsidata-in
    uint32 maxcmdsn; // scsidata-in
    uint32 datasn; // scsidata-in
    uint32 bufoffset; // scsidata-in, r2t
    uint32 ddtlen; // Desired Data Transfer Length : r2t
    uint32 rcount; // scsidata-in,scsirsp

    uint32 reason; // logoutreq

    uint8 response; // logoutrsp, scsirsp
    uint16 time2wait; // logoutrsp
    uint16 time2retain; // logoutrsp

    struct scsi_cmd cmd; // scsicmd
}; // struct iscsi_pdu


struct io_lap_time {
    uint64 time_usec_rx;
    uint64 time_usec_iostart;
    uint64 time_usec_ioend;
    uint64 time_usec_tx;
    uint8 scsi_opcode;
    uint64 lba;
    uint32 len;
};


struct iscsi_task {
    struct list_element listelem;
    
    uint32 itt;

    struct iscsi_conn *conn;        // iscsi connection
    struct list list_pdu;
    // disk io
    // lun

    struct volume *vol;

    struct list list_page;
    uint32 page_totallen;
    uint32 page_filled;

    uint32 ttt;
    uint32 datasn;

    struct io_lap_time laptime;
}; // struct iscsi_task


int iscsi_enqueue_and_tx_pdu(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu);

byte *iscsi_alloc_dsbuf(struct iscsi_conn *conn, uint32 dslen);
int iscsi_free_dsbuf(struct iscsi_conn *conn, byte *ds, uint32 dslen);
int iscsi_add_pdu_to_task(struct iscsi_conn *conn, struct iscsi_task *task, struct iscsi_pdu *pdu);
struct iscsi_task *iscsi_search_task(struct iscsi_conn *conn, uint32 itt);
void iscsi_unpack_pdu(struct iscsi_conn *conn, struct iscsi_pdu *pdu);
void iscsi_pack_pdu(struct iscsi_conn *conn, struct iscsi_pdu *pdu);
void iscsi_set_sn(struct iscsi_conn *conn, struct iscsi_pdu *pdu);
struct iscsi_task *iscsi_create_task(struct iscsi_conn *conn, uint32 itt);
int iscsi_remove_task(struct iscsi_conn *conn, struct iscsi_task *task);
struct iscsi_pdu *iscsi_create_pdu(struct iscsi_conn *conn);
void iscsi_remove_pdu(struct iscsi_conn *conn, struct iscsi_pdu *pdu);
void iscsi_dump_pdu(struct iscsi_conn *conn, struct iscsi_pdu *pdu);
void iscsi_dump_pdu_in_hex(struct iscsi_conn *conn, struct iscsi_pdu *pdu);

struct volume_cmd *iscsi_alloc_volcmd(struct iscsi_conn *conn);
int iscsi_free_volcmd(struct iscsi_conn *conn, struct volume_cmd *volcmd);

#define LOCK_LIST_VOLCMD(conn) do { pthread_mutex_lock(&(conn->lock_list_volcmd)); } while (0)
#define UNLOCK_LIST_VOLCMD(conn) do { pthread_mutex_unlock(&(conn->lock_list_volcmd)); } while (0)

uint16 iscsi_get_tsih(struct iscsi_target *target);


#endif // __ISCSI_H__
