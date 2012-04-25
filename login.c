/*
 * SISO : Simple iSCSI Storage
 * 
 * process login sequence.
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

#include <errno.h>
#include <string.h>  // memset
#include <strings.h> // strcasecmp
#include <openssl/md5.h>
#include <openssl/sha.h>
#include "target.h"
#include "iscsi.h"
#include "misc.h"
#include "siso.h"

static struct iscsi_pdu *create_login_rsp(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    uint8 sclass,
    uint8 sdetail);

static int generate_challenge_and_response(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu,
    enum iscsi_session_type session_type);
static int check_challenge_response(
    struct iscsi_conn *conn,
    char *chap_n,
    char *chap_r,
    enum iscsi_session_type session_type);

static enum iscsi_session_type unpack_session_type(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu);
static char *unpack_initiator_name(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu);
static char *unpack_target_name(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu);
static enum iscsi_auth_method unpack_auth_method(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu);
static int is_auth_required(struct iscsi_conn *conn, enum iscsi_session_type session_type);

static enum iscsi_chap_algorithm unpack_chap_algorithm(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu);

static char *unpack_chap_username(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu);
static char *unpack_chap_response(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu);

static int scan_operational_text(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct iscsi_pdu *pdu_rsp);

struct iscsi_pdu *exec_csg_security_chap_auth(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req)
{
    struct iscsi_pdu *pdu_rsp = NULL;
    char *chap_n = NULL;
    char *chap_r = NULL;
    int rv = 0;

    // Transition bit must be specified as 0 (stay security stage).
    if ((pdu_req->Tbit && pdu_req->nsg == ISCSI_NSG_OPERATIONAL) ||
	(pdu_req->Tbit && pdu_req->nsg == ISCSI_NSG_FULL_FEATURE)) {
    } else {
	goto failure_init;
    }

    // Check username and response
    chap_n = unpack_chap_username(conn, pdu_req);
    chap_r = unpack_chap_response(conn, pdu_req);
    if (chap_r == NULL || chap_n == NULL) {
	goto failure_init;
    }
    rv = check_challenge_response(conn, chap_n, chap_r, conn->session_type);
    if (rv == -EACCES) {
	goto failure_auth;
    } else if (rv) {
	goto failure_init;
    }

    // Create LoginResponse as success.
    pdu_rsp = create_login_rsp(conn, pdu_req,
			       ISCSI_SCLASS_SUCCESS,
			       ISCSI_SDETAIL_ACCEPT);
    if (pdu_rsp == NULL) {
	goto failure_internal;
    }

    // Transit stage to NSG.
    if (pdu_req->nsg == ISCSI_NSG_OPERATIONAL) {
	conn->stage = ISCSI_STAGE_OPERATIONAL;
    } else if (pdu_req->nsg == ISCSI_NSG_FULL_FEATURE) {
	conn->stage = ISCSI_STAGE_FULL_FEATURE;
    } else {
	ASSERT((0), "pdu_req->nsg=%d\n", pdu_req->nsg);
    }

    return pdu_rsp;

failure_auth:
    pdu_rsp = create_login_rsp(conn, pdu_req,
			       ISCSI_SCLASS_INITIATOR_ERR,
			       ISCSI_SDETAIL_AUTH_FAILED);
    return pdu_rsp;

failure_init:
    pdu_rsp = create_login_rsp(conn, pdu_req,
			       ISCSI_SCLASS_INITIATOR_ERR,
			       ISCSI_SDETAIL_INIT_ERR);
    return pdu_rsp;

failure_internal:
    return NULL;
} // exec_csg_security_chap_auth


struct iscsi_pdu *exec_csg_security_chap_start(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req)
{
    struct iscsi_pdu *pdu_rsp = NULL;
    byte *text;
    uint32 textlen;
    enum iscsi_chap_algorithm chap_a;
    int rv;
    int len;

    // Transition bit must be specified as 0 (stay security stage).
    if (pdu_req->Tbit) {
	goto failure_init;
    }

    // Choose CHAP algorithm (CHAP_A).
    chap_a = unpack_chap_algorithm(conn, pdu_req);
    if (chap_a != ISCSI_CHAP_ALGORITHM_MD5 &&
	chap_a != ISCSI_CHAP_ALGORITHM_SHA1) {
	goto failure_init;
    }
    conn->chap_a = chap_a;

    // Choose CHAP ID (CHAP_I), and generate challenge-code (CHAP_C) and
    // expected response (CHAP_R).
    rv = generate_challenge_and_response(conn, pdu_req, conn->session_type);
    if (rv) {
	goto failure_internal;
    }

    log_dbg3("CHAP_A=%d\n", conn->chap_a);
    log_dbg3("CHAP_I=%u\n", conn->chap_i);
    log_dbg3("CHAP_C=%s\n", conn->chap_c_str);
    log_dbg3("CHAP_R(expected)=%s\n", conn->chap_r_exp_str);

    // Create LoginResponse PDU and set security text.
    pdu_rsp = create_login_rsp(conn, pdu_req,
			       ISCSI_SCLASS_SUCCESS,
			       ISCSI_SDETAIL_ACCEPT);
    if (pdu_rsp == NULL) {
	goto failure_internal;
    }
    text = pdu_rsp->dsvec[0].buf;
    textlen = pdu_rsp->dsvec[0].buflen;

    len = pack_kv(text, textlen, "CHAP_A", "%d", conn->chap_a);
    ASSERT((len != -1), "len == -1\n");
    text += len;
    textlen -= len;

    len = pack_kv(text, textlen, "CHAP_I", "%u", conn->chap_i);
    ASSERT((len != -1), "len == -1\n");
    text += len;
    textlen -= len;

    len = pack_kv(text, textlen, "CHAP_C", conn->chap_c_str);
    ASSERT((len != -1), "len == -1\n");
    text += len;
    textlen -= len;

    pdu_rsp->dsvec[0].len = pdu_rsp->dsvec[0].buflen - textlen;
    pdu_rsp->dslen = pdu_rsp->dsvec[0].len;

    log_dbg3("pdu_rsp->dsvec[0].{buf=%p, len="U32_FMT"}\n",
	     pdu_rsp->dsvec[0].buf, pdu_rsp->dsvec[0].len);
    if (logger_is_dbg3()) {
	print_hex((char *)(pdu_rsp->dsvec[0].buf), pdu_rsp->dsvec[0].len);
    }

    conn->stage = ISCSI_STAGE_SECURITY_CHAP_CHALLENGE;

    return pdu_rsp;

failure_init:
    pdu_rsp = create_login_rsp(conn, pdu_req,
			       ISCSI_SCLASS_INITIATOR_ERR,
			       ISCSI_SDETAIL_INIT_ERR);
    return pdu_rsp;

failure_internal:
    return NULL;
} // exec_csg_security_chap_start


struct iscsi_pdu *exec_csg_security_start(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req)
{
    char *initiator_name;
    char *target_name;
    enum iscsi_auth_method auth;
    enum iscsi_session_type session_type;
    struct iscsi_pdu *pdu_rsp = NULL;
    byte *text;
    uint32 textlen;
    int len;
    int rv;
    
    // Check security-text key/value pairs.
    // (see RFC 3720 Chapter 11)
    initiator_name = unpack_initiator_name(conn, pdu_req);
    auth = unpack_auth_method(conn, pdu_req);
    session_type = unpack_session_type(conn, pdu_req);
    target_name = unpack_target_name(conn, pdu_req);

    // ToDo : Check TargetName
    if (initiator_name == NULL) {
	log_err("Illegal LoginRequest (InitiatorName=null)\n");
	goto failure_init;
    }
    if (auth == ISCSI_AUTH_NULL ||
	auth == ISCSI_AUTH_UNKNOWN) {
	log_err("Illegal LoginRequest (CSG=0x%02X, AuthMethod is not specified(%d))\n",
		pdu_req->csg, auth);
	goto failure_init;
    }
    if (session_type == ISCSI_SESSION_UNKNOWN) {
	log_err("Illegal LoginRequest (CSG=0x%02X, unknown session type)\n",
		pdu_req->csg, session_type);
	goto failure_init;
    } else if (session_type == ISCSI_SESSION_NULL) {
	log_wrn("SessionType is not specified, so use \"Normal\".\n");
	session_type = ISCSI_SESSION_NORMAL;
    }
    if (session_type == ISCSI_SESSION_NORMAL && target_name == NULL) {
	log_err("Illegal LoginRequest (CSG=0x%02X, SessionType=Discovery, TargetName but is not specified(%d))\n",
		pdu_req->csg, auth);
	goto failure_init;
    }

    // Bind iSCSI connection to iSCSI target/session.
    conn->cid = pdu_req->cid;
    if (session_type == ISCSI_SESSION_NORMAL) {
	rv = iscsi_bind_connection(target_name, pdu_req->sid, conn);
	if (rv == -ENOENT) {
	    goto failure_target;
	} else if (rv == -ENOMEM) {
	    goto failure_internal;
	} else if (rv) {
	    goto failure_init;
	}
    }

    // Create LoginResponse PDU and set security text.
    pdu_rsp = create_login_rsp(conn, pdu_req,
			       ISCSI_SCLASS_SUCCESS,
			       ISCSI_SDETAIL_ACCEPT);
    if (pdu_rsp == NULL) {
	goto failure_internal;
    }
    text = pdu_rsp->dsvec[0].buf;
    textlen = pdu_rsp->dsvec[0].buflen;

    log_dbg1("auth=%d\n", auth);

    switch (auth) {
    case ISCSI_AUTH_NONE:
	// Check CHAP authentication requirement.
	if (is_auth_required(conn, session_type)) {
	    log_err("Illegal LoginRequest (CHAP authentication is required).\n");
	    goto failure_auth;
	}
	// NSG must be specified as operational or full-feature.
	if (pdu_req->Tbit && pdu_req->nsg == ISCSI_NSG_OPERATIONAL) {
	    conn->stage = ISCSI_STAGE_OPERATIONAL;
	} else if (pdu_req->Tbit && pdu_req->nsg == ISCSI_NSG_FULL_FEATURE) {
	    conn->stage = ISCSI_STAGE_FULL_FEATURE;
	} else {
	    goto failure_init;
	}
	len = pack_kv(text, textlen, "AuthMethod", "None");
	ASSERT((len != -1), "len == -1\n");
	text += len;
	textlen -= len;
	break;
    case ISCSI_AUTH_CHAP:
	if (!is_auth_required(conn, session_type)) {
	    log_err("Illegal LoginRequest (CHAP authenication is not required).\n");
	    goto failure_auth;
	}
	// Transition bit must be specified as 0
	if (pdu_req->Tbit) {
	    goto failure_init;
	}
	conn->stage = ISCSI_STAGE_SECURITY_CHAP_START;
	
	len = pack_kv(text, textlen, "AuthMethod", "CHAP");
	ASSERT((len != -1), "len == -1\n");
	text += len;
	textlen -= len;
	break;
    case ISCSI_AUTH_NULL:
    case ISCSI_AUTH_UNKNOWN:
    default:
	goto failure_init;
    }

    len = pack_kv(text, textlen, "TargetPortalGroupTag", "1");
    ASSERT((len != -1), "len == -1\n");
    text += len;
    textlen -= len;
    pdu_rsp->dsvec[0].len = pdu_rsp->dsvec[0].buflen - textlen;
    pdu_rsp->dslen = pdu_rsp->dsvec[0].len;

    log_dbg3("pdu_rsp->dsvec[0].{buf=%p, len="U32_FMT"}\n",
	     pdu_rsp->dsvec[0].buf, pdu_rsp->dsvec[0].len);
    if (logger_is_dbg3()) {
	print_hex((char *)(pdu_rsp->dsvec[0].buf), pdu_rsp->dsvec[0].len);
    }

    conn->session_type = session_type;
    strcpy(conn->initiator_name, initiator_name);

    return pdu_rsp;

failure_init:
    if (pdu_rsp != NULL) {
        iscsi_remove_pdu(conn, pdu_rsp);
	pdu_rsp = NULL;
    }
    pdu_rsp = create_login_rsp(conn, pdu_req,
			       ISCSI_SCLASS_INITIATOR_ERR,
			       ISCSI_SDETAIL_INIT_ERR);
    return pdu_rsp;

failure_auth:
    if (pdu_rsp != NULL) {
        iscsi_remove_pdu(conn, pdu_rsp);
	pdu_rsp = NULL;
    }
    pdu_rsp = create_login_rsp(conn, pdu_req,
			       ISCSI_SCLASS_INITIATOR_ERR,
			       ISCSI_SDETAIL_AUTH_FAILED);
    return pdu_rsp;

failure_target:
    if (pdu_rsp != NULL) {
        iscsi_remove_pdu(conn, pdu_rsp);
	pdu_rsp = NULL;
    }
    pdu_rsp = create_login_rsp(conn, pdu_req,
			       ISCSI_SCLASS_INITIATOR_ERR,
			       ISCSI_SDETAIL_TGT_NOT_FOUND);
    return pdu_rsp;
			  
failure_internal:
    if (pdu_rsp != NULL) {
        iscsi_remove_pdu(conn, pdu_rsp);
	pdu_rsp = NULL;
    }
    return NULL;
} // exec_csg_securty_start


struct iscsi_pdu *exec_csg_security(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req)
{
    struct iscsi_pdu *pdu_rsp = NULL;

    log_dbg1("conn->stage=%02X\n", conn->stage);
    switch (conn->stage) {
    case ISCSI_STAGE_START:
	pdu_rsp = exec_csg_security_start(conn, pdu_req);
	break;
    case ISCSI_STAGE_SECURITY_CHAP_START:
	pdu_rsp = exec_csg_security_chap_start(conn, pdu_req);
	break;
    case ISCSI_STAGE_SECURITY_CHAP_CHALLENGE:
	pdu_rsp = exec_csg_security_chap_auth(conn, pdu_req);
	break;
    default:
	goto failure_init;
	break;
    }
    return pdu_rsp;

failure_init:
    pdu_rsp = create_login_rsp(conn, pdu_req,
			       ISCSI_SCLASS_INITIATOR_ERR,
			       ISCSI_SDETAIL_INIT_ERR);
    return pdu_rsp;
} // exec_csg_security


static int is_auth_required(struct iscsi_conn *conn, enum iscsi_session_type session_type)
{
    int required = 0;
    enum iscsi_auth_method auth;

    switch (session_type) {
    case ISCSI_SESSION_DISCOVERY:
	auth = conn->siso->auth;
	break;
    case ISCSI_SESSION_NORMAL:
	auth = conn->target->auth;
	break;
    default:
	ASSERT((0), "session_type=%d\n", session_type);
	break;
    }

    if (auth == ISCSI_AUTH_CHAP) {
	required = 1;
    } else {
	ASSERT((auth == ISCSI_AUTH_NONE),
	       "auth(%d) != ISCSI_AUTH_NONE(%d)\n",
	       auth, ISCSI_AUTH_NONE);
    }
    return required;
} // is_auth_required


struct iscsi_pdu *exec_csg_operational(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req)
{
    char *initiator_name;
    char *target_name;
    enum iscsi_auth_method auth;
    enum iscsi_session_type session_type;
    struct iscsi_pdu *pdu_rsp = NULL;
    int rv;

    // check NSG
    if (pdu_req->nsg != ISCSI_NSG_FULL_FEATURE) {
	log_err("Illegal LoginRequest (CSG=0x%02X, NSG=0x%02X).\n",
		pdu_req->csg, pdu_req->nsg);
	goto failure_init;
    }

    log_dbg1("conn->stage=0x%02X\n", conn->stage);
    switch (conn->stage) {
    case ISCSI_STAGE_START:
	// Check security-text key/value pairs.
	// (see RFC 3720 Chapter 11)
	initiator_name = unpack_initiator_name(conn, pdu_req);
	auth = unpack_auth_method(conn, pdu_req);
	session_type = unpack_session_type(conn, pdu_req);
	target_name = unpack_target_name(conn, pdu_req);
	if (initiator_name == NULL) {
	    log_err("Illegal LoginRequest (InitiatorName=null)\n");
	    goto failure_init;
	}
	strcpy(conn->initiator_name, initiator_name);
	if (auth != ISCSI_AUTH_NULL) {
	    // Must not specify authentication method if bypass
	    // security-negotiation stage.
	    log_err("Illegal LoginRequest (CSG=0x%02X, AuthMethod is specified(%d))\n",
		    pdu_req->csg, auth);
	    goto failure_init;
	}
	if (session_type == ISCSI_SESSION_UNKNOWN) {
	    log_err("Illegal LoginRequest (CSG=0x%02X, unknown session type)\n",
		    pdu_req->csg, session_type);
	    goto failure_init;
	} else if (session_type == ISCSI_SESSION_NULL) {
	    log_wrn("SessionType is not specified, so use \"Normal\".\n");
	    session_type = ISCSI_SESSION_NORMAL;
	}
	conn->session_type = session_type;
	if (session_type == ISCSI_SESSION_NORMAL && target_name == NULL) {
	    log_err("Illegal LoginRequest (CSG=0x%02X, SessionType=Discovery, TargetName but is not specified(%d))\n",
		    pdu_req->csg, auth);
	    goto failure_init;
	}
	// Bind iSCSI connection to iSCSI target/session.
	conn->cid = pdu_req->cid;
	if (session_type == ISCSI_SESSION_NORMAL) {
	    rv = iscsi_bind_connection(target_name, pdu_req->sid, conn);
	    if (rv == -ENOENT) {
		goto failure_target;
	    } else if (rv == -ENOMEM) {
		goto failure_internal;
	    } else if (rv) {
		goto failure_init;
	    }
	    ASSERT((conn->target != NULL), "conn->target == NULL\n");
	}
	// Check authentication requirement
	if (is_auth_required(conn, conn->session_type)) {
	    log_err("Illegal LoginRequest (CHAP authentication is required).\n");
	    goto failure_init;
	}
	break;
    case ISCSI_STAGE_OPERATIONAL:
	break;
    default:
	log_err("Illegal stage transition (CSG=%d, NSG=%d, internal=%d)\n",
		pdu_req->csg, pdu_req->nsg, conn->stage);
	goto failure_init;
    }

    // Create LoginResponse PDU
    pdu_rsp = create_login_rsp(conn, pdu_req,
			       ISCSI_SCLASS_SUCCESS,
			       ISCSI_SDETAIL_ACCEPT);
    if (pdu_rsp == NULL) {
	goto failure_internal;
    }

    // Scan operational text
    rv = scan_operational_text(conn, pdu_req, pdu_rsp);
    if (rv) {
	goto failure_init;
    }

    conn->stage = ISCSI_STAGE_FULL_FEATURE;

    return pdu_rsp;

failure_init:
    if (pdu_rsp != NULL) {
        iscsi_remove_pdu(conn, pdu_rsp);
	pdu_rsp = NULL;
    }
    pdu_rsp = create_login_rsp(conn, pdu_req,
			       ISCSI_SCLASS_INITIATOR_ERR,
			       ISCSI_SDETAIL_INIT_ERR);
    return pdu_rsp;

failure_target:
    if (pdu_rsp != NULL) {
        iscsi_remove_pdu(conn, pdu_rsp);
	pdu_rsp = NULL;
    }
    pdu_rsp = create_login_rsp(conn, pdu_req,
			       ISCSI_SCLASS_INITIATOR_ERR,
			       ISCSI_SDETAIL_TGT_NOT_FOUND);
    return pdu_rsp;

failure_internal:
    if (pdu_rsp != NULL) {
        iscsi_remove_pdu(conn, pdu_rsp);
	pdu_rsp = NULL;
    }
    return NULL;
} // exec_csg_operational


int exec_login_req(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req)
{
    struct iscsi_pdu *pdu_rsp = NULL;
    int rv;
    log_dbg1("pdu_req->csg=%u\n", pdu_req->csg);
    
    switch (pdu_req->csg) {
    case ISCSI_CSG_SECURITY:
	pdu_rsp = exec_csg_security(conn, pdu_req);
	break;
    case ISCSI_CSG_OPERATIONAL:
	pdu_rsp = exec_csg_operational(conn, pdu_req);
	break;
    case ISCSI_CSG_FULL_FEATURE:
    default:
	ASSERT((0), "pdu_req->csg = 0x%02X\n", pdu_req->csg);
	break;
    }

    if (pdu_rsp == NULL) {
	goto failure;
    }

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
    if (pdu_rsp != NULL) {
	if (pdu_rsp->task == NULL) {
	    iscsi_remove_pdu(conn, pdu_rsp);
	}
    }
    return -1;
} // exec_login_req


static int check_challenge_response(
    struct iscsi_conn *conn,
    char *chap_n,
    char *chap_r,
    enum iscsi_session_type session_type)
{
    ASSERT((conn != NULL), "conn == NULL\n");
    ASSERT((conn->siso != NULL), "conn->siso == NULL\n");
    
    char *username;

    switch (session_type) {
    case ISCSI_SESSION_DISCOVERY:
	username = conn->siso->username;
	break;
    case ISCSI_SESSION_NORMAL:
	ASSERT((conn->target != NULL), "conn->target == NULL\n");
	ASSERT((conn->session != NULL), "conn->session == NULL\n");
	username = conn->target->username;
	break;
    default:
	ASSERT((0), "session_type=%d\n", session_type);
	break;
    }

    if (strcmp(chap_n, username)) {
	log_err("Unable to login (Unknown username \"%s\").\n", chap_n);
	goto failure_auth;
    }
    if (strcmp(chap_r, conn->chap_r_exp_str)) {
	log_err("Unable to login (Incollect secret).\n");
	goto failure_auth;
    }
    return 0;

failure_auth:
    return -EACCES;
} // check_challenge_response


static struct iscsi_pdu *create_login_rsp(
struct iscsi_conn *conn,
struct iscsi_pdu *pdu_req,
uint8 sclass,
uint8 sdetail)
{
    struct iscsi_pdu *pdu_rsp;
    int dsbuflen;
    byte *dsbuf;

    pdu_rsp = iscsi_create_pdu(conn);
    if (pdu_rsp == NULL) {
	return NULL;
    }

    pdu_rsp->opcode = ISCSI_OP_LOGIN_RSP;
    pdu_rsp->Cbit = 0;
    if (sclass == ISCSI_SCLASS_SUCCESS) {
	// IF no error occurs, permit to transit next stage.
	pdu_rsp->Tbit = pdu_req->Tbit;
	pdu_rsp->csg = pdu_req->csg;
	pdu_rsp->nsg = pdu_req->nsg;
    } else {
	// If some error occurs, DO NOT transit next stage.
	pdu_rsp->Tbit = 0;
	pdu_rsp->csg = pdu_req->csg;
	pdu_rsp->nsg = pdu_req->csg;
    }

    pdu_rsp->vmax = ISCSI_VERSION;
    pdu_rsp->vact = ISCSI_VERSION;
    pdu_rsp->dslen = 0;
    pdu_rsp->ahslen = 0;
    pdu_rsp->itt = pdu_req->itt;
    pdu_rsp->sid = conn->sid;

    pdu_rsp->sclass = sclass;
    pdu_rsp->sdetail = sdetail;

    dsbuflen = ISCSI_PDU_DSLEN_MAX;
    dsbuf = iscsi_alloc_dsbuf(conn, dsbuflen);
    if (dsbuf == NULL) {
	goto failure;
    }
    pdu_rsp->dsvec[0].buf = dsbuf;
    pdu_rsp->dsvec[0].buflen = dsbuflen;
    pdu_rsp->dsvec[0].offset = 0;
    pdu_rsp->dsvec[0].len = 0;
    pdu_rsp->dsvec[0].page = NULL;
    pdu_rsp->dslen = 0;
    pdu_rsp->dsvec_cnt = 1;

    return pdu_rsp;

failure:
    if (dsbuf != NULL) {
	if (pdu_rsp->dsvec[0].buf == NULL) {
	    iscsi_free_dsbuf(conn, dsbuf, dsbuflen);
	} else {
	}
	iscsi_remove_pdu(conn, pdu_rsp);
    }
    return NULL;
} // create_login_rsp


static int generate_challenge_and_response(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu,
    enum iscsi_session_type session_type)
{
    uint32 i;
    char *secret;
    SHA_CTX ctx_sha1;
    MD5_CTX ctx_md5;

    switch (session_type) {
    case ISCSI_SESSION_DISCOVERY:
	ASSERT((conn->siso->auth == ISCSI_AUTH_CHAP),
	       "conn->siso->auth(%d) != ISCSI_AUTH_CHAP(%d)\n",
	       conn->siso->auth, ISCSI_AUTH_CHAP);
	secret = conn->siso->secret;
	break;
    case ISCSI_SESSION_NORMAL:
	ASSERT((conn->target->auth == ISCSI_AUTH_CHAP),
	       "conn->target->auth(%d) != ISCSI_AUTH_CHAP(%d)\n",
	       conn->target->auth, ISCSI_AUTH_CHAP);
	secret = conn->target->secret;
	break;
    default:
	ASSERT((0), "session_type=%d\n", session_type);
	break;
    }

    conn->chap_i++;

    // generate challenge-code
    conn->chap_c_len = ISCSI_CHAP_CHALLENGE_LEN;
    sprintf(&(conn->chap_c_str[0]), "0x");
    for (i = 0; i < conn->chap_c_len; i++) {

	conn->chap_c_num[i] = (uint8)rand();
	sprintf(&(conn->chap_c_str[i*2+2]), "%02X", conn->chap_c_num[i]);
    }
    conn->chap_c_str[conn->chap_c_len * 2 + 2] = '\0';

    // generate response-code
    switch (conn->chap_a) {
    case ISCSI_CHAP_ALGORITHM_MD5:
	MD5_Init(&ctx_md5);
	MD5_Update(&ctx_md5, &(conn->chap_i), 1);
	MD5_Update(&ctx_md5, secret, strlen(secret));
	MD5_Update(&ctx_md5, conn->chap_c_num, conn->chap_c_len);
	MD5_Final(conn->chap_r_exp_num, &ctx_md5);
	sprintf(&(conn->chap_r_exp_str[0]), "0x");
	for (i = 0; i < DIGEST_LEN_MD5; i++) {
	    sprintf(&(conn->chap_r_exp_str[i*2+2]), "%02X", conn->chap_r_exp_num[i]);
	}
	conn->chap_r_exp_str[DIGEST_LEN_MD5 * 2 + 2] = '\0';
	log_dbg3("CHAP_C:\n");
	if (logger_is_dbg3()) {
	    print_hex(conn->chap_c_str, conn->chap_c_len * 2 + 1);
	}
	log_dbg3("CHAP_R(MD5):\n");
	if (logger_is_dbg3()) {
	    print_hex(conn->chap_r_exp_str, DIGEST_LEN_MD5 * 2 + 1);
	}
	break;
    case ISCSI_CHAP_ALGORITHM_SHA1:
	SHA1_Init(&ctx_sha1);
	SHA1_Update(&ctx_sha1, &(conn->chap_i), 1);
	SHA1_Update(&ctx_sha1, secret, strlen(secret));
	SHA1_Update(&ctx_sha1, conn->chap_c_num, conn->chap_c_len);
	SHA1_Final(conn->chap_r_exp_num, &ctx_sha1);
	sprintf(&(conn->chap_r_exp_str[0]), "0x");
	for (i = 0; i < DIGEST_LEN_SHA1; i++) {
	    sprintf(&(conn->chap_r_exp_str[i*2+2]), "%02X", conn->chap_r_exp_num[i]);
	}
	conn->chap_r_exp_str[DIGEST_LEN_SHA1 * 2 + 2] = '\0';
	log_dbg3("CHAP_C:\n");
	print_hex(conn->chap_c_str, conn->chap_c_len * 2 + 1);
	log_dbg3("CHAP_R(SHA1):\n");
	print_hex(conn->chap_r_exp_str, DIGEST_LEN_SHA1 * 2 + 1);
	break;
    default:
	ASSERT((0), "conn->chap_a=%u\n", conn->chap_a);
	break;
    }

    return 0;
} // generate_challenge_and_response


static enum iscsi_chap_algorithm unpack_chap_algorithm(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu)
{
    enum iscsi_chap_algorithm chap_a;
    char *value = NULL;

    ASSERT((pdu->opcode == ISCSI_OP_LOGIN_REQ),
	   "pdu->opcode(0x%02X) != ISCSI_OP_LOGIN_REQ(0x%02X)\n",
	   pdu->opcode, ISCSI_OP_LOGIN_REQ);

    value = seek_value((char *)pdu->dsvec[0].buf,
		       pdu->dsvec[0].len,
		       "CHAP_A");
    if (value == NULL) {
	chap_a = ISCSI_CHAP_ALGORITHM_NULL;
    } else if (!strcasecmp(value, "5")) {
	chap_a = ISCSI_CHAP_ALGORITHM_MD5;
    } else if (!strcasecmp(value, "7")) {
	chap_a = ISCSI_CHAP_ALGORITHM_SHA1;
    } else {
	log_err("Illegal CHAP algorithm (ITT=0x%08lX, CSG=%d, NSG=%d, CHAP_A=%s)\n",
		pdu->itt, pdu->csg, pdu->nsg, value);
	chap_a = ISCSI_CHAP_ALGORITHM_UNKNOWN;
    }
    return chap_a;
} // unpack_chap_algorithm    


static enum iscsi_session_type unpack_session_type(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu)
{
    enum iscsi_session_type session;
    char *value = NULL;

    ASSERT((pdu->opcode == ISCSI_OP_LOGIN_REQ),
	   "pdu->opcode(0x%02X) != ISCSI_OP_LOGIN_REQ(0x%02X)\n",
	   pdu->opcode, ISCSI_OP_LOGIN_REQ);

    value = seek_value((char *)pdu->dsvec[0].buf,
		       pdu->dsvec[0].len,
		       "SessionType");
    if (value == NULL) {
	session = ISCSI_SESSION_NULL;
    } else if (!strcasecmp(value, "Discovery")) {
	session = ISCSI_SESSION_DISCOVERY;
    } else if (!strcasecmp(value, "Normal")) {
	session = ISCSI_SESSION_NORMAL;
    } else {
	log_err("Illegal session type (ITT=0x%08lX, CSG=%d, NSG=%d, SessionType=%s)\n",
		pdu->itt, pdu->csg, pdu->nsg, value);
	session = ISCSI_SESSION_UNKNOWN;
    }
    return session;
} // unpack_session_type


static char *unpack_initiator_name(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu)
{
    char *initiator;
    initiator = seek_value((char *)pdu->dsvec[0].buf,
			   pdu->dsvec[0].len,
			   "InitiatorName");
    return initiator;
} // unpack_initiator_name


static char *unpack_target_name(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu)
{
    char *target;
    target = seek_value((char *)pdu->dsvec[0].buf,
			   pdu->dsvec[0].len,
			   "TargetName");
    return target;
} // unpack_target_name


static char *unpack_chap_username(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu)
{
    char *chap_n; // username
    chap_n = seek_value((char *)pdu->dsvec[0].buf,
			pdu->dsvec[0].len,
			"CHAP_N");
    return chap_n;
} // unpack_chap_username


static char *unpack_chap_response(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu)
{
    char *chap_r; // response
    chap_r = seek_value((char *)pdu->dsvec[0].buf,
			pdu->dsvec[0].len,
			"CHAP_R");
    return chap_r;
} // unpack_chap_response


static enum iscsi_auth_method unpack_auth_method(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu)
{
    enum iscsi_auth_method auth;
    char *value = NULL;

    value = seek_value((char *)pdu->dsvec[0].buf,
		       pdu->dsvec[0].len,
		       "AuthMethod");
    if (value == NULL) {
	auth = ISCSI_AUTH_NULL;
    } else if (!strcasecmp(value, "None")) {
	auth = ISCSI_AUTH_NONE;
    } else if (!strcasecmp(value, "CHAP")) {
	auth = ISCSI_AUTH_CHAP;
    } else {
	log_err("Illegal auth method (ITT=0x%08lX, CSG=%d, NSG=%d, AuthMethod=%s)\n",
		pdu->itt, pdu->csg, pdu->nsg, value);
	auth = ISCSI_AUTH_UNKNOWN;
    }
    return auth;
} // unpack_auth_method


/*
static int text2kv(byte *text, int textlen, struct keyvalue *kv)
{
    int i, len, cnt;
    int mode;
#define KVPAIR_KEY 1
#define KVPAIR_VALUE 2

    if (textlen <= 0) {
	return -1;
    }

    cnt = 0;
    i = 0;
    len = 0;
    mode = KVPAIR_KEY;

    do {
	if (text[i+len] == '=') {
	    if (mode != KVPAIR_KEY) {
		cnt = -1;
		break;
	    }
	    strncpy(kv[cnt].key, &text[i], len);
	    kv[cnt].key[len] = '\0';
	    i += (len + 1);
	    len = 0;
	    mode = KVPAIR_VALUE;
	} else if (text[i+len] == '\0') {
	    if (mode != KVPAIR_VALUE) {
		cnt = -1;
		break;
	    }
	    strncpy(kv[cnt].value, &text[i], len);
	    kv[cnt].value[len] = '\0';
	    i += (len + 1);
	    len = 0;
	    mode = KVPAIR_KEY;
	    cnt++;
	} else {
	    len++;
	}
    } while (i + len < textlen);

#ifdef __DEBUG
    for (i = 0; i < cnt; i++) {
	log_dbg3("kv[%d].key=%s\n", i, kv[i].key);
	log_dbg3("kv[%d].value=%s\n", i, kv[i].value);
    }
#endif // __DEBUG
    if (cnt == -1) {
	log_err("Detected invalid key-value pair.\n");
	print_hex(text, textlen);
    }
    return cnt;
} // text2kv
*/

struct iscsi_keyvalue_ops;

struct iscsi_keyvalue_table {
    char *key;
    uint32 val_def;
    uint32 val_min;
    uint32 val_max;
    uint32 *param;
    struct iscsi_keyvalue_ops *ops;
};

struct iscsi_keyvalue_ops {
    int (*unpack)(struct iscsi_conn *conn, byte *buf, uint32 *val);
    int (*pack)(struct iscsi_conn *conn, byte *buf, uint32 buflen, char *key, uint32 val);
    int (*set)(struct iscsi_conn *conn, struct iscsi_keyvalue_table *table, uint32 val);
};

static int unpack_kv_range(
struct iscsi_conn *conn,
byte *buf,
uint32 *val)
{
    int rv = 0;
    char *endptr;
    uint32 num;

    ASSERT((buf != NULL), "buf == NULL");

    if (buf[0] == '\0') {
	return -1;
    }

    endptr = NULL;
    num = strtol((char *)buf, &endptr, 0);
    if (*endptr == '\0') {
	rv = 0;
	*val = num;
    } else {
	log_err("Detected invalid value (\"%s\").\n", val);
	rv = -1;
    }
    
    return rv;
} // unpack_kv_range


static int unpack_kv_digest(
struct iscsi_conn *conn,
byte *buf,
uint32 *val)
{
    int rv;
    byte *p;

    rv = 0;

    log_dbg3("\n");

    p = buf;

    do {
	log_dbg3("Unpack : \"%s\"\n", p);
	if (!strncmp((char *)p, "None", sizeof("None")-1)) {
	    log_dbg3("None\n");
	    *val |= DIGEST_NONE;
	    p += (sizeof("None") - 1);
	} else if (!strncmp((char *)p, "CRC32C", sizeof("CRC32C")-1)) {
	    log_dbg3("CRC32C\n");
	    *val |= DIGEST_CRC32C;
	    p += (sizeof("CRC32C") - 1);
	} else {
	    log_dbg3("Detected unknown value (%s)\n", p);
	    rv = -1;
	    break;
	}
	if (*p == ',') {
	    log_dbg3("Detected \",\"\n");
	    p++;
	}
    } while (*p != '\0');

    return rv;
} // unpack_kv_digest


static int unpack_kv_bool(
struct iscsi_conn *conn,
byte *buf,
uint32 *val)
{
    int rv;
    byte *p;

    p = buf;
    rv = 0;

    log_dbg3("p=%s\n", p);
    if (!strncmp((char *)p, "Yes", sizeof("Yes")-1)) {
	log_dbg3("Yes\n");
	if (p[sizeof("Yes")-1] != '\0') {
	    rv = -1;
	} else {
	    *val = 1;
	}
    } else if (!strncmp((char *)p, "No", sizeof("No")-1)) {
	log_dbg3("No\n");
	if (p[sizeof("No")-1] != '\0') {
	    rv = -1;
	} else {
	    *val = 0;
	}
    }

    return rv;
} // unpack_kv_bool


static int set_kv_or(
struct iscsi_conn *conn,
struct iscsi_keyvalue_table *table,
uint32 val)
{
    log_dbg3("BEFORE: val="U32_FMT", *(table->param)="U32_FMT"\n", val, *(table->param));
    *(table->param) |= val;
    log_dbg3("AFTER:  *(table->param)="U32_FMT"\n", *(table->param));
    
    return 0;
} // set_kv_or


static int set_kv_and(
struct iscsi_conn *conn,
struct iscsi_keyvalue_table *table,
uint32 val)
{
    log_dbg3("BEFORE: val="U32_FMT", *(table->param)="U32_FMT"\n", val, *(table->param));
    *(table->param) |= val;
    log_dbg3("AFTER:  *(table->param)="U32_FMT"\n", *(table->param));
    
    return 0;
} // set_kv_and


static int set_kv_min(
struct iscsi_conn *conn,
struct iscsi_keyvalue_table *table,
uint32 val)
{
    log_dbg3("BEFORE: val="U32_FMT", *(table->param)="U32_FMT"\n", val, *(table->param));
    if (val < *(table->param)) {
	*(table->param) = val;
    }
    log_dbg3("AFTER:  *(table->param)="U32_FMT"\n", *(table->param));
    
    return 0;
} // set_kv_min


static int set_kv_max(
struct iscsi_conn *conn,
struct iscsi_keyvalue_table *table,
uint32 val)
{
    log_dbg3("BEFORE: val="U32_FMT", *(table->param)="U32_FMT"\n", val, *(table->param));
    if (val > *(table->param)) {
	*(table->param) = val;
    }
    log_dbg3("AFTER:  *(table->param)="U32_FMT"\n", *(table->param));
    
    return 0;
} // set_kv_max


static int set_kv_digest(
struct iscsi_conn *conn,
struct iscsi_keyvalue_table *table,
uint32 val)
{
    if (! (val & DIGEST_NONE)) {
	log_err("Not supported yet! (val=0x%X)\n", val);
	return -1;
    }
    *(table->param) = DIGEST_NONE;
    
    return 0;
} // set_kv_digest


static int pack_kv_range(
struct iscsi_conn *conn,
byte *buf,
uint32 buflen,
char *key,
uint32 val)
{
    int rv;

    log_dbg3("buflen="U32_FMT", key=%s, val="U32_FMT"\n", buflen, key, val);

    rv = pack_kv(buf, buflen, (char *)key, ""U32_FMT"", val);

    log_dbg3("rv=%d\n", rv);

    return rv;
} // pack_kv_range


static int pack_kv_bool(
struct iscsi_conn *conn,
byte *buf,
uint32 buflen,
char *key,
uint32 val)
{
    int rv;

    log_dbg3("buflen="U32_FMT", key=%s, val="U32_FMT"\n", buflen, key, val);

    rv = pack_kv(buf, buflen, (char *)key, "%s", val ? "Yes" : "No");

    log_dbg3("rv=%d\n", rv);

    return rv;
} // pack_kv_bool


static int pack_kv_digest(
struct iscsi_conn *conn,
byte *buf,
uint32 buflen,
char *key,
uint32 val)
{
    int rv;

    log_dbg3("val=0x%X, DIGEST_NONE=0x%X, DIGEST_CRC32C=0x%X, buflen="U32_FMT"\n",
	    val, DIGEST_NONE, DIGEST_CRC32C, buflen);

    if (buflen == 0) {
	return -1;
    }

    rv = 0;

    switch (val) {
    case DIGEST_NONE:
	rv = pack_kv(buf, buflen, (char *)key, "None");
	break;
    case DIGEST_CRC32C:
	rv = pack_kv(buf, buflen, (char *)key, "CRC32");
	break;
    default:
	rv = -1;
    }

    return rv;
} // pack_kv_digest


int scan_operational_text(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req,
    struct iscsi_pdu *pdu_rsp)
{
    static struct iscsi_keyvalue_ops digest_ops = {
	.unpack = unpack_kv_digest,
	.pack = pack_kv_digest,
	.set = set_kv_digest,
    };
    static struct iscsi_keyvalue_ops min_ops = {
	.unpack = unpack_kv_range,
	.pack = pack_kv_range,
	.set = set_kv_min,
    };
    static struct iscsi_keyvalue_ops max_ops = {
	.unpack = unpack_kv_range,
	.pack = pack_kv_range,
	.set = set_kv_max,
    };
    static struct iscsi_keyvalue_ops or_ops = {
	.unpack = unpack_kv_bool,
	.pack = pack_kv_bool,
	.set = set_kv_or,
    };
    static struct iscsi_keyvalue_ops and_ops = {
	.unpack = unpack_kv_bool,
	.pack = pack_kv_bool,
	.set = set_kv_and,
    };

    struct iscsi_keyvalue_table kv_table[] = {
	{"ErrorRecoveryLevel",
	 DEFAULT_ERROR_RECOVERY_LEVEL, 0, 2,
	 &(conn->error_recovery_level), &min_ops},
	{"InitialR2T",
	 DEFAULT_INITIAL_R2T, 0, 1,
	 &(conn->initial_r2t), &or_ops},
	{"ImmediateData",
	 DEFAULT_IMMEDIATE_DATA, 0, 1,
	 &(conn->immediate_data), &and_ops},
	{"MaxBurstLength",
	 DEFAULT_MAX_BURST_LENGTH, 512, 16777215,
	 &(conn->max_burst_length), &min_ops},
	{"FirstBurstLength",
	 DEFAULT_FIRST_BURST_LENGTH, 512, 16777215,
	 &(conn->first_burst_length), &min_ops},
	{"MaxConnections",
	 DEFAULT_MAX_CONNECTIONS, 1, 65535,
	 &(conn->max_connections), &min_ops},
	{"DataPDUInOrder",
	 DEFAULT_DATA_PDU_IN_ORDER, 0, 1,
	 &(conn->data_pdu_in_order), &or_ops},
	{"DataSequenceInOrder",
	 DEFAULT_DATA_SEQUENCE_IN_ORDER, 0, 1,
	 &(conn->data_sequence_in_order), &or_ops},
	{"MaxOutstandingR2T",
	 DEFAULT_MAX_OUTSTANDING_R2T, 1, 65535,
	 &(conn->max_outstanding_r2t), &min_ops},
	{"DefaultTime2Wait",
	 DEFAULT_DEFAULT_TIME2WAIT, 0, 3600,
	 &(conn->default_time2wait), &max_ops},
	{"DefaultTime2Retain",
	 DEFAULT_DEFAULT_TIME2RETAIN, 0, 3600,
	 &(conn->default_time2retain), &min_ops},
	{"HeaderDigest",
	 DEFAULT_HEADER_DIGEST, DIGEST_NONE, DIGEST_ALL,
	 &(conn->data_digest), &digest_ops},
	{"DataDigest",
	 DEFAULT_DATA_DIGEST, DIGEST_NONE, DIGEST_ALL,
	 &(conn->header_digest), &digest_ops},
	{NULL,},
    };

    struct iscsi_keyvalue_table *table;
    char *val_str;
    uint32 val_num;
    int rv;

    if (pdu_req->dsvec_cnt == 0) {
	return 0;
    }

    table = kv_table;
    while (table->key != NULL) {
	val_str = seek_value((char *)pdu_req->dsvec[0].buf,
			     pdu_req->dsvec[0].len,
			     (char *)table->key);
	if (val_str != NULL) {
	    rv = table->ops->unpack(conn, (byte *)val_str, &val_num);
	    if (rv) {
		// ToDo : Implement error handling
		log_err("Not implemented yet!\n");
		abort();
	    }
	    log_dbg3("*(table->param)="U32_FMT"(0x%lX)\n", *(table->param));
	    rv = table->ops->set(conn, table, val_num);
	    log_dbg3("*(table->param)="U32_FMT"(0x%lX)\n", *(table->param));
	    if (rv) {
		// ToDo : Implement error handling
		log_err("Not implemented yet!\n");
		abort();
	    }
	    rv = table->ops->pack(conn,
				  (byte *)&pdu_rsp->dsvec[0].buf[pdu_rsp->dsvec[0].len],
				  pdu_rsp->dsvec[0].buflen - pdu_rsp->dsvec[0].len,
				  (char *)table->key,
				  *(table->param));
	    if (rv <= 0) {
		// ToDo : Implement error handling
		log_err("Not implemented yet!\n");
		abort();
	    }
	    pdu_rsp->dsvec[0].len += rv;
	    pdu_rsp->dslen = pdu_rsp->dsvec[0].len;
	}
	table++;
    }
    return 0;
} // scan_operational_text
