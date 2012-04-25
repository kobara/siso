/*
 * SISO : Simple iSCSI Storage
 * 
 * iSCSI target.
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


#include <errno.h>       // errno
#include <string.h> // strcpy

#include "target.h"
#include "iscsi.h"
#include "connection.h"
#include "vol.h"
#include "config.h"
#include "siso.h"
#include "session.h"
#include "misc.h"

static struct iscsi_session *lookup_session(
    struct iscsi_target *target,
    union iscsi_sid sid);

struct iscsi_target *iscsi_target_create(
struct siso_info *siso,
const char *target_name)
{
    ASSERT((target_name != NULL), "target_name == NULL\n");

    struct iscsi_target *target = NULL;

    target = malloc_safe(sizeof(struct iscsi_target));
    if (target == NULL) {
	log_err("Unable to allocate memory (%d bytes).\n",
		sizeof(struct iscsi_target));
	goto failure;
    }

    target->siso = siso;

    listelem_init(&(target->listelem), target);

    strncpy(target->name, target_name, sizeof(target->name));
    if (target->name[sizeof(target->name) -1] != '\0') {
	// overflow
	log_err("TargetName \"%s\" is too long.\n", target_name);
	goto failure;
    }
    log_dbg3("TargetName = \"%s\"\n", target->name);

    target->auth = ISCSI_AUTH_NONE;
    target->username[0] = '\0';
    target->secret[0] = '\0';

    list_init(&(target->list_vol));
    list_init(&(target->list_session));

    pthread_mutex_init(&(target->lock_list_session), NULL);
/*
    int rv;
    rv = iscsi_target_load_config(target, pathname_conf);
    if (rv) {
	goto failure;
    }

    rv = init_server_side_sockets(target);
    if (rv < 1) {
	goto failure;
    }
    vol_run(target);
*/

    return target;

failure:
    //   vol_stop
    //   vol_destroy
    //   close_server_side_sockets(target)
    if (target != NULL) {
	free_safe(target, sizeof(struct iscsi_target));
	target = NULL;
    }
    return NULL;
} // iscsi_target_create


struct volume *iscsi_target_lookup_lu(struct iscsi_target *target, uint64 lun)
{
    struct volume *vol = NULL;

    log_dbg1("target=%p\n", target);
    if (list_is_empty(&(target->list_vol))) {
	log_dbg1("There are no LUs in target \"%s\"\n", target->name);
	return NULL;
    }
    do_each_list_elem(struct volume *, &(target->list_vol), vol, listelem) {
	log_dbg1("vol->lun=%llu\n", vol->lun);
	if (vol->lun == lun) {
	    log_dbg1("Found LU (LUN=%llu) in target \"%s\".\n",
		     lun, target->name);
	    return vol;
	}
    } while_each_list_elem(struct volume *, &(target->list_vol), vol, listelem);

    log_dbg1("Not found LU (LUN=%llu) in target \"%s\".\n",
	     lun, target->name);

    return NULL;
} // iscsi_target_lookup_lu


int iscsi_target_add_lu(
    struct iscsi_target *target,
    uint64 lun,
    char *pathname,
    enum volume_type type,
    uint64 capacity,
    uint32 sector_size,
    char *pathname_iotrace,
    void *data)
{
    struct volume *vol;
    int rv;

    vol = vol_create(target, lun, pathname, type, capacity, sector_size, pathname_iotrace, data);
    if (vol == NULL) {
	goto failure;
    }
    log_dbg1("Initialized LU %llu in target \"%s\".\n",
	     lun, target->name);

    rv = vol_run(vol);
    if (rv) {
	ASSERT((0), "NOT IMPLEMENTED YET\n");
    }

    list_add_elem(&(target->list_vol), &(vol->listelem));
    log_dbg3("target->list_vol.len = "U32_FMT"\n", target->list_vol.len);

    return 0;

failure:
    return -1;
} // iscsi_target_add_lu



int iscsi_target_destroy(struct iscsi_target *target)
{
    // NOT IMPLEMENTED YET

    return -1;
} // iscsi_target_destroy


/**
 * Bind an iSCSI connection to an iSCSI session.
 * (If an iSCSI session is not exist, create an iSCSI session)
 */
int iscsi_bind_connection(
    const char *target_name,
    union iscsi_sid sid,
    struct iscsi_conn *conn)
{
    struct iscsi_target *target = NULL;
    struct iscsi_session *session = NULL;
    int rv = 0;

    ASSERT((conn != NULL), "conn == NULL\n");
    ASSERT((conn->siso != NULL), "conn->siso == NULL\n");
    ASSERT((conn->session == NULL), "conn->session != NULL\n");
    ASSERT((conn->target == NULL), "conn->target != NULL\n");

    log_dbg1("target_name=%s\n", target_name);
    target = siso_lookup_target(conn->siso, target_name);
    if (target == NULL) {
	return -ENOENT;
    }
    conn->target = target;
    
    LOCK_SESSIONS(target);
    {
	session = lookup_session(target, conn->sid);

	if (conn->sid.id.tsih[0] == 0x00 || conn->sid.id.tsih[1] == 0x00) {
	    // Create session and attach connection to the session.
	    ASSERT((session == NULL), "session != NULL\n");
	    log_dbg1("create iscsi session\n");
	    session = iscsi_create_session(target, sid, conn);
	    if (session == NULL) {
		rv = -ENOMEM;
		goto done;
	    }
	    log_dbg1("conn->session=%p\n", conn->session);
	    // Enlink this iSCSI session to iSCSI session list.
	    list_add_elem(&(target->list_session), &(session->listelem));
	} else {
	    // Current implementation doesn't support multi-connection.
	    log_err("Current implementation doesn't support multi-connection.\n");
	    rv = -EINVAL;
	}
    }
done:
    UNLOCK_SESSIONS(target);

    if (!rv) {
	// detach iSCSI connection from tempolary list.
	siso_detach_connection(conn->siso, conn);
    }

    return rv;
} // iscsi_bind_connection


/**
 * Unbind an iSCSI connection from an iSCSI session.
 * (If an iSCSI session is empty, destroy an iSCSI session)
 */
int iscsi_unbind_connection(
    struct iscsi_conn *conn)
{
    ASSERT((conn->target != NULL), "connn->target == NULL\n");
    ASSERT((conn->session != NULL), "connn->session == NULL\n");

    struct iscsi_session *session = NULL;
    struct iscsi_target *target = NULL;

    session = conn->session;
    target = conn->target;

    log_dbg1("session=%p\n", session);
    log_dbg1("target=%p\n", target);

    ASSERT((session != NULL), "session == NULL\n");
    ASSERT((target != NULL), "target == NULL\n");

    LOCK_SESSIONS(target);
    {
	log_dbg1("session->list_conn.len="U32_FMT"\n", session->list_conn.len);

	// Delist an iSCSI connection from an iSCSI session.
	LOCK_CONNS(session);
	{
	    list_unlist_elem(&(session->list_conn), &(conn->listelem_session));
	    conn->session = NULL;
	    conn->target = NULL;
	}
	UNLOCK_CONNS(session);

	log_dbg1("session->list_conn.len="U32_FMT"\n", session->list_conn.len);

	// If an iSCSI session is empty, delist and destroy iSCSI session.
	if (iscsi_is_session_empty(session)) {
	    log_dbg1("iSCSI session is empty, so remove iSCSI session.\n");
	    // Delist iSCSI sesion from iSCSI session list.
	    list_unlist_elem(&(target->list_session), &(session->listelem));
	    // destroy iSCSI session.
	    iscsi_destroy_session(session);
	}
    }
    UNLOCK_SESSIONS(target);

    log_dbg1("conn->session=%p\n", conn->session);
    log_dbg1("conn->target=%p\n", conn->target);

    siso_attach_connection(conn->siso, conn);
    
    return 0;
} // iscsi_unbind_connection

#if 0
int iscsi_destroy_connection(
    struct iscsi_conn *conn)
{
} // iscsi_destroy_connection
#endif


/**
 * Lookup an iSCSI session.
 * @param[in] target An iSCSI target.
 * @param[in] sid    iSCSI session ID.
 * @return           An iSCSI session if found. Not found, NULL. 
 */
static struct iscsi_session *lookup_session(
    struct iscsi_target *target,
    union iscsi_sid sid)
{
    ASSERT((target != NULL), "target == NULL\n");

    struct iscsi_session *session = NULL;

    if (list_is_empty(&(target->list_session))) {
	log_dbg1("There are no sessions in target \"%s\".\n",
		 target->name);
	return NULL;
    }

    do_each_list_elem(struct iscsi_session *, &(target->list_session), session, listelem) {
	if (session->sid.id64 == sid.id64) {
	    // found
	    log_dbg1("Found the session (SID=0x%016llX) in target \"%s\".\n",
		     sid, target->name);
	    return session;
	}
    } while_each_list_elem(struct iscsi_session *, &(target->list_session), session, listelem);

    return NULL;
} // lookup_session
