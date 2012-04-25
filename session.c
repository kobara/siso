/*
 * SISO : Simple iSCSI Storage
 * 
 * iSCSI session.
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


#include "session.h"
#include "siso.h"
#include "target.h"
#include "connection.h"
#include "iscsi.h"
#include "misc.h"

/**
 * Create an iSCSI session and bind an iSCSI connection.
 */
struct iscsi_session *iscsi_create_session(
    struct iscsi_target *target,
    union iscsi_sid sid,
    struct iscsi_conn *conn)
{
    ASSERT((target != NULL), "target == NULL\n");
    ASSERT((conn != NULL), "conn == NULL\n");

    struct iscsi_session *session;
    uint16 tsih;

    session = malloc_safe(sizeof(struct iscsi_session));
    if (session == NULL) {
	goto failure;
    }
    listelem_init(&(session->listelem), session);
    list_init(&(session->list_conn));
    pthread_mutex_init(&(session->lock_list_conn), NULL);

    session->target = target;

    // Get TSIH and set.
    ASSERT((conn->sid.id.tsih[0] == 0x00 && conn->sid.id.tsih[1] == 0x00),
	   "conn->sid.id.tsih[0] != 0x00 || conn->sid.id.tsih[1] != 0x00\n");
    ASSERT((target->siso != NULL), "target->siso == NULL\n");
    conn->sid.id64 = sid.id64;
    tsih = siso_get_tsih(target->siso);
    log_dbg1("tsih=0x%04X\n", tsih);
    conn->sid.id.tsih[0] = (tsih >> 8);
    conn->sid.id.tsih[1] = (tsih & 0xFF);
    session->sid = conn->sid;

    LOCK_CONNS(session);
    {
	// enlist iSCSI connection to this iSCSI session.
	list_add_elem(&(session->list_conn), &(conn->listelem_session));
    }
    UNLOCK_CONNS(session);

    conn->session = session;

    return session;
failure:
    return NULL;
} // iscsi_create_session


/**
 * Destroy an iSCSI session.
 * @param[in,out] session  An iSCSI session
 */
int iscsi_destroy_session(
    struct iscsi_session *session)
{
    ASSERT((session != NULL), "session == NULL\n");
    ASSERT((session->target != NULL), "session->target == NULL\n");
    ASSERT((iscsi_is_session_empty(session)), "!iscsi_is_session_empty(session)\n");

    free_safe(session, sizeof(struct iscsi_session));

    return 0;
} // iscsi_destroy_session


/**
 * Is a session empty?
 * @param[in] session  An iSCSI session
 * @retval    1        Empty.
 * @retval    0        In use.
 */
int iscsi_is_session_empty(struct iscsi_session *session)
{
    ASSERT((session != NULL), "session == NULL\n");
    return (session->list_conn.len == 0) ? 1 : 0;
} // iscsi_is_session_empty
