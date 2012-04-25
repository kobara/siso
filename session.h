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


#ifndef __SESSION_H__
#define __SESSION_H__

#include <pthread.h>
#include "misc.h"
#include "iscsi.h"

struct iscsi_target;
struct iscsi_conn;

struct iscsi_session {
    struct list_element listelem; // list element

    struct iscsi_target *target;  // iSCSI target

    union iscsi_sid sid;          // session ID
    struct list list_conn;        //< iSCSI connection list
    pthread_mutex_t lock_list_conn;
}; // iscsi_session

struct iscsi_session *iscsi_create_session(
    struct iscsi_target *target,
    union iscsi_sid sid,
    struct iscsi_conn *conn);
int iscsi_destroy_session(struct iscsi_session *session);
int iscsi_is_session_empty(struct iscsi_session *session);

#define LOCK_CONNS(session) do { pthread_mutex_lock(&(session->lock_list_conn)); } while (0)
#define UNLOCK_CONNS(session) do { pthread_mutex_unlock(&(session->lock_list_conn)); } while (0)

#endif // __SESSION_H__
