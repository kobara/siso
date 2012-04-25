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
