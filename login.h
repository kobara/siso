#ifndef __LOGIN_H__
#define __LOGIN_H__

struct iscsi_conn;
struct iscsi_pdu;

int exec_login_req(
    struct iscsi_conn *conn,
    struct iscsi_pdu *pdu_req);

#endif // __LOGIN_H__
