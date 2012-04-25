#ifndef __CONNECTION_H__
#define __CONNECTION_H__

#include "iscsi.h"

struct volume_cmd;
struct iscsi_conn;
struct siso_info;

struct iscsi_conn *iscsi_conn_create_and_launch(
    struct siso_info *siso,
    int fd,
    struct sockaddr_storage *cli_addr,
    socklen_t cli_addr_len);
int iscsi_volcmd_send_completion(struct volume_cmd *volcmd, uint8 result);

#endif // __CONNECTION_H__
