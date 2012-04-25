/*
 * SISO : Simple iSCSI Storage
 * 
 * iSCSI connection thread.
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
