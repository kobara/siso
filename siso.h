/*
 * SISO : Simple iSCSI Storage
 * 
 * SISO main thread.
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

#ifndef __IST_H__
#define __IST_H__

#include <pthread.h>
#include "iscsi.h"
#include "misc.h"


struct iscsi_target;

#define LISTEN_MAX 5
#define LISTEN_QUEUE_MAX 5

struct siso_info {
    char pathname_conf[FILENAME_MAX];
    char pathname_log[FILENAME_MAX];
    struct list list_target;
    pthread_mutex_t lock_list_target;

    struct list list_conn;
    pthread_mutex_t lock_list_conn;

    char username[ISCSI_NAME_MAXBUFLEN];
    char secret[ISCSI_NAME_MAXBUFLEN];
    enum iscsi_auth_method auth;

    struct epoll_event event_iscsi[LISTEN_MAX];
    struct epoll_event event_admin;

    int fd_ep;               // epoll file descriptor
    int fd_admin;            // administration file descriptor (UNIX domain)
    int fd_serv[LISTEN_MAX]; // socket file descriptor (IPv4/v6 socket)

    int serv_cnt; // # of servers

    uint16 port;

    uint16 tsih;
    pthread_mutex_t lock_tsih;
}; // struct siso_info

#define LOCK_TARGETS(siso) do { pthread_mutex_lock(&(siso->lock_list_target)); } while (0)
#define UNLOCK_TARGETS(siso) do { pthread_mutex_unlock(&(siso->lock_list_target)); } while (0)

int siso_init(struct siso_info *siso, const char *pathname_conf);
uint16 siso_get_tsih(struct siso_info *siso);
int siso_run(struct siso_info *siso);

void siso_detach_connection(struct siso_info *siso, struct iscsi_conn *conn);
void siso_attach_connection(struct siso_info *siso, struct iscsi_conn *conn);

struct iscsi_target *siso_lookup_target(struct siso_info *siso, const char *target_name);

#endif // __IST_H__
