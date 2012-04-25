#ifndef __TARGET_H__
#define __TARGET_H__

#include <pthread.h> // pthread_t
#include "iscsi.h"

struct siso_info;

// iSCSI target
struct iscsi_target {
    struct list_element listelem;
    
    struct siso_info *siso;
    struct list list_vol; // list of volumes

    char username[ISCSI_NAME_MAXBUFLEN];
    char secret[ISCSI_NAME_MAXBUFLEN];
    enum iscsi_auth_method auth;

    char name[ISCSI_NAME_MAXBUFLEN];

    int fd_sockev; // event descriptor for socket thread
    int fd_diskev; // event descriptor for disk thread

    pthread_t thread;

    struct list list_session;
    pthread_mutex_t lock_list_session;
};

#define LOCK_SESSIONS(siso) do { pthread_mutex_lock(&(siso->lock_list_session)); } while (0)
#define UNLOCK_SESSIONS(siso) do { pthread_mutex_unlock(&(siso->lock_list_session)); } while (0)

struct iscsi_target *iscsi_target_create(
struct siso_info *siso,
const char *target_name);

int iscsi_target_destroy(struct iscsi_target *target);

enum volume_type;

int iscsi_target_add_lu(
    struct iscsi_target *target,
    uint64 lun,
    char *pathname,
    enum volume_type type,
    uint64 capacity,
    uint32 sector_size,
    char *pathname_iotrace,
    void *data);
struct volume *iscsi_target_lookup_lu(struct iscsi_target *target, uint64 lun);
int iscsi_target_attach_connection(
    struct iscsi_target *target,
    struct iscsi_conn *conn);

int iscsi_bind_connection(
    const char *target_name,
    union iscsi_sid sid,
    struct iscsi_conn *conn);
int iscsi_unbind_connection(
    struct iscsi_conn *conn);

int iscsi_target_run(struct iscsi_target *target);

#endif // __TARGET_H__
