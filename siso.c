#include <string.h> // strcpy,memset
#include <errno.h>       // errno
#include <netinet/tcp.h> // TCP_NODELAY
#include <sys/socket.h>  // getnameinfo
#include <sys/epoll.h>   // epoll_*
#include <netdb.h>       // getnameinfo, NI_MAXHOST
#include <sys/un.h>      // unix domain socket
#include <unistd.h>      // unlink
#include "siso.h"
#include "misc.h"
#include "target.h"
#include "connection.h"
#include "session.h"
#include "iscsi.h"
#include "config.h"
#include "debug.h"

#define BUFSIZE 1024


uint16 g_tsih = 1; //< next TSIH(Target Session Identifying Handle)

static int init_iscsi_target_sockets(struct siso_info *siso);
static void *accept_connection(void *arg);
static int accept_iscsi_connection(
    struct siso_info *siso,
    int fd,
    struct sockaddr_storage *cli_addr,
    socklen_t cli_addr_len);
static int accept_admin_connection(
    struct siso_info *siso,
    int fd,
    struct sockaddr_un *cli_addr,
    socklen_t cli_addr_len);
static int init_admin_socket(struct siso_info *siso);
static int siso_admin_targets(
    struct siso_info *siso,
    uint8 opcode,
    byte **buf,
    uint32 *buflen);
static int siso_admin_sessions(
    struct iscsi_target *target,
    uint8 opcode,
    byte **buf,
    uint32 *buflen);
static int siso_admin_connections(
    struct iscsi_session *session,
    uint8 opcode,
    byte **buf,
    uint32 *buflen);

#define LOCK_CONNECTION_LIST(siso)  pthread_mutex_lock(&(siso->lock_list_conn))
#define UNLOCK_CONNECTION_LIST(siso)  pthread_mutex_unlock(&(siso->lock_list_conn))


int siso_init(struct siso_info *siso, const char *pathname_conf)
{
    int rv;
    int i;

    pthread_mutex_init(&(siso->lock_tsih), NULL);
    pthread_mutex_init(&(siso->lock_list_conn), NULL);
    pthread_mutex_init(&(siso->lock_list_target), NULL);
    list_init(&(siso->list_conn));
    list_init(&(siso->list_target));

    siso->tsih = 0;
    siso->port = ISCSI_PORT;
    siso->username[0] = '\0';
    siso->secret[0] = '\0';

    // Load configuration file and initialize (create target(s), volume(s), ...)
    strncpy(siso->pathname_conf, pathname_conf, sizeof(siso->pathname_conf));
    if (siso->pathname_conf[sizeof(siso->pathname_conf)-1] != '\0') {
	log_err("Configuration pathname \"%s\" is too long.\n", pathname_conf);
	goto failure;
    }

    rv = siso_load_config(siso, pathname_conf);
    if (rv) {
	goto failure;
    }

    siso->serv_cnt = 0;
    for (i = 0; i < LISTEN_MAX; i++) {
	siso->fd_serv[i] = 0;     // NULL
    }
    siso->fd_ep = epoll_create(LISTEN_MAX);

    // Initialize server-side sockets.
    rv = init_iscsi_target_sockets(siso);
    if (rv <= 0) {
	log_dbg1("rv=%d\n", rv);
	goto failure;
    }
    rv = init_admin_socket(siso);
    if (rv) {
	log_dbg1("rv=%d\n", rv);
	goto failure;
    }

    return 0;

failure:
    return -1;
} // siso_init


int siso_run(struct siso_info *siso)
{
    void *rv;
    
    // ToDo: launch thread
    rv = accept_connection(siso);

    return 0;
} // siso_run


uint16 siso_get_tsih(struct siso_info *siso)
{
    uint16 tsih;

    pthread_mutex_lock(&(siso->lock_tsih));

    // ToDo: check target lsiso
    siso->tsih++;
    tsih = siso->tsih;

    pthread_mutex_unlock(&(siso->lock_tsih));

    return tsih;
} // siso_get_tsih


#define ADMIN_OPCODE_SHOW_CONNECTIONS 0x01

static int accept_admin_connection(
    struct siso_info *siso,
    int fd,
    struct sockaddr_un *cli_addr,
    socklen_t cli_addr_len)
{
    byte text[64*1024];
    uint32 textlen = sizeof(text);
    ssize_t rdlen, wrlen;
    byte *buf = &(text[0]);
    uint32 buflen = textlen;
    int len;
    int err;
    int rv;

    log_info("Administration connection request from \"%s\"\n",
	     cli_addr->sun_path);

    // Read request
    rdlen = read(fd, text, textlen);
    err = errno;
    log_dbg1("rdlen=%ld, err=%d\n", rdlen, err);
    if (rdlen <= 0) {
	return -1;
    }
    print_hex(text, rdlen);

    uint8 opcode = ADMIN_OPCODE_SHOW_CONNECTIONS;

    // Generate response
    len = snprintf(buf, buflen, "<siso>\n");
    buf += len , buflen -= len;
    rv = siso_admin_targets(siso, opcode, &buf, &buflen);
    if (rv) {
	goto failure;
    }
    len = snprintf(buf, buflen, "<siso>\n");
    buf += len , buflen -= len;

    // Send response
    wrlen = write(fd, text, textlen - buflen);
    err = errno;
    log_dbg1("wrlen=%ld, err=%d\n", wrlen, err);

    close(fd);
    return 0;

failure:
    close(fd);
    return rv;
} // accept_admin_connection


static int siso_admin_targets(
    struct siso_info *siso,
    uint8 opcode,
    byte **buf,
    uint32 *buflen)
{
    int rv;
    struct iscsi_target *target = NULL;
    int len;

    log_dbg1("*buf=%p, *buflen="U32_FMT"\n", *buf, *buflen);

    LOCK_TARGETS(siso);
    {
	log_dbg1("siso->list_target.len=%"U32_FMT"\n", siso->list_target.len);
	if (! list_is_empty(&(siso->list_target))) {
	    do_each_list_elem (struct iscsi_target *, &(siso->list_target), target, listelem) {
//		log_dbg1("target=%p\n", target);
		len = snprintf(*buf, *buflen, "<target>\n");
		*buf += len , *buflen -= len;
		switch (opcode) {
		case ADMIN_OPCODE_SHOW_CONNECTIONS:
		    len = snprintf(*buf, *buflen, "<targetname>%s</targetname>\n",
				   target->name);
		    *buf += len , *buflen -= len;
		    rv = siso_admin_sessions(target, opcode, buf, buflen);
		    if (rv) {
			goto failure;
		    }
//		    log_dbg1("buf=%s\n", *buf);
		    break;
		default:
		    log_dbg1("Unknown opcode 0x%02X\n", opcode);
		    break;
		}
		len = snprintf(*buf, *buflen, "</target>\n");
		*buf += len , *buflen -= len;
	    } while_each_list_elem (struct iscsi_target *, &(siso->list_target), target, listelem);
	}
    }
failure:
    UNLOCK_TARGETS(siso);

    log_dbg1("*buf=%p, *buflen="U32_FMT"\n", *buf, *buflen);

    return rv;
} // siso_admin_targets


static int siso_admin_sessions(
    struct iscsi_target *target,
    uint8 opcode,
    byte **buf,
    uint32 *buflen)
{
    int rv = 0;
    int len;
    struct iscsi_session *session = NULL;

    log_dbg1("*buf=%p, *buflen="U32_FMT"\n", *buf, *buflen);

    LOCK_SESSIONS(target);
    {
	log_dbg1("target->list_session.len=%"U32_FMT"\n", target->list_session.len);

	if (! list_is_empty(&(target->list_session))) {
	    do_each_list_elem (struct iscsi_session *, &(target->list_session), session, listelem) {
		log_dbg1("session=%p\n", session);

		len = snprintf(*buf, *buflen, "<session>\n");
		*buf += len , *buflen -= len;
		switch (opcode) {
		case ADMIN_OPCODE_SHOW_CONNECTIONS:
		    log_dbg1("%lu\n", session->sid.id64);
		    len = snprintf(*buf, *buflen,
				   "<tsih>0x%02X%02X</tsih>\n",
				   session->sid.id.tsih[0],
				   session->sid.id.tsih[1]);
		    *buf += len , *buflen -= len;
		    len = snprintf(*buf, *buflen,
				   "<isid>0x%02X%02X%02X%02X%02X%02X</isid>\n",
				   session->sid.id.isid[0],
				   session->sid.id.isid[1],
				   session->sid.id.isid[2],
				   session->sid.id.isid[3],
				   session->sid.id.isid[4],
				   session->sid.id.isid[5]);
		    *buf += len , *buflen -= len;
		    rv = siso_admin_connections(session, opcode, buf, buflen);
		    if (rv) {
			goto failure;
		    }
		    break;
		default:
		    log_dbg1("Unknown opcode 0x%02X\n", opcode);
		    break;
		}
		len = snprintf(*buf, *buflen, "</session>\n");
		*buf += len , *buflen -= len;
	    } while_each_list_elem (struct iscsi_session *, &(target->list_session), session, listelem);
	}
    }
failure:
    UNLOCK_SESSIONS(target);

    log_dbg1("*buf=%p, *buflen="U32_FMT"\n", *buf, *buflen);

    return rv;
} // siso_admin_sessions


static int siso_admin_connections(
    struct iscsi_session *session,
    uint8 opcode,
    byte **buf,
    uint32 *buflen)
{
    int rv = 0;
    int len;
    int err;
    struct iscsi_conn *conn = NULL;
    char host_str[NI_MAXHOST] = "";
    char port_str[NI_MAXSERV] = "";

    log_dbg1("*buf=%p, *buflen="U32_FMT"\n", *buf, *buflen);

    LOCK_CONNS(session);
    {
	if (! list_is_empty(&(session->list_conn))) {
	    do_each_list_elem (struct iscsi_conn *, &(session->list_conn), conn, listelem_session) {
		len = snprintf(*buf, *buflen, "<connection>\n");
		*buf += len , *buflen -= len;
		switch (opcode) {
		case ADMIN_OPCODE_SHOW_CONNECTIONS:
		    len = snprintf(*buf, *buflen, "<cid>0x%04X</cid>\n", conn->cid);
		    *buf += len , *buflen -= len;
		    rv = getnameinfo((struct sockaddr *)&(conn->cli_addr),
				     conn->cli_addr_len,
				     host_str,
				     sizeof(host_str),
				     port_str,
				     sizeof(port_str),
				     NI_NUMERICHOST|NI_NUMERICSERV);
		    err = errno;
		    if (rv) {
			log_err("Unable to get socket name with \"getsockname\" (errno="U32_FMT")\n", err);
			goto failure;
		    }
		    len = snprintf(*buf, *buflen, "<address>%s:%s</address>\n", host_str, port_str);
		    *buf += len , *buflen -= len;
		default:
		    log_dbg1("Unknown opcode 0x%02X\n", opcode);
		    break;
		}
		len = snprintf(*buf, *buflen, "</connection>\n");
		*buf += len , *buflen -= len;
	    } while_each_list_elem (struct iscsi_conn *, &(session->list_conn), conn, listelem_session);
	}
    }
failure:
    UNLOCK_CONNS(session);

    log_dbg1("*buf=%p, *buflen="U32_FMT"\n", *buf, *buflen);

    return rv;
} // siso_admin_connections

    
/*
<Target>
<TargetName>targetname</TargetName>
<Session>
<SessionID>session-id</SessionID>
<Connection>
<ConnectionID>
connection-id
</ConnectionID>
<ConnectionFrom>
IPaddress:Port
</ConnectionFrom>
<ConnectTime>
epoc-time-in-sec
</ConnectTime>
</Connection>
*/

static int accept_iscsi_connection(
    struct siso_info *siso,
    int fd,
    struct sockaddr_storage *cli_addr,
    socklen_t cli_addr_len)
{
    char host_str[NI_MAXHOST] = "";
    char port_str[NI_MAXSERV] = "";
    int opt;
    struct iscsi_conn *conn = NULL;

    getnameinfo((struct sockaddr *)cli_addr, cli_addr_len,
		host_str, sizeof(host_str),
		port_str, sizeof(port_str), NI_NUMERICHOST|NI_NUMERICSERV);
    log_info("Accepted socket-connection from %s:%s.\n", host_str, port_str);

    opt = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt))) {
	log_err("Unable to set TCP_NODELAY on socket (%d).\n",
		errno);
    }
	
    conn = iscsi_conn_create_and_launch(siso, fd, cli_addr, cli_addr_len);
    if (conn == NULL) {
	// ToDo: implement error handling
	goto failure;
    }
    siso_attach_connection(siso, conn);

    return 0;
failure:
    return -1;
} // accept_iscsi_connection


static void *accept_connection(void *arg)
{
    struct epoll_event event;
    struct siso_info *siso;
    int ret;
    int fd;
    struct sockaddr_storage cli_addr;
    socklen_t cli_addr_len;
    int err;
    int rv;

    siso = (struct siso_info *)arg;
        
    while (1) {
	log_dbg3("Enter epoll_wait.\n");
	ret = epoll_wait(siso->fd_ep, &event, 1, -1);
	err = errno;

	log_dbg3("Returned from epoll_wait (ret=%d, errno=%d).\n", ret, err);
	if (ret == -1) {
	    if (err == EINTR) {
		continue;
	    } else {
		log_err("Unable to wait epoll events (errno=%d).",
			errno); 
		break;
	    }
	} else if (ret == 0) {
	    log_dbg3("Timeout.\n");
	    continue;
	}

	cli_addr_len = sizeof(cli_addr);
	fd = accept(event.data.fd, (struct sockaddr *)&cli_addr, &cli_addr_len);
	if (fd < 0) {
	    log_err("Unnable to accept on socket (%d).\n", errno);
	    break;
	}
	if (event.data.fd == siso->fd_admin) {
	    rv = accept_admin_connection(siso,
					 fd,
					 (struct sockaddr_un *)&cli_addr,
					 cli_addr_len);
	} else {
	    rv = accept_iscsi_connection(siso,
					 fd,
					 &cli_addr,
					 cli_addr_len);
	}
	log_dbg1("rv=%d\n", rv);
	if (rv) {
	    goto failure;
	}
    } // while

    return NULL;

failure:
    // ToDo: implement error handling
    return NULL;
} // accept_connection


static int init_admin_socket(struct siso_info *siso)
{
    int fd;
    int err;
    struct sockaddr_un saddr_un;
    int rv;

    fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
	err = errno;
	log_err("Unable to create UNIX domain socket (%d).\n", err);
	rv = -err;
	goto failure;
    }
    memset(&saddr_un, 0x00, sizeof(saddr_un));
    saddr_un.sun_family = PF_UNIX;
#define ADMIN_SOCKET_NAME "/tmp/siso_admin"
    memcpy(saddr_un.sun_path, ADMIN_SOCKET_NAME, sizeof(ADMIN_SOCKET_NAME));
    unlink(ADMIN_SOCKET_NAME);

    rv = bind(fd, (struct sockaddr *)&saddr_un, sizeof(saddr_un));
    if (rv) {
	err = errno;
	log_err("Unable to bind socket (%d).\n", err);
	rv = -err;
	goto failure;
    }
    rv = listen(fd, LISTEN_QUEUE_MAX);
    if (rv) {
	err = errno;
	log_err("Unable to listen on socket (%d).\n", err);
	rv = -err;
	goto failure;
    }

    siso->fd_admin = fd;
    siso->event_admin.data.fd = fd;
    siso->event_admin.events = EPOLLET | EPOLLIN;
    rv = epoll_ctl(siso->fd_ep,
		    EPOLL_CTL_ADD,
		    fd,
		    &(siso->event_admin));
    if (rv == -1) {
	err = -errno;
	log_err("Unable to add fd to epoll context (%d).\n",
		err);
	rv = -err;
	goto failure;
    }
    return 0;

failure:
    return rv;
} // init_admin_socket
/*
#include<stdio.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<sys/un.h>


#define BUFFSIZE 256
#define ERR -1


    int main(int argc, char *argv[])
    {
	int socket_fd;//ソケット用のファイルディスクリプタ
	int accept_fd;
	struct sockaddr_un server;//サーバ構造体
	struct sockaddr_un client;//クライアント構造体
	int fromlen;
	char buf[BUFFSIZE];
	int message_len;

	if(argc != 2){
	    printf("Usage: [command_name] [response message]\n");
	    exit(1);
	}

	if( (socket_fd = socket(PF_UNIX, SOCK_STREAM, 0)) == ERR){
	    perror("server: socket");
	    exit(1);
	}

	bzero((char * )&server, sizeof(server));
	server.sun_family = PF_UNIX;//プロトコルファミリをunixに指定（UNIXドメイン）
	bcopy("server_socket", server.sun_path, sizeof("server_socket"));

	unlink("server_socket");

	if(bind(socket_fd, (struct sockaddr *)&server, sizeof(server)) == ERR){
	    perror("server: bind");
	    exit(1);
	}

	if(listen(socket_fd, 5) == ERR){//5つのリクエストを受けます
	    perror("server: listen");
	    exit(1);
	}

	bzero((char *)&client, sizeof(client));
	fromlen = sizeof(client);

	if((accept_fd = accept(socket_fd, (struct sockaddr *)&client, &fromlen)) == ERR){
	    perror("server: accept");
	    exit(1);
	}

	printf("\nconnect request from: %s\n", client.sun_path);

	if(read(accept_fd, buf, BUFFSIZE) == ERR){
	    perror("server: read");
	    exit(1);
	}

	　　printf("\n<SERVER> message from client : %s\n", buf);

	message_len = strlen(argv[1]) + 1;
	if(write(accept_fd, argv[1], message_len) == ERR){//クライアントとのインターフェースとなるファイルディスクリプタを指定してメッセージのやり取り
	    perror("server: write");
	    exit(1);
	}

	close(accept_fd);
	close(socket_fd);

	exit(0);
    }
*/

static int init_iscsi_target_sockets(struct siso_info *siso)
{
    struct addrinfo hints, *res, *res0;
    char port_str[64];
    int i;
    int fd;
    int opt;
    int ret;
    int rv;
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(struct sockaddr_storage);
    int err;
    char addr[NI_MAXHOST];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6; // IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    snprintf(port_str, sizeof(port_str), "%d", siso->port);
    rv = getaddrinfo(NULL, port_str, &hints, &res0); 
    if (rv) {
	err = errno;
	log_err("Cannot get address info (errno=%d).\n", err);
	rv = -err;
	goto failure;
    }

    for (i = 0, res = res0; res && i < LISTEN_MAX; i++, res = res->ai_next) {
	fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (fd < 0) {
	    err = errno;
	    log_err("Unable to create socket (%d, %d, %d, %d).\n",
		    err,
		    res->ai_family,
		    res->ai_socktype,
		    res->ai_protocol);
	    continue;
	}

	opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
	    err = errno;
	    log_err("Unable to set SO_REUSEADDR on socket (%d).\n",
		    err);
	}
	if (bind(fd, res->ai_addr, res->ai_addrlen)) {
	    err = errno;
	    log_err("Unable to bind socket (%d).\n", err);
	    continue;
	}
	if (listen(fd, LISTEN_QUEUE_MAX)) {
	    err = errno;
	    log_err("Unable to listen on socket (%d).\n", err);
	    continue;
	}

	if (getsockname(fd, (struct sockaddr *)&ss, &slen)) {
	    err = errno;
	    // ToDo : implement error handling
	    log_err("Unable to get socket name with \"getsockname\" (errno="U32_FMT")\n", err);
	    rv = -err;
	    goto failure;
	}
	if (getnameinfo((struct sockaddr *)&ss, slen, addr, sizeof(addr), NULL, 0, NI_NUMERICHOST)) {
	    err = errno;
	    // ToDo : implement error handling
	    log_err("Unable to get socket name with \"getnameinfo\" (errno="U32_FMT")\n", err);
	    rv = -err;
 	    goto failure;
	}

	// set non-blocking & edge-triger epoll mode
	set_non_blocking(fd);

	log_dbg3("siso->serv_cnt=%d\n", siso->serv_cnt);
	siso->event_iscsi[siso->serv_cnt].data.fd = fd;
	siso->event_iscsi[siso->serv_cnt].events = EPOLLET | EPOLLIN;
	ret = epoll_ctl(siso->fd_ep,
			EPOLL_CTL_ADD,
			fd,
			&(siso->event_iscsi[siso->serv_cnt]));
	if (ret == -1) {
	    log_err("Unable to add fd to epoll context (%d).\n",
		    errno);
	    rv = -err;
	    goto failure;
	}

	siso->fd_serv[siso->serv_cnt] = fd;
	siso->serv_cnt++;
	log_dbg3("siso->serv_cnt=%d\n", siso->serv_cnt);

	log_info("listening %s:%u\n", addr, siso->port);
    }
    freeaddrinfo(res0);

    return siso->serv_cnt;

failure:
    return rv;
} // init_iscsi_target_sockets


/**
 * Attach an iSCSI connection to tempolary list.
 * @param[in,out] siso
 * @param[in,out] conn  An iSCSI connection.
 */
void siso_attach_connection(struct siso_info *siso, struct iscsi_conn *conn)
{
    ASSERT((conn->session == NULL), "conn->session == NULL\n");
    ASSERT((conn->target == NULL), "conn->target == NULL\n");

    LOCK_CONNECTION_LIST(siso);
    {
	log_dbg1("siso->list_conn.len="U32_FMT"\n", siso->list_conn.len);
	list_add_elem(&(siso->list_conn), &(conn->listelem_siso));
	log_dbg1("siso->list_conn.len="U32_FMT"\n", siso->list_conn.len);
    }
    UNLOCK_CONNECTION_LIST(siso);

    return;
} // siso_attach_connection


/**
 * Detach an iSCSI connection from tempolary list.
 * @param[in,out] siso
 * @param[in,out] conn  An iSCSI connection.
 */
void siso_detach_connection(struct siso_info *siso, struct iscsi_conn *conn)
{
    LOCK_CONNECTION_LIST(siso);
    {
	log_dbg1("siso->list_conn.len="U32_FMT"\n", siso->list_conn.len);
	list_unlist_elem(&(siso->list_conn), &(conn->listelem_siso));
	log_dbg1("siso->list_conn.len="U32_FMT"\n", siso->list_conn.len);
    }
    UNLOCK_CONNECTION_LIST(siso);

    return;
} // siso_detach_connection


/**
 * Lookup an iSCSI target by target-name.
 * @param[in] siso
 * @param[in] target_name
 * @return                An iSCSI target if found. Not found, NULL.
 */
struct iscsi_target *siso_lookup_target(
    struct siso_info *siso,
    const char *target_name)
{
    struct iscsi_target *target = NULL;
    struct iscsi_target *target_found = NULL;

    if (target_name == NULL) {
	return NULL;
    }

    if (! list_is_empty(&(siso->list_target))) {
	do_each_list_elem(struct iscsi_target *, &(siso->list_target), target, listelem) {
	    if (! strcmp(target->name, target_name)) {
		target_found = target;
		break;
	    }
	} while_each_list_elem(struct iscsi_target *, &(siso->list_target), target, listelem);
    }

    return target_found;
} // siso_lookup_target
