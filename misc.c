#include <unistd.h> // fcntl
#include <fcntl.h>  // fcntl
#include <string.h> // strlen
#include <errno.h>
#include <stdarg.h> // va_start, va_end, va_list
#include <stdio.h>  // freopen
#include <time.h>   // ctime, time
#include <sys/time.h> // gettimeofday
#include "misc.h"
#include "debug.h"

enum log_level g_loglv = LOGLV_INFO; //< logging level
pthread_mutex_t g_lock_logger;       //< logger lock
FILE *g_fp_log = NULL;               //< logger file pointer

int logger_init(char *pathname, int loglv)
{
    g_loglv = loglv;

    if (pathname != NULL) {
	if (g_fp_log != NULL) {
	    goto failure;
	}
	g_fp_log = freopen(pathname, "w", stdout);
	if (g_fp_log == NULL) {
	    fprintf(stderr,
		    "Unable to open logfile \"%s\" (errno=%d).\n",
		    pathname,
		    errno);
	    goto failure;
	}
    }
    pthread_mutex_init(&g_lock_logger, NULL);
    return 0;
failure:
    return -1;
} // logger_init


int logger_destroy(void)
{
    if (g_fp_log != NULL) {
	fclose(g_fp_log);
    }
    pthread_mutex_destroy(&g_lock_logger);
    return 0;
} // logger_destroy


inline enum log_level logger_getlv(void)
{
    return g_loglv;
} // logger_getlv


inline int logger_is_dbg3(void)
{
    return logger_getlv() >= LOGLV_DBG3 ? 1 : 0;
} // logger_is_dbg3

#define LOCK() do { pthread_mutex_lock(&g_lock_logger); } while (0)
#define UNLOCK() do { pthread_mutex_unlock(&g_lock_logger); } while (0)


int logger_log(
const char *file,
const char *func,
const int line,
const char *lv,
const char *format,
...)
{
    va_list va;
    time_t timer;
    char buf_time[255];

    LOCK();

    timer = time(NULL);

    snprintf(buf_time, sizeof(buf_time)-1, "%s ", ctime(&timer));
    buf_time[strlen(buf_time)-2] = '\0';

    if (logger_getlv() >= LOGLV_DBG1) {
	printf("%s [%s] 0x%04X %s:%s(%d) : ",
	       buf_time, lv, get_thread_id(), file, func, line);
    } else {
	printf("%s [%s] 0x%04X : ", buf_time, lv, get_thread_id());
    }
    va_start(va, format);
    vprintf(format, va);
    va_end(va);

    fflush(stdout);

    UNLOCK();

    return 0;
} // logger_log



int set_non_blocking(int fd)
{
    int res;

    res = fcntl(fd, F_GETFL);
    if (res == -1) {
	log_err("Unable to get fd flags (%d).\n", errno);
	return -1;
    }

    res = fcntl(fd, F_SETFL, res | O_NONBLOCK);
    if (res == -1) {
	log_err("Unable to set O_NONBLOCK (%d).\n", errno);
	return -1;
    }
    return 0;
} // set_non_blocking


inline void list_init(struct list *list)
{
    list->head = NULL;
    list->len = 0;
} // list_init


inline void listelem_init(struct list_element *elem, void *body)
{
    elem->list = NULL;
    elem->body = body;
    elem->prev = elem;
    elem->next = elem;
    return;
} // listelem_init


inline void list_add_elem(struct list *list, struct list_element *entry)
{
    if (list->head == NULL) {
	list->head = entry;
    } else {
	entry->prev = list->head->prev;
	entry->next = list->head;
	list->head->prev->next = entry;
	list->head->prev = entry;
    }
    entry->list = list;
    list->len++;
    return;
} // list_add_elem


inline void list_unlist_elem(struct list *list, struct list_element *elem)
{
    struct list_element *elem_next;

    ASSERT((list->len > 0), "list->len == 0\n");

    elem_next = elem->next;

    log_dbg3("list->head=%p, elem=%p, elem_next=%p\n", list->head, elem, elem_next);

    elem->prev->next = elem->next;
    elem->next->prev = elem->prev;
    elem->prev = elem;
    elem->next = elem;
    elem->list = NULL;

    if (list->head == elem) {
	if (elem_next == elem) {
	    ASSERT((list->len == 1), "list->len("U32_FMT") != 1\n", list->len);
	    list->head = NULL;
	} else {
	    ASSERT((list->len > 1), "list->len("U32_FMT") == 1\n", list->len);
	    list->head = elem_next;
	}
    } else {
	ASSERT((list->len > 1), "list->len("U32_FMT") == 1\n", list->len);
    }
    list->len--;
    return;
} // list_unlist_elem


int list_is_elem_listed(struct list *list, struct list_element *elem)
{
    if (elem->list == list) {
	return 1;
    }
    return 0;
} // list_is_elem_listed


inline int list_is_empty(struct list *list)
{
    log_dbg3("list->len="U32_FMT"\n", list->len);
    log_dbg3("list->head=%p\n", list->head);

    if (list->head == NULL) {
	ASSERT((list->len == 0), "list->len("U32_FMT") > 0\n", list->len);
	return 1;
    }
    ASSERT((list->len > 0), "list->len("U32_FMT") == 0\n", list->len);
    return 0;
} // list_is_empty


inline void *list_ref_head_elem(struct list *list)
{
    ASSERT((list != NULL), "list == NULL\n");
    if (list->head == NULL) {
	return NULL;
    }
    return list->head->body;
} // list_ref_head_elem


inline void *list_unlist_head_elem(struct list *list)
{
    struct list_element *elem;
    log_dbg3("list->head=%p\n", list->head);
    log_dbg3("list->len="U32_FMT"\n", list->len);
    elem = list->head;
    if (elem == NULL) {
	return NULL;
    }
    list_unlist_elem(list, elem);
    return elem->body;
} // list_unlist_head_elem


#define HEADER_CHECKER 0xAA
#define FOOTER_CHECKER 0xCC

void *malloc_safe(size_t size)
{
    void *ptr = NULL;

#ifdef __DEBUG
    ptr = malloc(size + 2);
    if (ptr == NULL) {
	return NULL;
    }
    ptr[0]        = HEADER_CHECKER;
    ptr[size + 1] = FOOTER_CHECKER;
    ptr++;
#else
    ptr = malloc(size);
    if (ptr == NULL) {
	return NULL;
    }
#endif
    return ptr;
} // malloc_safe


void free_safe(void *ptr, size_t size)
{
#ifdef __DEBUG
    ptr--;
    ASSERT((ptr[0] == HEADER_CHECKER),
	   "ptr[0](0x%02X) != HEADER_CHECKER(0x%02X)",
	   ptr[0], HEADER_CHECKER);
    ASSERT((ptr[%d] == FOOTER_CHECKER),
	   "ptr[%d](0x%02X) != FOOTER_CHECKER(0x%02X)",
	   size+1, ptr[size + 1], FOOTER_CHECKER);
    free(ptr);
#else
    free(ptr);
#endif    
} // free_safe


/**
 * Initialize a vector-IO buffer.
 */
void iovec_init(
struct iovecs *iov)
{
    iov->cnt = 0;
    iov->len = 0;
    return;
} // iovec_init


/**
 * Add a buffer to vector-IO buffer.
 */
void iovec_add(
struct iovecs *iov,
void *data,
int len)
{
    log_dbg3("data=%p, len=%ld\n", data, len);
    log_dbg3("BEFORE: iov->cnt=%d, iov->len=%ld\n", iov->cnt, iov->len);

    iov->vec[iov->cnt].iov_base = data;
    iov->vec[iov->cnt].iov_len = len;
    iov->cnt ++;
    iov->len += len;

    log_dbg3("AFTER:  iov->cnt=%d, iov->len=%ld\n", iov->cnt, iov->len);

    if (logger_is_dbg3()) {
	int i;
	for (i = 0; i < iov->cnt; i++) {
	    log_dbg3("iov->vec[%d].iov_base=%p\n", i, iov->vec[i].iov_base);
	    log_dbg3("iov->vec[%d].iov_len=%d\n", i, iov->vec[i].iov_len);
	}
    }

    return;
} // iovec_add


/**
 * Rewind a vector-IO buffer.
 */
int iovec_rewind(
struct iovecs *iov,
int len_rw)
{
    int iovcnt_new, len_rewind;
    int i = 0, j = 0;

    log_dbg3("len_rw=%ld\n", len_rw);
    log_dbg3("BEFORE: iov->cnt=%d, iov->len=%ld\n", iov->cnt, iov->len);

    if (len_rw == 0) {
	return 0;
    }

    iovcnt_new = iov->cnt;
    len_rewind = len_rw;
    i = 0;
    while (len_rewind > 0 && iov->vec[i].iov_len <= len_rewind) {

	log_dbg3("iov->vec[i=%d].iov_len=%ld, len_rewind=%ld\n",
		i, iov->vec[i].iov_len, len_rewind);

	len_rewind -= iov->vec[i].iov_len;
	i++;
	iovcnt_new--;
    }

    log_dbg3("i=%d, iovcnt_new=%d, len_rewind=%ld\n",
	    i, iovcnt_new, len_rewind);

    if (len_rewind > 0) {
	j = 0;
	iov->vec[j].iov_base = iov->vec[i].iov_base + len_rewind;
	iov->vec[j].iov_len = iov->vec[i].iov_len - len_rewind;
	i ++;
	j ++;
	len_rewind = 0;

	log_dbg3("i=%d, j=%d, len_rewind=%ld\n", i, j, len_rewind);

	while (i < iov->cnt) {
	    iov->vec[j] = iov->vec[i];
	    i++;
	    j++;
	}
	log_dbg3("i=%d, j=%d\n", i, j);

    }
    ASSERT(len_rewind == 0, "len_rewind=%ld\n", len_rewind);

    iov->cnt = iovcnt_new;
    iov->len -= len_rw;

    log_dbg3("AFTER: iov->cnt=%d, iov->len=%ld\n", iov->cnt, iov->len);

    return 0;
} // iovec_rewind


pid_t get_thread_id(void)
{
    return syscall(SYS_gettid);
} // get_thread_id


/**
 * Convert key-value pair format to iSCSI text style
 *   delimiter  -> '='
 *   terminator -> '\0'
 */
int convert_kv_format(
char *inbuf, int inbuflen,
char *outbuf, int outbuflen,
char delimiter,
char terminator,
int remove_blank) // 1:remove :NOT remove
{
    int remain;
    char *before;
    char *after;

    before = inbuf;
    after = outbuf;

    remain = inbuflen;

    while (remain > 0) {
	if (*before == delimiter) {
	    *after = '=';
	    after++;
	} else if (*before == terminator) {
	    *after = '\0';
	    after++;
	} else if (remove_blank && (*before == ' ' || *before == '\t')) {
	} else {
	    *after = *before;
	    after++;
	}
	before++;
	remain--;
    }
    return after - outbuf;
} // convert_kv_format


char *seek_value(char *text, int textlen, char *key)
{
    int pos, len, keylen;
    char *val;

    if (textlen <= 0) {
	return NULL;
    }

    keylen = strlen(key);
    pos = 0;
    len = 0;

    val = NULL;
    do {
	if (text[pos+len] != '=') {
	    // seek to delimiter (end of key)
	    len++;
	} else {
	    if (len == keylen && !strncmp(key, &text[pos], len)) {
		// found value
		val = &text[pos + len + 1];
		break;
	    } else {
		// not found value -> seek to next key.
		while (pos + len < textlen) {
		    len++;
		    if (text[pos+len] == '\0') {
			pos = pos + len + 1;
			len = 0;
			break;
		    }
		    if (text[pos+len] == '=') {
			log_err("Detected invalid key-value pair.\n");
			print_hex(text, textlen);
			return NULL;
		    }
		}
	    }
	}
    } while (pos + len < textlen);

    return val;
} // seek_value


int pack_kv(
byte *text,
uint32 textlen,
char *key,
char *valfmt,
...)
{
    va_list va;
    char *buf;
    int buflen, len;

    if (textlen <= 1) {
	return -1;
    }

    buf = (char *)text;
    buflen = textlen;

    // add key
    len = snprintf(buf, buflen, key);
    if (len == -1 || len >= buflen) {
	// trimmed
	return -1;
    }
    buf[len] = '=';
    buf += len + 1;
    buflen -= (len + 1);

    va_start(va, valfmt);
    len = vsnprintf(buf, buflen, valfmt, va);
    va_end(va);
    if (len == -1 || len >= buflen) {
	return -1;
    }
    buf += len + 1;
    buflen -= (len + 1);

    log_dbg3("text=%s, textlen=%d, buflen=%d, len=%d\n",
	    text, textlen, buflen, textlen - buflen);
    return textlen - buflen;
} // pack_kv


/**
 * Identify IPv6 mapped IPv6 address
 *
 * @retval    1    is IPv4 mapped IPv6 address
 * @retval    0    is NOT IPv4 mapped IPv6 address
 * @param[in] addr IPv6 address
 * @note
 *    see RFC3513 2.5.5
 */ 
int is_ipv4_mapped_ipv6_addr(const struct sockaddr_in6 *addr)
{
    // see RFC3513 2.5.5
    int idx;
    for (idx = 0; idx < 10; idx++) {
	if (addr->sin6_addr.s6_addr[idx] != 0x00) {
	    return 0;
	}
    }
    for (idx = 10; idx < 11; idx++) {
	if (addr->sin6_addr.s6_addr[idx] != 0xFF) {
	    return 0;
	}
    }
    return 1;
} // is_ipv4_mapped_ipv6_addr



/**
 * Get current time in microseconds since the Epoch
 */
uint64 get_time_in_usec(void)
{
    struct timeval tv;
    uint64 usec;
    int rv;

    rv = gettimeofday(&tv, NULL);
    usec = tv.tv_sec * 1000*1000 + tv.tv_usec;
    return usec;
} // get_time_in_usec
