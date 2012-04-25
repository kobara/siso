#ifndef __MISC_H__
#define __MISC_H__

#include <stdio.h>   // printf
#include <stdlib.h>  // abort
#include <sys/uio.h> // struct iovec
#include <openssl/sha.h> // SHA1_*
#include <openssl/md5.h> // MD5_*
#include <netinet/in.h>

#define min(x, y) (((x) < (y)) ? (x) : (y))
#define max(x, y) (((x) > (y)) ? (x) : (y))

#define DIGEST_LEN_SHA1 SHA_DIGEST_LENGTH
#define DIGEST_LEN_MD5  MD5_DIGEST_LENGTH

#if __BYTE_ORDER == __BIG_ENDIAN
#define cpu_to_be64(x) (x)
#define cpu_to_be32(x) (x)
#define cpu_to_be16(x) (x)
#define be64_to_cpu(x) (x)
#define be32_to_cpu(x) (x)
#define be16_to_cpu(x) (x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_be64(x) bswap_64(x)
#define cpu_to_be32(x) bswap_32(x)
#define cpu_to_be16(x) bswap_16(x)
#define be64_to_cpu(x) bswap_64(x)
#define be32_to_cpu(x) bswap_32(x)
#define be16_to_cpu(x) bswap_16(x)
#else
#error "Detected unknown endian."
#endif

#include <inttypes.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <pthread.h>

typedef u_int8_t uint8;
typedef u_int16_t uint16;
typedef u_int32_t uint32;
typedef u_int64_t uint64;
typedef char byte;

#define U32_FMT "%u"

enum log_level {
    LOGLV_FTL = 0x00,
    LOGLV_ERR = 0x01,
    LOGLV_WRN = 0x02,
    LOGLV_INFO = 0x10,
    LOGLV_DBG1 = 0x20,
    LOGLV_DBG2 = 0x21,
    LOGLV_DBG3 = 0x22,
};

int logger_init(char *pathname, int loglv);
int logger_destroy(void);
inline enum log_level logger_getlv(void);
inline int logger_is_dbg3(void);

#define log_ftl(...) do { if (logger_getlv() >= LOGLV_FTL) { logger_log(__FILE__, __FUNCTION__, __LINE__, "FTL ", __VA_ARGS__); } } while (0)
#define log_err(...) do { if (logger_getlv() >= LOGLV_ERR) { logger_log(__FILE__, __FUNCTION__, __LINE__, "ERR ", __VA_ARGS__); } } while (0)
#define log_wrn(...) do { if (logger_getlv() >= LOGLV_WRN) { logger_log(__FILE__, __FUNCTION__, __LINE__, "WRN ", __VA_ARGS__); } } while (0)
#define log_info(...) do { if (logger_getlv() >= LOGLV_INFO) { logger_log(__FILE__, __FUNCTION__, __LINE__, "INFO", __VA_ARGS__); } } while (0)
#define log_dbg3(...) do { if (logger_getlv() >= LOGLV_DBG3) { logger_log(__FILE__, __FUNCTION__, __LINE__, "DBG3", __VA_ARGS__); } } while (0)
#define log_dbg2(...) do { if (logger_getlv() >= LOGLV_DBG2) { logger_log(__FILE__, __FUNCTION__, __LINE__, "DBG2", __VA_ARGS__); } } while (0)
#define log_dbg1(...) do { if (logger_getlv() >= LOGLV_DBG1) { logger_log(__FILE__, __FUNCTION__, __LINE__, "DBG1", __VA_ARGS__); } } while (0)

inline int logger_log(
    const char *file,
    const char *func,
    const int line,
    const char *lv,
    const char *format,
    ...);

#define ASSERT(exp, ...) do { if (!(exp)) { log_ftl(__VA_ARGS__); abort(); } } while (0)

int set_non_blocking(int fd);

// list_elementent
struct list;

struct list_element {
    struct list *list;
    void *body;
    struct list_element *prev;
    struct list_element *next;
}; // struct list_element

struct list {
    struct list_element *head;
    uint32 len;
}; // struct list


#define do_each_list_elem(type, list, elem, list_elem)	\
    (elem) = ((list)->head->body); do

#define while_each_list_elem(type, list, elem, list_elem)			\
    while ( ((elem) = (type)((elem)->list_elem.next->body)), elem != (list)->head->body )

#define IOV_MAX 1024

struct iovecs {
    struct iovec vec[IOV_MAX]; // vector I/O buffers
    int cnt;       // number of vector I/O buffers
    size_t len;    // total length of vector IO buffer
}; // struct iovecs

void list_init(struct list *list);
void listelem_init(struct list_element *elem, void *body);

void list_add_elem(struct list *list, struct list_element *elem);
void list_unlist_elem(struct list *list, struct list_element *elem);
int list_is_empty(struct list *list);
int list_is_elem_listed(struct list *list, struct list_element *elem);
void *list_ref_head_elem(struct list *list);
void *list_unlist_head_elem(struct list *list);


void iovec_init(struct iovecs *iov);
void iovec_add(struct iovecs *iov, void *data, int len);
int iovec_rewind(struct iovecs *iov, int len_rw);

void *malloc_safe(size_t size);
void free_safe(void *ptr, size_t size);

pid_t get_thread_id(void);

int pack_kv(
    byte *text,
    uint32 textlen,
    char *key,
    char *valfmt,
    ...);
char *seek_value(char *text, int textlen, char *key);
int convert_kv_format(
    char *inbuf, int inbuflen,
    char *outbuf, int outbuflen,
    char delimiter,
    char terminator,
    int remove_blank);

int is_ipv4_mapped_ipv6_addr(const struct sockaddr_in6 *addr);
uint64 get_time_in_usec(void);

#endif // __MISC_H__
