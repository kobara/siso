#include <stdio.h>   // fopen, fgets, fclose
#include <string.h>  // strlen, strnlen
#include <strings.h> // strcasecmp
#include <errno.h>   // errno
#include "target.h"
#include "config.h"
#include "iscsi.h"
#include "scsi.h"
#include "vol.h"
#include "siso.h"

static char *seek_values(char *line, char *key);

struct config_perser {
    char *key;
    int (*op)(struct siso_info *siso, struct iscsi_target **target, char *vals);
};

static int perser_lu(struct siso_info *siso, struct iscsi_target **target, char *val);
static int perser_target_name(struct siso_info *siso, struct iscsi_target **target, char *val);
static int perser_port(struct siso_info *siso, struct iscsi_target **target, char *val);
static int perser_username(struct siso_info *siso, struct iscsi_target **target, char *val);
static int perser_secret(struct siso_info *siso, struct iscsi_target **target, char *val);
static int check_auth_param(
    const char *username,
    const char *secret,
    enum iscsi_auth_method *auth);
static struct iscsi_target *create_target(
    struct siso_info *siso,
    const char *target_name);

#define LINE_MAXBUFLEN 1024

int siso_load_config(struct siso_info *siso, const char *pathname)
{
    struct config_perser cfg_perser[] = {
	{"TargetName", &perser_target_name},
	{"Port", &perser_port},
	{"Username", &perser_username},
	{"Secret", &perser_secret},
	{"LU", &perser_lu},
	{NULL,},
    }; // struct cfg_perser

    struct iscsi_target *target = NULL;
    FILE *fp = NULL;
    int err;
    char line[LINE_MAXBUFLEN];
    char *p = NULL;
    char *vals = NULL;
    int rv = 0;
    int idx;

    ASSERT((siso != NULL), "siso == NULL\n");
    ASSERT((pathname != NULL), "pathname == NULL\n");

    fp = fopen(pathname, "r");
    err = errno;
    if (fp == NULL) {
	log_err("Unable to open configuration file \"%s\". (errno=%d)\n",
		pathname, err);
	goto failure;
    }

    target = NULL;
    while (1) {
	// read single line and remove end-of-line newline character.
	p = fgets(line, sizeof(line), fp);
	if (p == NULL) {
	    break;
	}
	ASSERT((strnlen(line, sizeof(line)) > 0),
	       "strnlen(line, sizeof(line)) == 0\n");
	p = &line[strnlen(line, sizeof(line)) - 1];
	if (*p == '\n') {
	    *p = '\0';
	}
	// seek and parse values.
	for (idx = 0; cfg_perser[idx].key != NULL; idx++) {
	    vals = seek_values(line, cfg_perser[idx].key);
	    if (vals != NULL) {
		log_dbg1("target=%p\n", target);
		log_dbg1("%s=%s\n", cfg_perser[idx].key, vals);
		rv = cfg_perser[idx].op(siso, &target, vals);
		if (rv) {
		    goto failure;
		}
		log_dbg1("target=%p\n", target);
		break;
	    }
	}
    }

    log_dbg1("\n");

    // Check and set discovery session's authentication method
    rv = check_auth_param(siso->username, siso->secret, &(siso->auth));
    if (rv) {
	goto failure;
    }

    log_dbg1("siso->list_target.len="U32_FMT"\n", siso->list_target.len);
    log_dbg1("siso->list_target.head=%p\n", siso->list_target.head);
    log_dbg1("siso->list_target.head->body=%p\n", siso->list_target.head->body);

    if (list_is_empty(&(siso->list_target))) {
	log_err("Unable to create target (There are no targets).\n");
	goto failure;
    }

    log_dbg1("\n");

    do_each_list_elem(struct iscsi_target *, &(siso->list_target), target, listelem) {
	// Check LU as LUN=0
	log_dbg1("target=%p\n", target);
	if (iscsi_target_lookup_lu(target, 0) == NULL) {
	    log_err("Unable to create LU (There is no LU as LUN=0 in target \"%s\").\n",
		    target->name);
	    goto failure;
	}
	log_dbg1("\n");
	// Check and set normal session's authentication method.
	rv = check_auth_param(target->username, target->secret, &(target->auth));
	if (rv) {
	    goto failure;
	}
	log_dbg1("\n");
    } while_each_list_elem(struct iscsi_target *, &(siso->list_target), target, listelem);

    log_dbg1("\n");

    fclose(fp);

    return 0;

failure:
    if (fp != NULL) {
	fclose(fp);
    }
    return -1;
} // siso_load_config


static int check_auth_param(
    const char *username,
    const char *secret,
    enum iscsi_auth_method *auth)
{
    ASSERT((auth != NULL), "auth == NULL\n");
    ASSERT((username != NULL), "username == NULL\n");
    ASSERT((secret != NULL), "secret == NULL\n");

    log_dbg1("username=%s, secret=%s\n", username, secret);
    //   set auth-method to CHAP if both username and secret are specified.
    //   set auth-method to None if both username and secret are omitted.
    //   otherwise, error. (incorrect configuration format)
    if (username[0] != '\0' && secret[0] != '\0') {
	*auth = ISCSI_AUTH_CHAP;
	log_dbg3("AuthMethod=CHAP\n");
    } else if (username[0] == '\0' && secret[0] == '\0') {
	*auth = ISCSI_AUTH_NONE;
	log_dbg3("AuthMethod=None\n");
    } else if (username[0] != '\0') {
	log_err("Unable to set authitencation method to CHAP (\"Secret\" parameter is not specified).\n");
	goto failure;
    } else if (secret[0] != '\0') {
	log_err("Unable to set authitencation method to CHAP (\"Username\" parameter is not specified).\n");
	goto failure;
    } else {
	ASSERT((0),
	       "{username[0]='%c', secret[0]='%c'}\n",
	       username[0], secret[0]);
    }
    return 0;

failure:
    return -1;
} // check_auth_param



static char *seek_values(char *line, char *key)
{
    char *val;
    char *p;

    val = NULL;
    p = line;

    while (*p == ' ' || *p == '\t') {
	p++;
    }
    if (*p == '#') {
	// This line is commented-out
	return NULL;
    }
    if (strncasecmp(p, key, strlen(key))) {
	// NOT found key
	return NULL;
    }
    val = (&p[strlen(key)]);
    if (*val != ' ' && *val != '\t') {
	// NOT found delimiter(s)
	return NULL;
    }
    while (*val == ' ' || *val == '\t') {
	val++;
    }
    if (*val == '\0') {
	return NULL;
    }
    return val;
} // seek_values


static int perser_lu(struct siso_info *siso, struct iscsi_target **target, char *val)
{
    char line_param[LINE_MAXBUFLEN];
    int line_param_len;
    char *p;
    enum volume_type type;
    char *type_str;
    char *capacity_str;
    uint64 capacity;
    char *pathname;
    uint64 lun;
    char *lun_str;
    char *pathname_iotrace;
    int rv;

    ASSERT((strlen(val) + 1 <= LINE_MAXBUFLEN),
	    "strlen(val)(%d) + 1 > LINE_MAXBUFLEN(%d)\n",
	    strlen(val), LINE_MAXBUFLEN);
    ASSERT((target != NULL), "target == NULL\n");

    if (*target == NULL) {
	log_err("Illegal configuration file format. (LU must follow TargetName)\n");
	goto failure;
    }

    line_param_len = convert_kv_format(val, strlen(val)+1,
				       line_param, LINE_MAXBUFLEN,
				       '=', ',', 1);
//    print_hex(line_param, line_param_len);

    lun_str = seek_value(line_param, line_param_len, "LUN");
    pathname = seek_value(line_param, line_param_len, "Path");
    type_str = seek_value(line_param, line_param_len, "Type");
    capacity_str = seek_value(line_param, line_param_len, "Capacity");
    pathname_iotrace = seek_value(line_param, line_param_len, "IOTracePath");

    // Check formats
    if (lun_str == NULL) {
	log_err("MUST specify LUN in LU parameter.\n");
	goto failure;
    }
    if (pathname == NULL) {
	log_err("MUST specify pathname in LU parameter.\n");
	goto failure;
    }
    if (type_str == NULL) {
	log_err("MUST specify type in LU parameter.\n");
	goto failure;
    }
    if (capacity_str == NULL) {
	log_err("MUST specify capacity in LU parameter.\n");
	goto failure;
    }

    long long int lun_ll;
    lun_ll = strtoll(lun_str, &p, 10);
    if (! (*lun_str != '\0' && *p == '\0')) {
	log_err("Unable to accept LUN \"%s\".\n", lun_str);
	goto failure;
    }
    if (lun_ll < 0 || lun_ll > SCSI_LUN_MAX) {
	log_err("Unable to accept LUN %lld(0x%llX).\n", lun_ll);
	goto failure;
    }
    lun = (uint64)lun_ll;

    long long int capacity_ll;
    capacity_ll = strtoll(capacity_str, &p, 10);
    if (! (*capacity_str != '\0' && *p == '\0')) {
	log_err("Unable to accept CAPACITY \"%s\".\n", capacity_str);
	goto failure;
    }
#define SCSI_CAPACITY_MAX (1024LL*1024*1024*4)
    if (capacity_ll < 0 || capacity_ll > SCSI_CAPACITY_MAX) {
	log_err("Unable to accept CAPACITY %lld(0x%llX).\n", capacity_ll);
	goto failure;
    }
    capacity = (uint64)capacity_ll;

    if (!strcasecmp(type_str, "Standard")) {
	type = VOLTYPE_STANDARD;
    } else {
	log_err("Unable to accept the LU type \"%s\"\n", type_str);
	return -1;
    }

    log_dbg1("LUN=%llu\n", lun);
    log_dbg1("Path=%s\n", pathname);
    log_dbg1("Type=%d\n", type);
    log_dbg1("Capacity=%d\n", capacity);
    log_dbg1("IOTracePath=%s\n", pathname_iotrace);

    rv = iscsi_target_add_lu(*target, lun, pathname, type, capacity, SECTOR_SIZE_DEFAULT, pathname_iotrace, NULL);
    if (rv) {
	goto failure;
    }

    return 0;

failure:
    return -1;
} // perser_lun


static int perser_port(struct siso_info *siso, struct iscsi_target **target, char *val)
{
    ASSERT((target != NULL), "target == NULL\n");
    ASSERT((siso != NULL), "siso == NULL\n");

    long long int port_ll;
    char *p;

    if (*target != NULL) {
	log_err("A parameter \"Port\" is available only for global (NOT target) section.\n");
	return -1;
    }

    port_ll = strtoll(val, &p, 10);
    if (! (*val != '\0' && *p == '\0')) {
	log_err("Unable to accept TargetPort \"%s\".\n", val);
	return -1;
    }
    if (port_ll < 0 || port_ll > 65536) {
	log_err("Unable to accept TargetPort %lld.\n", port_ll);
    }

    siso->port = (uint16)port_ll;

    log_dbg1("Port = %u\n", siso->port);
    return 0;
} // perser_port


static int perser_target_name(struct siso_info *siso, struct iscsi_target **target, char *val)
{
    ASSERT((target != NULL), "target == NULL\n");

    *target = create_target(siso, val);
    log_dbg1("target=%p\n", *target);
    if (*target == NULL) {
	return -1;
    }
    log_dbg1("TargetName = \"%s\"\n", (*target)->name);
    return 0;
} // perser_target_name


static struct iscsi_target *create_target(struct siso_info *siso, const char *target_name)
{
    struct iscsi_target *target = NULL;

    // Check target duplication
    if (siso_lookup_target(siso, target_name) != NULL) {
	log_err("Unable to create a target (target \"%s\" is already defined).\n",
		target_name);
	goto failure;
    }

    // Create a target and add to target-list.
    target = iscsi_target_create(siso, target_name);
    if (target == NULL) {
	goto failure;
    }
    LOCK_TARGETS(siso);
    {
	list_add_elem(&(siso->list_target), &(target->listelem));
    }
    UNLOCK_TARGETS(siso);
    
    log_dbg1("siso->list_target.len="U32_FMT"\n", siso->list_target.len);
    log_dbg1("siso->list_target.head=%p\n", siso->list_target.head);
    log_dbg1("siso->list_target.head->body=%p\n", siso->list_target.head->body);

    return target;

failure:
    if (target != NULL) {
	iscsi_target_destroy(target);
	target = NULL;
    }
    return NULL;
} // create_target


static int perser_username(struct siso_info *siso, struct iscsi_target **target, char *val)
{
    ASSERT((siso != NULL), "siso == NULL\n");
    ASSERT((target != NULL), "target == NULL\n");

    char *username = NULL;
    int username_buflen;

    if (*target != NULL) {
	username = (*target)->username;
	username_buflen = sizeof((*target)->username);
    } else {
	username = siso->username;
	username_buflen = sizeof(siso->username);
    }

    strncpy(username, val, username_buflen);
    if (username[username_buflen -1] != '\0') {
	log_err("Username \"%s\" is too long.\n", val);
	return -1;
    }

    log_dbg1("Username = \"%s\"\n", username);
    return 0;
} // perser_username


static int perser_secret(struct siso_info *siso, struct iscsi_target **target, char *val)
{
    ASSERT((siso != NULL), "siso == NULL\n");
    ASSERT((target != NULL), "target == NULL\n");

    char *secret = NULL;
    int secret_buflen;

    if (*target != NULL) {
	secret = (*target)->secret;
	secret_buflen = sizeof((*target)->secret);
    } else {
	secret = siso->secret;
	secret_buflen = sizeof(siso->secret);
    }

    strncpy(secret, val, secret_buflen);
    if (secret[secret_buflen -1] != '\0') {
	log_err("Secret \"%s\" is too long.\n", val);
	return -1;
    }

    log_dbg3("Secret = \"%s\"\n", secret);
    return 0;
} // perser_secret
