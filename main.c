/*
 * SISO : Simple iSCSI Storage
 * 
 * main function.
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

#include <stdio.h>
#include <unistd.h> // getopt
#include "siso.h"

#define VERSION_MAJOR 0
#define VERSION_MINOR 0
#define VERSION_RIVISION 0

#define FILENAME_EXEC "siso"
#define FILENAME_CONF "siso.conf"
#define FILENAME_LOG  "siso.log"

int main(int argc, char *argv[])
{
    struct siso_info siso;
    int opt;
    int rv;
    char *pathname_conf = FILENAME_CONF;
    char *pathname_log = FILENAME_LOG;

    while ((opt = getopt(argc, argv, "vuhl:c:")) != -1) {
	switch (opt) {
	case 'c':
	    pathname_conf = optarg;
	    break;
	case 'l':
	    pathname_log = optarg;
	    break;
	case 'v':
	    printf("SISO : Simple iSCSI Storage version %d.%d.%d\n",
		   VERSION_MAJOR, VERSION_MINOR, VERSION_RIVISION);
	    printf("  Makoto Kobara\n");
	    goto exit_success;
	    break;
	default:
	case 'h':
	case 'u':
	    printf("Usage: %s [options]\n", FILENAME_EXEC);
	    printf("  -c <pathname> : Set config-file to <pathname> (default: \"%s\")\n", FILENAME_CONF);
	    printf("  -l <pathname> : Set log-file to <pathname> (default: \"%s\")\n", FILENAME_LOG);
	    printf("  -v            : Show version\n");
	    printf("  -u            : Show usage\n");
	    printf("  -h            : Show usage\n");
	    goto exit_success;
	}
    }

    rv = logger_init(pathname_log, LOGLV_INFO);
    if (rv) {
	return EXIT_FAILURE;
    }

    rv = siso_init(&siso, pathname_conf);
    if (rv) {
	return EXIT_FAILURE;
    }
    rv = siso_run(&siso);

    printf("done.\n");

    logger_destroy();

exit_success:
    return EXIT_SUCCESS;
} // main
