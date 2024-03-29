/* Global variables
 *
 * Copyright (C) 2008-2010  Robert Ernst <robert.ernst@linux-solutions.at>
 *
 * This file may be distributed and/or modified under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation and appearing in the file LICENSE.GPL included in the
 * packaging of this file.
 *
 * This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
 * WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See COPYING for GPL licensing information.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "mini_snmpd.h"

const struct in_addr inaddr_any = { INADDR_ANY };

int       g_family  = AF_INET;
int       g_timeout = 250; // once a 2,5 seconds
int       g_auth    = 0;
int       g_daemon  = 1;
int       g_syslog  = 0;
int       g_verbose = 0;
int       g_quit    = 0;

char     *g_community      = "public";
char     *g_vendor         = VENDOR;
char     *g_description    = NULL;
char     *g_location       = NULL;
char     *g_contact        = NULL;
char     *g_bind_to_device = NULL;
char     *g_serial         = NULL;
char     *g_mfg            = NULL;
char     *g_model          = NULL;
char     *g_cid            = NULL;
char     *g_ifmap          = NULL;

char     *g_disk_list[MAX_NR_DISKS];
size_t    g_disk_list_length;

ifaces_t  g_ifaces_list[MAX_NR_INTERFACES];
size_t    g_interface_list_length = 0;

in_port_t g_udp_port = 161;
in_port_t g_tcp_port = 161;

int       g_udp_sockfd4 = -1;
int       g_udp_sockfd6 = -1;
int       g_tcp_sockfd4 = -1;
int       g_tcp_sockfd6 = -1;

client_t  g_udp_client = { 0, };
client_t *g_tcp_client_list[MAX_NR_CLIENTS];
size_t    g_tcp_client_list_length = 0;

value_t   g_mib[MAX_NR_VALUES];
size_t    g_mib_length = 0;

view_t    g_view[MAX_NR_VIEWS];
size_t    g_view_length;

#ifdef NDM
struct ndm_core_t *g_ndmcore = NULL;
struct ndm_core_response_t *g_ndmresp = NULL;
#endif

/* vim: ts=4 sts=4 sw=4 nowrap
 */
