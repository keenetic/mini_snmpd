/* Linux backend
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
#ifdef __linux__

#include <sys/sysinfo.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <math.h>
#include <sys/stat.h>


#include "mini_snmpd.h"


/* We need the uptime in 1/100 seconds, so we can't use sysinfo() */
unsigned int get_process_uptime(void)
{
#ifndef NDM
	static unsigned int uptime_start = 0;
#endif
	unsigned int uptime_now = get_system_uptime();

#ifndef NDM
	if (uptime_start == 0)
		uptime_start = uptime_now;

	return uptime_now - uptime_start;
#endif
	return uptime_now;
}

/* We need the uptime in 1/100 seconds, so we can't use sysinfo() */
unsigned int get_system_uptime(void)
{
	char buf[128];

	if (read_file("/proc/uptime", buf, sizeof(buf)) == -1)
		return -1;

	return (unsigned int)(atof(buf) * 100);
}

void get_loadinfo(loadinfo_t *loadinfo)
{
	int i;
	char buf[128];
	char *ptr;

	if (read_file("/proc/loadavg", buf, sizeof(buf)) == -1) {
		memset(loadinfo, 0, sizeof(loadinfo_t));
		return;
	}

	ptr = buf;
	for (i = 0; i < 3; i++) {
		while (isspace(*ptr))
			ptr++;

		if (*ptr != 0)
			loadinfo->avg[i] = strtod(ptr, &ptr) * 100;
	}
}

void get_meminfo(meminfo_t *meminfo)
{
	field_t fields[] = {
		{ "MemTotal",  1, { &meminfo->total   }},
		{ "MemFree",   1, { &meminfo->free    }},
		{ "MemShared", 1, { &meminfo->shared  }},
		{ "Buffers",   1, { &meminfo->buffers }},
		{ "Cached",    1, { &meminfo->cached  }},
		{ NULL,        0, { NULL              }}
	};

	if (parse_file("/proc/meminfo", fields, 255, 0))
		memset(meminfo, 0, sizeof(meminfo_t));
}

void get_cpuinfo(cpuinfo_t *cpuinfo)
{
	field_t fields[] = {
		{ "cpu ",  4, { &cpuinfo->user, &cpuinfo->nice, &cpuinfo->system, &cpuinfo->idle }},
		{ "intr ", 1, { &cpuinfo->irqs   }},
		{ "ctxt ", 1, { &cpuinfo->cntxts }},
		{ NULL,    0, { NULL             }}
	};

	if (parse_file("/proc/stat", fields, 255, 0))
		memset(cpuinfo, 0, sizeof(cpuinfo_t));
}

void get_ipinfo(ipinfo_t *ipinfo)
{
	long long garbage;
	field_t fields[] = {
		{ "Ip", 13,
			{ &ipinfo->ipForwarding,
			  &ipinfo->ipDefaultTTL,
			  &garbage,
			  &garbage,
			  &garbage,
			  &garbage,
			  &garbage,
			  &garbage,
			  &garbage,
			  &garbage,
			  &garbage,
			  &garbage,
			  &ipinfo->ipReasmTimeout } },
		{ NULL,  0, { NULL              } }
	};

	if (parse_file("/proc/net/snmp", fields, 255, 1))
		memset(ipinfo, 0, sizeof(ipinfo_t));
}

void get_tcpinfo(tcpinfo_t *tcpinfo)
{
	field_t fields[] = {
		{ "Tcp", 14,
			{ &tcpinfo->tcpRtoAlgorithm,
			  &tcpinfo->tcpRtoMin,
			  &tcpinfo->tcpRtoMax,
			  &tcpinfo->tcpMaxConn,
			  &tcpinfo->tcpActiveOpens,
			  &tcpinfo->tcpPassiveOpens,
			  &tcpinfo->tcpAttemptFails,
			  &tcpinfo->tcpEstabResets,
			  &tcpinfo->tcpCurrEstab,
			  &tcpinfo->tcpInSegs,
			  &tcpinfo->tcpOutSegs,
			  &tcpinfo->tcpRetransSegs,
			  &tcpinfo->tcpInErrs,
			  &tcpinfo->tcpOutRsts } },
		{ NULL,   0, { NULL        } }
	};

	if (parse_file("/proc/net/snmp", fields, 255, 1))
		memset(tcpinfo, 0, sizeof(tcpinfo_t));
}

void get_udpinfo(udpinfo_t *udpinfo)
{
	field_t fields[] = {
		{ "Udp", 4,
			{ &udpinfo->udpInDatagrams,
			  &udpinfo->udpNoPorts,
			  &udpinfo->udpInErrors,
			  &udpinfo->udpOutDatagrams } },
		{ NULL,  0, { NULL              } }
	};

	if (parse_file("/proc/net/snmp", fields, 255, 1))
		memset(udpinfo, 0, sizeof(udpinfo_t));
}

void get_diskinfo(diskinfo_t *diskinfo)
{
	size_t i;
	struct statfs fs;
	struct stat st;

	memset(diskinfo, 0, sizeof(diskinfo_t));

	for (i = 0; i < g_disk_list_length; i++) {
		if (!stat(g_disk_list[i], &st)) {
			if (!S_ISDIR(st.st_mode)) {
				continue;
			}
		} else {
			continue;
		}

		if (statfs(g_disk_list[i], &fs) == -1) {
			diskinfo->total[i]               = 0;
			diskinfo->free[i]                = 0;
			diskinfo->used[i]                = 0;
			diskinfo->blocks_used_percent[i] = 0;
			diskinfo->inodes_used_percent[i] = 0;
			continue;
		}

		diskinfo->total[i] = ((float)fs.f_blocks * fs.f_bsize) / 1024;
		diskinfo->free[i]  = ((float)fs.f_bfree  * fs.f_bsize) / 1024;
		diskinfo->used[i]  = ((float)(fs.f_blocks - fs.f_bfree) * fs.f_bsize) / 1024;
		diskinfo->blocks_used_percent[i] =
			((float)(fs.f_blocks - fs.f_bfree) * 100 + fs.f_blocks - 1) / fs.f_blocks;
		if (fs.f_files <= 0)
			diskinfo->inodes_used_percent[i] = 0;
		else
			diskinfo->inodes_used_percent[i] =
				((float)(fs.f_files - fs.f_ffree) * 100 + fs.f_files - 1) / fs.f_files;
	}
}

static void get_netinfo_loopback(netinfo_t *netinfo)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifreq;
	field_t fields;

	memset(&fields, 0, sizeof(field_t));

	fields.prefix    = strdup("lo");
	fields.len       = 12;
	fields.value[0]  = &netinfo->rx_bytes[NDM_LOOPBACK_INDEX_];
	fields.value[1]  = &netinfo->rx_packets[NDM_LOOPBACK_INDEX_];
	fields.value[2]  = &netinfo->rx_errors[NDM_LOOPBACK_INDEX_];
	fields.value[3]  = &netinfo->rx_drops[NDM_LOOPBACK_INDEX_];
	fields.value[8]  = &netinfo->tx_bytes[NDM_LOOPBACK_INDEX_];
	fields.value[9]  = &netinfo->tx_packets[NDM_LOOPBACK_INDEX_];
	fields.value[10] = &netinfo->tx_errors[NDM_LOOPBACK_INDEX_];
	fields.value[11] = &netinfo->tx_drops[NDM_LOOPBACK_INDEX_];

	snprintf(ifreq.ifr_name, sizeof(ifreq.ifr_name), "lo");
	if (fd == -1 || ioctl(fd, SIOCGIFFLAGS, &ifreq) == -1) {
		netinfo->status[NDM_LOOPBACK_INDEX_] = 4;
	} else {
		if (ifreq.ifr_flags & IFF_UP)
			netinfo->status[NDM_LOOPBACK_INDEX_] = (ifreq.ifr_flags & IFF_RUNNING) ? 1 : 7;
		else
			netinfo->status[NDM_LOOPBACK_INDEX_] = 2;
	}

	netinfo->admin_status[NDM_LOOPBACK_INDEX_] = 1; // up
	netinfo->mtu[NDM_LOOPBACK_INDEX_] = g_ifaces_list[NDM_LOOPBACK_INDEX_].mtu;

	if (fd != -1)
		close(fd);

	if (parse_file("/proc/net/dev", &fields, 1, 0))
		memset(netinfo, 0, sizeof(*netinfo));

	free(fields.prefix);
}

void get_netinfo(netinfo_t *netinfo)
{
	size_t i;

	memset(netinfo, 0, sizeof(netinfo_t));

	get_netinfo_loopback(netinfo);

	for (i = 0; i < g_interface_list_length; ++i) {
		char request[128];

		if (!strcmp(g_ifaces_list[i].iface, NDM_LOOPBACK_IFACE_))
			continue;

		/* Perform first 'show interface Iface0' request */

		snprintf(request, sizeof(request), "show interface %s", g_ifaces_list[i].iface);

		if ((g_ndmresp = ndm_core_request(g_ndmcore,
				NDM_CORE_REQUEST_PARSE, NDM_CORE_MODE_CACHE, NULL,
				"%s", request)) == NULL)
		{
			lprintf(LOG_ERR, "(%s:%d) ndm request failed: %s", __FILE__, __LINE__, strerror(errno));
			ndm_core_response_free(&g_ndmresp);

			exit(EXIT_SYSCALL);
		}

		if (!ndm_core_response_is_ok(g_ndmresp)) {
			lprintf(LOG_ERR, "(%s:%d) ndm response is invalid", __FILE__, __LINE__);
			ndm_core_response_free(&g_ndmresp);

			exit(EXIT_SYSCALL);
		}

		const struct ndm_xml_node_t* root = ndm_core_response_root(g_ndmresp);

		if (root == NULL) {
			lprintf(LOG_ERR, "(%s:%d) null ndm response", __FILE__, __LINE__);
			ndm_core_response_free(&g_ndmresp);

			exit(EXIT_SYSCALL);
		}

		if (ndm_xml_node_type(root) != NDM_XML_NODE_TYPE_ELEMENT)
			continue;

		if( !strcmp(ndm_xml_node_name(root), "response") )
		{
			const struct ndm_xml_node_t* node =
				ndm_xml_node_first_child(root, NULL);
			int admin_status = 2; // down
			int oper_status = 2; // down
			int imtu = NDM_MIN_MTU_;
			int is_port = 0;

			while (node != NULL) {
				const char *cn = ndm_xml_node_name(node);
				const char *cv = ndm_xml_node_value(node);

				if( !strcmp(cn, "id") &&
					!strcmp(cn, g_ifaces_list[i].iface) )
				{
					lprintf(LOG_ERR, "(%s:%d) invalid interface returned", __FILE__, __LINE__);
					ndm_core_response_free(&g_ndmresp);

					exit(EXIT_SYSCALL);
				}

				if( !strcmp(cn, "interface-name") && strlen(cv) > 0 )
				{
					if( g_ifaces_list[i].name != NULL )
					{
						free(g_ifaces_list[i].name);
					}

					g_ifaces_list[i].name = strdup(cv);
					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				if( !strcmp(cn, "type") && !strcmp(cv, "Port") )
				{
					imtu = NDM_ETH_MTU_;
					is_port = 1;
					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				if( !strcmp(cn, "summary") )
				{
					const struct ndm_xml_node_t* layer =
						ndm_xml_node_first_child(node, NULL);

					while (layer != NULL) {
						if( !strcmp(ndm_xml_node_name(layer), "layer") ) {
							const struct ndm_xml_node_t* status =
								ndm_xml_node_first_child(layer, NULL);

							while( status != NULL ) {
								const char *cln = ndm_xml_node_name(status);
								const char *clv = ndm_xml_node_value(status);

								if( !strcmp(cln, "conf") )
								{
									admin_status = (!strcmp(clv, "running") ? 1 : 2);

								} else
								if( !strcmp(cln, "link") )
								{
									oper_status = (!strcmp(clv, "running") ? 1 : 2);
								}

								status = ndm_xml_node_next_sibling(status, NULL);
							}
						}

						layer = ndm_xml_node_next_sibling(layer, NULL);
					}
				}

				if( !strcmp(cn, "speed") )
				{
					const long speed = atol(cv);

					if (speed >= 10 && speed <= 10000)
					{
						netinfo->speed[i] = speed * 1000 * 1000;
					}

					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				if( !strcmp(cn, "last-change") )
				{
					const double timef = atof(cv);
					const long long timel = timef * 100;

					if( timel >= 0 && timel <= INT_MAX )
					{
						netinfo->last_change[i] = timel;
					}

					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				if( !strcmp(cn, "last-overflow") )
				{
					const double timef = atof(cv);
					const long long timel = timef * 100;

					if( timel >= 0 && timel <= INT_MAX )
					{
						netinfo->discont_time[i] = timel;
					}

					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				if( !strcmp(cn, "mtu") )
				{
					const long lmtu = atol(cv);

					if( lmtu >= NDM_MIN_MTU_ &&
						lmtu <= NDM_MAX_MTU_ &&
						imtu == NDM_MIN_MTU_ )
					{
						imtu = lmtu;
					}

					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				if( !strcmp(cn, "rssi") )
				{
					if( strlen(cv) > 0 )
					{
						netinfo->rssi[i] = atol(cv);

					} else
					{
						netinfo->rssi[i] = -254;
					}

					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				if( !strcmp(cn, "rsrp") )
				{
					if( strlen(cv) > 0 )
					{
						netinfo->rsrp[i] = atol(cv);

					} else
					{
						netinfo->rsrp[i] = -254;
					}

					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				if( !strcmp(cn, "rsrq") )
				{
					if( strlen(cv) > 0 )
					{
						netinfo->rsrq[i] = atol(cv);

					} else
					{
						netinfo->rsrq[i] = -254;
					}

					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				if( !strcmp(cn, "sinr") )
				{
					if( strlen(cv) > 0 )
					{
						netinfo->sinr[i] = atol(cv);

					} else
					{
						netinfo->sinr[i] = -254;
					}

					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				node = ndm_xml_node_next_sibling(node, NULL);
			}

			netinfo->mtu[i] = imtu;
			netinfo->is_port[i] = is_port;
			netinfo->admin_status[i] = admin_status;
			netinfo->status[i] = oper_status;
		}

		ndm_core_response_free(&g_ndmresp);

		/* Perform second 'show interface Iface0 stat' request */

		snprintf(request, sizeof(request),
			"show interface %s stat", g_ifaces_list[i].iface);

		if ((g_ndmresp = ndm_core_request(g_ndmcore,
				NDM_CORE_REQUEST_PARSE, NDM_CORE_MODE_CACHE, NULL,
				"%s", request)) == NULL)
		{
			lprintf(LOG_ERR, "(%s:%d) ndm request failed: %s", __FILE__, __LINE__, strerror(errno));
			ndm_core_response_free(&g_ndmresp);

			exit(EXIT_SYSCALL);
		}

		if (!ndm_core_response_is_ok(g_ndmresp)) {
			lprintf(LOG_ERR, "(%s:%d) ndm response is invalid", __FILE__, __LINE__);
			ndm_core_response_free(&g_ndmresp);

			exit(EXIT_SYSCALL);
		}

		root = ndm_core_response_root(g_ndmresp);

		if (root == NULL) {
			lprintf(LOG_ERR, "(%s:%d) null ndm response", __FILE__, __LINE__);
			ndm_core_response_free(&g_ndmresp);

			exit(EXIT_SYSCALL);
		}

		if( ndm_xml_node_type(root) != NDM_XML_NODE_TYPE_ELEMENT )
			continue;

		if( !strcmp(ndm_xml_node_name(root), "response") )
		{
			const struct ndm_xml_node_t* node = ndm_xml_node_first_child(root, NULL);

			while (node != NULL) {
				const char *cn = ndm_xml_node_name(node);
				const char *cv = ndm_xml_node_value(node);

				if( !strcmp(cn, "rxpackets") )
				{
					const long long rxp = atoll(cv);

					if( rxp >= 0 )
					{
						netinfo->rx_packets[i] = rxp;
					}

					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				if( !strcmp(cn, "rx-multicast-packets") )
				{
					const long long rxmcp = atoll(cv);

					if( rxmcp >= 0 )
					{
						netinfo->rx_mc_packets[i] = rxmcp;
					}

					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				if( !strcmp(cn, "rx-broadcast-packets") )
				{
					long long rxbcp = atoll(cv);

					if( rxbcp >= 0 )
					{
						netinfo->rx_bc_packets[i] = rxbcp;
					}

					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				if( !strcmp(cn, "rxbytes") )
				{
					long long rxb = atoll(cv);

					if( rxb >= 0 )
					{
						netinfo->rx_bytes[i] = rxb;
					}

					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				if( !strcmp(cn, "rxerrors") )
				{
					long long rxe = atoll(cv);

					if( rxe >= 0 )
					{
						netinfo->rx_errors[i] = rxe;
					}

					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				if( !strcmp(cn, "rxdropped") )
				{
					long long rxd = atoll(cv);

					if( rxd >= 0 )
					{
						netinfo->rx_drops[i] = rxd;
					}

					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				if( !strcmp(cn, "txpackets") )
				{
					long long txp = atoll(cv);

					if( txp >= 0 )
					{
						netinfo->tx_packets[i] = txp;
					}

					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				if( !strcmp(cn, "tx-multicast-packets") )
				{
					long long txmcp = atoll(cv);

					if( txmcp >= 0 )
					{
						netinfo->tx_mc_packets[i] = txmcp;
					}

					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				if( !strcmp(cn, "tx-broadcast-packets") )
				{
					long long txbcp = atoll(cv);

					if( txbcp >= 0 )
					{
						netinfo->tx_bc_packets[i] = txbcp;
					}

					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				if( !strcmp(cn, "txbytes") )
				{
					long long txb = atoll(cv);

					if( txb >= 0 )
					{
						netinfo->tx_bytes[i] = txb;
					}

					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				if( !strcmp(cn, "txerrors") )
				{
					long long txe = atoll(cv);

					if( txe >= 0 )
					{
						netinfo->tx_errors[i] = txe;
					}

					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				if( !strcmp(cn, "txdropped") )
				{
					long long txd = atoll(cv);

					if( txd >= 0 )
					{
						netinfo->tx_drops[i] = txd;
					}

					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				node = ndm_xml_node_next_sibling(node, NULL);
			}
		}

		ndm_core_response_free(&g_ndmresp);
	}
}

#endif /* __linux__ */

/* vim: ts=4 sts=4 sw=4 nowrap
 */
