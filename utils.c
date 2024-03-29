/* Utility functions
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

#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>

#include "mini_snmpd.h"

void *allocate(size_t len)
{
	char *buf = malloc(len);

	if (!buf) {
		lprintf(LOG_DEBUG, "Failed allocating memory: %m\n");
		return NULL;
	}

	return buf;
}


static inline int parse_lineint(char *buf, field_t *f, size_t *skip_prefix)
{
	char *ptr, *prefixptr;
	size_t i;

	ptr = buf;
	while (isspace(*ptr))
		ptr++;
	if (!*ptr)
		return 0;

	/* Check if buffer begins with prefix */
	prefixptr = f->prefix;
	while (*prefixptr) {
		if (*prefixptr++ != *ptr++)
			return 0;
	}
	if (*ptr == ':')	/* Prefix may have a ':', skip it too! */
		ptr++;
	else if (!isspace(*ptr))/* If there is NO ':' after prefix there must be a space, otherwise we got a partial match */
		return 0; 

	if (skip_prefix != NULL) {
		if (*skip_prefix > 0) {
			(*skip_prefix)--;
			return 0;
		}
	}

	for (i = 0; i < f->len; i++) {
		while (isspace(*ptr))
			ptr++;

		if (f->value[i]) {
			*(f->value[i]) = strtoll(ptr, NULL, 0);
		}

		while (!isspace(*ptr))
			ptr++;
	}

	return 1;
}

int parse_file(char *file, field_t fields[], size_t limit, size_t skip_prefix)
{
	char buf[512];
	FILE *fp;

	if (!file || !fields)
		return -1;

	fp = fopen(file, "r");
	if (!fp)
		return -1;

	while (fgets(buf, sizeof(buf), fp)) {
		int i;

		for (i = 0; i < limit && fields[i].prefix; i++) {
			if (parse_lineint(buf, &fields[i], &skip_prefix))
				break;
		}
	}

	return fclose(fp);
}

int read_file(const char *filename, char *buf, size_t size)
{
	int ret;
	FILE *fp;
	size_t len;

	fp = fopen(filename, "r");
	if (!fp) {
		lprintf(LOG_WARNING, "Failed opening %s: %m\n", filename);
		return -1;
	}

	len = fread(buf, 1, size - 1, fp);
	ret = fclose(fp);
	if (len == 0 || ret == -1) {
		lprintf(LOG_WARNING, "Failed reading %s: %m\n", filename);
		return -1;
	}

	buf[len] = '\0';

	return 0;
}

int ticks_since(const struct timeval *tv_last, struct timeval *tv_now)
{
	float ticks;

	if (gettimeofday(tv_now, NULL) == -1) {
		lprintf(LOG_WARNING, "could not get ticks: %m\n");
		return -1;
	}

	if (tv_now->tv_sec < tv_last->tv_sec || (tv_now->tv_sec == tv_last->tv_sec && tv_now->tv_usec < tv_last->tv_usec)) {
		lprintf(LOG_WARNING, "could not get ticks: time running backwards\n");
		return -1;
	}

	ticks = (float)(tv_now->tv_sec - 1 - tv_last->tv_sec) * 100.0 + (float)((tv_now->tv_usec + 1000000 - tv_last->tv_usec) / 10000);
#ifdef DEBUG
	lprintf(LOG_DEBUG, "seconds since last update: %.2f\n", ticks / 100);
#endif
	if (ticks < INT_MIN)
		return INT_MIN;
	if (ticks > INT_MAX)
		return INT_MAX;

	return ticks;
}

#ifdef DEBUG
void dump_packet(const client_t *client)
{
	size_t i, len = 0;
	char *buf = allocate(BUFSIZ);
	char straddr[my_inet_addrstrlen];
	struct my_in_addr_t client_addr;

	if (!buf)
		return;

	client_addr = client->addr;
	for (i = 0; i < client->size; i++) {
		len += snprintf(buf + len, BUFSIZ - len, i ? " %02X" : "%02X", client->packet[i]);
		if (len >= BUFSIZ)
			break;
	}

	inet_ntop(my_af_inet, &client_addr, straddr, sizeof(straddr));
	lprintf(LOG_DEBUG, "%s %d bytes %s %s:%d (%s)\n",
		client->outgoing ? "transmitted" : "received", (int) client->size,
		client->outgoing ? "to" : "from", straddr,
		ntohs(client->port), buf);

	free(buf);
}

void dump_mib(const value_t *value, int size)
{
	int i;
	char *buf = allocate(BUFSIZ);

	if (!buf)
		return;

	for (i = 0; i < size; i++) {
		if (snmp_element_as_string(&value[i].data, buf, BUFSIZ) == -1)
			strncpy(buf, "?", BUFSIZ);

		lprintf(LOG_DEBUG, "mib entry[%d]: oid='%s', max_length=%zu, data='%s'\n",
			i, oid_ntoa(&value[i].oid), value[i].data.max_length, buf);
	}

	free(buf);
}

void dump_response(const response_t *response)
{
	size_t i;
	char *buf = allocate(MAX_PACKET_SIZE);

	if (!buf)
		return;

	lprintf(LOG_DEBUG, "response: status=%d, index=%d, nr_entries=%zu\n",
		response->error_status, response->error_index, response->value_list_length);
	for (i = 0; i < response->value_list_length; i++) {
		if (snmp_element_as_string(&response->value_list[i].data, buf, MAX_PACKET_SIZE) == -1)
			strncpy(buf, "?", MAX_PACKET_SIZE);

		lprintf(LOG_DEBUG, "response: entry[%zu]='%s','%s'\n", i, oid_ntoa(&response->value_list[i].oid), buf);
	}

	free(buf);
}
#endif /* DEBUG */

char *oid_ntoa(const oid_t *oid)
{
	size_t i, len = 0;
	static char buf[MAX_NR_SUBIDS * 10 + 2];

	buf[0] = '\0';
	for (i = 0; i < oid->subid_list_length; i++) {
		len += snprintf(buf + len, sizeof(buf) - len, ".%u", oid->subid_list[i]);
		if (len >= sizeof(buf))
			break;
	}

	return buf;
}

oid_t *oid_aton(const char *str)
{
	static oid_t oid;
	char *ptr = (char *)str;

	if (str == NULL)
		return NULL;

	oid.subid_list_length = 0;
	while (*ptr != 0) {
		if (oid.subid_list_length >= MAX_NR_SUBIDS)
			return NULL;

		if (*ptr != '.')
			return NULL;

		ptr++;
		if (*ptr == 0)
			return NULL;

		oid.subid_list[oid.subid_list_length++] = strtoul(ptr, &ptr, 0);
	}

	if (oid.subid_list_length < 2 || (oid.subid_list[0] * 40 + oid.subid_list[1]) > 0xFF)
		return NULL;

	return &oid;
}

int oid_is_prefix(const oid_t *oid1, const oid_t* oid2)
{
	if (oid2->subid_list_length < oid1->subid_list_length)
		return 0;

	for (size_t i = 0; i < oid1->subid_list_length; ++i) {
		if (oid1->subid_list[i] != oid2->subid_list[i])
			return 0;
	}

	return 1;
}

int oid_cmp(const oid_t *oid1, const oid_t *oid2)
{
	size_t i;

	for (i = 0; i < MAX_NR_OIDS; i++) {
		int subid1, subid2;

		subid1 = (oid1->subid_list_length > i) ? (int)oid1->subid_list[i] : -1;
		subid2 = (oid2->subid_list_length > i) ? (int)oid2->subid_list[i] : -1;

		if (subid1 == -1 && subid2 == -1)
			return 0;
		if (subid1 > subid2)
			return 1;
		if (subid1 < subid2)
			return -1;
	}

	return 0;
}

int split(const char *str, char *delim, char **list, int max_list_length)
{
	int len = 0;
	char *ptr;
	char *buf = strdup(str);

	if (!buf)
		return 0;

	for (ptr = strtok(buf, delim); ptr; ptr = strtok(NULL, delim)) {
		if (len < max_list_length)
			list[len++] = strdup(ptr);
	}

	free(buf);

	return len;
}

client_t *find_oldest_client(void)
{
	size_t i, found = 0, pos = 0;
	time_t timestamp = (time_t)LONG_MAX;

	for (i = 0; i < g_tcp_client_list_length; i++) {
		if (timestamp > g_tcp_client_list[i]->timestamp) {
			timestamp = g_tcp_client_list[i]->timestamp;
			found = 1;
			pos = i;
		}
	}

	return found ? g_tcp_client_list[pos] : NULL;
}

#ifdef CONFIG_ENABLE_DEMO
void get_demoinfo(demoinfo_t *demoinfo)
{
	static int did_init = 0;

	if (did_init == 0) {
		srand(time(NULL));
		did_init = 1;
	}

	demoinfo->random_value_1 = rand();
	demoinfo->random_value_2 = rand();
}
#endif

/* vim: ts=4 sts=4 sw=4 nowrap
 */
