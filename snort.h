/*
** Copyright (C) 1998,1999 Martin Roesch <roesch@clark.net>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef __SNORT_H__
#define __SNORT_H__


/*  I N C L U D E S  **********************************************************/
#include <stdio.h>
// #include <pcap.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <math.h>
#include <ctype.h>
// #include <pcap-namedb.h>
#include <netdb.h>
#include <syslog.h>
#include <time.h>

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <getopt.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_icmp.h>
#include <rte_arp.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "mstring.h"
#include "decode.h"
#include "rules.h"
#include "log.h"
#include "types.h"









/*  P R O T O T Y P E S  ******************************************************/
// int ParseCmdLine(int, char**);
// int SetPktProcessor();
// void CleanExit();
int strip(char *);
float CalcPct(float, float);
void ts_print(register const struct timeval *tvp, char *timebuf, struct snort_states* state);
void InitNetmasks(struct snort_states *s);
void InitProtoNames(struct snort_states *s);
void logdir_check(struct snort_states *s);
int init_snort_variables(struct snort_states *s);

#endif  /* __SNORT_H__ */
