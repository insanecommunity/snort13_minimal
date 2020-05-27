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

#ifdef HAVE_CONFIG_H
// #include "config.h"
#endif

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



/*  D E F I N E S  ************************************************************/
#define STD_BUF  256

#define RF_ANY_SIP    0x01
#define RF_ANY_DIP    0x02
#define RF_ANY_SP     0x04
#define RF_ANY_DP     0x10
#define RF_ANY_FLAGS  0x20

#define DEFAULT_LOG_DIR   "/var/log/snort_dpdk"
#define DEFAULT_DAEMON_ALERT_FILE  "/var/log/snort.alert"

#define ALERT_FULL     0x01
#define ALERT_FAST     0x02
#define ALERT_NONE     0x03



/*  D A T A  S T R U C T U R E S  *********************************************/
/* struct to contain the program variables and command line args */
typedef struct _progvars
{
   int data_flag;
   int verbose_flag;
   int showarp_flag;
   int showeth_flag;
   int alert_mode;
   int pkt_cnt;
   u_long netmask;
   int use_rules;
   char config_file[STD_BUF];
   char log_dir[STD_BUF];
} PV;

/* struct to collect packet statistics */
typedef struct _PacketCount
{
   u_long other;
   u_long tcp;
   u_long udp;
   u_long icmp;
   u_long arp;
   u_long ipx;
} PacketCount;

/*  G L O B A L S  ************************************************************/
struct snort_states {
   PV pv;                 /* program vars (command line args) */
   // char *pktidx;          /* index ptr for the current packet */
   FILE *log_ptr;         /* log file ptr */
   FILE *alert;           /* alert file ptr */
   FILE *binfrag_ptr;     /* binary fragment file ptr */
   FILE *binlog_ptr;      /* binary output file ptr */
   int thiszone;          /* time zone info */
   PacketCount pc;        /* packet count information */
   u_long netmasks[33];   /* precalculated netmask array */
   char protocol_names[18][6];
   int MTU;               /* Maximum xfer unit */
   ListHead Alert;      /* Alert Block Header */
   ListHead Log;        /* Log Block Header */
   ListHead Pass;       /* Pass Block Header */
   RuleTreeNode *rtn_tmp;  /* temp data holder */
   OptTreeNode *otn_tmp;   /* OptTreeNode temp ptr */
   int file_line;      /* current line being processed in the rules file */
   int rule_count;     /* number of rules generated */
   int head_count;     /* number of header blocks (chain heads?) */
   int opt_count;      /* number of chains */

#ifndef BENCHMARK
   int check_count;    /* number of tests for a given rule to determine a match */
   int cmpcount;       /* compare counter */
#endif

   char *data_dump_buffer;  /* printout buffer for PrintNetData */
   int dump_ready;          /* flag to indicate status of printout buffer */
   int dump_size;
};


/*  P R O T O T Y P E S  ******************************************************/
// int ParseCmdLine(int, char**);
// int SetPktProcessor();
// void CleanExit();
int strip(char *);
float CalcPct(float, float);
void ts_print(register const struct timeval *tvp, char *timebuf, struct snort_states* state);
void InitNetmasks();
void InitProtoNames();
void logdir_check(void);
int init_snort_variables(void);

#endif  /* __SNORT_H__ */
