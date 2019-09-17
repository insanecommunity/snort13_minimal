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

#ifndef __RULES_H__
#define __RULES_H__

/*  I N C L U D E S  **********************************************************/
#include "snort.h"

#ifdef SOLARIS
#define INADDR_NONE -1
#endif


/*  D E F I N E S  ************************************************************/
#define RULE_LOG   0
#define RULE_PASS  1
#define RULE_ALERT 2

#define EXCEPT_SRC_IP  0x01
#define EXCEPT_DST_IP  0x02
#define ANY_SRC_PORT   0x04
#define ANY_DST_PORT   0x08
#define ANY_FLAGS      0x10
#define EXCEPT_SRC_PORT 0x20
#define EXCEPT_DST_PORT 0x40
#define BIDIRECTIONAL   0x80

#define R_FIN          0x01
#define R_SYN          0x02
#define R_RST          0x04
#define R_PSH          0x08
#define R_ACK          0x10
#define R_URG          0x20
#define R_RES2         0x40
#define R_RES1         0x80


#define MODE_EXIT_ON_MATCH   0
#define MODE_FULL_SEARCH     1

#define CHECK_SRC            0x01
#define CHECK_DST            0x02
#define INVERSE              0x04

/*  D A T A  S T R U C T U R E S  *********************************************/
typedef struct _OptTreeNode
{
   int chain_node_number;

   int type;            /* alert, log, or pass */

   int check_tcp_flags; /* program flag */
   u_char tcp_flags;    /* self explainatory */
   
   int check_ack;
   u_long tcp_ack;      /* tcp ack value (useful for detecting packets with 
                           their ack flags set and no value in the ACK 
                           field e.g. NMAP) */
   int check_seq;
   u_long tcp_seq;      /* some bad proggies initialize connections with static 
                           numbers */
   int check_ip_id;
   u_long ip_id;        /* IP header ID number; same concept as tcpseq & ack */

   int icmp_type;       /* ICMP type */
   int use_icmp_type;
   int icmp_code;       /* ICMP code */
   int use_icmp_code;

   int ttl;             /* TTL value */ 

   int min_frag;        /* minimum fragment size */

   int check_dsize;     /* check the payload size */
   int dsize;           /* payload data size */

   int pattern_match_flag; /* program flag */
   int offset;             /* pattern search start offset */
   int depth;              /* pattern search depth */
   u_int pattern_size;     /* size of app layer pattern */
   char *pattern_buf;      /* app layer pattern to match on */

   char *logto;         /* log file in which to write packets which 
                           match this rule*/

   char *message;       /* alert message */

   struct _OptTreeNode *next;

} OptTreeNode;



typedef struct _RuleTreeNode
{
   int head_node_number;

   u_long sip;          /* src IP */
   u_long smask;        /* src netmask */
   u_long dip;          /* dest IP */
   u_long dmask;        /* dest netmask */

   int not_sp_flag;     /* not implemented yet... */

   u_short hsp;         /* hi src port */
   u_short lsp;         /* lo src port */

   int not_dp_flag;     /* not implemented yet... */

   u_short hdp;         /* hi dest port */
   u_short ldp;         /* lo dest port */

   u_char flags;        /* control flags */

   struct _RuleTreeNode *right;

   OptTreeNode *down;   /* list of rule options to associate with this
                           rule node */

} RuleTreeNode;



typedef struct _ListHead
{
   RuleTreeNode *TcpList;
   RuleTreeNode *UdpList;
   RuleTreeNode *IcmpList;
} ListHead; 



/*  P R O T O T Y P E S  ******************************************************/
void ParseRulesFile(char *);
void ParseRule(char *);
int RuleType(char *);
int WhichProto(char *);
int ParseIP(char *, u_long *, u_long *);
int ParsePort(char *, u_short *,  u_short *, char *, int *);
void ApplyRules(Packet*);
void ParsePattern(char *);
void ParseFlags(char *);
int ConvPort(char *, char *);
void ParseRuleOptions(char *, int);
void ParseIcode(char *);
void ParseItype(char *);
void ParseMessage(char *);
void ParseFlags(char *);
void ParseLogto(char *);
void XferHeader(RuleTreeNode *, RuleTreeNode *);
int TestHeader(RuleTreeNode *, RuleTreeNode *);
int EvalPacket(ListHead *, int, Packet * );
int EvalHeader(RuleTreeNode *, int, Packet *);
int EvalOpts(OptTreeNode *, Packet *);
void ProcessHeadNode(RuleTreeNode *, ListHead *, int);
void DumpChain(RuleTreeNode *, char *);
int CheckAddrPort(u_long, u_long, u_short, u_short, Packet *, char, int);



#endif /* __RULES_H__ */
