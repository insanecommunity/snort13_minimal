#ifndef __TYPES_H__
#define __TYPES_H__


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>


/*  D E F I N E S  from snort.h ************************************************************/
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

/* end from snort.h */

/*  D E F I N E S from rule.h ************************************************************/
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

/* end from rule.h */


/*  D E F I N E S from decode.h ************************************************************/
#define ETHERNET_MTU            1500
#define ETHERNET_TYPE_IP        0x0800
#define ETHERNET_TYPE_ARP       0x0806
#define ETHERNET_TYPE_REVARP    0x8035
#define ETHERNET_TYPE_IPX       0x8137

#define ETHERNET_HEADER_LEN     14
#define SLIP_HEADER_LEN         16
#define IP_HEADER_LEN           20
#define TCP_HEADER_LEN          20
#define UDP_HEADER_LEN          8
#define ICMP_HEADER_LEN         4

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_RES2 0x40
#define TH_RES1 0x80

#define TCPOPT_EOL      0
#define TCPOPT_NOP      1
#define TCPOPT_MAXSEG   2

#define L2TP_PORT 1701
#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67

#define SNAPLEN      1514
#define PROMISC      1
#define READ_TIMEOUT 500

#define ARPOP_REQUEST   1               /* ARP request                  */
#define ARPOP_REPLY     2               /* ARP reply                    */
#define ARPOP_RREQUEST  3               /* RARP request                 */
#define ARPOP_RREPLY    4               /* RARP reply                   */

#define ICMP_ECHOREPLY          0       /* Echo Reply                   */
#define ICMP_DEST_UNREACH       3       /* Destination Unreachable      */
#define ICMP_SOURCE_QUENCH      4       /* Source Quench                */
#define ICMP_REDIRECT           5       /* Redirect (change route)      */
#define ICMP_ECHO               8       /* Echo Request                 */
#define ICMP_TIME_EXCEEDED      11      /* Time Exceeded                */
#define ICMP_PARAMETERPROB      12      /* Parameter Problem            */
#define ICMP_TIMESTAMP          13      /* Timestamp Request            */
#define ICMP_TIMESTAMPREPLY     14      /* Timestamp Reply              */
#define ICMP_INFO_REQUEST       15      /* Information Request          */
#define ICMP_INFO_REPLY         16      /* Information Reply            */
#define ICMP_ADDRESS            17      /* Address Mask Request         */
#define ICMP_ADDRESSREPLY       18      /* Address Mask Reply           */
#define NR_ICMP_TYPES           18

/* Codes for ICMP UNREACHABLES */
#define ICMP_NET_UNREACH        0       /* Network Unreachable          */
#define ICMP_HOST_UNREACH       1       /* Host Unreachable             */
#define ICMP_PROT_UNREACH       2       /* Protocol Unreachable         */
#define ICMP_PORT_UNREACH       3       /* Port Unreachable             */
#define ICMP_FRAG_NEEDED        4       /* Fragmentation Needed/DF set  */
#define ICMP_SR_FAILED          5       /* Source Route failed          */
#define ICMP_NET_UNKNOWN        6
#define ICMP_HOST_UNKNOWN       7
#define ICMP_HOST_ISOLATED      8
#define ICMP_NET_ANO            9
#define ICMP_HOST_ANO           10
#define ICMP_NET_UNR_TOS        11
#define ICMP_HOST_UNR_TOS       12
#define ICMP_PKT_FILTERED       13      /* Packet filtered */
#define ICMP_PREC_VIOLATION     14      /* Precedence violation */
#define ICMP_PREC_CUTOFF        15      /* Precedence cut off */
#define NR_ICMP_UNREACH         15      /* instead of hardcoding immediate value */

/* ip option type codes */
#define IPOPT_EOL               0x00
#define IPOPT_NOP               0x01
#define IPOPT_RR                0x07
#define IPOPT_TS                0x44
#define IPOPT_SECURITY          0x82
#define IPOPT_LSRR              0x83
#define IPOPT_LSRR_E            0x84
#define IPOPT_SATID             0x88
#define IPOPT_SSRR              0x89

/* tcp option codes */
#define TOPT_EOL                0x00
#define TOPT_NOP                0x01
#define TOPT_MSS                0x02
#define TOPT_WS                 0x03
#define TOPT_TS                 0x08
#ifndef TCPOPT_WSCALE
#define TCPOPT_WSCALE           3       /* window scale factor (rfc1072) */
#endif
#ifndef TCPOPT_ECHO
#define TCPOPT_ECHO             6       /* echo (rfc1072) */
#endif
#ifndef TCPOPT_ECHOREPLY
#define TCPOPT_ECHOREPLY        7       /* echo (rfc1072) */
#endif
#ifndef TCPOPT_TIMESTAMP
#define TCPOPT_TIMESTAMP        8       /* timestamps (rfc1323) */
#endif

#define EXTRACT_16BITS(p) ((u_short) ntohs (*(u_short *)(p)))

#ifdef WORDS_MUSTALIGN

/* force word-aligned ntohl parameter */
#define EXTRACT_32BITS(p)  ({ u_long __tmp; memmove(&__tmp, (p), sizeof(u_long)); (u_long) ntohl(__tmp);})

#else

/* allows unaligned ntohl parameter - dies w/SIGBUS on SPARCs */
#define EXTRACT_32BITS(p) ((u_long) ntohl (*(u_long *)(p)))

#endif /* WORDS_MUSTALIGN */


/* end from decode.h */


/*  D A T A  S T R U C T U R E S  from rules.h  *********************************************/
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


/* end from rules.h */


/*  D A T A  S T R U C T U R E S from decode.h  *********************************************/

// typedef struct rte_ether_hdr EtherHdr;
// typedef struct rte_ipv4_hdr IPHdr;
// typedef struct rte_tcp_hdr TCPHdr;
// typedef struct rte_udp_hdr UDPHdr;
// typedef struct rte_icmp_hdr ICMPHdr;
// typedef struct rte_arp_hdr ARPHdr;

typedef struct _EtherHdr
{
  u_char  ether_dst[6];
  u_char  ether_src[6];
  u_short ether_type;

} EtherHdr;

typedef struct _IPHdr
{
#if defined(WORDS_BIGENDIAN)
  u_char    ip_ver:4,         /* IP version */
            ip_hlen:4;        /* IP header length */
#else
  u_char    ip_hlen:4, ip_ver:4;
#endif
  u_char    ip_tos;           /* type of service */
  u_short   ip_len;           /* datagram length */
  u_short   ip_id;            /* identification  */
  u_short   ip_off;           /* fragment offset */
  u_char    ip_ttl;           /* time to live field */
  u_char    ip_proto;         /* datagram protocol */
  u_short   ip_csum;          /* checksum */
  struct in_addr ip_src;      /* source IP */
  struct in_addr ip_dst;      /* dest IP */

} IPHdr;


typedef struct _TCPHdr
{       
        u_short th_sport;       /* source port */
        u_short th_dport;       /* destination port */
        u_long th_seq;          /* sequence number */
        u_long th_ack;          /* acknowledgement number */
#ifdef WORDS_BIGENDIAN
        u_char  th_off:4,       /* data offset */
                th_x2:4;        /* (unused) */
#else
        u_char  th_x2:4, th_off:4;
#endif
        u_char  th_flags;
        u_short th_win;         /* window */
        u_short th_sum;         /* checksum */
        u_short th_urp;         /* urgent pointer */

} TCPHdr;


typedef struct _UDPHdr
{
  u_short uh_sport;
  u_short uh_dport;
  u_short uh_len;
  u_short uh_chk;

} UDPHdr;


typedef struct _ICMPhdr
{
  u_char type;
  u_char code;
  u_short csum;

} ICMPHdr;

typedef struct _echoext
{
  u_short id;
  u_short seqno;

} echoext;


typedef struct _Packet
{
   struct rte_mbuf* pkth;    /* The mbuf element */
   
   EtherHdr *eh;
   IPHdr    *iph;
   TCPHdr   *tcph;
   UDPHdr   *udph;
   ICMPHdr  *icmph;

   echoext  *ext;

   u_char   *data;
   u_short  dsize;

   u_char   frag_flag;
   u_short  frag_offset;
   u_char   mf;
   u_char   df;

   u_short  sp;
   u_short  dp;
   
   char ip_options[256];
   char tcp_options[256];
} Packet;

/* some of you are asking "why is this include down here?" Well, 
I do have a reason, and that'll do for right now... */
#include "snort.h"

typedef struct _ARPHdr
{
  unsigned short  ar_hrd;         /* format of hardware address   */
  unsigned short  ar_pro;         /* format of protocol address   */
  unsigned char   ar_hln;         /* length of hardware address   */
  unsigned char   ar_pln;         /* length of protocol address   */
  unsigned short  ar_op;          /* ARP opcode (command)         */
} ARPHdr;

typedef struct _EtherARP
{
  ARPHdr        ea_hdr;         /* fixed-size header */
  unsigned char arp_sha[6];     /* sender hardware address */
  unsigned char arp_spa[4];     /* sender protocol address */
  unsigned char arp_tha[6];     /* target hardware address */
  unsigned char arp_tpa[4];     /* target protocol address */
} EtherARP;



typedef struct _IPOptions
{
   u_char code;
   u_char len;
   u_char *data;
} IPOptions;


/* end from decode.h */


/*  D A T A  S T R U C T U R E S from snort.h  *********************************************/
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

/* end from snort.h */




#endif