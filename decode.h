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

#ifndef __DECODE_H__
#define __DECODE_H__


/*  I N C L U D E S  **********************************************************/

#include <stdio.h>
// #include <pcap.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h> 
#include <signal.h>
#include <math.h>
#include <ctype.h>
// #include <pcap-namedb.h>
#include <netdb.h> 
#include <syslog.h>
#include <rte_mbuf.h>
#include <rte_prefetch.h>
// #include <rte_ether.h>
// #include <rte_ip.h>
// #include <rte_arp.h>
// #include <rte_tcp.h>
// #include <rte_udp.h>
// #include <rte_icmp.h>

#include "types.h"









/*  P R O T O T Y P E S  ******************************************************/
void DecodeEthPkt(struct rte_mbuf *pkthdr, struct snort_states *);
void DecodeIP(u_char *, int, Packet *, struct snort_states *);
void DecodeARP(u_char *, int, int, struct snort_states *);
void DecodeIPX(u_char *, int, struct snort_states *);
void DecodeTCP(u_char *, int, Packet *, struct snort_states *);
void DecodeUDP(u_char *, int, Packet *, struct snort_states *);
void DecodeICMP(u_char *, int, Packet *, struct snort_states *);
void DecodeIPOptions(u_char *, int, Packet *, struct snort_states *);
void DecodeTCPOptions(u_char *, int, Packet *, struct snort_states *);
/*void CleanUp();*/

#endif  /* __DECODE_H__ */
