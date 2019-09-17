#ifndef __TRANSMUTE_H__
#define __TRANSMUTE_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

#define TCPDUMP_MAGIC 0xa1b2c3d4


typedef struct _pcap_file_header 
{
   u_int magic;
   u_short version_major;
   u_short version_minor;
   u_int thiszone;	/* gmt to local correction */
   u_int sigfigs;	/* accuracy of timestamps */
   u_int snaplen;	/* max length saved portion of each pkt */
   u_int linktype;	/* data link type (DLT_*) */
} pcap_file_header;

typedef struct _pcap_pkthdr 
{
   struct timeval ts;	/* time stamp */
   u_int caplen;	/* length of portion present */
   u_int len;	        /* length this packet (off wire) */
} pcap_pkthdr;



int ReadPcapHeader(FILE *, pcap_file_header *);
int GetNextPkt(FILE *, pcap_pkthdr *, u_char *);





#endif /* __TRANSMUTE_H__ */
