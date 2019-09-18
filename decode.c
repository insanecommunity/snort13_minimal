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

#include "decode.h"

/****************************************************************************
 *
 * Function: DecodeEthPkt(char *, struct pcap_pkthdr*, u_char*)
 *
 * Purpose: Decode those fun loving ethernet packets, one at a time!
 *
 * Arguments: user => I don't know what this is for, I don't use it but it has
 *                    to be there
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 *
//  ****************************************************************************/
// void DecodeEthPkt(char *user, struct pcap_pkthdr *pkthdr, u_char *pkt)
// {
//    int pkt_len;  /* suprisingly, the length of the packet */
//    int cap_len;  /* caplen value */
//    Packet p;

//    bzero(&p, sizeof(Packet));

//    p.pkth = pkthdr;
//    p.pkt = pkt;

//    /* set the lengths we need */
//    pkt_len = pkthdr->len;       /* total packet length */
//    cap_len = pkthdr->caplen;    /* captured packet length */

// #ifdef DEBUG
//    printf("Packet!\n");
// #endif

//    /* do a little validation */
//    if(p.pkth->caplen < ETHERNET_HEADER_LEN)
//    {
//       if(pv.verbose_flag)
//          fprintf(stderr, "Captured data length < Ethernet header length! (%d bytes)\n", p.pkth->caplen);
//       return;
//    }

//    /* lay the ethernet structure over the packet data */
//    p.eh = (EtherHdr *) pkt;

//    /* grab out the network type */

// #ifdef DEBUG
//    fprintf(stdout, "%X   %X\n", *p.eh->ether_src, *p.eh->ether_dst);
// #endif

//    switch(ntohs(p.eh->ether_type))
//    {
//       case ETHERNET_TYPE_IP:
//                       DecodeIP(p.pkt+ETHERNET_HEADER_LEN, pkt_len-ETHERNET_HEADER_LEN, &p);
//                       return;

//       case ETHERNET_TYPE_ARP:
//       case ETHERNET_TYPE_REVARP:
//                       pc.arp++;
//                       if(pv.showarp_flag)
//                          DecodeARP(p.pkt+ETHERNET_HEADER_LEN, pkt_len-ETHERNET_HEADER_LEN, pkthdr->caplen);
//                       return;
//       default:
//              pc.other++;
//              return;
//    }

//    return;
// }

void DecodeEthPkt(struct rte_mbuf *pkthdr)
{
   int pkt_len;  /* suprisingly, the length of the packet */
   int cap_len;  /* caplen value */
   Packet p;
   void* pkt_addr = NULL;

   bzero(&p, sizeof(Packet));

   p.pkth = pkthdr;



   /* set the lengths we need */
   pkt_len = pkthdr->pkt_len;      /* total packet length */
   cap_len = pkthdr->data_len;    /* captured packet length */
   
   pkt_addr = rte_pktmbuf_mtod(pkthdr, void *);  /* Get the real pkt address */
   // rte_prefetch0(pkt_addr);

#ifdef DEBUG
   printf("Packet!\n");
#endif

   /* do a little validation */
   if(cap_len < ETHERNET_HEADER_LEN)
   {
      if(pv.verbose_flag)
         fprintf(stderr, "Captured data length < Ethernet header length! (%d bytes)\n", cap_len);
      return;
   }

   /* lay the ethernet structure over the packet data */
   p.eh = (EtherHdr *) pkt_addr;

   /* grab out the network type */

#ifdef DEBUG
   fprintf(stdout, "%X   %X\n", *p.eh->ether_src, *p.eh->ether_dst);
#endif

   switch(ntohs(p.eh->ether_type))
   {
      case ETHERNET_TYPE_IP:
                      DecodeIP(p.pkth+ETHERNET_HEADER_LEN, pkt_len-ETHERNET_HEADER_LEN, &p);
                      return;

      case ETHERNET_TYPE_ARP:
      case ETHERNET_TYPE_REVARP:
                      pc.arp++;
                      if(pv.showarp_flag)
                         DecodeARP(p.pkth+ETHERNET_HEADER_LEN, pkt_len-ETHERNET_HEADER_LEN, cap_len);
                      return;
      default:
             pc.other++;
             return;
   }

   return;
}


/****************************************************************************
 *
 * Function: DecodeIP(u_char *, int)
 *
 * Purpose: Decode the IP network layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeIP(u_char *pkt, const int len, Packet *p)
{
   u_int ip_len; /* length from the start of the ip hdr to the pkt end */
   u_int hlen;   /* ip header length */


   /* lay the IP struct over the raw data */
   p->iph = (IPHdr *) pkt;

#ifdef DEBUG
   printf("ip header starts at: %p\n", p->iph);
#endif

   /* do a little validation */
   if(len < IP_HEADER_LEN)
   {
      if(pv.verbose_flag)
         fprintf(stderr, "IP header truncated! (%d bytes)\n", len);
      
      return;
   }

   ip_len = ntohs(p->iph->ip_len);

   /* set the IP header length */
   hlen = p->iph->ip_hlen * 4;

   /* test for IP options */
   if(p->iph->ip_hlen > 5)
   {
      DecodeIPOptions((pkt + IP_HEADER_LEN), hlen - IP_HEADER_LEN, p);
   }

   /* set the remaining packet length */
   ip_len -= hlen;

   /* check for fragmented packets */
   p->frag_offset = ntohs(p->iph->ip_off);

   /* get the values of the more fragments and don't fragment flags */
   p->df = (p->frag_offset & 0x4000) >> 14;
   p->mf = (p->frag_offset & 0x2000) >> 13;

   p->frag_offset &= 0x1FFF;

   /* make sure the packet hasn't been truncated in transit */
   if(len < ip_len)
   {
      if(pv.verbose_flag)
      {  
         fprintf(stderr, "Truncated IP packet!  IP header says %d bytes, actually %d bytes\n", ip_len, len);

         PrintNetData(stdout, pkt, len);

         return;
      }
   }

   /* if this packet isn't a fragment */
   if(!(p->frag_offset) && !(p->mf))
   {
#ifdef DEBUG
      printf("IP header length: %d\n", hlen);
#endif

      switch(p->iph->ip_proto)
      {
         case IPPROTO_TCP:
                      pc.tcp++;
                      DecodeTCP(pkt + hlen, len - hlen, p);
                      ClearDumpBuf();
                      return;

         case IPPROTO_UDP:
                      pc.udp++;
                      DecodeUDP(pkt + hlen, len - hlen, p);
                      ClearDumpBuf();
                      return;

         case IPPROTO_ICMP:
                      pc.icmp++;
                      DecodeICMP(pkt + hlen, len - hlen, p);
                      ClearDumpBuf();
                      return;

         default:
                pc.other++;
                ClearDumpBuf();
                return;
      }
   }
   else /* if the packet is fragmented */
   {
      /* set the packet fragment flag */
      p->frag_flag = 1;

      /* increment the packet counter */
      switch(p->iph->ip_proto)
      {
         case IPPROTO_TCP:
                      pc.tcp++;
                      break;
   
         case IPPROTO_UDP:
                      pc.udp++;
                      break;

         case IPPROTO_ICMP:
                      pc.icmp++;
                      break;

         default:
                      pc.other++;
                      break;
      }

      /* set the payload pointer and payload size */
      p->data = pkt + hlen;
      p->dsize = len - hlen;

      /* print the packet to the screen */
      if(pv.verbose_flag)   
      {                                
         PrintIPPkt(stdout, p->iph->ip_proto, p);
      }                     
      
      ApplyRules(p);
  

      ClearDumpBuf();
   }
}



/****************************************************************************
 *
 * Function: DecodeTCP(u_char *, int)
 *
 * Purpose: Decode the TCP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeTCP(u_char *pkt, const int len, Packet *p)
{
   int hlen;      /* TCP header length */

   /* lay TCP on top of the data */
   p->tcph = (TCPHdr *) pkt;

#ifdef DEBUG
   printf("tcp header starts at: %p\n", p->tcph);
#endif

   /* stuff more data into the printout data struct */
   p->sp = ntohs(p->tcph->th_sport);
   p->dp = ntohs(p->tcph->th_dport);

   /* multiply the payload offset value by 4 */
   hlen = p->tcph->th_off << 2;

   /* if options are present, decode them */
   if(hlen > 20)
   {
      DecodeTCPOptions((u_char *)(pkt+20), (hlen - 20), p);
   }

   /* set the data pointer and size */
   p->data = (u_char *)(pkt + hlen);

   p->dsize = len - hlen;

   /* print/log/test the packet */
   if(pv.verbose_flag)
   {
      PrintIPPkt(stdout, IPPROTO_TCP, p);
   }
   
   ApplyRules(p);

}


/****************************************************************************
 *
 * Function: DecodeUDP(u_char *, int)
 *
 * Purpose: Decode the UDP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeUDP(u_char *pkt, const int len, Packet *p)
{
   /* set the ptr to the start of the UDP header */
   p->udph = (UDPHdr *) pkt;

#ifdef DEBUG
   printf("UDP header starts at: %p\n", p->udph);
#endif

   /* fill in the printout data structs */
   p->sp = ntohs(p->udph->uh_sport);
   p->dp = ntohs(p->udph->uh_dport);

   p->data = (u_char *)(pkt + UDP_HEADER_LEN);
   p->dsize = len - UDP_HEADER_LEN;

   if(pv.verbose_flag)
   {
      PrintIPPkt(stdout, IPPROTO_UDP, p);
   }
   
   ApplyRules(p);

}





/****************************************************************************
 *
 * Function: DecodeICMP(u_char *, int)
 *
 * Purpose: Decode the ICMP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeICMP(u_char *pkt, const int len, Packet *p)
{
   /* set the header ptr first */
   p->icmph = (ICMPHdr *) pkt;

   p->dsize = len - ICMP_HEADER_LEN;
   p->data = pkt + ICMP_HEADER_LEN;

#ifdef DEBUG
   printf("ICMP type: %d   code: %d\n", p->icmph->code, p->icmph->type);
#endif
   switch(p->icmph->type)
   {
      case ICMP_ECHOREPLY:
                         /* setup the pkt id ans seq numbers */
                         p->ext = (echoext *)(pkt + ICMP_HEADER_LEN);
                         p->dsize -= sizeof(echoext);
                         p->data += sizeof(echoext);
                         break;
      case ICMP_ECHO:
                         /* setup the pkt id ans seq numbers */
                         p->ext = (echoext *)(pkt + ICMP_HEADER_LEN);
                         p->dsize -= 4;  /* add the size of the echo ext to 
                                            the data ptr and subtract it from
                                            the data size */
                         p->data += 4;
                         break;
   }

   if(pv.verbose_flag)
   {
      PrintIPPkt(stdout, IPPROTO_ICMP, p);
   }


   ApplyRules(p);


   return;
}



/****************************************************************************
 *
 * Function: DecodeARP(u_char *, int)
 *
 * Purpose: Decode ARP stuff
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            caplen => unused...
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeARP(u_char *pkt, int len, int caplen)
{
   EtherARP *arph;        /* ARP hdr ptr */
   char timebuf[64];      /* timestamp buffer */
   struct in_addr saddr;  /* src addr */
   struct in_addr daddr;  /* dest addr */
   char type[32];         /* type buf */

   arph = (EtherARP *) pkt;

   if(len < sizeof(EtherARP))
   {
      printf("Truncated packet\n");
      return;
   }

   memcpy((void *) &saddr, (void *) &arph->arp_spa, sizeof (struct in_addr));
   memcpy((void *) &daddr, (void *) &arph->arp_tpa, sizeof (struct in_addr));

   switch (ntohs(arph->ea_hdr.ar_op))
   {
      case ARPOP_REQUEST:
                  sprintf(type, "ARP request");
                  break;

      case ARPOP_REPLY:
                  sprintf(type, "ARP reply");
                  break;

      case ARPOP_RREQUEST:
                  sprintf(type, "RARP request");
                  break;

      case ARPOP_RREPLY:
                  sprintf(type, "RARP reply");
                  break;

      default:
                 sprintf(type, "unknown");
                 return;
   }

   if(pv.verbose_flag)
   {
      memcpy((void *) &saddr, (void *) &arph->arp_spa, sizeof (struct in_addr));
      fprintf(stdout, "%s: %s %s", timebuf, "ARP", inet_ntoa(saddr));
      memcpy((void *) &daddr, (void *) &arph->arp_tpa, sizeof (struct in_addr));
      fprintf(stdout, " -> %s  %s\n", inet_ntoa(daddr), type);
   }

   return;
}


/****************************************************************************
 *
 * Function: DecodeIPX(u_char *, int)
 *
 * Purpose: Well, it doesn't do much of anything right now...
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeIPX(u_char *pkt, int len)
{
   if(pv.verbose_flag)
   {
      puts("IPX packet");
   }

   return;
}




/****************************************************************************
 *
 * Function: DecodeTCPOptions(u_char *, int)
 *
 * Purpose: Fairly self explainatory name, don't you think?
 *
 * Arguments: o_list => ptr to the option list
 *            o_len => length of the option list
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeTCPOptions(u_char *o_list, int o_len, Packet *p)
{
   u_char *cp;
   int i;
   int opt;
   int len; 
   int datalen;
   int index_counter = 0;
   char tmpbuf[128];

   cp = o_list;

   bzero(tmpbuf, 128);

   strncpy(p->tcp_options, "TCP Options => ", 15);

   while (o_len > 0)
   {
      if(index_counter > 200)
      {
         strncat(p->tcp_options, "\n\x0", 2);
         return;
      }

      /* Check for zero length options */
      opt = *cp++;

      if((opt == TCPOPT_EOL) || 
         (opt == TCPOPT_NOP))
      {
            len = 1;
      }
      else
      {
         len = *cp++;  /* total including type, len */

         if(len < 2 || len > o_len)
         {
            if(pv.verbose_flag)
            {
               printf("Illegal TCP Options from %s, reported size %d, tcp header reports %d\n", inet_ntoa(p->iph->ip_src), 
                      len, o_len);

               PrintNetData(stdout, (p->eh + ETHERNET_HEADER_LEN), (p->pkth->data_len - ETHERNET_HEADER_LEN));
               ClearDumpBuf();
            }

            break;
         }

         /* account for length byte */
         o_len--;

      }

      /* account for type byte */
      o_len--;

      /* Handle the rest of the options */
      datalen = 0;

      switch (opt)
      {
         case TCPOPT_MAXSEG:
                  datalen = 2;
                  sprintf(tmpbuf, "MSS: %u ", EXTRACT_16BITS(cp));
                  strncat(p->tcp_options, tmpbuf, strlen(tmpbuf));
                  index_counter += strlen(tmpbuf);
                  bzero(tmpbuf, 128);

                  break;

         case TCPOPT_EOL:
                  strncat(p->tcp_options, "EOL ", 5);
                  index_counter += 4;
                  break;

         case TCPOPT_NOP:
                  strncat(p->tcp_options, "NOP ", 5);
                  index_counter += 4;
                  break;

         case TCPOPT_WSCALE:
                  datalen = 1;
                  sprintf(tmpbuf, "WS: %u ", *cp);
                  strncat(p->tcp_options, tmpbuf, strlen(tmpbuf));
                  index_counter += strlen(tmpbuf);
                  bzero(tmpbuf, 128);
                  break;

         case TCPOPT_ECHO:
                  datalen = 4;
                  sprintf(tmpbuf,"Echo: %lu ", EXTRACT_32BITS(cp));
                  strncat(p->tcp_options, tmpbuf, strlen(tmpbuf));
                  index_counter += strlen(tmpbuf);
                  bzero(tmpbuf, 128);
                  break;

         case TCPOPT_ECHOREPLY:
                  datalen = 4;
                  sprintf(tmpbuf, "Echo Rep: %lu ", EXTRACT_32BITS(cp));
                  strncat(p->tcp_options, tmpbuf, strlen(tmpbuf));
                  index_counter += strlen(tmpbuf);
                  bzero(tmpbuf, 128);
                  break;

         case TCPOPT_TIMESTAMP:
                  datalen = 8;
                  sprintf(tmpbuf, "TS: %lu %lu ", EXTRACT_32BITS(cp), EXTRACT_32BITS(cp + 4));
                  strncat(p->tcp_options, tmpbuf, strlen(tmpbuf));
                  index_counter += strlen(tmpbuf);
                  bzero(tmpbuf, 128);
                  break;

         default:
                  datalen = len - 2;
                  sprintf(tmpbuf, "Opt %d:", opt);
                  strncat(p->tcp_options, tmpbuf, strlen(tmpbuf));
                  index_counter += strlen(tmpbuf);
                  bzero(tmpbuf, 128);

                  for(i = 0; i < datalen; ++i)
                  {
                      sprintf(tmpbuf, " %02x", cp[i]);
                      strncat(p->tcp_options, tmpbuf, strlen(tmpbuf));
                      index_counter += 2;
                  }
                  break;
      }

          /*
           * Account for data printed
           */

          cp += datalen;
          o_len -= datalen;
   }

   strncat(p->tcp_options, "\n\x0", 2);
   index_counter += 1;

}



/****************************************************************************
 *
 * Function: DecodeIPOptions(u_char *, int)
 *
 * Purpose: Once again, a fairly self-explainatory name
 *
 * Arguments: o_list => ptr to the option list
 *            o_len => length of the option list
 *
 * Returns: void function
 *
 ****************************************************************************/
void DecodeIPOptions(u_char *o_list, int o_len, Packet *p)
{
   u_char *cp;
   int i;
   int opt;
   int len; 
   int datalen;
   char tmpbuf[128];

   cp = o_list;

   bzero(tmpbuf, 128);

   strncpy(p->ip_options,  "IP Options => ", 15);

   while (o_len > 0)
   {
      /* Check for zero length options */

      opt = *cp;
      cp++;

      if((opt == IPOPT_EOL) || 
         (opt == IPOPT_NOP))
      {
            len = 1;
      }
      else
      {
         len = *cp;  /* total including type, len */
         cp++;

         if(len < 2 || len > o_len)
         {
            if(pv.verbose_flag)
            {
               printf("Illegal IP options from %s: option says %d, IP header says %d\nPacket Dump:\n",
               inet_ntoa(p->iph->ip_src), len, o_len);
               PrintNetData(stdout, p->eh+ETHERNET_HEADER_LEN, p->pkth->data_len-ETHERNET_HEADER_LEN);
               ClearDumpBuf();
            }

            break;
         }

         /* account for length byte */
         o_len--;

      }

      /* account for type byte */
      o_len--;

      /* Handle the rest of the options */
      datalen = 0;

      switch (opt)
      {
         case IPOPT_RR:
                  datalen = len - 2;
                  strncat(p->ip_options,  "RR ", 4);

                  break;

         case IPOPT_EOL:
                  strncat(p->ip_options,  "EOL ", 5);
                  break;

         case IPOPT_NOP:
                  strncat(p->ip_options,  "NOP ", 5);
                  break;

         case IPOPT_TS:
                  datalen = len - 2;
                  strncat(p->ip_options,  "TS ", 4);
                  break;

         case IPOPT_SECURITY:
                  datalen = len - 2;
                  strncat(p->ip_options,  "SEC ", 5);
                  break;

         case IPOPT_LSRR:
         case IPOPT_LSRR_E:
                  datalen = len - 2;
                  strncat(p->ip_options,  "LSRR ", 6);
                  break;

         case IPOPT_SATID:
                  datalen = len - 2;
                  strncat(p->ip_options,  "SID ", 5);
                  break;

         case IPOPT_SSRR:
                  datalen = len - 2;
                  strncat(p->ip_options,  "SSRR ", 6);
                  break;

         default:
                  datalen = len - 2;
                  sprintf(tmpbuf, "Opt %d: ", opt);
                  strncat(p->ip_options,  tmpbuf, strlen(tmpbuf));
                  bzero(tmpbuf, 128);

                  for(i = 0; i < datalen; i+=2)
                  {
                      sprintf(tmpbuf, "%02X ", cp[i]);

                      if((i+1) < datalen)
                      {
                         sprintf(tmpbuf+2, "%02X ", cp[i+1]);
                      }

                      if((i > 1) && (i%20) == 0)
                      {
                         sprintf(tmpbuf+5, "\n");
                      }
                         
                      strncat(p->ip_options,  tmpbuf, strlen(tmpbuf));
                      bzero(tmpbuf, 128);
                  }
                  break;
      }

          /*
           * Account for data printed
           */

          cp += datalen;
          o_len -= datalen;
   }
   strncat(p->ip_options,  "\n\x0", 2);
}
