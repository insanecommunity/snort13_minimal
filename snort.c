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

/******************************************************************************
 *
 * Program: Snort
 *
 * Purpose: Check out the README file for info on what you can do
 *          with Snort.
 *
 * Author: Martin Roesch (roesch@clark.net)
 *
 * Last Modified: 9/26/99
 *
 * Comments: Ideas and code stolen liberally from Mike Borella's IP Grab 
 *           program. Check out his stuff at http://www.borella.net.  I
 *           also have ripped some util functions from TCPdump, plus Mike's
 *           prog is derived from it as well.  All hail TCPdump....
 *
 * HP-UX 10.x note from Chris Sylvain:
 * if you run snort and receive the error message
 *  "ERROR: OpenPcap() device lan0 open:
 *                    recv_ack: promisc_phys: Invalid argument"
 * it's because there's another program running using the DLPI service.
 * The HP-UX implementation doesn't allow more than one libpcap program
 * at a time to run, unlike Linux.
 *
 ******************************************************************************/

/*  I N C L U D E S  **********************************************************/
#include "snort.h"




/****************************************************************************
 *
 * Function: main(int, char *)
 *
 * Purpose:  Handle program entry and exit, call main prog sections
 *
 * Arguments: See command line args in README file
 *
 * Returns: 0 => normal exit, 1 => exit on error
 *
 ****************************************************************************/
int init_snort_variables(struct snort_states* s)
{
   /* make this prog behave nicely when signals come along */
   // signal(SIGKILL, CleanExit);
   // signal(SIGTERM, CleanExit);
   // signal(SIGINT, CleanExit);
   // signal(SIGQUIT, CleanExit);
   // signal(SIGHUP, CleanExit);

   PV* pv = &s->pv;

   InitNetmasks(s);
   InitProtoNames(s);



   /* initialize the packet counter to loop forever */
   pv->pkt_cnt = -1;

   /* set the default alert mode */
   pv->alert_mode = ALERT_FULL;

   /* chew up the command line */
   // ParseCmdLine(argc, argv);
   /* be verbose */
   pv->verbose_flag = 0;
   s->MTU = ETHERNET_MTU; /* Set ethernet MTU */


   /* check log dir */
   strncpy(pv->log_dir,DEFAULT_LOG_DIR,strlen(DEFAULT_LOG_DIR)+1);
   logdir_check(s);


   AlertFunc = FastAlert;
   OpenAlertFile(s);

   // /* open up our libpcap packet capture interface */
   // OpenPcap(pv.interface);

   /* set the packet processor (ethernet, slip or raw)*/
   // SetPktProcessor();
   /* We simply use the default ethernet packet processor here */


   // /* Read all packets on the device.  Continue until cnt packets read */
   // if(pcap_loop(pd, pv.pkt_cnt, grinder, NULL) < 0)
   // {
   //    fprintf(stderr, "pcap_loop: %s", pcap_geterr(pd));
   //    CleanExit();
   // }

   // /* close the capture interface */
   // pcap_close(pd);

  return 0;
}


/****************************************************************************
 *
 * Function: GoDaemon()
 *
 * Purpose: CyberPsychotic sez: basically we only check if logdir exist and 
 *          writable, since it might screw the whole thing in the middle. Any
 *          other checks could be performed here as well.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/

void logdir_check(struct snort_states* s)
{
   struct stat st;
   PV *pv = &s->pv;

   stat(pv->log_dir,&st);

   if (!S_ISDIR(st.st_mode)) {
      if(mkdir(pv->log_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) {
         if(errno != EEXIST)  {
            printf("Problem creating directory %s\n",pv->log_dir);
         }
      }
   }
   /* Test again */
   stat(pv->log_dir,&st);
   if(!S_ISDIR(st.st_mode) || access(pv->log_dir,W_OK) == -1) 
   {
      fprintf(stderr,"\n*Error* :"
              "Can not get write to logging directory %s.\n"
              "(directory doesn't "
              "exist or permissions are set incorrectly)\n\n",
              pv->log_dir);
      exit(0);
   }        

}


/****************************************************************************
 *
 * Function: ParseCmdLine(int, char *)
 *
 * Purpose:  Parse command line args
 *
 * Arguments: argc => count of arguments passed to the routine
 *            argv => 2-D character array, contains list of command line args
 *
 * Returns: 0 => success, 1 => exit on error
 *
//  ****************************************************************************/
// int ParseCmdLine(int argc, char *argv[])
// {
//    char ch;                      /* storage var for getopt info */
//    extern char *optarg;          /* for getopt */
//    extern int optind;            /* for getopt */

// #ifdef DEBUG
//    printf("Parsing command line...\n");
// #endif

//    /* loop through each command line var and process it */
//    while((ch = getopt(argc, argv, "pNA:F:DtM:br:xeh:l:dc:n:i:vV?aso")) != EOF)
//    {
// #ifdef DEBUG
//       printf("Processing cmd line switch: %c\n", ch);
// #endif
//       switch(ch)
//       {
//          case 'A': /* alert mode */
//                  if(!strncasecmp(optarg,"none", 4))
//                     pv.alert_mode = ALERT_NONE;

//                  if(!strncasecmp(optarg,"full", 4))
//                     pv.alert_mode = ALERT_FULL;

//                  if(!strncasecmp(optarg,"fast", 4))
//                     pv.alert_mode = ALERT_FAST;
      
//                  break;

//          case 'v': /* be verbose */
//                  pv.verbose_flag = 1;
// #ifdef DEBUG
//                  printf("Verbose Flag active\n");
// #endif
//                  break;


//          case 'c': /* use configuration file x ( which currently isn't used) */
//                  strncpy(pv.config_file, optarg, STD_BUF - 1);
//                  pv.use_rules = 1;
//                  ParseRulesFile(pv.config_file);
// #ifdef DEBUG
//                  printf("Config file = %s\n", pv.config_file);
// #endif
//                  break;

//          case 'i': /* listen on interface x */
//                  pv.interface = (char *) malloc(strlen(optarg) + 1);
//                  bzero(pv.interface, strlen(optarg)+1);
//                  strncpy(pv.interface, optarg, strlen(optarg));
// #ifdef DEBUG
//                  printf("Interface = %s\n", pv.interface);
// #endif
//                  break;
//       }
//    }

//    return 0;
// }


/****************************************************************************
 *
 * Function: SetPktProcessor()
 *
 * Purpose:  Set which packet processing function we're going to use based on 
 *           what type of datalink layer we're using
 *
 * Arguments: None.
 *
 * Returns: 0 => success
 *
 ****************************************************************************/
// int SetPktProcessor()
// {
//    grinder = (pcap_handler) DecodeEthPkt;
//    MTU = ETHERNET_MTU; 
//    return 0;
// }
   

/****************************************************************************
 *
 * Function: OpenPcap(char *)
 *
 * Purpose:  Open the libpcap interface
 *
 * Arguments: intf => name of the interface to open 
 *
 * Returns: 0 => success, exits on problems
 *
 ****************************************************************************/
// int OpenPcap(char *intf)
// {
//    bpf_u_int32 localnet, netmask;    /* net addr holders */
//    struct bpf_program fcode;         /* Finite state machine holder */
//    char errorbuf[PCAP_ERRBUF_SIZE];  /* buffer to put error strings in */
 
//    /* look up the device and get the handle */
//    if(pv.interface == NULL)
//    {
//       pv.interface = pcap_lookupdev(errorbuf);

//       if(pv.interface == NULL)
//       {
//          fprintf(stderr, "ERROR: OpenPcap() interface lookup: \n\t%s\n", 
//                  errorbuf);
//          exit(1);
//       }
//    }
 
//    /* get the device file descriptor */
//    pd = pcap_open_live(pv.interface, SNAPLEN,PROMISC, READ_TIMEOUT, errorbuf);

//    /*pd = pcap_open_live(pv.interface, SNAPLEN, PROMISC, READ_TIMEOUT, errorbuf);*/
//    if (pd == NULL) 
//    {
//       fprintf(stderr, "ERROR: OpenPcap() device %s open: \n\t%s\n", 
//               pv.interface, errorbuf);
//       exit(1);
//    }
 
//    /* get local net and netmask */
//    if(pcap_lookupnet(pv.interface, &localnet, &netmask, errorbuf) < 0)
//    {
//       fprintf(stderr, "ERROR: OpenPcap() device %s network lookup: \n\t%s\n", 
//               pv.interface, errorbuf);
//       exit(1);
//    }
  
//    /* compile command line filter spec info fcode FSM */
//    if(pcap_compile(pd, &fcode, pv.pcap_cmd, 0, netmask) < 0)
//    {
//       fprintf(stderr, "ERROR: OpenPcap() FSM compilation failed: \n\t%s\n", 
//               pcap_geterr(pd));
//       exit(1);
//    } 
  
//    /* set the pcap filter */
//    if(pcap_setfilter(pd, &fcode) < 0)
//    {
//       fprintf(stderr, "ERROR: OpenPcap() setfilter: \n\t%s\n", pcap_geterr(pd));
//       exit(1);
//    }
 
//    /* get data link type */
//    datalink = pcap_datalink(pd);

//    if (datalink < 0) 
//    {
//       fprintf(stderr, "ERROR: OpenPcap() datalink grab: \n\t%s\n", pcap_geterr(pd));
//       exit(1);
//    }

//    return 0;
// }
 
// /****************************************************************************
//  *
//  * Function: CleanExit()
//  *
//  * Purpose:  Clean up misc file handles and such and exit
//  *
//  * Arguments: None.
//  *
//  * Returns: void function
//  *
//  ****************************************************************************/
// void CleanExit()
// {
//    struct pcap_stat ps;
//    float drop;
//    float recv;


//    /* make sure everything that needs to go to the screen gets there */
//    fflush(stdout);

//    printf("\nExiting...\n");

//    if(pv.alert_mode == ALERT_FAST)
//    {
//       fclose(alert);
//    }

//    /* collect the packet stats */
//    if(pcap_stats(pd, &ps))
//    {
//       pcap_perror(pd, "pcap_stats");
//    }
//    else
//    {
//       recv = ps.ps_recv;
//       drop = ps.ps_drop;

//       puts("\n\n===============================================================================");
//       printf("Snort received %d packets", ps.ps_recv);

//       if(ps.ps_recv)
//       {
// #ifndef LINUX
//          printf(" and dropped %d(%.3f%%) packets\n\n", ps.ps_drop, 
//                 CalcPct(drop, recv));
// #else
//          printf(".\nPacket loss statistics are unavailable under Linux.  Sorry!\n\n");
// #endif
//       }
//       else
//       {
//          puts(".\n");
//       }
//       puts("Breakdown by protocol:");
//       printf("    TCP: %-10ld (%.3f%%)\n", pc.tcp, CalcPct((float)pc.tcp, recv));
//       printf("    UDP: %-10ld (%.3f%%)\n", pc.udp, CalcPct((float)pc.udp, recv));
//       printf("   ICMP: %-10ld (%.3f%%)\n", pc.icmp, CalcPct((float)pc.icmp, recv));
//       printf("    ARP: %-10ld (%.3f%%)\n", pc.arp, CalcPct((float)pc.arp, recv));
//       printf("    IPX: %-10ld (%.3f%%)\n", pc.ipx, CalcPct((float)pc.ipx, recv));
//       printf("  OTHER: %-10ld (%.3f%%)\n", pc.other, CalcPct((float)pc.other, recv));

//       puts("===============================================================================");
//    }


//    pcap_close(pd);

//    exit(0);
// }


float CalcPct(float cnt, float total)
{
   float pct;

   if(cnt > 0.0)
      pct = cnt/total;
   else
      return 0.0;

   pct *= 100.0;

   return pct;
}



/****************************************************************************
 *  
 * Function: ts_print(register const struct, char *)
 * 
 * Purpose: Generate a time stamp and stuff it in a buffer.  This one has
 *          millisecond precision.  Oh yeah, I ripped this code off from
 *          TCPdump, props to those guys.
 * 
 * Arguments: timeval => clock struct coming out of libpcap
 *            timebuf => buffer to stuff timestamp into
 *      
 * Returns: void function
 * 
 ****************************************************************************/
void ts_print(register const struct timeval *tvp, char *timebuf, struct snort_states* state)
{               
   register int s;  
   struct tm *lt;   /* place to stick the adjusted clock data */

   lt = localtime((time_t *)&tvp->tv_sec);

   s = (tvp->tv_sec + state->thiszone) % 86400;

   (void)sprintf(timebuf, "%02d/%02d-%02d:%02d:%02d.%06u ", lt->tm_mon+1, 
                 lt->tm_mday, s / 3600, (s % 3600) / 60, s % 60, 
                 (u_int)tvp->tv_usec);
}




/****************************************************************************
 *
 * Function: strip(char *)
 *
 * Purpose: Strips a data buffer of CR/LF/TABs.  Replaces CR/LF's with
 *          NULL and TABs with spaces.
 *
 * Arguments: data => ptr to the data buf to be stripped
 *
 * Returns: size of the newly stripped string
 *
 ****************************************************************************/
int strip(char *data)
{
   int size;
   char *end;
   char *idx;

   idx = data;
   end = data + strlen(data);
   size = end - idx;

   while(idx != end)
   {
      if((*idx == '\n') ||
         (*idx == '\r'))
      {
         *idx = 0;
         size--;
      }

      if(*idx == '\t')
      {
         *idx = ' ';
      }

      idx++;
   }

   return size;
}




/****************************************************************************
 *
 * Function: InitNetMasks()
 *
 * Purpose: Loads the netmask struct in network order.  Yes, I know I could
 *          just load the array when I define it, but this is what occurred
 *          to me when I wrote this at 3:00 AM.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void InitNetmasks(struct snort_states* s)
{
   u_long* netmasks = s->netmasks; 
   netmasks[0] = 0x0;
   netmasks[1] = 0x80000000;
   netmasks[2] = 0xC0000000;
   netmasks[3] = 0xE0000000;
   netmasks[4] = 0xF0000000;
   netmasks[5] = 0xF8000000;
   netmasks[6] = 0xFC000000;
   netmasks[7] = 0xFE000000;
   netmasks[8] = 0xFF000000;
   netmasks[9] = 0xFF800000;
   netmasks[10] = 0xFFC00000;
   netmasks[11] = 0xFFE00000;
   netmasks[12] = 0xFFF00000;
   netmasks[13] = 0xFFF80000;
   netmasks[14] = 0xFFFC0000;
   netmasks[15] = 0xFFFE0000;
   netmasks[16] = 0xFFFF0000;
   netmasks[17] = 0xFFFF8000;
   netmasks[18] = 0xFFFFC000;
   netmasks[19] = 0xFFFFE000;
   netmasks[20] = 0xFFFFF000;
   netmasks[21] = 0xFFFFF800;
   netmasks[22] = 0xFFFFFC00;
   netmasks[23] = 0xFFFFFE00;
   netmasks[24] = 0xFFFFFF00;
   netmasks[25] = 0xFFFFFF80;
   netmasks[26] = 0xFFFFFFC0;
   netmasks[27] = 0xFFFFFFE0;
   netmasks[28] = 0xFFFFFFF0;
   netmasks[29] = 0xFFFFFFF8;
   netmasks[30] = 0xFFFFFFFC;
   netmasks[31] = 0xFFFFFFFE;
   netmasks[32] = 0xFFFFFFFF;
}



/****************************************************************************
 *
 * Function: InitProtoNames()
 *
 * Purpose: Initializes the protocol names
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void InitProtoNames(struct snort_states* s)
{  
   char* protocol_names = s->protocol_names;
   strncpy(protocol_names[1], "ICMP", 5);
   strncpy(protocol_names[6], "TCP", 4);
   strncpy(protocol_names[17], "UDP", 4);
}
