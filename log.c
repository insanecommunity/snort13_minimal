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

#include "log.h"
#include "states.h"

// extern OptTreeNode *otn_tmp; /* global ptr to current rule data */




/****************************************************************************
 *
 * Function: OpenLogFile()
 *
 * Purpose: Create the log directory and file to put the packet log into.
 *          This function sucks, I've got to find a better way to do this
 *          this stuff.
 *
 * Arguments: None.
 *
 * Returns: 0 on success, exits on error
 *
 ****************************************************************************/
int OpenLogFile(int mode, Packet *p)
{
   char log_path[STD_BUF]; /* path to log file */
   char log_file[STD_BUF]; /* name of log file */
   char proto[5];          /* logged packet protocol */
 
   /* zero out our buffers */
   bzero(log_path, STD_BUF);
   bzero(log_file, STD_BUF);
   bzero(proto, 5);

   if(mode == DUMP)
   {
      sprintf(log_file, "%s/PACKET_FRAG", pv.log_dir);

      if((log_ptr = fopen(log_file, "a")) == NULL)
      {
          fprintf(stderr, "ERROR: OpenLogFile() => fopen(%s) log file: %s\n",
                  log_file, strerror(errno));
          exit(1);
      }

      return 0;
   }

   if(mode == BOGUS)
   {
      sprintf(log_file, "%s/PACKET_BOGUS", pv.log_dir);

      if((log_ptr = fopen(log_file, "a")) == NULL)
      {
          fprintf(stderr, "ERROR: OpenLogFile() => fopen(%s) log file: %s\n",
                  log_file, strerror(errno));
          exit(1);
      }

      return 0;
   }

   if(mode == NON_IP)
   {
      sprintf(log_file, "%s/PACKET_NONIP", pv.log_dir);

      if((log_ptr = fopen(log_file, "a")) == NULL)
      {
          fprintf(stderr, "ERROR: OpenLogFile() => fopen(%s) log file: %s\n",
                  log_file, strerror(errno));
          exit(1);
      }

      return 0;
   }

   if(otn_tmp != NULL)
   {
      if(otn_tmp->logto != NULL)
      {
         sprintf(log_file, "%s/%s", pv.log_dir, otn_tmp->logto);

         if((log_ptr = fopen(log_file, "a")) == NULL) 
         {
            fprintf(stderr, "ERROR: OpenLogFile() => fopen(%s) log file: %s\n", log_file, strerror(errno));
            exit(1);
         }

         return 0;
      }
   }

   // /* figure out which way this packet is headed in relation to the homenet */
   // if((p->iph->ip_dst.s_addr & pv.netmask) == pv.homenet)
   // {
   //    if((p->iph->ip_src.s_addr & pv.netmask) != pv.homenet)
   //    {
   //       sprintf(log_path, "%s/%s", pv.log_dir, inet_ntoa(p->iph->ip_src));
   //    }
   //    else
   //    {
   //       if( p->sp >= p->dp )
   //       {
   //          sprintf(log_path, "%s/%s", pv.log_dir, inet_ntoa(p->iph->ip_src));
   //       }
   //       else
   //       {
   //          sprintf(log_path, "%s/%s", pv.log_dir, inet_ntoa(p->iph->ip_dst));
   //       }
   //    }
   // }
   // else
   // {
   //    if((p->iph->ip_src.s_addr & pv.netmask) == pv.homenet)
   //    {
   //       sprintf(log_path, "%s/%s", pv.log_dir, inet_ntoa(p->iph->ip_dst));
   //    }
   //    else
   //    {
   //       if(p->sp >= p->dp)
   //       {
   //          sprintf(log_path, "%s/%s", pv.log_dir, inet_ntoa(p->iph->ip_src));
   //       }
   //       else
   //       {
   //          sprintf(log_path, "%s/%s", pv.log_dir, inet_ntoa(p->iph->ip_dst));
   //       }
   //    }
   // }

#ifdef DEBUG
   fprintf(stderr, "Creating directory: %s\n",log_path);
#endif

   /* build the log directory */
   if(mkdir(log_path,S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH))
   {
#ifdef DEBUG
      if(errno != EEXIST)
      {
         printf("Problem creating directory %s\n",log_path);
      }
#endif
   }

#ifdef DEBUG
   printf("Directory Created!\n");
#endif

   /* build the log filename */
   if(p->iph->ip_proto == IPPROTO_TCP||
      p->iph->ip_proto == IPPROTO_UDP)
   {
      if(p->frag_offset||p->mf)
      {
         sprintf(log_file, "%s/IP_FRAG", log_path);
      }
      else
      {
         if(p->sp >= p->dp)
         {
            sprintf(log_file, "%s/%s:%d-%d", log_path, protocol_names[p->iph->ip_proto], 
                    p->sp, p->dp);
         }
         else
         {
            sprintf(log_file, "%s/%s:%d-%d", log_path, protocol_names[p->iph->ip_proto], 
                    p->dp, p->sp);
         }
      }
   }
   else
   {
      if(p->frag_flag)
      {
         sprintf(log_file, "%s/IP_FRAG", log_path);
      }
      else
      {
         if(p->iph->ip_proto == IPPROTO_ICMP)
         {
            sprintf(log_file, "%s/%s_%s", log_path, "ICMP", IcmpFileName(p));
         }
      }
   }

#ifdef DEBUG
   printf("Opening file: %s\n", log_file);
#endif

   /* finally open the log file */
   if((log_ptr = fopen(log_file, "a")) == NULL)
   {
       fprintf(stderr, "ERROR: OpenLogFile() => fopen(%s) log file: %s\n",
               log_file, strerror(errno));
       exit(1);
   }

#ifdef DEBUG
   printf("File opened...\n");
#endif

   return 0;
}



/****************************************************************************
 *
 * Function: PrintNetData(FILE *, char *,int)
 *
 * Purpose: Do a side by side dump of a buffer, hex dump of buffer bytes on
 *          the left, decoded ASCII on the right.
 *
 * Arguments: fp => ptr to stream to print to
 *            start => pointer to buffer data
 *            len => length of data buffer
 *
 * Returns: void function
 *
 ****************************************************************************/
void PrintNetData(FILE *fp, char *start, const int len)
{
   char *end;              /* ptr to buffer end */
   int i;                  /* counter */
   int j;                  /* counter */
   int dbuf_size;          /* data buffer size */
   int done;               /* flag */
   char *data;             /* index pointer */
   char *frame_ptr;        /* we use 66 byte frames for a printed line */
   char *d_ptr;            /* data pointer into the frame */
   char *c_ptr;            /* char pointer into the frame */
   char conv[] = "0123456789ABCDEF"; /* xlation lookup table */

   /* initialization */
   done = 0;

   if(start == NULL)
   {
      printf("Got NULL ptr in PrintNetData()\n");
      return;
   }

   /* zero, print a <CR> and get out */
   if(!len)
   {
      fputc('\n', fp);
      return;
   }

   /* if we've already prepared this particular data buffer, just print it 
      out again to save time */
   if(dump_ready)
   {
      fwrite(data_dump_buffer, dump_size, 1, fp);
      fflush(fp);
      return;
   }

   end = start + (len-1); /* set the end of buffer ptr */

   if(len > MTU)
   {
      printf("Got bogus buffer length (%X) for PrintNetData, defaulting to 16 bytes!\n", len);
      dbuf_size = 66 + 67;
      end = start + 32;
   }
   else
   {
      /* figure out how big the printout data buffer has to be */
      dbuf_size = ((len/16) * 66) + 67;
   }

   /* generate the buffer */
   data_dump_buffer = (char *) malloc(dbuf_size);

   /* make sure it got allocated properly */   
   if(data_dump_buffer == NULL)
   {
      fprintf(stderr, "Failed allocating %X bytes! (Length: %X)\n", 
              dbuf_size, len);
      perror("PrintNetData()");
      // CleanExit();
   }

   /* clean it out */
   memset(data_dump_buffer, 0x20, dbuf_size);


   /* set the byte buffer pointer to step thru the data buffer */
   data = start;

   /* set the frame pointer to the start of the printout buffer */
   frame_ptr = data_dump_buffer;

   /* loop thru the whole buffer */
   while(!done)
   {
      /* initialize counters and frame index pointers */
      i = 0;
      j = 0;
      d_ptr = frame_ptr;
      c_ptr = (frame_ptr + C_OFFSET);

      /* process 16 bytes per frame */
      for(i=0; i<16; i++)
      {
         /* look up the ASCII value of the first nybble of the 
            current data buffer */
         *d_ptr = conv[((*data&0xFF) >> 4)];
         d_ptr++;

         /* look up the second nybble */
         *d_ptr = conv[((*data&0xFF)&0x0F)];
         d_ptr++;

         /* put a space in between */
         *d_ptr = 0x20;
         d_ptr++;

         /* print out the char equivalent */
         if(*data > 0x1F && *data < 0x7F)
            *c_ptr = (*data&0xFF);
         else
            *c_ptr = 0x2E;

         c_ptr++;
 
         /* increment the pointer or finish up */
         if(data < end)
            data++;
         else
         {
            /* finish up the buffer printout and set the "ready" flags */
            done = 1;
            dump_ready = 1;

            *c_ptr='\n';
            c_ptr++;
            *c_ptr='\n';
            c_ptr++;
            *c_ptr = 0;

            dump_size = (int) (c_ptr - data_dump_buffer);
            fwrite(data_dump_buffer, dump_size, 1, fp);
            return;
         }
      }

      *c_ptr = '\n';
      frame_ptr += FRAME_SIZE;
   }
}



/****************************************************************************
 *
 * Function: PrintIPPkt(FILE *, int, char *, int)
 *
 * Purpose: Dump the packet to the stream pointer
 *
 * Arguments: fp => pointer to print data to
 *            type => packet protocol
 *            data_ptr => pointer to the application layer data
 *            data_len => size of the app layer data
 *
 * Returns: void function
 *
 ****************************************************************************/
void PrintIPPkt(FILE *fp, int type, Packet *p)
{
   char timestamp[23];
   
#ifdef DEBUG
   printf("PrintIPPkt type = %d\n", type);
#endif

   bzero(timestamp, 23);
   ts_print(&p->pkth->timestamp, timestamp);

   /* dump the timestamp */
   fwrite(timestamp, 22, 1, fp);

   /* dump the ethernet header if we're doing that sort of thing */
   if(pv.showeth_flag)
   {
      PrintEthHeader(fp, p);
   }

   /* etc */
   PrintIPHeader(fp, p);

   /*if this isn't a fragment, print the other header info */
   if((p->frag_offset == 0) && (p->mf == 0))
   {
      switch(p->iph->ip_proto)
      {
         case IPPROTO_TCP:
                   PrintTCPHeader(fp, p);
                   break;

         case IPPROTO_UDP:
                   PrintUDPHeader(fp, p);
                   break;

         case IPPROTO_ICMP:
                   PrintICMPHeader(fp, p);
                   break;

         default: break;
      }
   }

   /* dump the application layer data */
   if(pv.data_flag)
      PrintNetData(fp, p->data, p->dsize); 
   else
      fputc('\n', fp);
}




/****************************************************************************
 *
 * Function: OpenAlertFile()
 *
 * Purpose: Set up the file pointer/file for alerting
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ***************************************************************************/
void OpenAlertFile()
{
   char filename[STD_BUF];
   
   // if(!pv.daemon_flag)
      sprintf(filename, "%s/alert", pv.log_dir);
   // else
   //    strncpy(filename, DEFAULT_DAEMON_ALERT_FILE,
   //            strlen(DEFAULT_DAEMON_ALERT_FILE)+1);

#ifdef DEBUG
   printf("Opening alert file: %s\n", filename);
#endif

   if((alert = fopen(filename, "a")) == NULL)
   {
       fprintf(stderr, "ERROR in OpenAlertFile() => fopen() alert file: %s\n",
               strerror(errno));
       exit(1);
   }
} 



/****************************************************************************
 *
 * Function: ClearDumpBuf()
 *
 * Purpose: Clear out the buffer that PrintNetData() generates
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ***************************************************************************/
void ClearDumpBuf()
{
   if(data_dump_buffer != NULL)
      free(data_dump_buffer);

   data_dump_buffer = NULL;

   dump_ready = 0;
}



/****************************************************************************
 *
 * Function: AlertMsg(char *)
 *
 * Purpose: Generate an alert message and send it to the proper place
 *
 * Arguments: msg => the message to send
 *
 * Returns: void function
 *
 ***************************************************************************/
void FullAlert(Packet *p, char *msg)
{
   char timestamp[23];
   
   /* regular logging to the alert file */
   OpenAlertFile();

   if(msg != NULL)
   {
      fwrite("[**] ", 5, 1, alert);
      fwrite(msg, strlen(msg), 1, alert);
      fwrite(" [**]\n", 6, 1, alert);
   }
   else
   {
      fwrite("[**] Snort Alert! [**]", 22, 1, alert);
   }

#ifdef DEBUG
   printf("Logging Alert data!\n");
#endif

   bzero(timestamp, 23);
   ts_print(&p->pkth->timestamp, timestamp);

   /* dump the timestamp */
   fwrite(timestamp, 22, 1, alert);

   /* print the packet header to the alert file */

   if(pv.showeth_flag)
   {
      PrintEthHeader(alert, p);
   }

   PrintIPHeader(alert, p);

   /*if this isn't a fragment, print the other header info */
   if((!p->frag_offset)&&(!p->mf)) 
   {
      switch(p->iph->ip_proto)
      {
         case IPPROTO_TCP:
            PrintTCPHeader(alert, p);
            break;

         case IPPROTO_UDP:
            PrintUDPHeader(alert, p);
            break;

         case IPPROTO_ICMP:
            PrintICMPHeader(alert, p);
            break;

         default: break;
      }
   }

   fputc('\n', alert);
  
   fclose(alert);

   return;
}



/****************************************************************************
 *
 * Function: FastAlert(Packet *, char *)
 *
 * Purpose: Write a minimal alert message to the alert file
 *
 * Arguments: p => pointer to the packet data struct
 *            msg => the message to print in the alert
 *
 * Returns: void function
 *
 ***************************************************************************/
void FastAlert(Packet *p, char *msg)
{
   char timestamp[23];

   if(msg != NULL)
   {
      fwrite("[**] ", 5, 1, alert);
      fwrite(msg, strlen(msg), 1, alert);
      fwrite(" [**]\n", 6, 1, alert);
   }
   
   bzero(timestamp, 23);
   ts_print(&p->pkth->timestamp, timestamp);

   /* dump the timestamp */
   fwrite(timestamp, 22, 1, alert);

   /* print the packet header to the alert file */
   if(p->frag_flag)
   {
      /* just print the straight IP header */
      fputs(inet_ntoa(p->iph->ip_src), alert);
      fwrite(" -> ", 4, 1, alert);
      fputs(inet_ntoa(p->iph->ip_dst), alert);
   }
   else
   {
      if(p->iph->ip_proto == IPPROTO_ICMP)
      {
         /* just print the straight IP header */
         fputs(inet_ntoa(p->iph->ip_src), alert);
         fwrite(" -> ", 4, 1, alert);
         fputs(inet_ntoa(p->iph->ip_dst), alert);
      }
      else
      {
         /* print the header complete with port information */
         fputs(inet_ntoa(p->iph->ip_src), alert);
         fprintf(alert, ":%d -> ", p->sp);
         fputs(inet_ntoa(p->iph->ip_dst), alert);
         fprintf(alert, ":%d", p->dp);
      }
   }

   fputc('\n', alert);

   return;
}




/****************************************************************************
 *
 * Function: SyslogAlert(Packet *, char *)
 *
 * Purpose: Send the current alert to syslog
 *
 * Arguments: p => pointer to the packet data struct
 *            msg => the message to print in the alert
 *
 * Returns: void function
 *
 ***************************************************************************/
void SyslogAlert(Packet *p, char *msg)
{
   char sip[16];
   char dip[16];

   /* have to do this since inet_ntoa is fucked up and writes to 
      a static memory location */
   strncpy(sip, inet_ntoa(p->iph->ip_src), 16);
   strncpy(dip, inet_ntoa(p->iph->ip_dst), 16);

   if(p->iph->ip_proto == IPPROTO_ICMP || p->frag_flag)
   {
      if(msg != NULL)
      {
         /* ICMP packets don't get port info... */
         syslog(LOG_AUTHPRIV|LOG_ALERT, "%s: %s -> %s", msg, 
                sip, dip);
      }
      else
      {
         /* ICMP packets don't get port info... */
         syslog(LOG_AUTHPRIV|LOG_ALERT, "ALERT: %s -> %s",  
                sip, dip);
      }
   }
   else
   {
      if(msg != NULL)
      {
         syslog(LOG_AUTHPRIV|LOG_ALERT, "%s: %s:%i -> %s:%i", msg,
                sip, p->sp, dip, p->dp);
      }
      else
      {
         syslog(LOG_AUTHPRIV|LOG_ALERT, "ALERT: %s:%i -> %s:%i", 
                sip, p->sp, dip, p->dp);
      }
   }

   return;
}

   

/****************************************************************************
 *
 * Function: SmbAlert(Packet *, char *)
 *
 * Purpose: Send the current alert to a waiting WinPopup client
 *
 * Arguments: p => pointer to the packet data struct
 *            msg => the message to print in the alert
 *
 * Returns: void function
 *
 ***************************************************************************/
#ifdef ENABLE_SMB_ALERTS
void SmbAlert(Packet *p, char *msg)
{
   char command_line[2048];
   FILE *output;
   FILE *tempmsg;
   FILE *workstations;
   char workfile[STD_BUF];
   char tempwork[STD_BUF];

#ifdef DEBUG
   printf("Generating SMB alert!\n");
#endif

   /* set the workstation name filename */
   sprintf(workfile, "%s",pv.smbmsg_dir);

   /* erase the old message file */
   unlink("/tmp/.snortmsg");

   /* open the message file and the workstation names file */
   if(((tempmsg = fopen("/tmp/.snortmsg","w")) != NULL) && 
      ((workstations = fopen(workfile,"r")) != NULL))
   {
      /* clear the read buffers */
      bzero(workfile, STD_BUF);

      /* write the alert message into the buffer */
      fwrite("SNORT ALERT - Possible Network Attack or Probe:\n", 48, 1, 
             tempmsg); 
      if(msg != NULL)
      {
         fwrite(" [**] ", 5, 1, tempmsg); 
         fwrite(msg, strlen(msg), 1, tempmsg);
         fwrite(" [**]\n", 6, 1, tempmsg); 
      }

      PrintIPHeader(tempmsg, p);
      fwrite("\nCheck Snort logs for more information.", 39, 1, tempmsg);

      /* close the alert message file */
      fclose(tempmsg);

      bzero(tempwork, STD_BUF);

      /* read in the name of each workstation to send the message to */
      while((fgets(tempwork, STD_BUF-1, workstations)) != NULL)
      {
         /* if the line isn't blank */
         if(tempwork[0] != 0x0A)
         {
            /* chop the <CR> */
            strip(tempwork);

            /* build the command line */
            sprintf(command_line, "cat /tmp/.snortmsg | smbclient -U Snort -M %s", tempwork);

#ifdef DEBUG
            printf("Sending WinPopup alert to: %s\n", tempwork);
            printf("Command Line: %s\n", command_line);
#endif

            /* run the command */
            output = popen(command_line,"r");

            pclose(output);
            bzero(tempwork, STD_BUF);
            bzero(command_line, 2048);
         }
      }

      fclose(workstations);
   }
}
#endif



/****************************************************************************
 *
 * Function: NoAlert(Packet *, char *)
 *
 * Purpose: Don't alert at all
 *
 * Arguments: p => pointer to the packet data struct
 *            msg => the message to not print in the alert
 *
 * Returns: void function
 *
 ***************************************************************************/
void NoAlert(Packet *p, char *msg)
{
   return;
}


/****************************************************************************
 *
 * Function: LogPkt(Packet *)
 *
 * Purpose: Log packets that match one of the Snort rules, plus the rules
 *          message 
 *
 * Arguments: p => pointer to the packet data structure
 *
 * Returns: void function
 *
 ***************************************************************************/
void LogPkt(Packet *p)
{
   OpenLogFile(0, p);
 
   if(otn_tmp->message != NULL)
   {
      fwrite("[**] ", 5, 1, log_ptr);
      fwrite(otn_tmp->message, strlen(otn_tmp->message), 1, log_ptr);
      fwrite(" [**]\n", 6, 1, log_ptr);
   }

   PrintIPPkt(log_ptr, p->iph->ip_proto, p);

   fclose(log_ptr);
}


/****************************************************************************
 *
 * Function: NoLog(Packet *)
 *
 * Purpose: Don't log anything
 *
 * Arguments: p => packet to not log
 *
 * Returns: void function
 *
 ***************************************************************************/
void NoLog(Packet *p)
{
   return;
}


/****************************************************************************
 *
 * Function: PrintEthHeader(FILE *)
 *
 * Purpose: Print the packet Ethernet header to the specified stream
 *
 * Arguments: fp => file stream to print to 
 *
 * Returns: void function
 *
 ***************************************************************************/
void PrintEthHeader(FILE *fp, Packet *p)
{
   /* src addr */
   fprintf(fp, "%X:%X:%X:%X:%X:%X -> ", p->eh->ether_src[0],
           p->eh->ether_src[1], p->eh->ether_src[2], p->eh->ether_src[3],
           p->eh->ether_src[4], p->eh->ether_src[5]);

   /* dest addr */
   fprintf(fp, "%X:%X:%X:%X:%X:%X ", p->eh->ether_dst[0],
           p->eh->ether_dst[1], p->eh->ether_dst[2], p->eh->ether_dst[3],
           p->eh->ether_dst[4], p->eh->ether_dst[5]);

   /* protocol and pkt size */
   fprintf(fp, "type:0x%X len:0x%X\n", ntohs(p->eh->ether_type), p->pkth->pkt_len);
}



/****************************************************************************
 *
 * Function: PrintIPHeader(FILE *)
 *
 * Purpose: Dump the IP header info to the specified stream
 *
 * Arguments: fp => stream to print to
 *
 * Returns: void function
 *
 ***************************************************************************/
void PrintIPHeader(FILE *fp, Packet *p)
{
   if(p->frag_flag)
   {
      /* just print the straight IP header */
      fputs(inet_ntoa(p->iph->ip_src), fp);
      fwrite(" -> ", 4, 1, fp);
      fputs(inet_ntoa(p->iph->ip_dst), fp);
   }
   else
   {
      if(p->iph->ip_proto == IPPROTO_ICMP)
      {
         /* just print the straight IP header */
         fputs(inet_ntoa(p->iph->ip_src), fp);
         fwrite(" -> ", 4, 1, fp);
         fputs(inet_ntoa(p->iph->ip_dst), fp);
      }
      else
      {
         /* print the header complete with port information */
         fputs(inet_ntoa(p->iph->ip_src), fp);
         fprintf(fp, ":%d -> ", p->sp);
         fputs(inet_ntoa(p->iph->ip_dst), fp);
         fprintf(fp, ":%d", p->dp);
      }
   }

   if(!pv.showeth_flag)
   {
      fputc('\n', fp);
   } 
   else
   {
      fputc(' ', fp);
   } 

   fprintf(fp, "%s TTL:%d TOS:0x%X ID:%d ", protocol_names[p->iph->ip_proto], 
           p->iph->ip_ttl, p->iph->ip_tos, ntohs(p->iph->ip_id));

   /* printf more frags/don't frag bits */
   if(p->df)
      fprintf(fp, " DF");

   if(p->mf)
      fprintf(fp, " MF");

   fputc('\n', fp);

   /* print IP options */
   if(p->ip_options[0] != 0)
   {
      fwrite(p->ip_options, 1, strlen(p->ip_options), fp);
   }

   /* print fragment info if necessary */
   if(p->frag_flag)
   {
      fprintf(fp, "Frag Offset: 0x%X   Frag Size: 0x%X", 
              (p->frag_offset & 0xFFFF), p->dsize);
      fputc('\n', fp);
   }
} 



/****************************************************************************
 *
 * Function: PrintTCPHeader(FILE *)
 *
 * Purpose: Dump the TCP header info to the specified stream
 *
 * Arguments: fp => file stream to print data to
 *
 * Returns: void function
 *
 ***************************************************************************/
void PrintTCPHeader(FILE *fp, Packet *p)
{
   /* print TCP flags */
   if(p->tcph->th_flags & TH_SYN) fwrite("S",1,1,fp); else fwrite("*",1,1,fp);
   if(p->tcph->th_flags & TH_FIN) fwrite("F",1,1,fp); else fwrite("*",1,1,fp);
   if(p->tcph->th_flags & TH_RST) fwrite("R",1,1,fp); else fwrite("*",1,1,fp);
   if(p->tcph->th_flags & TH_PUSH) fwrite("P",1,1,fp); else fwrite("*",1,1,fp);
   if(p->tcph->th_flags & TH_ACK) fwrite("A",1,1,fp); else fwrite("*",1,1,fp);
   if(p->tcph->th_flags & TH_URG) fwrite("U",1,1,fp); else fwrite("*",1,1,fp);

   /* if somebody is using the reserved bits in the TCP header flags field... */
   if(p->tcph->th_flags & TH_RES2) fwrite("2",1,1,fp);
   if(p->tcph->th_flags & TH_RES1) fwrite("1",1,1,fp);

   /* print other TCP info */
   fprintf(fp, " Seq: 0x%lX   Ack: 0x%lX   Win: 0x%X\n",
           (u_long)ntohl(p->tcph->th_seq),
           (u_long)ntohl(p->tcph->th_ack), 
           ntohs(p->tcph->th_win));

   /* dump the TCP options */
   if(p->tcp_options[0] != 0)
   {
      fwrite(p->tcp_options, 1, strlen(p->tcp_options), fp);
   }
}


/****************************************************************************
 *
 * Function: PrintUDPHeader(FILE *)
 *
 * Purpose: Dump the UDP header to the specified file stream
 *
 * Arguments: fp => file stream
 *
 * Returns: void function
 *
 ***************************************************************************/
void PrintUDPHeader(FILE *fp, Packet *p)
{
   /* not much to do here... */
   fprintf(fp, "Len: %d\n", ntohs(p->udph->uh_len));
}



/****************************************************************************
 *
 * Function: PrintICMPHeader(FILE *)
 *
 * Purpose: Print ICMP header
 *
 * Arguments: fp => file stream
 *
 * Returns: void function
 *
 ***************************************************************************/
void PrintICMPHeader(FILE *fp, Packet *p)
{
   switch(p->icmph->type)
   {
      case ICMP_ECHOREPLY:
           fprintf(fp, "ID:%d   Seq:%d  ", p->ext->id, p->ext->seqno);
           fwrite("ECHO REPLY\n", 10, 1, fp);
           break;

      case ICMP_DEST_UNREACH:
           fwrite("DESTINATION UNREACHABLE: ", 25, 1, fp); 
           switch(p->icmph->code)
           {
              case ICMP_NET_UNREACH:
                 fwrite("NET UNREACHABLE", 15, 1, fp);
                 break;

              case ICMP_HOST_UNREACH:
                 fwrite("HOST UNREACHABLE", 16, 1, fp);
                 break;

              case ICMP_PROT_UNREACH:
                 fwrite("PROTOCOL UNREACHABLE", 20, 1, fp);
                 break;

              case ICMP_PORT_UNREACH:
                 fwrite("PORT UNREACHABLE", 16, 1, fp);
                 break;

              case ICMP_FRAG_NEEDED:
                 fwrite("FRAGMENTATION NEEDED", 20, 1, fp);
                 break;

              case ICMP_SR_FAILED:
                 fwrite("SOURCE ROUTE FAILED", 19, 1, fp);
                 break;

              case ICMP_NET_UNKNOWN:
                 fwrite("NET UNKNOWN", 11, 1, fp);
                 break;

              case ICMP_HOST_UNKNOWN:
                 fwrite("HOST UNKNOWN", 12, 1, fp);
                 break;

              case ICMP_HOST_ISOLATED:
                 fwrite("HOST ISOLATED", 13, 1, fp);
                 break;

              case ICMP_NET_ANO:
                 fwrite("NET ANO", 7, 1, fp);
                 break;

              case ICMP_HOST_ANO:
                 fwrite("HOST ANO", 8, 1, fp);
                 break;

              case ICMP_NET_UNR_TOS:
                 fwrite("NET UNREACHABLE TOS", 19, 1, fp);
                 break;

              case ICMP_HOST_UNR_TOS:
                 fwrite("HOST UNREACHABLE TOS", 20, 1, fp);
                 break;

              case ICMP_PKT_FILTERED:
                 fwrite("PACKET FILTERED", 15, 1, fp);
                 break;

              case ICMP_PREC_VIOLATION:
                 fwrite("PREC VIOLATION", 14, 1, fp);
                 break;

              case ICMP_PREC_CUTOFF:
                 fwrite("PREC CUTOFF", 12, 1, fp);
                 break;

              default:
                 fwrite("UNKNOWN", 7, 1, fp);
                 break;

            }

            break;

      case ICMP_SOURCE_QUENCH:
           fwrite("SOURCE QUENCH", 13, 1, fp);
           break;

      case ICMP_REDIRECT:
           fwrite("REDIRECT", 8, 1, fp);
           break;
      case ICMP_ECHO:
           fprintf(fp, "ID:%d   Seq:%d  ", p->ext->id, p->ext->seqno);
           fwrite("ECHO\n", 4, 1, fp);
           break;

      case ICMP_TIME_EXCEEDED:
           fwrite("TTL EXCEEDED", 12, 1, fp);
           break;

      case ICMP_PARAMETERPROB:
           fwrite("PARAMETER PROBLEM", 17, 1, fp);
           break;

      case ICMP_TIMESTAMP:
           fwrite("TIMESTAMP REQUEST", 17, 1, fp);
           break;

      case ICMP_TIMESTAMPREPLY:
           fwrite("TIMESTAMP REPLY", 15, 1, fp);
           break;

      case ICMP_INFO_REQUEST:
           fwrite("INFO REQUEST", 12, 1, fp);
           break;

      case ICMP_INFO_REPLY:
           fwrite("INFO REPLY", 10, 1, fp);
           break;

      case ICMP_ADDRESS:
           fwrite("ADDRESS REQUEST", 15, 1, fp);
           break;

      case ICMP_ADDRESSREPLY:
           fwrite("ADDRESS REPLY", 13, 1, fp);
           break;
      
      default:
           fwrite("UNKNOWN", 7, 1, fp);
           break;
   }

   putc('\n', fp);

}
 


/****************************************************************************
 *
 * Function: LogBin()
 *
 * Purpose: Log packets in binary (tcpdump) format
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ***************************************************************************/
void LogBin(Packet *p)
{
   /* sizeof(struct pcap_pkthdr) = 16 bytes */
   fwrite(p->pkth, 16, 1, binlog_ptr);
   fwrite(p->eh, p->pkth->data_len, 1, binlog_ptr);
}




/****************************************************************************
 *
 * Function: IcmpFileName(Packet *p)
 *
 * Purpose: Set the filename of an ICMP output log according to its type
 *
 * Arguments: p => Packet data struct
 *
 * Returns: the name of the file to set
 *
 ***************************************************************************/
char *IcmpFileName(Packet *p)
{
   switch(p->icmph->type)
   {
      case ICMP_ECHOREPLY:
         return "ECHO_REPLY";

      case ICMP_DEST_UNREACH:
         switch(p->icmph->code)
         {
            case ICMP_NET_UNREACH:
               return "NET_UNRCH";

            case ICMP_HOST_UNREACH:
               return "HST_UNRCH";

            case ICMP_PROT_UNREACH:
               return "PROTO_UNRCH";

            case ICMP_PORT_UNREACH:
               return "PORT_UNRCH";

            case ICMP_FRAG_NEEDED:
               return "UNRCH_FRAG_NEEDED";

            case ICMP_SR_FAILED:
               return "UNRCH_SOURCE_ROUTE_FAILED";

            case ICMP_NET_UNKNOWN:
               return "UNRCH_NETWORK_UNKNOWN";

            case ICMP_HOST_UNKNOWN:
               return "UNRCH_HOST_UNKNOWN";

            case ICMP_HOST_ISOLATED:
               return "UNRCH_HOST_ISOLATED";

            case ICMP_NET_ANO:
               return "UNRCH_NET_ANO";

            case ICMP_HOST_ANO:
               return "UNRCH_HOST_ANO";

            case ICMP_NET_UNR_TOS:
               return "UNRCH_NET_UNR_TOS";

            case ICMP_HOST_UNR_TOS:
               return "UNRCH_HOST_UNR_TOS";

            case ICMP_PKT_FILTERED:
               return "UNRCH_PACKET_FILT";

            case ICMP_PREC_VIOLATION:
               return "UNRCH_PREC_VIOL";

            case ICMP_PREC_CUTOFF:
               return "UNRCH_PREC_CUTOFF";

            default:
               return "UNKNOWN";

         }

      case ICMP_SOURCE_QUENCH:
         return "SRC_QUENCH";

      case ICMP_REDIRECT:
         return "REDIRECT";

      case ICMP_ECHO:
         return "ECHO";

      case ICMP_TIME_EXCEEDED:
         return "TTL_EXCEED";

      case ICMP_PARAMETERPROB:
         return "PARAM_PROB";

      case ICMP_TIMESTAMP:
         return "TIMESTAMP";

      case ICMP_TIMESTAMPREPLY:
         return "TIMESTAMP_RPL";

      case ICMP_INFO_REQUEST:
         return "INFO_REQ";

      case ICMP_INFO_REPLY:
         return "INFO_RPL";

      case ICMP_ADDRESS:
         return "ADDR";

      case ICMP_ADDRESSREPLY:
         return "ADDR_RPL";
      
      default:
         return "UNKNOWN";
   }
}



// /****************************************************************************
//  *
//  * Function: InitLogFile()
//  *
//  * Purpose: Initialize the tcpdump log file header
//  *
//  * Arguments: None.
//  *
//  * Returns: void function
//  *
//  ***************************************************************************/
// void InitLogFile()
// {
//    struct pcap_file_header pfh;
//    char logdir[STD_BUF];

//    bzero(logdir, STD_BUF);

//    sprintf(logdir,"%s/snort.log", pv.log_dir);

// #ifdef DEBUG
//    printf("Opening %s\n", logdir);
// #endif

//    /* overwrites the last frag file */
//    if((binlog_ptr = fopen(logdir, "w")) == NULL)
//    {
//       perror("InitBinFrag()");
//       exit(1);
//    }

//    /* set to tcpdump defaults */
// #ifndef WORDS_BIGENDIAN
//    pfh.magic = 0xa1b2c3d4;
// #else
//    pfh.magic = 0xc3d4a1b2;
// #endif

//    pfh.version_major = 2;
//    pfh.version_minor = 4;
//    pfh.thiszone = 0;
//    pfh.sigfigs = 6;
//    pfh.snaplen = MTU;
//    pfh.linktype = 1;

//    /* write out the file header */
//    fwrite(&pfh, sizeof(struct pcap_file_header), 1, binlog_ptr);

// #ifdef DEBUG
//    printf("Binfrag log file initialized\n");
// #endif

//    return;
// }

