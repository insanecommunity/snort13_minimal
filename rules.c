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

#include "rules.h"

ListHead Alert;      /* Alert Block Header */
ListHead Log;        /* Log Block Header */
ListHead Pass;       /* Pass Block Header */

RuleTreeNode *rtn_tmp;  /* temp data holder */
OptTreeNode *otn_tmp;   /* OptTreeNode temp ptr */

int file_line;      /* current line being processed in the rules file */
int rule_count;     /* number of rules generated */
int head_count;     /* number of header blocks (chain heads?) */
int opt_count;      /* number of chains */

#ifdef BENCHMARK
int check_count;    /* number of tests for a given rule to determine a match */
int cmpcount;       /* compare counter */
#endif

/****************************************************************************
 *
 * Function: ParseRulesFile(char *)
 *
 * Purpose:  Read the rules file a line at a time and send each rule to
 *           the rule parser
 *
 * Arguments: file => rules file filename
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseRulesFile(char *file)
{
   FILE *thefp;       /* file pointer for the rules file */
   char buf[STD_BUF]; /* file read buffer */

#ifdef DEBUG
   printf("Opening rules file: %s\n", file);
#endif
   printf("\n+++++++++++++++++++++++++++++++++++++++++++++++++++\n");
   printf("Initializing rule chains...\n");

   /* open the rules file */
   if((thefp = fopen(file,"r")) == NULL)
   {
      printf("Unable to open rules file: %s\n", file);
      exit(1);
   }

   /* clear the line buffer */
   bzero(buf, STD_BUF);

   /* loop thru each file line and send it to the rule parser */
   while((fgets(buf, STD_BUF, thefp)) != NULL)
   {
      /* inc the line counter so the error messages know which line to 
         bitch about */
      file_line++;

#ifdef DEBUG2
      printf("Got line %d: %s", file_line, buf);
#endif
      /* if it's not a comment or a <CR>, send it to the parser */
      if((buf[0] != '#') && (buf[0] != 0x0a) && (buf[0] != ';'))
      {
         ParseRule(buf);
      }

      bzero(buf, STD_BUF);
   }

   printf("%d Snort rules read...\n", rule_count);
   printf("%d Option Chains linked into %d Chain Headers\n", opt_count, head_count);
   printf("+++++++++++++++++++++++++++++++++++++++++++++++++++\n\n");

   fclose(thefp);

#ifdef DEBUG
   DumpChain(Alert.TcpList, "Alert TCP Chains");
   DumpChain(Alert.UdpList, "Alert UDP Chains");
   DumpChain(Alert.IcmpList, "Alert ICMP Chains");


   DumpChain(Log.TcpList, "Log TCP Chains");
   DumpChain(Log.UdpList, "Log UDP Chains");
   DumpChain(Log.IcmpList, "Log ICMP Chains");


   DumpChain(Pass.TcpList, "Pass TCP Chains");
   DumpChain(Pass.UdpList, "Pass UDP Chains");
   DumpChain(Pass.IcmpList, "Pass ICMP Chains");
#endif

   return;
}



/****************************************************************************
 *
 * Function: ParseRule(char *)
 *
 * Purpose:  Process an individual rule and add it to the rule list
 *
 * Arguments: rule => rule string
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseRule(char *rule)
{
   char **toks;          /* dbl ptr for mSplit call, holds rule tokens */
   int num_toks;         /* holds number of tokens found by mSplit */
   int rule_type;        /* rule type enumeration variable */
   int protocol;
   RuleTreeNode proto_node;

   /* clean house */
   bzero(&proto_node, sizeof(RuleTreeNode));

   /* chop off the <CR/LF> from the string */
   strip(rule);

   /* break out the tokens from the rule string */
   toks = mSplit(rule, " ", 10, &num_toks,0);

   /* figure out what we're looking at */
   rule_type = RuleType(toks[0]);

   /* set the rule protocol */
   protocol = WhichProto(toks[1]);

#ifdef DEBUG
      printf("[*] Rule start\n");
#endif

   /* Process the IP address and CIDR netmask */
   /* changed version 1.2.1 */
   /* "any" IP's are now set to addr 0, netmask 0, and the normal rules are 
      applied instead of checking the flag */
   /* if we see a "!<ip number>" we need to set a flag so that we can properly        
      deal with it when we are processing packets */
   if(*toks[2]=='!')  /*we found a negated address*/
   {
      proto_node.flags |= EXCEPT_SRC_IP;
      ParseIP(&toks[2][1], (u_long *) &proto_node.sip, (u_long *) &proto_node.smask);
   }
   else
   {
      ParseIP(toks[2], (u_long *) &proto_node.sip, (u_long *) &proto_node.smask);
   }

   /* do the same for the port */
   if(ParsePort(toks[3], (u_short *) &proto_node.hsp, 
               (u_short *) &proto_node.lsp, toks[1], 
               (int *) &proto_node.not_sp_flag))
   {
      proto_node.flags |= ANY_SRC_PORT;
   }

   if(proto_node.not_sp_flag)
      proto_node.flags |= EXCEPT_SRC_PORT;

   /* New in version 1.3: support for bidirectional rules */
   /* this checks the rule "direction" token and sets the bidirectional
      flag if the token = '<>' */
   if(!strncmp("<>", toks[4], 2))
   {
      printf("Bidirectional rule!\n");
      proto_node.flags |= BIDIRECTIONAL;
   }

   /* changed version 1.2.1 */
   /* "any" IP's are now set to addr 0, netmask 0, and the normal rules are
       applied instead of checking the flag */
   /* if we see a "!<ip number>" we need to set a flag so that we can properly        
      deal with it when we are processing packets */
   if(*toks[5]=='!')  /*we found a negated address*/
   {
#ifdef DEBUG
      printf("setting exception flag for dest IP\n");
#endif
      proto_node.flags |= EXCEPT_DST_IP;
      ParseIP(&toks[5][1], (u_long *) &proto_node.dip, (u_long *) &proto_node.dmask);
   }
   else
      ParseIP(toks[5], (u_long *) &proto_node.dip, (u_long *) &proto_node.dmask);

   if(ParsePort(toks[6], (u_short *) &proto_node.hdp, 
                (u_short *) &proto_node.ldp, toks[1], 
                 (int *) &proto_node.not_dp_flag))
   {
      proto_node.flags |= ANY_DST_PORT;
   }
      
   if(proto_node.not_dp_flag)
      proto_node.flags |= EXCEPT_DST_PORT;

#ifdef DEBUG
   printf("proto_node.flags = 0x%X\n", proto_node.flags);
#endif

   switch(rule_type)
   {
      case RULE_ALERT:
         ProcessHeadNode(&proto_node, &Alert, protocol); 
         break;

      case RULE_LOG:
         ProcessHeadNode(&proto_node, &Log, protocol); 
         break;

      case RULE_PASS:
         ProcessHeadNode(&proto_node, &Pass, protocol); 
         break;
   }

   rule_count++;
   ParseRuleOptions(rule, rule_type);

   free(toks);

   return;
}


/****************************************************************************
 *
 * Function: ProcessHeadNode(RuleTreeNode *, ListHead *, int)
 *
 * Purpose:  Process the header block info and add to the block list if 
 *           necessary
 *
 * Arguments: test_node => data generated by the rules parsers
 *            list => List Block Header refernece
 *            protocol => ip protocol
 *
 * Returns: void function
 *
 ***************************************************************************/
void ProcessHeadNode(RuleTreeNode *test_node, ListHead *list, int protocol)
{
   int match = 0;
   RuleTreeNode *rtn_idx;
   int count = 0;

   /* select the proper protocol list to attach the current rule to */
   switch(protocol)
   {
      case IPPROTO_TCP:
            rtn_idx =  list->TcpList; 
            break;

      case IPPROTO_UDP:
            rtn_idx =  list->UdpList; 
            break;

      case IPPROTO_ICMP:
            rtn_idx =  list->IcmpList; 
            break;

      default: rtn_idx = NULL;
             break;
   }

   /* if the list head is NULL (empty), make a new one and attach the ListHead to it */
   if(rtn_idx == NULL)
   {
      head_count++;

      switch(protocol)
      {
      case IPPROTO_TCP:
            list->TcpList = (RuleTreeNode *) calloc(sizeof(RuleTreeNode), sizeof(char)); 
            rtn_tmp = list->TcpList;
            break;

      case IPPROTO_UDP:
            list->UdpList = (RuleTreeNode *) calloc(sizeof(RuleTreeNode), sizeof(char)); 
            rtn_tmp = list->UdpList;
            break;

      case IPPROTO_ICMP:
            list->IcmpList = (RuleTreeNode *) calloc(sizeof(RuleTreeNode), sizeof(char)); 
            rtn_tmp = list->IcmpList;
            break;
      }

      /* copy the prototype header data into the new node */
      XferHeader(test_node, rtn_tmp);

      rtn_tmp->head_node_number = head_count; 

      /* null out the down (options) pointer */
      rtn_tmp->down = NULL;

      return;
   }

   /* see if this prototype node matches any of the existing header nodes */
   match = TestHeader(rtn_idx,test_node);

   while((rtn_idx->right != NULL) && !match)
   {
      count++;
      match = TestHeader(rtn_idx,test_node);

      if(!match)
         rtn_idx = rtn_idx->right;
      else
         break;
   }

   match = TestHeader(rtn_idx,test_node);

   /* if it doesn't match any of the existing nodes, make a new node and stick
      it at the end of the list */
   if(!match)
   {
#ifdef DEBUG
      printf("Building New Chain head node\n");
#endif

      head_count++;

      /* build a new node */
      rtn_idx->right = (RuleTreeNode *) calloc(sizeof(RuleTreeNode), sizeof(char));
   
      /* set the global ptr so we can play with this from anywhere */
      rtn_tmp = rtn_idx->right;

      /* uh oh */
      if(rtn_tmp == NULL)
      {
         fprintf(stderr, "ERROR: Unable to allocate Rule Head Node!!\n");
         exit(1);
      }

      /* copy the prototype header info into the new header block */
      XferHeader(test_node, rtn_tmp);

      rtn_tmp->head_node_number = head_count; 
      rtn_tmp->down = NULL;
#ifdef DEBUG
      printf("New Chain head flags = 0x%X\n", rtn_tmp->flags); 
#endif
   }
   else
   {
      rtn_tmp = rtn_idx;
#ifdef DEBUG
      printf("Chain head %d  flags = 0x%X\n", count, rtn_tmp->flags); 
#endif

#ifdef DEBUG
   printf("Adding options to chain head %d\n", count);
#endif
   }
}


/****************************************************************************
 *
 * Function: ParseRuleOptions(char *, int)
 *
 * Purpose:  Process an individual rule's options and add it to the 
 *           appropriate rule chain
 *
 * Arguments: rule => rule string
 *            rule_type => enumerated rule type (alert, pass, log)
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseRuleOptions(char *rule, int rule_type)
{
   char **toks = NULL;
   char **opts;
   char *idx;
   char *aux;
   int num_toks;
   int i;
   int num_opts;
   OptTreeNode *otn_idx;

   /* set the OTN to the beginning of the list */
   otn_idx = rtn_tmp->down;

   /* make a new one and stick it either at the end of the list or 
      hang it off the RTN pointer */
   if(otn_idx != NULL)
   {
      /* loop to the end of the list */
      while(otn_idx->next != NULL)
      {
         otn_idx = otn_idx->next;
      }

      /* setup the new node */
      otn_idx->next = (OptTreeNode *) malloc(sizeof(OptTreeNode));

      /* set the global temp ptr */
      otn_tmp = otn_idx->next;

      if(otn_tmp == NULL)
      {
         perror("ERROR: Unable to alloc OTN!");
         exit(1);
      }

      otn_tmp->next = NULL;
      opt_count++;

   }
   else
   {
      /* first entry on the chain, make a new node and attach it */
      otn_idx = (OptTreeNode *) malloc(sizeof(OptTreeNode));
      bzero(otn_idx, sizeof(OptTreeNode));

      otn_tmp = otn_idx;
      if(otn_tmp == NULL)
      {
         fprintf(stderr, "ERROR: Unable to alloc OTN!\n");
         exit(1);
      }
      otn_tmp->next = NULL;
      rtn_tmp->down = otn_tmp;
      opt_count++;
   }

   otn_tmp->chain_node_number = opt_count;
   otn_tmp->type = rule_type;

   /* find the start of the options block */
   idx = index(rule, '(');
   i = 0;

   if(idx != NULL)
   {
      idx++;
     
      /* find the end of the options block */
      aux = strrchr(idx,')');

      *aux = 0;


      /* seperate all the options out, the seperation token is a semicolon */
      /* NOTE: if you want to include a semicolon in the content of your rule,
         it must be preceeded with a '\' */
      toks = mSplit(idx, ";", 10, &num_toks,'\\');

#ifdef DEBUG
      printf("   Got %d tokens\n", num_toks);
#endif
      /* decrement the number of toks */
      num_toks--;

      while(num_toks)
      {
#ifdef DEBUG
         printf("   option: %s\n", toks[i]);
#endif

         /* break out the option name from its data */
         opts = mSplit(toks[i], ":", 4, &num_opts,'\\');
         
#ifdef DEBUG
         printf("   option name: %s\n", opts[0]);
         printf("   option args: %s\n", opts[1]);
#endif
      
         /* advance to the beginning of the data (past the whitespace) */
         while(isspace((int)*opts[0])) opts[0]++;

         /* figure out which option tag we're looking at */
	 if(!strcasecmp(opts[0], "content"))
         {
	    ParsePattern(opts[1]);
	 }
         else if(!strcasecmp(opts[0], "msg"))
	 {
            ParseMessage(opts[1]);
         }
         else if(!strcasecmp(opts[0], "flags"))
         {
            ParseFlags(opts[1]);
         }
         else if(!strcasecmp(opts[0], "ttl"))
         {
            aux = opts[1];
            while(isspace((int)*aux)) aux++;
            otn_tmp->ttl = atoi(opts[1]);
#ifdef DEBUG
            printf("Set TTL to %d\n", otn_tmp->ttl);
#endif
         }
         else if(!strcasecmp(opts[0], "itype"))
         {
            ParseItype(opts[1]);
         }
         else if(!strcasecmp(opts[0], "icode"))
         {
            ParseIcode(opts[1]);
         }
         else if(!strcasecmp(opts[0], "minfrag"))
         {
            aux = opts[1];
            while(isspace((int)*aux)) aux++;
            otn_tmp->min_frag = atoi(opts[1]);
#ifdef DEBUG
            printf("Minfrag set to %d\n", otn_tmp->min_frag);
#endif
         }
         else if(!strcasecmp(opts[0], "ack")) 
         {
            aux = opts[1];
            while(isspace((int)*aux)) aux++;
            otn_tmp->tcp_ack = atoi(opts[1]);
            otn_tmp->check_ack = 1;
#ifdef DEBUG
            printf("Ack set to %lX\n", otn_tmp->tcp_ack);
#endif
         }
         else if(!strcasecmp(opts[0], "seq")) 
         {
            aux = opts[1];
            while(isspace((int)*aux)) aux++;
            otn_tmp->tcp_seq = atoi(opts[1]);
            otn_tmp->check_seq = 1;
#ifdef DEBUG
            printf("Seq set to %lX\n", otn_tmp->tcp_seq);
#endif
         }
         else if(!strcasecmp(opts[0], "id")) 
         {
            aux = opts[1];
            while(isspace((int)*aux)) aux++;
            otn_tmp->ip_id = atoi(opts[1]);
            otn_tmp->check_ip_id = 1;
#ifdef DEBUG
            printf("ID set to %ld\n", otn_tmp->ip_id);
#endif
         }
         else if(!strcasecmp(opts[0], "logto"))
         {
            ParseLogto(opts[1]); 
         }
         else if(!strcasecmp(opts[0], "dsize"))
         {
            aux = opts[1];
            while(isspace((int)*aux)) aux++;
            otn_tmp->dsize = atoi(aux);
            otn_tmp->check_dsize = 1;
#ifdef DEBUG
            printf("Payload length = %ld\n", otn_tmp->dsize);
#endif
         }
         else if(!strcasecmp(opts[0], "offset"))
         {
            aux = opts[1];
            while(isspace((int)*aux)) aux++;
            otn_tmp->offset= atoi(aux);
#ifdef DEBUG
            printf("Pattern offset = %ld\n", otn_tmp->offset);
#endif
         }
         else if(!strcasecmp(opts[0], "depth"))
         {
            aux = opts[1];
            while(isspace((int)*aux)) aux++;
            otn_tmp->depth= atoi(aux);
            if(otn_tmp->depth < otn_tmp->pattern_size)
            {
               fprintf(stderr, "ERROR Line %d => Rule depth is smaller than the pattern size!\n", file_line);
               exit(1);
            }
#ifdef DEBUG
            printf("Pattern search depth = %ld\n", otn_tmp->depth);
#endif
         }


         free(opts);
	 --num_toks;
	 i++;
      }
   }

   if((otn_tmp->depth || otn_tmp->offset) && !otn_tmp->pattern_match_flag)
   {
      fprintf(stderr, "ERROR Line %d => no pattern specified for depth or offset, RTFM!\n", file_line);
      exit(1);
   }

   free(toks);
}


/****************************************************************************
 *
 * Function: RuleType(char *)
 *
 * Purpose:  Determine what type of rule is being processed and return its
 *           equivalent value
 *
 * Arguments: func => string containing the rule type
 *
 * Returns: The rule type designation
 *
 ***************************************************************************/
int RuleType(char *func)
{
   if(!strncasecmp(func, "log",3))
      return RULE_LOG;

   if(!strncasecmp(func, "alert",5))
      return RULE_ALERT;

   if(!strncasecmp(func, "pass",4))
      return RULE_PASS;

   
   printf("ERROR line %d => Unknown Rule action: %s\n", file_line, func);
   CleanExit();
  
   return 0;
}

      

/****************************************************************************
 *
 * Function: WhichProto(char *)
 *
 * Purpose: Figure out which protocol the current rule is talking about
 *
 * Arguments: proto_str => the protocol string
 *
 * Returns: The integer value of the protocol
 *
 ***************************************************************************/
int WhichProto(char *proto_str)
{
   if(!strncasecmp(proto_str, "tcp", 3))
      return IPPROTO_TCP;

   if(!strncasecmp(proto_str, "udp", 3))
      return IPPROTO_UDP;

   if(!strncasecmp(proto_str, "icmp", 4))
      return IPPROTO_ICMP;

   fprintf(stderr, "ERROR Line %d => Bad protocol: %s\n", file_line, proto_str);
   exit(1);
}


/****************************************************************************
 *
 * Function: ParseIP(char *, u_long *, u_long *)
 *
 * Purpose: Convert a supplied IP address to it's network order 32-bit long
           value.  Also convert the CIDR block notation into a real 
 *          netmask. 
 *
 * Arguments: addr => address string to convert
 *            ip_addr => storage point for the converted ip address
 *            netmask => storage point for the converted netmask
 *
 * Returns: 0 for normal addresses, 1 for an "any" address
 *
 ***************************************************************************/
int ParseIP(char *addr, u_long *ip_addr, u_long *netmask)
{
   char **toks;                /* token dbl buffer */
   int num_toks;               /* number of tokens found by mSplit() */
   int nmask;                  /* netmask temporary storage */
   struct hostent *host_info;  /* various struct pointers for stuff */
   struct sockaddr_in sin;     /* addr struct */

   /* check for wildcards */
   if(!strncasecmp(addr, "any", 3))
   {
      *ip_addr = 0;
      *netmask = 0;
      return 1;
   }
 
   /* break out the CIDR notation from the IP address */
   toks = mSplit(addr,"/",2,&num_toks,0);

   if(num_toks != 2)
   {
      fprintf(stderr, "ERROR Line %d => No netmask specified for IP address %s\n", file_line, addr);
      exit(1);
   }

   /* convert the CIDR notation into a real live netmask */
   nmask = atoi(toks[1]);

   if((nmask > 0)&&(nmask < 33))
   {
      *netmask = netmasks[nmask];
   }
   else
   {
      fprintf(stderr, "ERROR Line %d => Invalid CIDR block for IP addr %s\n", file_line, addr);
      exit(1);
   }

#ifndef WORDS_BIGENDIAN
   /* since PC's store things the "wrong" way, shuffle the bytes into
      the right order */
   *netmask = htonl(*netmask);
#endif

   /* convert names to IP addrs */
   if(isalpha((int)toks[0][0]))
   {
      /* get the hostname and fill in the host_info struct */
      if((host_info = gethostbyname(toks[0])))
      {
         bcopy(host_info->h_addr, (char *)&sin.sin_addr, host_info->h_length);
      }
      else if((sin.sin_addr.s_addr = inet_addr(toks[0])) == INADDR_NONE)
      {
         fprintf(stderr,"ERROR Line %d => Couldn't resolve hostname %s\n", 
                 file_line, toks[0]);
         exit(1);
      }

      *ip_addr = ((u_long)(sin.sin_addr.s_addr) & (*netmask));
      return 1;
   }

   /* convert the IP addr into its 32-bit value */
   if((*ip_addr = inet_addr(toks[0])) == -1)
   {
      fprintf(stderr, "ERROR Line %d => Rule IP addr (%s) didn't x-late, WTF?\n",
              file_line, toks[0]);
      exit(0);
   }
   else
   {
      /* set the final homenet address up */
      *ip_addr = ((u_long)(*ip_addr) & (*netmask));
   }

   free(toks);

   return 0;
}



/****************************************************************************
 *
 * Function: ParsePort(char *, u_short *)
 *
 * Purpose:  Convert the port string over to an integer value
 *
 * Arguments: rule_port => port string
 *            port => converted integer value of the port
 *
 * Returns: 0 for a normal port number, 1 for an "any" port
 *
 ***************************************************************************/
int ParsePort(char *rule_port, u_short *hi_port, u_short *lo_port, char *proto, int *not_flag)
{
   char **toks;                /* token dbl buffer */
   int num_toks;               /* number of tokens found by mSplit() */

   *not_flag = 0;

   /* check for wildcards */
   if(!strncasecmp(rule_port, "any", 3))
   {
      *hi_port = 0;
      *lo_port = 0;
      return 1;
   }

   if(rule_port[0] == '!')
   {
      *not_flag = 1;
      rule_port++;
   }

   if(rule_port[0] == ':')
   {
      *lo_port = 0;
   }

   toks = mSplit(rule_port, ":", 2, &num_toks,0);

   switch(num_toks)
   {
      case 1:
              *hi_port = ConvPort(toks[0], proto);

              if(rule_port[0] == ':')
              {
                 *lo_port = 0;
              }
              else
              {
                 *lo_port = *hi_port;

                 if(index(rule_port, ':') != NULL)
                 {
                    *hi_port = 65535;
                 }
              }

              return 0;

      case 2:
              *lo_port = ConvPort(toks[0], proto);

              if(toks[1][0] == 0)
                 *hi_port = 65535;
              else
                 *hi_port = ConvPort(toks[1], proto);

              return 0;

      default:
               fprintf(stderr, "ERROR Line %d => port conversion failed on \"%s\"\n",
                       file_line, rule_port);
               exit(1);
   }             

   return 0;
}


/****************************************************************************
 *       
 * Function: ConvPort(char *, char *)
 *    
 * Purpose:  Convert the port string over to an integer value
 * 
 * Arguments: port => port string
 *            proto => converted integer value of the port
 *
 * Returns:  the port number
 *
 ***************************************************************************/
int ConvPort(char *port, char *proto)
{
   int conv;  /* storage for the converted number */
   struct servent *service_info;

   /* convert a "word port" (http, ftp, imap, whatever) to its
      corresponding numeric port value */
   if(isalpha((int)port[0]) != 0)
   {
      service_info = getservbyname(port, proto);
 
      if(service_info != NULL)
      {
         conv = ntohs(service_info->s_port);
         return conv; 
      }
      else
      {
         fprintf(stderr, "ERROR Line %d => getservbyname() failed on \"%s\"\n",
                 file_line, port);
         exit(1);
      }
   }

   if(!isdigit((int)port[0]))
   {
      fprintf(stderr, "ERROR Line %d => Invalid port: %s\n", file_line, port);
      exit(1);
   }  
   
   /* convert the value */
   conv = atoi(port);
   
   /* make sure it's in bounds */
   if((conv >= 0) && (conv < 65536))
   {
      return conv;
   }
   else
   {
      fprintf(stderr, "ERROR Line %d => bad port number: %s", file_line, port);
      exit(1);
   }
}
 






/****************************************************************************
 *
 * Function: ParsePattern(char *)
 *
 * Purpose: Process the application layer patterns and attach them to the
 *          appropriate rule.  My god this is ugly code.
 *
 * Arguments: rule => the rule string 
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParsePattern(char *rule)
{
   u_char tmp_buf[2048];
 
   /* got enough ptrs for you? */
   char *start_ptr;
   char *end_ptr;
   char *idx;
   char *dummy_idx;
   char *dummy_end;
   char hex_buf[9];
   u_int dummy_size = 0;
   unsigned int size;
   int hexmode = 0;
   int hexsize = 0;
   int pending = 0;
   int cnt = 0;
   int literal = 0;

   /* clear out the temp buffer */
   bzero(tmp_buf, 2048);

   /* find the start of the data */
   start_ptr = index(rule,'"');

   if(start_ptr == NULL)
   {
      fprintf(stderr, "ERROR Line %d => Content data needs to be enclosed in quotation marks (\")!\n", file_line);
      exit(1);
   }

   /* move the start up from the beggining quotes */
   start_ptr++;
   
   /* find the end of the data */
   end_ptr = strrchr(start_ptr, '"');

   if(end_ptr == NULL)
   {
      fprintf(stderr, "ERROR Line %d => Content data needs to be enclosed in quotation marks (\")!\n", file_line);
      exit(1);
   }

   /* set the end to be NULL */
   *end_ptr = 0;

   /* how big is it?? */
   size = end_ptr - start_ptr;
   
   /* uh, this shouldn't happen */
   if(size <= 0)
   {
      fprintf(stderr, "ERROR Line %d => Bad pattern length!\n", file_line);
      exit(1);
   }

   /* set all the pointers to the appropriate places... */
   idx = start_ptr;

   /* set the indexes into the temp buffer */
   dummy_idx = tmp_buf;
   dummy_end = (dummy_idx + size);

   /* why is this buffer so small? */
   bzero(hex_buf, 9);
   memset(hex_buf, '0', 8);

   /* BEGIN BAD JUJU..... */
   while(idx < end_ptr)
   {
#ifdef DEBUG
      printf("processing char: %c\n", *idx);
#endif
      switch(*idx)
      {
         case '|':
#ifdef DEBUG
               printf("Got bar... ");
#endif
               if(!literal)
               {
#ifdef DEBUG
                  printf("not in literal mode... ");
#endif
                  if(!hexmode)
                  {
#ifdef DEBUG
                     printf("Entering hexmode\n");
#endif
                     hexmode = 1;
                  }
                  else
                  {
#ifdef DEBUG
                     printf("Exiting hexmode\n");
#endif
                     hexmode = 0;
                  }

                  if(hexmode)
                     hexsize = 0;
               }
               else
               {
#ifdef DEBUG
                  printf("literal set, Clearing\n");
#endif
                  literal = 0;
                  tmp_buf[dummy_size] = start_ptr[cnt];
                  dummy_size++;
               }

               break;

         case '\\':
#ifdef DEBUG
               printf("Got literal char... ");
#endif
               if(!literal)
               {
#ifdef DEBUG
                  printf("Setting literal\n");
#endif
                  literal = 1;
               }
               else
               {
#ifdef DEBUG
                  printf("Clearing literal\n");
#endif
                  tmp_buf[dummy_size] = start_ptr[cnt];
                  literal = 0;
                  dummy_size++;
               }

               break;

         default:
               if(hexmode)
               {
                  if(isxdigit((int)*idx))
                  {
                     hexsize++;

                     if(!pending)
                     {
                        hex_buf[7] = *idx;
                        pending++;
                     }
                     else
                     {
                        hex_buf[8] = *idx;
                        pending--;

                        if(dummy_idx < dummy_end)
                        {
                           tmp_buf[dummy_size] = (u_long) strtol(hex_buf, (char **)NULL, 16);

                           dummy_size++;
                           bzero(hex_buf, 9);
                           memset(hex_buf, '0', 8);
                        }
                        else
                        {
                           fprintf(stderr, "ERROR => ParsePattern() dummy buffer overflow, make a smaller pattern please! (Max size = 2048)\n");
                           exit(1);
                        }
                     }
                  }
                  else
                  {
                     if(*idx != ' ')
                     {
                        fprintf(stderr, "ERROR Line %d => What is this \"%c\"(0x%X) doing in your binary buffer?  Valid hex values only please! (0x0 - 0xF) Position: %d\n", file_line, (char) *idx, (char) *idx, cnt);
                        exit(1);
                     }
                  }
               }
               else
               {
                  if(*idx >= 0x1F && *idx <= 0x7e)
                  {
                     if(dummy_idx < dummy_end)
                     {
                        tmp_buf[dummy_size] = start_ptr[cnt];
                        dummy_size++;
                     }
                     else
                     {
                        fprintf(stderr, "ERROR Line %d=> ParsePattern() dummy buffer overflow!\n", file_line);
                        exit(1);
                     }

                     if(literal)
                     {
                        literal = 0;
                     }
                  }
	          else
	          {
                     if(literal)
                     {
                        tmp_buf[dummy_size] = start_ptr[cnt];
                        dummy_size++;
#ifdef DEBUG
                        printf("Clearing literal\n");
#endif
                        literal = 0;
                     }
                     else
                     {
                        fprintf(stderr, "ERROR Line %d=> character value out of range, try a binary buffer dude\n", file_line);
	                exit(1);
                     }
	          }
               }
              
               break;
      }

      dummy_idx++;
      idx++;
      cnt++;
   }

   /* ...END BAD JUJU */

   if((otn_tmp->pattern_buf=(char *)malloc(sizeof(char)*dummy_size))==NULL)
   {
      fprintf(stderr, "ERROR => ParsePattern() pattern_buf malloc filed!\n");
      exit(1);
   }

   memcpy(otn_tmp->pattern_buf, tmp_buf, dummy_size);

   otn_tmp->pattern_size = dummy_size;
   otn_tmp->pattern_match_flag = 1;


   return;
}  



/****************************************************************************
 *
 * Function: Parseflags(char *)
 *
 * Purpose: Figure out which TCP flags the current rule is interested in
 *
 * Arguments: rule => the rule string 
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseFlags(char *rule)
{
   char *fptr;
   char *fend;
   
   fptr = rule;

   while(!isalnum((char) *fptr))
	   fptr++;

   otn_tmp->tcp_flags = 0;
   otn_tmp->check_tcp_flags = 1;

   /* find the end of the alert string */
   fend = fptr + strlen(fptr); 

   while(fptr < fend)
   {
      switch((*fptr&0xFF))
      {
         case 'f':
         case 'F':
                 otn_tmp->tcp_flags |= R_FIN;
                 break;

         case 's':
         case 'S':
                 otn_tmp->tcp_flags |= R_SYN;
                 break;

         case 'r':
         case 'R':
                 otn_tmp->tcp_flags |= R_RST;
                 break;

         case 'p':
         case 'P':
                 otn_tmp->tcp_flags |= R_PSH;
                 break;

         case 'a':
         case 'A':
                 otn_tmp->tcp_flags |= R_ACK;
                 break;

         case 'u':
         case 'U':
                 otn_tmp->tcp_flags |= R_URG;
                 break;

         case '0':
		 otn_tmp->tcp_flags = 0;
                 otn_tmp->check_tcp_flags = 1;
		 break;

         case '1': /* reserved bit flags */
                 otn_tmp->tcp_flags |= R_RES1;
                 break;

         case '2': /* reserved bit flags */
                 otn_tmp->tcp_flags |= R_RES2;
                 break;

         default:
                 fprintf(stderr, "ERROR Line %d: bad TCP flag = \"%c\"\n", file_line, *fptr);
                 fprintf(stderr, "      Valid otions: UAPRSF or 0 for NO flags (e.g. NULL scan)\n");
                 exit(1);
      }

      fptr++;
   }

}



/****************************************************************************
 *
 * Function: ParseMessage(char *)
 *
 * Purpose: Stuff the alert message onto the rule 
 *
 * Arguments: msg => the msg string 
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseMessage(char *msg)
{
   char *ptr;
   char *end;
   int size;

   /* figure out where the message starts */
   ptr = index(msg,'"');

   if(ptr == NULL)
   {
      ptr = msg;
   }
   else
      ptr++;
   
   end = index(ptr,'"');

   if(end != NULL)
      *end = 0;

   while(isspace((int) *ptr)) ptr++;

   /* find the end of the alert string */
   size = strlen(msg);

   /* alloc space for the string and put it in the rule */
   if(size > 0)
   {
      otn_tmp->message = (char *)malloc((sizeof(char)*size));
      strncpy(otn_tmp->message, ptr, size);
      otn_tmp->message[size-1] = 0;
   }
   else 
   {
      fprintf(stderr, "ERROR Line %d: bad alert message size %d\n", file_line, size);
   }
}



/****************************************************************************
 *
 * Function: ParseItype(char *)
 *
 * Purpose: convert the icmp type number into something usable
 *
 * Arguments: number => duh numbuh
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseItype(char *number)
{
   char *type;

   type = number;

   while(isspace((int)*type))
      type++;

   if(isdigit((int)*type))
   {
      otn_tmp->icmp_type = atoi(type);

      if((otn_tmp->icmp_type > 18)||
	 (otn_tmp->icmp_type < 0))
      {
         fprintf(stderr, "ERROR Line %d: Bad ICMP type: %s\n", file_line, type);
	 exit(1);
      }
	      
      otn_tmp->use_icmp_type = 1;	      
      return;
   }
   else
   {
      fprintf(stderr, "ERROR Line %d: Bad ICMP type: %s\n", file_line, type);
      exit(1);
   }  
}



/****************************************************************************
 *
 * Function: ParseIcode(char *)
 *
 * Purpose: Figure out this ICMP code and stick where it belongs
 *
 * Arguments: type => the number to convert
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseIcode(char *type)
{
   while(isspace((int)*type))
      type++;

   if(isdigit((int)*type))
   {
      otn_tmp->icmp_code = atoi(type);

      if((otn_tmp->icmp_code > 15)||
	 (otn_tmp->icmp_code < 0))
      {
         fprintf(stderr, "ERROR Line %d: Bad ICMP code: %s\n", file_line, type);
	 exit(1);
      }
      otn_tmp->use_icmp_code = 1;	      
      return;
   }
   else
   {
      fprintf(stderr, "ERROR Line %d: Bad ICMP code: %s\n", file_line, type);
      exit(1);
   }  
}



/****************************************************************************
 *
 * Function: ParseLogto(char *)
 *
 * Purpose: stuff the special log filename onto the proper rule option
 *
 * Arguments: filename => the file name
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseLogto(char *filename)
{
   char *sptr;
   char *eptr;

   /* grab everything between the starting " and the end one */
   sptr = index(filename, '"');
   eptr = strrchr(filename, '"');

   /* increment past the first quote */
   sptr++;

   /* zero out the second one */
   *eptr = 0;

   /* malloc up a nice shiny buffer */
   otn_tmp->logto = (char *) malloc(strlen(sptr) + 1);

   bzero(otn_tmp->logto, strlen(sptr)+1);

   strncpy(otn_tmp->logto, sptr, strlen(sptr));
}





/****************************************************************************
 *
 * Function: XferHeader(RuleTreeNode *, RuleTreeNode *)
 *
 * Purpose: Transfer the rule block header data from point A to point B
 *
 * Arguments: rule => the place to xfer from
 *            rtn => the place to xfer to
 *
 * Returns: void function
 *
 ***************************************************************************/
void XferHeader(RuleTreeNode *rule, RuleTreeNode *rtn)
{
   rtn->sip = rule->sip;
   rtn->dip = rule->dip;
   rtn->smask = rule->smask;
   rtn->dmask = rule->dmask;
   rtn->hsp = rule->hsp;
   rtn->lsp = rule->lsp;
   rtn->hdp = rule->hdp;
   rtn->ldp = rule->ldp;
   rtn->flags = rule->flags;
}



/****************************************************************************
 *
 * Function: TestHeader(RuleTreeNode *, RuleTreeNode *)
 *
 * Purpose: Check to see if the two header blocks are identical
 *
 * Arguments: rule => uh
 *            rtn  => uuuuhhhhh....
 *
 * Returns: 1 if they match, 0 if they don't
 *
 ***************************************************************************/
int TestHeader(RuleTreeNode *rule, RuleTreeNode *rtn)
{
   if(rtn->sip == rule->sip)
   {
      if(rtn->dip == rule->dip)
      {
         if(rtn->dmask == rule->dmask)
         {
            if(rtn->smask == rule->smask)
            {
               if(rtn->hsp == rule->hsp)
               {
                  if(rtn->lsp == rule->lsp)
                  {
                     if(rtn->hdp == rule->hdp)
                     {
                        if(rtn->ldp == rule->ldp)
                        {
                           if(rtn->flags == rule->flags)
                           {
                              return 1;
                           }
                        }
                     }
                  }
               }
            }
         }
      }
   }

   return 0;
}




/****************************************************************************
 *
 * Function: ApplyRules()
 *
 * Purpose: Apply the three rules lists to the current packet
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ***************************************************************************/
void ApplyRules(Packet *p)
{
#ifdef BENCHMARK
   cmpcount = 0;
#endif

#ifdef DEBUG
      printf("[*] AlertList\n");
#endif
     if(!EvalPacket(&Alert, RULE_ALERT, p))
     {
#ifdef BENCHMARK
         printf(" **** cmpcount: %d **** \n", cmpcount); 
         cmpcount = 0;
#endif
#ifdef DEBUG
         printf("[*] PassList\n");
#endif
         if(!EvalPacket(&Pass, RULE_PASS, p))
         {
#ifdef BENCHMARK
            printf(" **** cmpcount: %d **** \n", cmpcount); 
            cmpcount = 0;
#endif
#ifdef DEBUG
            printf("[*] LogList\n");
#endif
            EvalPacket(&Log, RULE_LOG, p);
#ifdef BENCHMARK
            printf(" **** cmpcount: %d **** \n", cmpcount); 
#endif
         }
      }
}



/****************************************************************************
 *
 * Function: EvalPacket(ListHead *, int )
 *
 * Purpose: Figure out which rule tree to call based on protocol
 *
 * Arguments: List => the rule list to check
 *            mode => the rule mode (alert, log, etc)
 *
 * Returns: 1 on a match, 0 on a miss
 *
 ***************************************************************************/
int EvalPacket(ListHead *List, int mode, Packet *p)
{
   RuleTreeNode *rtn_idx;

   /* figure out which list to look at */
   switch(p->iph->ip_proto)
   {
      case IPPROTO_TCP:
         rtn_idx = List->TcpList;
         break;

      case IPPROTO_UDP:
         rtn_idx = List->UdpList;
         break;

      case IPPROTO_ICMP:
         rtn_idx = List->IcmpList;
         break;

      default: rtn_idx = NULL;
   }

   return EvalHeader(rtn_idx, mode, p);
}



/****************************************************************************
 *
 * Function: EvalHeader(RuleTreeNode *, int )
 *
 * Purpose: Implement BAD ASS RECURSIVE detection engine!  This part looks at 
 *          the IP header info (and ports if necessary) and decides whether
 *          or not to proceed down the rule option chain.  Did I mention it's
 *          recursive?  For all you fans of the old goto system, sorry.... :)
 *
 * Arguments: rtn_idx => the rule block node to test
 *            mode => the rule mode (alert, log, etc)
 *
 * Returns: 1 on a match, 0 on a miss
 *
 ***************************************************************************/
int EvalHeader(RuleTreeNode *rtn_idx, int mode, Packet *p)
{
   int rule_match = 0;
   int test_result;

   if(rtn_idx == NULL)
   {
      return 0;
   }

#ifdef DEBUG
   printf("[*] Rule Head %d\n", rtn_idx->head_node_number);
#endif

#ifdef BENCHMARK
   cmpcount++;
#endif

   /* NEW: added version 1.3 */
   /* new bidirectional rule handling */
   if(rtn_idx->flags & BIDIRECTIONAL)
   {
#ifdef DEBUG
      printf("Checking bidirectional rule...\n");
#endif
      test_result = CheckAddrPort(rtn_idx->sip, rtn_idx->smask, rtn_idx->hsp, rtn_idx->lsp, p, rtn_idx->flags, CHECK_SRC);

      if(test_result)
      {
#ifdef DEBUG
         printf("   Src->Src check passed\n");
#endif
         test_result = CheckAddrPort(rtn_idx->dip, rtn_idx->dmask, rtn_idx->hdp,rtn_idx->ldp, p, rtn_idx->flags, CHECK_DST);

         if(!test_result)
         {
#ifdef DEBUG
            printf("   Dst->Dst check failed, checking inverse combination\n");
#endif
            /* dst mismatch on a src match might not mean failure */
            /* check the inverse */
            test_result = CheckAddrPort(rtn_idx->dip, rtn_idx->dmask, rtn_idx->hdp,rtn_idx->ldp, p, rtn_idx->flags, (CHECK_SRC|INVERSE));

            if(test_result)
            {
#ifdef DEBUG
               printf("   Inverse Dst->Src check passed\n");
#endif
               test_result = CheckAddrPort(rtn_idx->sip, rtn_idx->smask, rtn_idx->hsp, rtn_idx->lsp, p, rtn_idx->flags, (CHECK_DST|INVERSE));
                
               if(!test_result)
               {
#ifdef DEBUG
                  printf("   Inverse Src->Dst check failed\n");
#endif
                  /* no match */
                  return EvalHeader(rtn_idx->right, mode, p);
               }
#ifdef DEBUG
               else
               {
                  printf("Inverse addr/port match\n");
               }
#endif
            }
            else
            {
#ifdef DEBUG
               printf("   Inverse Dst->Src check failed, trying next rule\n");
#endif
               return EvalHeader(rtn_idx->right, mode, p);
            }
         }
#ifdef DEBUG
         else
         {
            printf("dest IP/port match\n");
         }
#endif
      }
      else
      {
#ifdef DEBUG
         printf("   Src->Src check failed, trying inverse test\n");
#endif
         test_result = CheckAddrPort(rtn_idx->dip, rtn_idx->dmask, rtn_idx->hdp,rtn_idx->ldp, p, rtn_idx->flags, CHECK_SRC|INVERSE);

         if(test_result)
         {
#ifdef DEBUG
            printf("   Dst->Src check passed\n");
#endif
            test_result = CheckAddrPort(rtn_idx->sip, rtn_idx->smask, rtn_idx->hsp, rtn_idx->lsp, p, rtn_idx->flags, CHECK_DST|INVERSE);
         
            if(!test_result)
            {
#ifdef DEBUG
               printf("   Src->Dst check failed\n");
#endif
               /* no match */
               return EvalHeader(rtn_idx->right, mode, p);
            }
#ifdef DEBUG
            else
            {
               printf("Inverse addr/port match\n");
            }
#endif
         }
         else
         {
#ifdef DEBUG
            printf("   Inverse test failed, testing next rule...\n");
#endif
            /* no match, give up and try the next rule */
            return EvalHeader(rtn_idx->right, mode, p);
         }
      }
   }
   else
   {
   /* new exception processing in version 1.2.1  courtesy of Ron Snyder*/
   /* Here is what  we want to see:
               INPUTS                          Result
        IP matches     except_flag_is_set       keep looking
        IP matches     except_flag_is_not_set     found
        IP not match   except_flag_is_set         found
        IP not match   except_flag_is_not_set   keep looking
      So it looks to me like we need to xor a successful ip match
      with whether or not the EXCEPT_XXX_IP flag is set

      (the result of that is negated so that the most commonly
      experienced result is listed first)
    */
      if(!((rtn_idx->sip == (p->iph->ip_src.s_addr & rtn_idx->smask))
         ^ (EXCEPT_SRC_IP == (rtn_idx->flags & EXCEPT_SRC_IP))))
      {
#ifdef DEBUG
         printf("  Mismatch on SIP\n");
#endif
         return EvalHeader(rtn_idx->right, mode, p);
      }
#ifdef DEBUG
      else
      {
         printf("  SIP match\n");
      }
#endif

#ifdef BENCHMARK
      cmpcount++;
#endif

      /* comment above the source ip check code apply also to this
         section
      */

#ifdef DEBUG
      printf("rule flags = 0x%X\n", rtn_idx->flags);
#endif

      if (!((rtn_idx->dip == (p->iph->ip_dst.s_addr & rtn_idx->dmask))
          ^ (EXCEPT_DST_IP == (rtn_idx->flags & EXCEPT_DST_IP))))
      {
#ifdef DEBUG
         printf("  Mismatch on DIP\n");
#endif
         return EvalHeader(rtn_idx->right, mode, p);
      }
#ifdef DEBUG
      else
      {
         printf("  DIP match\n");
      }
#endif

#ifdef BENCHMARK
      cmpcount++;
#endif
      if(!(rtn_idx->flags & ANY_SRC_PORT))
      {
#ifdef BENCHMARK
         cmpcount++;
#endif
         if((p->sp > rtn_idx->hsp) || (p->sp < rtn_idx->lsp))
         {
#ifdef DEBUG
            printf("   SP mismatch!\n");
#endif
            if(!(rtn_idx->flags & EXCEPT_SRC_PORT))
               return EvalHeader(rtn_idx->right, mode, p);
         }
         else
         {
#ifdef DEBUG
            printf("  SP match!\n");
#endif
            if(rtn_idx->flags & EXCEPT_SRC_PORT)
               return EvalHeader(rtn_idx->right, mode, p);
         }
      }
#ifdef DEBUG
      else
      {
         printf("  SP match\n");
      }
#endif

#ifdef BENCHMARK
      cmpcount++;
#endif
      if(!(rtn_idx->flags & ANY_DST_PORT))
      {
#ifdef BENCHMARK
         cmpcount++;
#endif
         if((p->dp > rtn_idx->hdp) || (p->dp < rtn_idx->ldp))
         {
#ifdef DEBUG
            printf("   Mismatch on DP!\n");
#endif
            if(!(rtn_idx->flags & EXCEPT_DST_PORT))
               return EvalHeader(rtn_idx->right, mode, p);
         }
         else
         { 
#ifdef DEBUG
            printf("DP match!\n");
#endif
            if(rtn_idx->flags & EXCEPT_DST_PORT)
               return EvalHeader(rtn_idx->right, mode, p);
         }
      }
#ifdef DEBUG
      else
      {
         printf("  DP match\n");
      }
#endif
   }

#ifdef DEBUG
      printf("        <!!> Got head match, checking options chain\n");
#endif

   rule_match = EvalOpts(rtn_idx->down, p);
      
#ifdef DEBUG
   printf("        <!!> rule match code is: %d\n", rule_match);
#endif

#ifdef BENCHMARK
   cmpcount++;
#endif
   if(rule_match)
   {
      switch(mode)
      {
         case RULE_PASS: 
#ifdef BENCHMARK
            printf(" **** cmpcount: %d **** \n", cmpcount); 
#endif
            return 1;

         case RULE_ALERT: 
#ifdef DEBUG
            printf("        <!!> Finishing alert packet!\n");
#endif

#ifdef BENCHMARK
            printf("        <!!> Check count = %d\n", check_count);
            check_count = 0;
            printf(" **** cmpcount: %d **** \n", cmpcount); 
#endif
            (*LogFunc)(p);

            return 1;

         case RULE_LOG: 
#ifdef DEBUG
            printf("        <!!> Logging packet!\n");
#endif
            (*LogFunc)(p);

#ifdef BENCHMARK 
            printf("        <!!> Check count = %d\n", check_count);
            check_count = 0;
            printf(" **** cmpcount: %d **** \n", cmpcount); 
#endif
            return 1;
      }
   }

   if(!rule_match)
      return EvalHeader(rtn_idx->right, mode, p);

#ifdef BENCHMARK
   printf(" **** cmpcount: %d **** \n", cmpcount); 
#endif

   return 0;
}




int CheckAddrPort(u_long addr, u_long mask, u_short hi_port, u_short lo_port, Packet *p, char flags, int mode)
{
   u_long  pkt_addr;
   u_short pkt_port;
   int     any_port_flag = 0;
   int     except_addr_flag = 0;
   int     except_port_flag = 0;


   /* set up the packet particulars */
   if((mode & CHECK_SRC)== CHECK_SRC)
   {
      pkt_addr = p->iph->ip_src.s_addr;
      pkt_port = p->sp;

      if((mode & INVERSE)==INVERSE)
      {
         if(flags & EXCEPT_DST_IP)
         {
            except_addr_flag = 1;
         }

         if(flags & ANY_DST_PORT)
         {
            any_port_flag = 1;
         }

         if(flags & EXCEPT_DST_PORT)
         {
            except_port_flag = 1;
         }
      }
      else
      {
         if(flags & EXCEPT_SRC_IP)
         {
            except_addr_flag = 1;
         }

         if(flags & ANY_SRC_PORT)
         {
            any_port_flag = 1;
         }

         if(flags & EXCEPT_SRC_PORT)
         {
            except_port_flag = 1;
         }
      }
   }
   else
   {
      pkt_addr = p->iph->ip_dst.s_addr;
      pkt_port = p->dp;

      if((mode & INVERSE)==INVERSE)
      {
         if(flags & EXCEPT_SRC_IP)
         {
            except_addr_flag = 1;
         }

         if(flags & ANY_SRC_PORT)
         {
            any_port_flag = 1;
         }

         if(flags & EXCEPT_SRC_PORT)
         {
            except_port_flag = 1;
         }
      }
      else
      {
         if(flags & EXCEPT_DST_IP)
         {
            except_addr_flag = 1;
         }

         if(flags & ANY_DST_PORT)
         {
            any_port_flag = 1;
         }

         if(flags & EXCEPT_DST_PORT)
         {
            except_port_flag = 1;
         }
      }
   }

   /* test the rule address vs. the packet address */
   if (!((addr == (pkt_addr & mask))
       ^ (except_addr_flag)))
   {
      return 0;
   }

   /* if the any port flag is up, we're all done (success)*/
   if(any_port_flag)
      return 1;

   /* check the packet port against the rule port */
   if((pkt_port > hi_port) || (pkt_port < lo_port))
   {
      /* if the exception flag isn't up, fail */
      if(!except_port_flag)
      {
         return 0;
      }
   }
   else
   {
      /* if the exception flag is up, fail */
      if(except_port_flag)
      {
         return 0;
      }
   }

   /* ports and address match */
   return 1;
}



/****************************************************************************
 *
 * Function: EvalOpts(OptTreeNode *)
 *
 * Purpose: Implements section 2 of recursive detection engine.  Goes
 *          thru the options chain and see if the current packet matches
 *          any of the rules
 *
 * Arguments: List => the OTN list
 *
 * Returns: 1 on a match, 0 on no match
 *
 ***************************************************************************/
int EvalOpts(OptTreeNode *List, Packet *p)
{
   if(List == NULL)
   {
      return 0;
   }

#ifdef DEBUG
   printf("   => Checking Option Node %d\n", List->chain_node_number);
#endif

/********************* TTL Check **********************************/
#ifdef BENCHMARK
   cmpcount++;
#endif
   /* test the TTL value */
   if(List->ttl)
   {
#ifdef BENCHMARK
      cmpcount++;
#endif
      if(List->ttl !=  p->iph->ip_ttl)
      {
#ifdef DEBUG
         printf("Doing TTL check! %d\n", List->ttl);
#endif
         return EvalOpts(List->next, p);
      }
#ifdef DEBUG
      else
      {
         printf("Got TTL match!\n");
      }
#endif
   }

/*********************** Frag size check **************************/
#ifdef BENCHMARK
   cmpcount++;
#endif
   /* check for tiny fragments */
   if(List->min_frag)
   {
      /* we're only interested in the first fragment of a set,
         if it's below the min_frag size */

      /* the first fragment of a packet will have a fragment offset of 0
         and the more frags bit will be set */
#ifdef BENCHMARK
      cmpcount++;
#endif
      if(!p->frag_offset && p->mf)
      {
#ifdef BENCHMARK
         cmpcount++;
#endif
         if(List->min_frag < p->dsize)
         {
            return EvalOpts(List->next, p);
         }
      }
      else
      {
         return EvalOpts(List->next, p);
      }
   }

/**************************** IP Header ID check **************************/
#ifdef BENCHMARK
   cmpcount++;
#endif
      /* test the IP header ID number */
   if(List->check_ip_id)
   {
#ifdef BENCHMARK
      cmpcount++;
#endif
      if(List->ip_id != ntohs(p->iph->ip_id))
      {
         return EvalOpts(List->next, p);
      }
#ifdef DEBUG
      else
      {
         printf("Got ip ID match!\n");
      }
#endif
   }

/************************* TCP Checks **********************************/
#ifdef BENCHMARK
   check_count++;

   cmpcount++;
#endif

/*************************** TCP flag check ****************************/
#ifdef BENCHMARK
      cmpcount++;
#endif
      /* test for TCP flags */
      if(List->check_tcp_flags)
      {
         if(p->tcph == NULL)
         {
            return EvalOpts(List->next, p);
         }
#ifdef DEBUG
         printf("Checking TCP flags [%X:%X]\n", List->tcp_flags, p->tcph->th_flags);
#endif
#ifdef BENCHMARK
         cmpcount++;
#endif
         if(List->tcp_flags != p->tcph->th_flags)
         {
#ifdef DEBUG
            printf("No match\n");
#endif
            return EvalOpts(List->next, p);
         }
#ifdef DEBUG
         else
         {
            printf("Got TCP flag match!\n");
         }
#endif
      }

/**************************** TCP Ack value check ************************/
#ifdef BENCHMARK
      cmpcount++;
#endif
         /* test the TCP ack number */
      if(List->check_ack)
      {
         if(p->tcph == NULL)
         {
            return EvalOpts(List->next, p);
         }
#ifdef BENCHMARK
         cmpcount++;
#endif
         if(List->tcp_ack != ntohl(p->tcph->th_ack))
         {
            return EvalOpts(List->next, p);
         }
#ifdef DEBUG
         else
         {
            printf("Got TCP ack match!\n");
         }
#endif
      }

/***************************** TCP seq number check *********************/
#ifdef BENCHMARK
      cmpcount++;
#endif
      /* test the TCP sequence number */
      if(List->check_seq)
      {
         if(p->tcph == NULL)
         {
            return EvalOpts(List->next, p);
         }
#ifdef BENCHMARK
         cmpcount++;
#endif
         if(List->tcp_seq != ntohl(p->tcph->th_seq))
         {
            return EvalOpts(List->next, p);
         }
#ifdef DEBUG
         else
         {
            printf("Got TCP seq match!\n");
         }
#endif
      }

/************************** ICMP Checks ****************************/
#ifdef BENCHMARK
   cmpcount++;
#endif

/************************* ICMP type check *************************/
     /* check the ICMP type field */
#ifdef BENCHMARK
      cmpcount++;
#endif
      if(List->use_icmp_type)
      {
         if(p->icmph == NULL)
         {
            return EvalOpts(List->next, p);
         }
#ifdef BENCHMARK
      cmpcount++;
      printf("Doing ICMP type check!\n");
#endif
         if(List->icmp_type != p->icmph->type)
         {
            return EvalOpts(List->next, p);
         }
#ifdef DEBUG
         else
         {
            printf("Got icmp type match!\n");
         }
#endif
      }

/************************** ICMP code check **************************/
#ifdef BENCHMARK
      cmpcount++;
#endif
      /* check the ICMP code field */
      if(List->use_icmp_code)
      {
         if(p->icmph == NULL)
         {
            return EvalOpts(List->next, p);
         }
#ifdef BENCHMARK
      cmpcount++;
#endif
         if(List->icmp_code != p->icmph->code)
         {
            return EvalOpts(List->next, p);
         }
#ifdef DEBUG
         else
         {
            printf("Got icmp code match!\n");
         }
#endif
      }

/************************* Payload size check *************************/

   if(List->check_dsize)
   {
      if(List->dsize != p->dsize)
      {
         return EvalOpts(List->next, p);
      }
   }

/************************* Payload check ******************************/
   /* do payload pattern matching */
#ifdef BENCHMARK
   cmpcount++;
#endif
   if(List->pattern_match_flag)
   {
      int sub_depth;
      int found;
 
#ifdef BENCHMARK
      cmpcount++;
#endif
      if(List->offset > p->dsize)
      {
         return EvalOpts(List->next, p);
      }

      
      if((List->depth + List->offset) > p->dsize)
      {
         sub_depth = p->dsize - List->offset;
      
         if(sub_depth < List->pattern_size)
            return EvalOpts(List->next, p);
     

         if(!mSearch((p->data+List->offset), sub_depth, 
                     List->pattern_buf, List->pattern_size))
         {
#ifdef DEBUG
            printf("Pattern match failed!\n");
#endif
            return EvalOpts(List->next, p);
         }
#ifdef DEBUG
         printf("Pattern match sucessful\n");
#endif
      }
      else
      {
         if(List->depth)
         {
            found = mSearch((p->data+List->offset), List->depth, List->pattern_buf, List->pattern_size);
         }
         else
         {
            found = mSearch((p->data+List->offset), p->dsize, List->pattern_buf, List->pattern_size);
         }

         if(!found)
         {
#ifdef DEBUG
            printf("Pattern match failed!\n");
#endif
            return EvalOpts(List->next, p);
         }
#ifdef DEBUG
         printf("Pattern match sucessful\n");
#endif
      }
   }

   /* do the appropriate follow on action */
   switch(List->type)
   {
      case RULE_PASS: 
         return 1;
                      
      case RULE_ALERT: 
         otn_tmp = List;

#ifdef DEBUG
         printf("        <!!> Generating alert! \"%s\"\n", List->message);
#endif
         (*AlertFunc)(p, List->message);

         return 1;

      case RULE_LOG: 
#ifdef DEBUG
         printf("        <!!> Setting OTN log ptr\n");
#endif
         otn_tmp = List;

         return 1;
   }

   return  0;
}


/****************************************************************************
 *
 * Function: DumpChain(RuleTreeNode *, char *)
 *
 * Purpose: print out the chain lists by header block node group
 *
 * Arguments: rtn_idx => the RTN index pointer
 *            name => the name of the list being printed out 
 *
 * Returns: void function
 *
 ***************************************************************************/
void DumpChain(RuleTreeNode *rtn_idx, char *name)
{
   OptTreeNode *otn_idx;

   printf("%s\n", name);

   if(rtn_idx == NULL)
      printf("    Empty!\n\n");

   /* walk thru the RTN list */
   while(rtn_idx != NULL)
   {
      printf("SRC IP: 0x%.8lX / 0x%.8lX\n", rtn_idx->sip, rtn_idx->smask);
      printf("DST IP: 0x%.8lX / 0x%.8lX\n", rtn_idx->dip, rtn_idx->dmask);
      printf("SRC PORT: %d - %d \n", rtn_idx->lsp, rtn_idx->hsp);
      printf("DST PORT: %d - %d \n", rtn_idx->ldp, rtn_idx->hdp);
      printf("Flags: ");
      if(rtn_idx->flags & EXCEPT_SRC_IP) printf("EXCEPT_SRC_IP ");
      if(rtn_idx->flags & EXCEPT_DST_IP) printf("EXCEPT_DST_IP ");
      if(rtn_idx->flags & ANY_SRC_PORT) printf("ANY_SRC_PORT ");
      if(rtn_idx->flags & ANY_DST_PORT) printf("ANY_DST_PORT ");
      if(rtn_idx->flags & EXCEPT_SRC_PORT) printf("EXCEPT_SRC_PORT ");
      if(rtn_idx->flags & EXCEPT_DST_PORT) printf("EXCEPT_DST_PORT ");
      printf("\n");

      /* print the RTN header number */
      printf("Head: %d\n", rtn_idx->head_node_number);
      printf("      |\n");
      printf("       ->");

      otn_idx = rtn_idx->down;

      /* walk thru the OTN chain */
      while(otn_idx != NULL)
      {
         printf(" %d", otn_idx->chain_node_number);
         otn_idx = otn_idx->next;
      }
 
      printf("|=-\n");

      rtn_idx = rtn_idx->right;
   }
}
