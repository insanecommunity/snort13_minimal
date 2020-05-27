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

#include "types.h"


#ifdef SOLARIS
#define INADDR_NONE -1
#endif







/*  P R O T O T Y P E S  ******************************************************/
void ParseRulesFile(char *,struct snort_states*);
void ParseRule(char *,struct snort_states*);
int RuleType(char *, struct snort_states *);
int WhichProto(char *, struct snort_states *);
int ParseIP(char *, u_long *, u_long *, struct snort_states *);
int ParsePort(char *, u_short *,  u_short *, char *, int *, struct snort_states *);
void ApplyRules(Packet*, struct snort_states *);
void ParsePattern(char *, struct snort_states *);
void ParseFlags(char *, struct snort_states *);
int ConvPort(char *, char *, struct snort_states *);
void ParseRuleOptions(char *, int, struct snort_states *);
void ParseIcode(char *, struct snort_states *);
void ParseItype(char *, struct snort_states *);
void ParseMessage(char *, struct snort_states *);
void ParseLogto(char *, struct snort_states *);
void XferHeader(RuleTreeNode *, RuleTreeNode *);
int TestHeader(RuleTreeNode *, RuleTreeNode *);
int EvalPacket(ListHead *, int, Packet *, struct snort_states* );
int EvalHeader(RuleTreeNode *, int, Packet *, struct snort_states *);
int EvalOpts(OptTreeNode *, Packet *, struct snort_states *);
void ProcessHeadNode(RuleTreeNode *, ListHead *, int, struct snort_states *);
void DumpChain(RuleTreeNode *, char *);
int CheckAddrPort(u_long, u_long, u_short, u_short, Packet *, char, int);



#endif /* __RULES_H__ */
