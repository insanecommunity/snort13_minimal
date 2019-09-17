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

#ifndef __LOG_H__
#define __LOG_H__


/*  I N C L U D E S  **********************************************************/
#include "snort.h"

#ifdef SOLARIS
#define LOG_AUTHPRIV LOG_AUTH
#endif

#ifdef HPUX
#define LOG_AUTHPRIV LOG_AUTH
#endif

#ifdef IRIX
#define LOG_AUTHPRIV LOG_AUTH
#endif

#define FRAME_SIZE        66
#define C_OFFSET          49

#define DUMP              1
#define BOGUS             2
#define NON_IP            3

/*  D A T A  S T R U C T U R E S  *********************************************/

void (*LogFunc)(Packet *);
void (*AlertFunc)(Packet *, char *);

/*  P R O T O T Y P E S  ******************************************************/
int OpenLogFile(int,Packet*);
void OpenAlertFile();
void PrintIPPkt(FILE *, int,Packet*);
void PrintNetData(FILE *, char *, const int);
void ClearDumpBuf();
void PrintEthHeader(FILE *, Packet *);
void PrintIPHeader(FILE *, Packet *);
void PrintTCPHeader(FILE *, Packet *);
void PrintICMPHeader(FILE *, Packet *);
void PrintUDPHeader(FILE *, Packet *);
void LogAlertData();
void AlertMsg(Packet *, char *);
char *IcmpFileName(Packet *);

void InitLogFile();
void LogBin(Packet *);
void LogPkt(Packet *);
void NoLog(Packet *);

void FastAlert(Packet *, char *);
void FullAlert(Packet *, char *);
void NoAlert(Packet *, char *);
void SyslogAlert(Packet *, char *);
void SmbAlert(Packet *, char *);


#endif /* __LOG_H__ */
