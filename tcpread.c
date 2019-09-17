#include "tcpread.h"


/*
int main(int argc, char *argv[])
{
   pcap_file_header pfh;
   pcap_pkthdr pph;
   u_char packet[1500];
   FILE *fp = NULL;

   printf("Opening %s for reading, fp = %p\n", argv[1], fp);

   if((fp = fopen(argv[1], "r")) == NULL)
   {
      perror("OpenPcapFile() fopen");
      exit(1);
   }

   printf("file opened, ptr = %p\n", fp);

   ReadPcapHeader(fp, &pfh);

   printf("Pcap file header =>\n");
   printf("Magic: %ld  version: %d.%d  snaplen: %d  linktype: %d\n", 
          pfh.magic, pfh.version_major, pfh.version_minor, pfh.snaplen, 
          pfh.linktype);

   bzero(packet, 1500);

   while(GetNextPkt(fp, &pph, &packet))
   {
      printf("Packet =>  secs: %d  usecs: %d  caplen: %d  len: %d\n", 
             pph.ts.tv_sec, pph.ts.tv_usec, pph.caplen, pph.len);
      bzero(packet, 1500);
*/
      /* put your ethernet decoder function here!! */
/*   }
   fclose(fp);

   return 0;
}
*/


int ReadPcapHeader(FILE *fp, pcap_file_header *file_head)
{
   int read_size;

   read_size = fread(file_head, 1, sizeof(pcap_file_header), fp);

   if(read_size < sizeof(pcap_file_header))
   {
      fprintf(stderr, "Error reading TCPdump file header %d:%d!\n", 
              read_size, sizeof(pcap_file_header));
      exit(1);
   }

   return 0;
}


int GetNextPkt(FILE *fp, pcap_pkthdr *head, u_char *data)
{
   int read_size;

   read_size = fread(head, 1, sizeof(pcap_pkthdr), fp);

   if(read_size == 0)
      return 0;

   if(read_size < sizeof(pcap_pkthdr))
   {
      fprintf(stderr, "ERROR reading pcap packet header, exiting!\n");
      exit(1);
   }

   read_size = fread(data, 1, head->caplen, fp);

   if(read_size < head->caplen)
   {
      fprintf(stderr, "ERROR reading packet data, exiting!\n");
      exit(1);
   }

   return 1;
}
   

