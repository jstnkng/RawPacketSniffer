#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/types.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>

//Justin King
//CIS 457
//packetSniffer.c

int main(int argc, char** argv)
{
	int packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (packet_socket<0)
	{
		perror("Socket error");
		return 1;
	}

	struct sockaddr_ll serveraddr, clientaddr;
	serveraddr.sll_family = AF_PACKET;
	serveraddr.sll_protocol = htons(ETH_P_ALL);
	serveraddr.sll_ifindex = if_nametoindex("h1-eth0");

	int e = bind(packet_socket,(struct sockaddr*)&serveraddr, sizeof(serveraddr));
	if (e<0)
	{
		perror("Binding error");
		return 2;
	}

	while(1)
	{
		unsigned char buf[1514];
		int len = sizeof(clientaddr);
		int n = recvfrom(packet_socket, &buf, 1514,0, (struct sockaddr*) &clientaddr, &len);
		if (clientaddr.sll_pkttype == PACKET_OUTGOING){
			continue;
		}

		struct ether_header *eth = (struct ether_header *) &buf;
		printf("---------------------");
		printf("\nEthernet header\n");
		printf("\t-Destination:");
		int i;
		//Loop through all the bytes in the destination host to print the destination address
		for (i =0; i < sizeof(eth->ether_dhost); i++)
		{
			if (i > 0) printf(":");
			printf("%.2X", eth->ether_dhost[i]);
		} 
		printf("\n");
		printf("\t-Source:");
		int x;
		//Loop through all the bytes in the source host to print the source address
		for (x = 0; x < sizeof(eth->ether_shost); x++)
		{
			if (x > 0) printf(":");
			printf("%.2X", eth->ether_shost[x]);
		}
		printf("\n");

		//Print the packet type as an unsigned short
		printf("\t-Type: %" PRIu16 "\n", eth->ether_type);
		
		//If the packet type is IPv4 (0x800)
		if ((int)eth->ether_type == 8)
		{
			//Skip over the first 14 bytes (ethernet header) to get the IP header
			unsigned char* adjusted = buf + 14;
			struct iphdr *ip = (struct iphdr *) adjusted;
			struct in_addr source, dest;
			source.s_addr = ip->saddr;
			dest.s_addr = ip->daddr;
			printf("IP Header\n");
			printf("\t-Source IP: %s\n", inet_ntoa(source));
			printf("\t-Destination IP: %s\n", inet_ntoa(dest));
		}
	}
}
