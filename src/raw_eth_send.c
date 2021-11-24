#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include "checksum.h"

#define N				256
#define PACKET_SIZE		1000
#define IPV6			0x86dd
#define HEADER			0x60098a90
#define MAC_ADDR_SIZE	6
#define IPV6_SIZE		8		

/* Destination */
const uint8_t mac_dst[MAC_ADDR_SIZE] = { 0x08, 0x00, 0x27, 0x77, 0x9c, 0x5c };
const uint16_t dst_addr[IPV6_SIZE] = {  0x2804, 0x07f4, 0xf980, 0x213d, 
										0xb0ac, 0x4284, 0x3ab2, 0x3554 };
/* Source */
const uint8_t mac_src[MAC_ADDR_SIZE] = { 0x08, 0x00, 0x27, 0x43, 0x73, 0xbc };
const uint16_t src_addr[IPV6_SIZE] = {  0x2804, 0x07f4, 0xf980, 0x213d, 
										0x3856, 0x208a, 0x3eb2, 0x9c5d };

struct ethernet_s {
	uint8_t mac_dst[MAC_ADDR_SIZE];
	uint8_t mac_src[MAC_ADDR_SIZE];
	uint16_t ethertype;
};

/* Descrição do cabeçalho IPV6 */
struct ipv6_s {
	uint32_t header;
	uint16_t payload_length;
	uint8_t next_header;
	uint8_t hop_limit;
	uint16_t src_addr[IPV6_SIZE];
	uint16_t dst_addr[IPV6_SIZE];
};

/* Descrição do cabeçalho TCP */
struct tcp_s {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_number;
	uint32_t ack_number;
	uint16_t flags;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent_pointer;
};

int main(int argc, char *argv[])
{
	int fd;
	uint8_t packet[PACKET_SIZE];
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_address;
	char ifname[IFNAMSIZ];
	struct ethernet_s *ethernet;
	struct ipv6_s *ipv6;
	struct tcp_s *tcp;

	// Defino interface de rede a ser utilizada	
	if (argc != 2) {
		printf("Usage: %s iface\n", argv[0]);
		return 1;
	}
	strcpy(ifname, argv[1]);

	/* Cria um descritor de socket do tipo RAW */
	if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket");
		exit(1);
	}

	/* Obtem o indice da interface de rede */
	memset(&if_idx, 0, sizeof (struct ifreq));
	strncpy(if_idx.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		exit(1);
	}

	/* Obtem o endereco MAC da interface local */
	memset(&if_mac, 0, sizeof (struct ifreq));
	strncpy(if_mac.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		exit(1);
	}

	ethernet = (struct ethernet_s *)&packet;
	ipv6 = (struct ipv6_s *)&packet[sizeof(struct ethernet_s)];
	tcp = (struct tcp_s *)&packet[sizeof(struct ethernet_s) + sizeof(struct ipv6_s)];

	/* Configura SocketRaw */
	socket_address.sll_family = htons(PF_PACKET);
	socket_address.sll_protocol = htons(ETH_P_ALL);
	socket_address.sll_halen = ETH_ALEN;
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	
	/* Pacote Ethernet II */
	memcpy(ethernet->mac_dst, mac_dst, MAC_ADDR_SIZE * sizeof(uint8_t));
	memcpy(ethernet->mac_src, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_SIZE * sizeof(uint8_t));
	ethernet->ethertype = htons(IPV6);

	/* Pacote IPV6 */
	ipv6->header = htonl((6 << 28) | (0 << 20) | 0);
	ipv6->payload_length = htons(sizeof(struct tcp_s));
	ipv6->next_header = 6;
	ipv6->hop_limit = 255;
	
	ipv6->src_addr[0] = htons(src_addr[0]);
	ipv6->src_addr[1] = htons(src_addr[1]);
	ipv6->src_addr[2] = htons(src_addr[2]);
	ipv6->src_addr[3] = htons(src_addr[3]);
	ipv6->src_addr[4] = htons(src_addr[4]);
	ipv6->src_addr[5] = htons(src_addr[5]);
	ipv6->src_addr[6] = htons(src_addr[6]);
	ipv6->src_addr[7] = htons(src_addr[7]);
	
	ipv6->dst_addr[0] = htons(dst_addr[0]);
	ipv6->dst_addr[1] = htons(dst_addr[1]);
	ipv6->dst_addr[2] = htons(dst_addr[2]);
	ipv6->dst_addr[3] = htons(dst_addr[3]);
	ipv6->dst_addr[4] = htons(dst_addr[4]);
	ipv6->dst_addr[5] = htons(dst_addr[5]);
	ipv6->dst_addr[6] = htons(dst_addr[6]);
	ipv6->dst_addr[7] = htons(dst_addr[7]);
	
	/* Pacote TCP */
	tcp->src_port = htons(60);
	tcp->dst_port = htons(8080);
	tcp->seq_number = htonl(0);
	tcp->ack_number = htonl(0);
	tcp->flags = htons(0x5002);
	tcp->window = htons(65535);
	tcp->checksum = htons(0);
	tcp->urgent_pointer = htons(0);
	// 0x6383
	printf("\nchecksum: 0x%04x\n", htons(in_cksum(packet + sizeof(struct ethernet_s), (sizeof(struct ipv6_s) + sizeof(struct tcp_s))/2)));

	/* Envia pacote */
	if (sendto(fd, packet, sizeof(struct ethernet_s) + sizeof(struct ipv6_s) + sizeof(struct tcp_s), 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
		perror("send");
		close(fd);
		exit(1);
	}
	
	printf("Pacote enviado.\n");

	close(fd);
	return 0;
}
