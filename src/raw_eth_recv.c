#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define PACKET_SIZE		1000
#define SYN				0xa002
#define SYNACK			0x0012
#define IPV6			0x86dd
#define MAC_ADDR_SIZE	6
#define IPV4_SIZE		4
#define IPV6_SIZE		8
#define OPTIONS_SIZE	12			

/* Descrição do cabeçalho ETHERNET */
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
	uint8_t options[OPTIONS_SIZE];
};

int main(int argc, char *argv[]) {
	int fd;
	uint8_t packet[PACKET_SIZE];
	struct ifreq ifr;
	char ifname[IFNAMSIZ];
	struct ethernet_s *ethernet = (struct ethernet_s *)&packet;
	struct ipv6_s *ipv6;
	struct tcp_s *tcp;

	// Defino interface de rede a ser utilizada	
	if (argc != 2) {
		printf("Usage: %s iface\n", argv[0]);
		return 1;
	}
	strcpy(ifname, argv[1]);

	/* Cria um descritor de socket do tipo RAW */
	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(fd < 0) {
		perror("socket");
		exit(1);
	}

	/* Obtem o indice da interface de rede */
	strcpy(ifr.ifr_name, ifname);
	if(ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl");
		exit(1);
	}

	/* Obtem as flags da interface */
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0){
		perror("ioctl");
		exit(1);
	}

	/* Coloca a interface em modo promiscuo */
	ifr.ifr_flags |= IFF_PROMISC;
	if(ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		perror("ioctl");
		exit(1);
	}

	printf("Esperando pacotes ... \n");
	while (1) {
		/* Limpa o buffer */
		memset(packet, 0, PACKET_SIZE);

		/* Recebe pacotes */
		if (recv(fd,(char *) &packet, PACKET_SIZE, 0) < 0) {
			perror("recv");
			close(fd);
			exit(1);
		}

		/* Converte o ethertype para short int*/
		ethernet->ethertype = ntohs(ethernet->ethertype);
		
		/* Verifico se o ethertype é IPV6 */
		if (ethernet->ethertype == IPV6) {
			// TBD: Identificar o campo flags é SYN (0x002)
			ipv6 = (struct ipv6_s *)&packet[sizeof(struct ethernet_s)];
			tcp = (struct tcp_s *)&packet[sizeof(struct ethernet_s) + sizeof(struct ipv6_s)];
			printf("ETHERNET II\n");
			printf("mac_addr_src: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet->mac_src[0], ethernet->mac_src[1], ethernet->mac_src[2], ethernet->mac_src[3], ethernet->mac_src[4], ethernet->mac_src[5]);
			printf("mac_addr_dst: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet->mac_dst[0], ethernet->mac_dst[1], ethernet->mac_dst[2], ethernet->mac_dst[3], ethernet->mac_dst[4], ethernet->mac_dst[5]);
			printf("   ethertype: 0x%04x\n", ethernet->ethertype);	
			printf("IPV6\n");
			printf(" ip_addr_src: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n", ipv6->src_addr[0], ipv6->src_addr[1], ipv6->src_addr[2], ipv6->src_addr[3], ipv6->src_addr[4], ipv6->src_addr[5], ipv6->src_addr[6], ipv6->src_addr[7]);
			printf(" ip_addr_dst: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n", ipv6->dst_addr[0], ipv6->dst_addr[1], ipv6->dst_addr[2], ipv6->dst_addr[3], ipv6->dst_addr[4], ipv6->dst_addr[5], ipv6->dst_addr[6], ipv6->dst_addr[7]);
			printf("TCP\n");
			printf("    src_port: %d\n", tcp->src_port);
			printf("    dst_port: %d\n", tcp->dst_port);
			printf("       flags: 0x%04x\n", tcp->flags);
			printf("\n\n");
		}
	}

	close(fd);
	return 0;
}
