#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define N 255
#define IP_LEN 4
#define REQUEST 0x0001
#define RESPONSE 0x0002
#define PROTOCOL 0x0806
#define MAC_ADDR_LEN 6
#define BUFFER_SIZE 1600
#define MAX_DATA_SIZE 1500
#define ARP_PACKET_LEN 28

// TODO: Implementar a aplicação do atacante.

int main(int argc, char *argv[])
{
	int fd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_address;
	char ifname[IFNAMSIZ];
	int frame_len = 0;
	/* Ethernet */
	char buffer[BUFFER_SIZE];
	char dest_mac[MAC_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; //broadcast
	short int ethertype = htons(PROTOCOL);
	/* ARP Protocol */
	int arp_len = 0;
	char arp_packet[ARP_PACKET_LEN];
	short int hwtype = htons(0x0001);
	short int ptype  = htons(0x0800);
	char hlen = 0x06;
	char plen = 0x04;
	short int op = htons(REQUEST);
	char sender_ha[MAC_ADDR_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	char sender_ip[IP_LEN] = {192, 168, 15, 15}; // Alterar para o IP da Interface de Rede
	char target_ha[MAC_ADDR_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; 
	char target_ip[IP_LEN] = {192, 168, 15, 1}; // Rede a ser descoberta

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

	/* Copia MAC e IP para estrutura ARP */
	memcpy(sender_ha, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);


	/* Indice da interface de rede */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;

	/* Tamanho do endereco (ETH_ALEN = 6) */
	socket_address.sll_halen = ETH_ALEN;

	/* Endereco MAC de destino */
	memcpy(socket_address.sll_addr, dest_mac, MAC_ADDR_LEN);

	/* Preenche o buffer com 0s */
	memset(buffer, 0, BUFFER_SIZE);

	/* Monta o cabecalho Ethernet */

	/* Preenche o campo de endereco MAC de destino */
	memcpy(buffer, dest_mac, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo de endereco MAC de origem */
	memcpy(buffer + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo EtherType */
	memcpy(buffer + frame_len, &ethertype, sizeof(ethertype));
	frame_len += sizeof(ethertype);

	/* Monta o Arp Packet */
	memset(arp_packet, 0, ARP_PACKET_LEN);

	/* Hardware Type */
	memcpy(arp_packet + arp_len, &hwtype, sizeof(hwtype));
	arp_len += sizeof(hwtype);

	/* Protocol Type */
	memcpy(arp_packet + arp_len, &ptype, sizeof(ptype));
	arp_len += sizeof(ptype);

	/* Hardware Length */
	memcpy(arp_packet + arp_len, &hlen, sizeof(hlen));
	arp_len += sizeof(hlen);

	/* Protocol Length */
	memcpy(arp_packet + arp_len, &plen, sizeof(plen));
	arp_len += sizeof(plen);

	/* Operation */
	memcpy(arp_packet + arp_len, &op, sizeof(op));
	arp_len += sizeof(op);

	/* Sender HA */
	memcpy(arp_packet + arp_len, sender_ha, MAC_ADDR_LEN);
	arp_len += MAC_ADDR_LEN;

	/* Sender IP */
	memcpy(arp_packet + arp_len, sender_ip, IP_LEN);
	arp_len += sizeof(sender_ip);

	/* Target HA */
	memcpy(arp_packet + arp_len, target_ha, MAC_ADDR_LEN);
	arp_len += MAC_ADDR_LEN;

	/* Laço para testar todas as N possibilidades de IPs */
	for(int k = 1; k < N; k++)
	{
		/* Testa se o ARP Request está sendo enviado para ele mesmo */
		if(k == sender_ip[IP_LEN-1]) continue;

		/* Atualiza o IP a ser descoberto */
		target_ip[3] = k;

		/* Target IP */
		memcpy(arp_packet + arp_len, target_ip, IP_LEN);

		/* Preenche o Data com Arp Packet */
		memcpy(buffer + frame_len, arp_packet, ARP_PACKET_LEN);

		/* Envia pacote */
		if (sendto(fd, buffer, frame_len+sizeof(arp_packet), 0, (struct sockaddr *) &socket_address, sizeof (struct sockaddr_ll)) < 0) {
			perror("send");
			close(fd);
			exit(1);
		}
	}

	printf("Pacotes enviado.\n");

	close(fd);
	return 0;
}
