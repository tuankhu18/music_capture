#include "filter_packet.h"
#include "common_macro.h"
void apacket_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main(char argc, char **argv) {
	
	/* */
	pcap_if_t *network_interfaces;
	pcap_if_t *network_if_iterator;
	char err_buf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	struct bpf_program fcode;

	/* end define variable*/
	
	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &network_interfaces, err_buf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", err_buf);
		exit(1);
	}

	int i = 1;
	for (network_if_iterator = network_interfaces; network_if_iterator != NULL; network_if_iterator = network_if_iterator->next, i++) {
		printf("%d %s %s\n", i, network_if_iterator->name, network_if_iterator->description);
	}

	int choose = 0;
	pcap_if_t *choosed_if;
	while (choose <= 0 || choose >= i) {
		printf("[?] choose interface to capture: ");
		scanf("%d", &choose);
	}

	for (i = 0, choosed_if = network_interfaces; i < choose - 1; i++, choosed_if = choosed_if->next);

	pcap_t *adhandle;
	int timeout_mili = 1000;
	if ((adhandle = pcap_open(choosed_if->name, 65536, PCAP_OPENFLAG_PROMISCUOUS
		, timeout_mili, NULL, err_buf)) == NULL) {
		printf("Can't open adapter\n");
		return -1;
	}

	printf("listening.......\n");

	if (choosed_if->addresses != NULL) {
		netmask = ((struct sockaddr_in *)(choosed_if->addresses->netmask))->sin_addr.S_un.S_addr;
	}
	else {
		netmask = 0xffffff; // 255.255.255.0
	}

	if (pcap_compile(adhandle, &fcode, filter_expression, 1, netmask) < 0) {
		printf("Can't compile packet\n");
		pcap_freealldevs(network_interfaces);
		return -1;
	}

	if (pcap_setfilter(adhandle, &fcode) < 0) {
		printf("Can't set filter\n");
		pcap_freealldevs(network_interfaces);
		return -1;
	}
	pcap_loop(adhandle, 0, apacket_handler, NULL);
	getchar();
}

void apacket_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	ETHER_HDR eth_header;
	IPV4_HDR ip_header;
	TCP_HDR tcp_header;
	UCHAR s_mac[6];
	memcpy(&eth_header, pkt_data, sizeof(ETHER_HDR));
	memcpy(&ip_header, pkt_data + sizeof(ETHER_HDR), sizeof(IPV4_HDR));
	memcpy(&tcp_header, pkt_data + sizeof(ETHER_HDR) + sizeof(IPV4_HDR), sizeof(TCP_HDR));

	//printf("Selected device has mac address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X", s_mac[0], s_mac[1], s_mac[2], s_mac[3], s_mac[4], s_mac[5]);
	char ip_src[INET_ADDRSTRLEN], ip_dst[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(ip_header.ip_srcaddr), ip_src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip_header.ip_destaddr), ip_dst, INET_ADDRSTRLEN);

	//printf("%s -> %s\n", ip_src, ip_dst);
	//printf("%d\n", tcp_header.data_offset);
	int datasize = header->caplen - sizeof(ETHER_HDR) - ip_header.ip_header_len*4 - tcp_header.data_offset * 4;
	//printf("Size: %d ", datasize);

	//memcpy(data, pkt_data + sizeof(ETHER_HDR) + ip_header.ip_header_len * 4 + tcp_header.data_offset * 4, datasize);
	print_data((const char*)pkt_data + sizeof(ETHER_HDR) + ip_header.ip_header_len * 4 + tcp_header.data_offset * 4, datasize);
}

void print_data(const char *data, int datasize) {
	const char *mp3_magic_byte = "ID3";
	const char *found_str = strstr(data, mp3_magic_byte);
	if (found_str != NULL) {
		printf("FOUNDDDDDDD\n");
		FOR(0, 10, 1) {
			printf("%c ", *(found_str++));
		}
		/*while (found_str != NULL) {
			printf("%c", found_str);
			found_str++;
		}*/
	};
}