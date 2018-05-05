#include "filter_packet.h"
#include "common_macro.h"

#define OUTPUT_DIR "C:\\Users\\TuanNA2\\Desktop\\tmp\\capture.mp3"
#define LOG_DIR "C:\\Users\\TuanNA2\\Desktop\\tmp\\log.mp3"
#define DUMP_FILE "C:\\Users\\TuanNA2\\Desktop\\tmp\\packet.pcap"

FILE *fout;
const char *file_name[] = { "sample.mp3", "sample2.mp3", "sample3.mp3" };
int file_name_index = 0;
unsigned long next_seq_number = 0;
unsigned int size = 0;

int main(char argc, char **argv) {

	/* declare variable */
	pcap_if_t *network_interfaces;
	pcap_if_t *network_if_iterator;
	char err_buf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	struct bpf_program fcode;
	pcap_t *adhandle;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int timeout_mili = 1000;
	pcap_dumper_t *dumpfile;

	/*Thread variable*/
	HANDLE hThread;
	/* */

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


	if ((adhandle = pcap_open(choosed_if->name, 65536, PCAP_OPENFLAG_PROMISCUOUS
		, timeout_mili, NULL, err_buf)) == NULL) {
		printf("Can't open adapter\n");
		return -1;
	}

	/* Open the dump file */
	dumpfile = pcap_dump_open(adhandle, DUMP_FILE);

	if (dumpfile == NULL)
	{
		fprintf(stderr, "\nError opening output file\n");
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

	pcap_freealldevs(network_interfaces);
	int res;
	//hThread = CreateThread(NULL, 0, MyThreadFunction, NULL, 0, 0);
	//pcap_dispatch(adhandle, 0, apacket_handler, NULL);
	/*while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
	if (res == 0) {
	continue;
	}

	pcap_dump((u_char *)dumpfile, header, pkt_data);

	}*/
	//while (true);
	remove(OUTPUT_DIR);
	remove(DUMP_FILE);
	fout = fopen(OUTPUT_DIR, "ab");
	pcap_loop(adhandle, 0, apacket_handler, NULL);
	getchar();
	return 1;
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

	int datasize = header->caplen - sizeof(ETHER_HDR) - ip_header.ip_header_len * 4 - tcp_header.data_offset * 4;

	//memcpy(data, pkt_data + sizeof(ETHER_HDR) + ip_header.ip_header_len * 4 + tcp_header.data_offset * 4, datasize);
	//print_data((const char*)pkt_data + sizeof(ETHER_HDR) + ip_header.ip_header_len * 4 + tcp_header.data_offset * 4, datasize);
	// packet nay co chua data file mp3
	if (little_to_big_endian(tcp_header.sequence) == next_seq_number) {
		//if (datasize == 1460){
		if (tcp_header.fin) {
			printf("Doneee\n");
			next_seq_number = 0;
		}
		else {
			save_music_data_to_file((const char*)pkt_data + sizeof(ETHER_HDR) + ip_header.ip_header_len * 4 + tcp_header.data_offset * 4, datasize);
			next_seq_number += datasize;
			//printf("Append to file\n");
			printf("\nSEQ: %u - next seq number: %u", little_to_big_endian(tcp_header.sequence), next_seq_number);
		}

	}

	if (is_mp3_packet((const char*)pkt_data + sizeof(ETHER_HDR) + ip_header.ip_header_len * 4 + tcp_header.data_offset * 4, datasize)) {
		next_seq_number = datasize + htonl(tcp_header.sequence);

		printf("\nSeq: %x - next_seq: %ud ", htonl(tcp_header.sequence), next_seq_number);
	}
}

DWORD WINAPI MyThreadFunction(LPVOID lpParam) {
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];


	/* Create the source string according to the new WinPcap syntax */
	if (pcap_createsrcstr(source,         // variable that will keep the source string
		PCAP_SRC_FILE,  // we want to open a file
		NULL,           // remote host
		NULL,           // port on the remote host
		DUMP_FILE,        // name of the file we want to open
		errbuf          // error buffer
	) != 0)
	{
		fprintf(stdout, "\nError creating a source string\n");
		return -1;
	}

	/* Open the capture file */
	if ((fp = pcap_open(source,         // name of the device
		65536,          // portion of the packet to capture
						// 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS,     // promiscuous mode
		1000,              // read timeout
		NULL,              // authentication on the remote machine
		errbuf         // error buffer
	)) == NULL)
	{
		fprintf(stdout, "\nUnable to open the file %s.\n", source);
		return -1;
	}

	// read and dispatch packets until EOF is reached
	pcap_loop(fp, 0, apacket_handler, NULL);
}

int is_mp3_packet(const char *data, int datasize) {
	const char *mp3_magic_byte = "ID3";
	const char *found_str = strstr(data, mp3_magic_byte);
	if (found_str != NULL) {
		printf("Write to file\n");
		remove(OUTPUT_DIR);
		save_music_data_to_file(found_str, datasize + data - found_str);
		return datasize;
	};

	return 0;
}

void print_data(const char *data, int datasize) {
	const char *mp3_magic_byte = "ID3";
	const char *found_str = strstr(data, mp3_magic_byte);
	if (found_str != NULL) {
		printf("Write to file\n");
		save_music_data_to_file(found_str, datasize + found_str - data);
	};
}

void save_music_data_to_file(const char *data, int datasize) {
	//fout = fopen(OUTPUT_DIR, "ab");
	printf("Len data %d", datasize);
	fwrite(data, sizeof(char), datasize, fout);
	//fclose(fout);
}

void save_data_to_log(const u_char *pkt_data, int datasize) {
	fout = fopen(LOG_DIR, "ab");

	//printf("Len data %d", datasize);
	IPV4_HDR *ih = (IPV4_HDR *)(pkt_data + 14); //length of ethernet header
	fprintf(fout, "%u -> %u len %d\n",
		ih->ip_srcaddr,
		ih->ip_destaddr,
		datasize
	);
	fclose(fout);
	if (ih->ip_srcaddr == 1698212032) {
		size += datasize;
		printf("\n curr_size: %u", size);
	}
}

void append_data_to_file(const char *data, int datasize, char *output) {
	fout = fopen(output, "ab");

	//printf("Len data %d", datasize);
	fwrite(data, sizeof(char), datasize, fout);

	fclose(fout);
}

unsigned int little_to_big_endian(unsigned int num) {
	unsigned int b0, b1, b2, b3;
	unsigned int res;

	b0 = (num & 0x000000ff) << 24u;
	b1 = (num & 0x0000ff00) << 8u;
	b2 = (num & 0x00ff0000) >> 8u;
	b3 = (num & 0xff000000) >> 24u;

	res = b0 | b1 | b2 | b3;
	return res;
}