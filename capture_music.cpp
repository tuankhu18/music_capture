#include "capture_music.h"
#include "common_macro.h"

#define OUTPUT_DIR "C:\\Users\\TuanNA2\\Desktop\\tmp\\capture.mp3"
#define LOG_DIR "C:\\Users\\TuanNA2\\Desktop\\tmp\\log.mp3"
#define DUMP_FILE "C:\\Users\\TuanNA2\\Desktop\\tmp\\packet.pcap"

FILE *fout;
//const char *file_name[] = { "sample.mp3", "sample2.mp3", "sample3.mp3" };
//int file_name_index = 0;
unsigned long next_seq_number = 0;
unsigned int size = 0;
PQUEUE packet_queue;
using namespace std;

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
	int timeout_mili = 10;
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


	if ((adhandle = pcap_open(choosed_if->name, 65536, PCAP_OPENFLAG_MAX_RESPONSIVENESS
		, timeout_mili, NULL, err_buf)) == NULL) {
		printf("Can't open adapter\n");
		return -1;
	}

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
	
	printf("listening.......\n");

	/* Open the dump file */
	remove(OUTPUT_DIR);
	remove(DUMP_FILE);
	dumpfile = pcap_dump_open(adhandle, DUMP_FILE);

	if (dumpfile == NULL)
	{
		fprintf(stderr, "\nError opening output file\n");
		return -1;
	}

	pcap_freealldevs(network_interfaces);
	int res;
	packet_queue = createQueue(8192);
	if (packet_queue == nullptr) {
		fprintf(stderr, "\nCant create queue for incoming packet\n");
		return -1;
	}
	hThread = CreateThread(NULL, 0, MyThreadFunction, NULL, 0, 0);
	//pcap_dispatch(adhandle, 0, apacket_handler, NULL);
	fout = fopen(OUTPUT_DIR, "ab");

	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (res == 0) {
			//printf("timeout ...\n");
			continue;
		}

		u_char *copy_pkt_data = (u_char*)malloc(sizeof(char) * header->caplen);
		memcpy(copy_pkt_data, pkt_data, sizeof(char) * header->caplen);
		enqueue(packet_queue, copy_pkt_data, header->caplen);
		pcap_dump((u_char *)dumpfile, header, pkt_data);

	}
	//while (true);
	
	////while (true) {
	//	pcap_dispatch(adhandle, 0, apacket_handler, (u_char*)dumpfile);
	//	WaitForMultipleObjects(1, &hThread, TRUE, INFINITE);
	////}
	
	getchar();
	return 1;
}

void create_queue() {
	packet_queue = (PQUEUE)malloc(sizeof(QUEUE));
	packet_queue->front = 0;
	packet_queue->rear = 0;
	packet_queue->size = 0;
}

void apacket_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	pcap_dump(dumpfile, header, pkt_data);
	u_char *copy_pkt_data = (u_char*)malloc(sizeof(char) * header->caplen);
	memcpy(copy_pkt_data, pkt_data, sizeof(char) * header->caplen);
	enqueue(packet_queue, copy_pkt_data, header->caplen);

}

DWORD WINAPI MyThreadFunction(LPVOID lpParam) {
	printf("Thread running.....");
	while (true) {
		ETHER_HDR eth_header;
		IPV4_HDR ip_header;
		TCP_HDR tcp_header;
		Pqueue_Entry queue_entry = dequeue(packet_queue);
		/*Check dequeue*/
		if (queue_entry == nullptr)
			continue;
		u_char *pkt_data = queue_entry->data;

		

		memcpy(&eth_header, pkt_data, sizeof(ETHER_HDR));
		memcpy(&ip_header, pkt_data + sizeof(ETHER_HDR), sizeof(IPV4_HDR));
		memcpy(&tcp_header, pkt_data + sizeof(ETHER_HDR) + sizeof(IPV4_HDR), sizeof(TCP_HDR));

		/*char ip_src[INET_ADDRSTRLEN], ip_dst[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(ip_header.ip_srcaddr), ip_src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ip_header.ip_destaddr), ip_dst, INET_ADDRSTRLEN);*/

		//printf("%s -> %s\n", ip_src, ip_dst);
		//printf("%d\n", tcp_header.data_offset);

		int datasize = queue_entry->pkt_size - sizeof(ETHER_HDR) - ip_header.ip_header_len * 4 - tcp_header.data_offset * 4;
		//int datasize = 1460;
		//memcpy(data, pkt_data + sizeof(ETHER_HDR) + ip_header.ip_header_len * 4 + tcp_header.data_offset * 4, datasize);
		//print_data((const char*)pkt_data + sizeof(ETHER_HDR) + ip_header.ip_header_len * 4 + tcp_header.data_offset * 4, datasize);
		// packet nay co chua data file mp3
		if (little_to_big_endian(tcp_header.sequence) == next_seq_number) {
			//if (datasize == 1460){
			if (tcp_header.fin) {
				printf("\nReceive doneee\n");
				next_seq_number = 0;
				fclose(fout);
			}
			else {
				save_music_data_to_file((const char*)pkt_data + sizeof(ETHER_HDR) + ip_header.ip_header_len * 4 + tcp_header.data_offset * 4, datasize);
				next_seq_number += datasize;
				//printf("Append to file\n");
				printf("\nSEQ: %u - next seq number: %u - current queue size: %d", little_to_big_endian(tcp_header.sequence), next_seq_number, packet_queue->size);
			}

		}
		else {
			if (is_mp3_packet((const char*)pkt_data + sizeof(ETHER_HDR) + ip_header.ip_header_len * 4 + tcp_header.data_offset * 4, datasize)) {
				next_seq_number = datasize + htonl(tcp_header.sequence);

				printf("\nSeq: %x - next_seq: %ud ", htonl(tcp_header.sequence), next_seq_number);
			}
		}

		/*Clean mem*/
		free(pkt_data);
		free(queue_entry);
	}
	return 1;
	
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