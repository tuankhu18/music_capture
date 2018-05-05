#pragma once
#define WIN32
#define HAVE_REMOTE
#define WPCAP
#define _CRT_SECURE_NO_WARNINGS

#include "pcap.h"
#include <stdio.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <string.h>

#pragma comment(lib,"Ws2_32.lib")
//Ethernet Header
typedef struct ethernet_header
{
	UCHAR dest[6]; //Total 48 bits
	UCHAR source[6]; //Total 48 bits
	USHORT type; //16 bits
}   ETHER_HDR, *PETHER_HDR, FAR * LPETHER_HDR, ETHERHeader;

typedef struct ip_hdr {
	unsigned char  ip_header_len : 4;
	unsigned char  ip_version : 4;
	unsigned char  ip_tos;
	unsigned short ip_total_length;
	unsigned short ip_id;

	unsigned char  ip_frag_offset : 5;

	unsigned char  ip_more_fragment : 1;
	unsigned char  ip_dont_fragment : 1;
	unsigned char  ip_reserved_zero : 1;

	unsigned char  ip_frag_offset1;

	unsigned char  ip_ttl;
	unsigned char  ip_protocol;
	unsigned short ip_checksum;
	unsigned int   ip_srcaddr;
	unsigned int   ip_destaddr;
}   IPV4_HDR, *PIPV4_HDR, FAR * LPIPV4_HDR, IPHeader;

// TCP header
typedef struct tcp_header
{
	unsigned short source_port;
	unsigned short dest_port;
	unsigned int sequence;
	unsigned int acknowledge;

	unsigned char ns : 1;
	unsigned char reserved_part1 : 3;
	unsigned char data_offset : 4;

	unsigned char fin : 1;
	unsigned char syn : 1;
	unsigned char rst : 1;
	unsigned char psh : 1;
	unsigned char ack : 1;
	unsigned char urg : 1;

	unsigned char ecn : 1;
	unsigned char cwr : 1;



	unsigned short window;
	unsigned short checksum;
	unsigned short urgent_pointer;
} TCP_HDR, *PTCP_HDR, FAR * LPTCP_HDR, TCPHeader, TCP_HEADER;

typedef struct thread_params {
	u_char *param;
	const struct pcap_pkthdr *header;
	const u_char *pkt_data;
} THR_PARAM, *PTHR_PARAM;

const char *filter_expression = "ip";

/* function propertype */
void print_data(const char *data, int datasize);
int is_mp3_packet(const char *data, int datasize);
void apacket_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void save_music_data_to_file(const char *data, int datasize);
unsigned int little_to_big_endian(unsigned int num);
void save_data_to_log(const u_char *data, int datasize);
void append_data_to_file(const char *data, int datasize, char *output);
DWORD WINAPI MyThreadFunction(LPVOID lpParam);