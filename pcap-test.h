#ifndef PCAP_TEST_H
#define PCAP_TEST_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <stdbool.h>

#define ETHERNET_HEADER_SIZE 14
#define IP_HEADER_SIZE 20
#define TCP_HEADER_SIZE 20

#define IPv4_ETHER_TYPE 0x800
#define IPv6_ETHER_TYPE 0x86DD
#define ARP_ETHER_TYPE 0x806

#define VERSION_IPv4 4
#define VERSION_IPv6 6

#define new(type, data_ptr) _Generic((type){0}, \
    ethernet_header: new_ethernet_header, \
    ip_header: new_ip_header, \
    tcp_header: new_tcp_header, \
    packet_bundle: new_packet_bundle)(data_ptr)

typedef unsigned char BYTE;
typedef unsigned char u_char;
typedef unsigned short u_short;

typedef struct _ethernet_header {
	BYTE dst_mac[6];
	BYTE src_mac[6];
    u_int16_t ether_type;
} ethernet_header;

typedef struct _ip_header {
	u_int8_t version : 4;  // ipv4 : 4, ipv6 : 6
    u_int8_t header_len : 4; // header_len * 4 : header length (byte)
    BYTE tos;  // order
    u_int16_t total_len;  // header+data length (byte)
    u_int16_t identification;  // packet id
    u_int8_t ip_flag : 3;  // first bit is 0, second : Is it fragment?, third : more fragment?
    u_int16_t fragment_offset : 13;  // offset of fragmented packets
    u_int8_t ttl;  // window : 128, linux : 64, other os : 255
    u_int8_t protocol; // 1 : ICMP, 6 : TCP, 17(0x11) : UDP
    u_int16_t header_checksum; // checksum
    BYTE src_ip[4];
    BYTE dst_ip[4];
    //BYTE ip_option[8]; // padding value
} ip_header;

typedef struct _tcp_header {
    u_int16_t src_port;
    u_int16_t dst_port;
    u_int32_t sequence_num;  // order num
    u_int32_t ack;  // acknowledgment number
    u_int8_t header_len : 4;  //data offsest : start of tcp segment (size of tcp header = 4 * offset)
    u_int8_t reserved :4;
    u_int8_t flags; 
    u_int16_t window_size;
    u_int16_t checksum;
    u_int16_t urgent_pointer;
} tcp_header;

typedef struct _packet_bundle {
    ethernet_header *ethernet;
    ip_header *ip;
    tcp_header *tcp;
    BYTE *other_data;
    struct _packet_bundle *this;
    int (* print_info)(struct _packet_bundle *);
    struct _packet_bundle *(* clean)(struct _packet_bundle *);
} packet_bundle;

void endian_switch(void *data_ptr, size_t size);
void safe_free(void *ptr, size_t size);

int print_packet_structure(packet_bundle *bundle);
void print_ethernet_header(ethernet_header ethernet);
void print_ip_header(ip_header ip);
void print_tcp_header(tcp_header tcp);
void print_data(BYTE *ptr);
ethernet_header *new_ethernet_header(BYTE *ptr);
ip_header *new_ip_header(BYTE *ptr);
tcp_header *new_tcp_header(BYTE *ptr);
packet_bundle *new_packet_bundle(BYTE *ptr);
packet_bundle *clean_packet_bundle(packet_bundle *this);

void usage();

#endif