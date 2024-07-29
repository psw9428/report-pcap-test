#ifndef PCAP_TEST_H
# include "pcap-test.h"
#endif

#define ethernet_type(x) ( \
    (x) == IPv4_ETHER_TYPE ? "IPv4" : \
    (x) == IPv6_ETHER_TYPE ? "IPv6" : \
    (x) == ARP_ETHER_TYPE ? "ARP" : \
    "Unknown")

int print_packet_structure(packet_bundle *bundle) {
    print_ethernet_header(*(bundle->ethernet));
    print_ip_header(*(bundle->ip));
    print_tcp_header(*(bundle->tcp));
    return (0);
}

void print_ethernet_header(ethernet_header ethernet) {
    printf("+-----------------------------------------------+\n");
    printf("|    destination_mac    |       source_mac      |\n");
    printf("+-----------------------------------------------+\n");
    printf("|   %02x:%02x:%02x:%02x:%02x:%02x   |   %02x:%02x:%02x:%02x:%02x:%02x   |\n", \
            ethernet.dst_mac[0], ethernet.dst_mac[1], ethernet.dst_mac[2], ethernet.dst_mac[3], ethernet.dst_mac[4], ethernet.dst_mac[5],\
            ethernet.src_mac[0], ethernet.src_mac[1], ethernet.src_mac[2], ethernet.src_mac[3], ethernet.src_mac[4], ethernet.src_mac[5]);
    printf("+-----------------------------------------------+\n");
    printf("ether type : %s (0x%x) \n", ethernet_type(ethernet.ether_type), ethernet.ether_type);
}

void print_ip_header(ip_header ip) {
    //printf("version : %s\n");
    printf("source ip : %d.%d.%d.%d\n", \
            ip.src_ip[0], ip.src_ip[1], ip.src_ip[2], ip.src_ip[3]);
    printf("destination ip : %d.%d.%d.%d\n", \
            ip.dst_ip[0], ip.dst_ip[1], ip.dst_ip[2], ip.dst_ip[3]);
}

void print_tcp_header(tcp_header tcp) {
    printf("source port : %d\n", tcp.src_port);
    printf("destination port : %d\n", tcp.dst_port);
}

ethernet_header *new_ethernet_header(BYTE *ptr) {
    ethernet_header *ethernet = (ethernet_header *)malloc(sizeof(ethernet_header));
    if (!ethernet) return (0);
    
    memcpy(ethernet->dst_mac, ptr, 6);
    ptr += 6;
    memcpy(ethernet->src_mac, ptr, 6);
    ptr += 6;
    memcpy(&(ethernet->ether_type), ptr, 2);
    endian_switch(&(ethernet->ether_type), 2);
    
    return (ethernet);
}

ip_header *new_ip_header(BYTE *ptr) {
    ip_header *ip = (ip_header *)malloc(sizeof(ip_header));
    if (!ip) return (0);
    
    ip->version = (0b11110000 & (u_int8_t)ptr[0]) >> 4;
    ip->header_len = (0b00001111 & (u_int8_t)ptr[0]);
    ptr++;

    ip->tos = ptr[0];
    ptr++;
    memcpy(&(ip->total_len), ptr, 2);
    endian_switch(&(ip->total_len), 2);
    ptr += 2;
    memcpy(&(ip->identification), ptr, 2);
    endian_switch(&(ip->identification), 2);
    ptr += 2;

    ip->ip_flag = ((u_int8_t)ptr[0] & 0b11100000) >> 5;
    ip->fragment_offset = ((u_int16_t *)ptr)[0] & 0xff33;
    ptr += 2;
    ip->ttl = (u_int8_t)ptr[0];
    ptr++;
    ip->protocol = (u_int8_t)ptr[0];
    ptr++;
    ip->header_checksum = ((u_int16_t *)ptr)[0];
    ptr += 2;
    memcpy(ip->src_ip, ptr, 4);
    ptr += 4;
    memcpy(ip->dst_ip, ptr, 4);
    ptr += 4;
    return (ip);
}

tcp_header *new_tcp_header(BYTE *ptr) {
    tcp_header *tcp = (tcp_header *)malloc(sizeof(tcp_header));
    if (!tcp) return (0);

    tcp->src_port = ((u_int16_t *)ptr)[0];
    ptr += 2;
    tcp->dst_port = ((u_int16_t *)ptr)[0];
    ptr += 2;
    tcp->sequence_num = ((u_int32_t *)ptr)[0];
    ptr += 4;
    tcp->ack = ((u_int32_t *)ptr)[0];

    return (tcp);
}

packet_bundle *new_packet_bundle(BYTE *ptr) {
    packet_bundle *bundle = (packet_bundle *)malloc(sizeof(packet_bundle));

    bundle->clean = clean_packet_bundle;
    bundle->print_info = print_packet_structure;

    bundle->ethernet = new(ethernet_header, ptr);
    if (!bundle->ethernet) return (bundle->clean(bundle));

    bundle->ip = new(ip_header, ptr + ETHERNET_HEADER_SIZE);
    if (!bundle->ip) return (bundle->clean(bundle));

    bundle->tcp = new(tcp_header, ptr + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE);
    if (!bundle->tcp) return (bundle->clean(bundle));
    bundle->this = bundle;

    return (bundle);
}

packet_bundle *clean_packet_bundle(packet_bundle *this) {
    if (this->ethernet) safe_free(this->ethernet, sizeof(this->ethernet));
    if (this->ip) safe_free(this->ip, sizeof(this->ip));
    if (this->tcp) safe_free(this->tcp, sizeof(this->tcp));
    if (this->this) safe_free(this->this, sizeof(this->this));
    return (0);
}