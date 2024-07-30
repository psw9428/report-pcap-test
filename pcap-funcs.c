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
    print_data(bundle->other_data);
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
    printf("------------------ip header------------------\n");
    printf("version : %s (0x%x)\n", \
            ip.version == 4 ? "IPv4" : \
            ip.version == 6 ? "IPv6" : \
            "Unknown", ip.version);
    printf("header length : %u byte\n", ip.header_len * 4);

    printf("| source ip : %u.%u.%u.%u | ", \
            ip.src_ip[0], ip.src_ip[1], ip.src_ip[2], ip.src_ip[3]);
    printf("destination ip : %u.%u.%u.%u |\n", \
            ip.dst_ip[0], ip.dst_ip[1], ip.dst_ip[2], ip.dst_ip[3]);
    printf("tos : %x\n", ip.tos);
    printf("total length (header + data) : %u byte\n", ip.total_len);
    printf("identification : 0x%x\n", ip.identification);
    printf("ip flag :");
    for (int i = 0; i < 3; i++) printf((ip.fragment_offset >> i) & 1 ? "1" : ".");
    printf("\nfragment offset : ");
    for (int i = 0; i < 13; i++) printf((ip.fragment_offset >> i) & 1 ? "1" : ".");
    printf("\nttl : %u\n", ip.ttl);
    printf("protocol : %s\n", \
            (ip.protocol == 1) ? "ICMP": \
            (ip.protocol == 6) ? "TCP" : \
            (ip.protocol == 17)? "UDP" : \
            "Unkown");
    printf("checksum : 0x%x\n", ip.header_checksum);    
}

void print_tcp_header(tcp_header tcp) {
    printf("-----------------tcp header------------------\n");
    printf("| source port : %u | ", tcp.src_port);
    printf("destination port : %u |\n", tcp.dst_port);
    printf("sequence number : %u\n", tcp.sequence_num);
    printf("acknowledgement number : %u\n", tcp.ack);
    printf("header length : %u byte\n", tcp.header_len * 4);
    printf("reserved : %x\n", tcp.reserved);
    printf("flags :");
    for (int i = 0; i < 8; i++) printf((tcp.flags >> i) & 1 ? "1" : ".");
    printf("\nwindow size : %u\n", tcp.window_size);
    printf("checksum : 0x%x\n", tcp.checksum);
    printf("urgent pointer : 0x%x\n", tcp.urgent_pointer);
}

void print_data(BYTE *ptr) {
    int len = strlen((char *)ptr);
    int i;
    printf("-----------------Data------------------");
    for (i = 0; i < 20 && i < len; i++) {
        if (i % 8 == 0) printf("\n");
        else if (i % 4 == 0) printf(" ");
        printf("0x%02x ", ptr[i]);
    }
    printf("\n\n");
}

ethernet_header *new_ethernet_header(BYTE *ptr) {
    ethernet_header *ethernet = (ethernet_header *)malloc(sizeof(ethernet_header));
    if (!ethernet) {
        printf("[*] new ip header memory allocation failed.\n");
        return (0);
    }
    
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
    if (!ip) {
        printf("[*] new ip header memory allocation failed.\n");
        return (0);
    }
    
    ip->version = (0b11110000 & (u_int8_t)ptr[0]) >> 4;
    ip->header_len = (0b00001111 & (u_int8_t)ptr[0]);
    // if ((int)(ip->header_len) * 4 != 20) {
    //     printf("[*] IP header is not 20 byte\n");
    //     safe_free(ip, sizeof(ip_header));
    //     return (0);
    // }

    ptr++;

    ip->tos = ptr[0];
    ptr++;
    memcpy(&(ip->total_len), ptr, 2);
    endian_switch(&(ip->total_len), 2);
    ptr += 2;
    memcpy(&(ip->identification), ptr, 2);
    endian_switch(&(ip->identification), 2);
    ptr += 2;

    ip->ip_flag = (u_int8_t)ptr[0] >> 5;
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
    if (!tcp) {
        printf("[*] new tcp header memory allocation failed.\n");
        return (0);
    }

    tcp->src_port = ((u_int16_t *)ptr)[0];
    endian_switch(&(tcp->src_port), sizeof(u_int16_t));
    ptr += 2;
    tcp->dst_port = ((u_int16_t *)ptr)[0];
    endian_switch(&(tcp->dst_port), sizeof(u_int16_t));
    ptr += 2;
    tcp->sequence_num = ((u_int32_t *)ptr)[0];
    ptr += 4;
    tcp->ack = ((u_int32_t *)ptr)[0];
    ptr += 4;
    tcp->header_len = (u_int8_t)ptr[0] >> 4;
    tcp->reserved = (u_int8_t)ptr[0] & 0b1111;
    ptr++;
    tcp->flags = (u_int8_t)ptr[0];
    ptr++;
    tcp->window_size = ((u_int16_t *)ptr)[0];
    tcp->checksum = ((u_int16_t *)ptr)[1];
    tcp->urgent_pointer = ((u_int16_t *)ptr)[2];
    endian_switch(&(tcp->window_size), sizeof(u_int16_t));
    endian_switch(&(tcp->urgent_pointer), sizeof(u_int16_t));

    // if ((int)(tcp->offset) * 4 != 20) {
    //     printf("[*] TCP header is not 20 byte\n");
    //     safe_free(tcp, sizeof(ip_header));
    //     return (0);
    // }

    return (tcp);
}

packet_bundle *new_packet_bundle(BYTE *ptr) {
    packet_bundle *bundle = (packet_bundle *)malloc(sizeof(packet_bundle));
    if (!bundle) {
        printf("[*] new pack bundle memory allocation failed.\n");
        return (0);
    }
    memset(bundle, 0, sizeof(packet_bundle));

    bundle->clean = clean_packet_bundle;
    bundle->print_info = print_packet_structure;

    bundle->ethernet = new(ethernet_header, ptr);
    if (!bundle->ethernet) return (bundle->clean(bundle));

    bundle->ip = new(ip_header, ptr + ETHERNET_HEADER_SIZE);
    if (!bundle->ip) return (bundle->clean(bundle));
    if (bundle->ip->protocol != 6) {
        printf("[*] This packet is not TCP!\n");
        return (bundle->clean(bundle));
    }

    bundle->tcp = new(tcp_header, ptr + ETHERNET_HEADER_SIZE + (bundle->ip->header_len * 4));
    if (!bundle->tcp) return (bundle->clean(bundle));

    BYTE *data_ptr = ptr+ETHERNET_HEADER_SIZE+(4*bundle->ip->header_len)+(4*bundle->tcp->header_len);
    bundle->other_data = (BYTE *)malloc(strlen((char *)data_ptr) + 1);
    if (!bundle->other_data) return (bundle->clean(bundle));
    strcpy((char *)(bundle->other_data), (char *)data_ptr);

    bundle->this = bundle;

    return (bundle);
}

packet_bundle *clean_packet_bundle(packet_bundle *this) {
    if (this->ethernet) safe_free(this->ethernet, sizeof(this->ethernet));
    this->ethernet = NULL;
    if (this->ip) safe_free(this->ip, sizeof(this->ip));
    this->ip = NULL;
    if (this->tcp) safe_free(this->tcp, sizeof(this->tcp));
    this->tcp = NULL;
    if (this->other_data) safe_free(this->other_data, strlen((char *)(this->other_data)) + 1);
    this->other_data = NULL;
    if (this->this) safe_free(this->this, sizeof(this->this));
    this->this = NULL;
    return (0);
}