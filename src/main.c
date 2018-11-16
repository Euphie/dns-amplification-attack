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

// 重新定义IP头部和UDP头部
typedef struct iphdr iph;
typedef struct udphdr udph;

// 定义伪头部，用于计算校验和
typedef struct
{
    u_int32_t saddr;
    u_int32_t daddr;
    u_int8_t filler;
    u_int8_t protocol;
    u_int16_t len;
}ps_hdr;

// DNS头部
typedef struct
{
    unsigned short id;
    unsigned short flags;
    unsigned short qcount;
    unsigned short ans;
    unsigned short auth;
    unsigned short add;
}dns_hdr;

// DNS询问
typedef struct
{
    unsigned short qtype;
    unsigned short qclass;
} question;

// 创建一个DNS头部
void create_dns_hdr(dns_hdr* dns)
{
    dns->id = (unsigned short) htons(getpid());
    dns->flags = htons(0x0100);
    dns->qcount = htons(1);
    dns->ans = 0;
    dns->auth = 0;
    dns->add = 0;
}

// www.google.com会变成3www6google3com
void format_dns_name(unsigned char* format,unsigned char* host)
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

int main() {
    // DNS报文
    unsigned char dns_data[128];
    
    // DNS头部
    dns_hdr* hdr;
    hdr = (dns_hdr*)dns_data;
    create_dns_hdr(hdr);
    
    // DNS查询
    // DNS查询分3部分：qname、qtype、qclass
    
    // qname
    unsigned char* qname;
    qname =(unsigned char*)&dns_data[sizeof(hdr)];
    unsigned char host[14] = "pan.baidu.com";
    format_dns_name(qname, host);
    
    // qtype和qclass
    question* ques;
    ques =(question*)&dns_data[sizeof(hdr) + (strlen((const char*)qname) + 1)];
    ques->qtype = htons(1);
    ques->qclass = htons(1);
    
    // 准备查询
    int fd;
    struct sockaddr_in dest;
    fd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP);
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr("114.114.114.114"); //dns servers
    
    printf("\nSending Packet...\n");
    if( sendto(fd, (char*)dns_data, sizeof(dns_hdr) + (strlen((const char*)qname) + 1) + sizeof(question), 0 ,(struct sockaddr*)&dest,sizeof(dest)) < 0)
    {
        perror("sendto failed\n");
    }
    
    printf("Done\n");
    printf("1234");
}
