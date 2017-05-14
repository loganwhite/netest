#include <stdio.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <stdlib.h>

#define	BUF_SIZ	4096

typedef struct iphdr    iphdr;
typedef struct tcphdr   tcphdr;
typedef struct udphdr   udphdr;
typedef struct icmphdr  icmphdr;

void analyseIP(iphdr* ip);
void analyseTCP(tcphdr* tcp);
void analyseUDP(udphdr* udp);
void analyseICMP(icmphdr* icmp);

void make_tcp_packet(tcphdr* tcp);
struct sockaddr_in generate_addr(u_int32_t addr);
u_int32_t get_saddr(iphdr* ip);

void swap(u_int16_t *a, u_int16_t *b);
u_int16_t checksum(unsigned short* buf, int size);

int
main(int argc, char** argv)
{
    int sockfd;
    iphdr* ip;
    char buf[BUF_SIZ];
    int n;
    u_int32_t saddr;
    struct sockaddr_in addr;

    if ((sockfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) == -1) {
    	printf("error open socket!\n");
    	exit(1);
    }

    while(1) {
        n = recv(sockfd, buf, sizeof(buf), 0); 
        if (n < 0) {
            printf("error receiving data\n");
            exit(1);
        } else if (n == 0) continue;
        ip = (iphdr*)buf;
        
        
        if (ip->protocol == IPPROTO_TCP) {
            analyseIP(ip);
            saddr = get_saddr(ip);
            addr = generate_addr(saddr);
            size_t iphdr_len = ip->ihl;
            tcphdr* tcp = (tcphdr*)(buf + iphdr_len);
            analyseTCP(tcp);
            make_tcp_packet(tcp);
            analyseTCP(tcp);
            if ((n = sendto(sockfd, (char*)tcp, sizeof(tcphdr), 0, (struct sockaddr*)&addr, sizeof(addr))) == -1) {
                printf("error send packet!\n");
                exit(1);
            }

            printf("\n\n");

        }/* else if (ip->protocol == IPPROTO_UDP) {
            udphdr* udp = (udphdr*)(buf + iphdr_len);
            analyseUDP(udp);
        } else if (ip->protocol == IPPROTO_ICMP) {
            icmphdr* icmp = (icmphdr*)(buf + iphdr_len);
            analyseICMP(icmp);
        } else printf("Other protocols!\n");*/        
    }
    close(sockfd);
    exit(0);

}

void analyseIP(iphdr* ip) 
{
    unsigned char*p = (unsigned char*)&ip->saddr;
    printf("Source IP\t: %u.%u.%u.%u\n",p[0],p[1],p[2],p[3]);
    p = (unsigned char*)&ip->daddr;
    printf("Destination IP\t: %u.%u.%u.%u\n",p[0],p[1],p[2],p[3]);
}

void analyseTCP(tcphdr* tcp) 
{
    printf("TCP ----- \n");
    printf("Source port: %u\n", ntohs(tcp->th_sport));
    printf("Dest port: %u\n", ntohs(tcp->th_dport));
}

/*void analyseUDP(udphdr* udp) 
{
    printf("UDP ----- \n");
    printf("Source port: %u\n", ntohs(udp->uh_sport));
    printf("Dest port: %u\n", ntohs(udp->uh_dport));
}

void analyseICMP(icmphdr* icmp) 
{
    printf("ICMP ----- \n");
    printf("type: %u\n", icmp->type);
    printf("sub code: %u\n", icmp->code);
}

void make_ip_packet(iphdr* ip) 
{
    swap(&ip->saddr, &ip->daddr);
    ip->ttl = 255;
    ip->check = checksum((unsigned short*)ip, sizeof(iphdr));
}*/

void make_tcp_packet(tcphdr* tcp)
{
    swap(&tcp->th_sport, &tcp->th_dport);
    tcp->th_flags = TH_RST;
    tcp->th_sum = checksum((unsigned short*)tcp, sizeof(tcphdr));
}

u_int16_t checksum(unsigned short* buf, int size) 
{
    unsigned long sum = 0;
	while (size > 1) {
		sum += *buf;
		buf++;
		size -= 2;
	}
	if (size == 1)
		sum += *(unsigned char *)buf;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}

struct sockaddr_in generate_addr(u_int32_t addr)
{
    struct sockaddr_in sock_addr;
    struct in_addr inet_addr;
    inet_addr.s_addr = addr;
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr = inet_addr;
    return sock_addr;
}

u_int32_t get_saddr(iphdr* ip)
{
    return ip->saddr;
}

void swap(u_int16_t *a, u_int16_t *b)
{
    u_int16_t tmp = *a;
    *a = *b;
    *b = tmp;
}