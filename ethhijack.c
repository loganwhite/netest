#include <stdio.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <stdlib.h>

#define	BUF_SIZ	4096

typedef struct iphdr    iphdr;
typedef struct tcphdr   tcphdr;
typedef struct udphdr   udphdr;
typedef struct icmphdr  icmphdr;
typedef struct ether_header ethhdr;

static u_int8_t mymac[] = {0x74,0x27,0xea,0xac,0x80,0x3c};

void analyseIP(iphdr* ip);
void analyseTCP(tcphdr* tcp);
void analyseUDP(udphdr* udp);
void analyseICMP(icmphdr* icmp);

void make_tcp_packet(tcphdr* tcp);
void make_ip_packet(iphdr* ip);
struct sockaddr_in generate_addr(u_int32_t addr);
u_int32_t get_saddr(iphdr* ip);
u_int8_t* get_mac_source_addr(ethhdr* eth);

void swap(u_int16_t *a, u_int16_t *b);
void swap_u32(u_int32_t*a, u_int32_t *b);
u_int16_t checksum(unsigned short* buf, int size);
void print_mac(u_int8_t* mac);
void maccpy(u_int8_t* src, u_int8_t* dst);

int
main(int argc, char** argv)
{
    int sockfd;
    ethhdr* eth;
    iphdr* ip;
    char buf[BUF_SIZ];
    int n;
    u_int32_t saddr;
    struct sockaddr_ll socket_address;

    if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
    	printf("error open socket!\n");
    	exit(1);
    }

    while(1) {
        n = recv(sockfd, buf, sizeof(buf), 0); 
        if (n < 0) {
            printf("error receiving data\n");
            exit(1);
        } else if (n == 0) continue;
        
        ethhdr *eth = (ethhdr *) buf;
	    iphdr *ip = (iphdr *) (buf + sizeof(ethhdr));
	    tcphdr *tcp = (tcphdr *) (buf + sizeof(iphdr) + sizeof(ethhdr));


        if (ip->protocol == IPPROTO_TCP) {
            int send_sockfd;
            int len = 0;
            u_int8_t* smac = get_mac_source_addr(eth);
            print_mac(smac);
            maccpy(eth->ether_shost, eth->ether_dhost);
            maccpy(mymac, eth->ether_shost);
            analyseIP(ip);
            make_ip_packet(ip);
            analyseIP(ip);
            
            analyseTCP(tcp);
            make_tcp_packet(tcp);
            analyseTCP(tcp);
            len += (sizeof(ethhdr) + sizeof(iphdr) + sizeof(tcphdr));
            if ((send_sockfd = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
            	printf("error open socket!\n");
            	exit(1);
            }

            socket_address.sll_ifindex = 0;
                /* Address length*/
            socket_address.sll_halen = ETH_ALEN;
                /* Destination MAC */
            socket_address.sll_addr[0] = mymac[0];
            socket_address.sll_addr[1] = mymac[1];
            socket_address.sll_addr[2] = mymac[2];
            socket_address.sll_addr[3] = mymac[3];
            socket_address.sll_addr[4] = mymac[4];
            socket_address.sll_addr[5] = mymac[5];

            if ((n = sendto(send_sockfd, buf, len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll))) == -1) {
                printf("error send packet!\n");
                close(send_sockfd);
                /*exit(1);*/
            } else close(send_sockfd);

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
*/
void make_ip_packet(iphdr* ip) 
{
    swap_u32(&ip->saddr, &ip->daddr);
    ip->ttl = 254;
    ip->check = checksum((unsigned short*)ip, sizeof(iphdr));
}

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

void swap_u32(u_int32_t *a, u_int32_t *b)
{
    u_int32_t tmp = *a;
    *a = *b;
    *b = tmp;
}

u_int8_t* get_mac_source_addr(ethhdr* eth)
{
    return eth->ether_shost;
}

void print_mac(u_int8_t* mac)
{
    int i;
    printf("mac -------\n");
    for (i = 0; i < 6; i++) 
        printf("%02x%c", mac[i], i == 5 ? '\n' : ':');
    printf("end of mac -------\n");
}

void maccpy(u_int8_t* src, u_int8_t* dst)
{
    int i;
    for (i = 0; i < 6; i++,*dst = *src) ;
}