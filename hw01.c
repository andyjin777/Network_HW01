#include<pcap.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

struct sockaddr_in source,dest;

int main(int argc, char *argv[]) {
    
     char *dev = argv[1];
     char error_buf[100];
     pcap_t *handle;
     
     handle = pcap_open_live(dev , 65536 , 1 , 0 , error_buf);
         
     if (handle == NULL) {
        printf("error device not open %s : %s\n" , dev , error_buf);
        exit(1);
    }
    
    pcap_loop(handle , -1 , process_packet , NULL);
    
    return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer) {

    int size = header->len;
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));

    if(iph->protocol == 6) {

        unsigned short iphdrlen;

        struct iphdr *iph = (struct iphdr *)( buffer  + sizeof(struct ethhdr) );
        iphdrlen = iph->ihl*4;

        struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
        int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
        struct ethhdr *eth = (struct ethhdr *)buffer;
        
        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = iph->saddr;

        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = iph->daddr;
        
        printf("eth.smac : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
        printf("eth.dmac : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
        printf("ip.sip : %s\n" , inet_ntoa(source.sin_addr) );
        printf("ip.dip : %s\n" , inet_ntoa(dest.sin_addr) );
        printf("tcp.sport: %u\n",ntohs(tcph->source));
        printf("tcp.dport: %u\n",ntohs(tcph->dest));
        printf("----------------------------\n");

    }

}
