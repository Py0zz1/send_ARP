#include <pcap.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>


#define BUF_SIZE 100
#define IP_HEADER_JMP 14
#define TCP_HEADER_JMP 20
#define DATA_JMP 20
#define SNAPLEN 65536
struct ether_add
{
    unsigned char mac_add[6];
};
struct ether_header
{
    struct ether_add src_mac;
    struct ether_add des_mac;
    unsigned short eth_type;
    //14bytes
};

struct ip_header
{
    unsigned char ip_version : 4;
    unsigned char ip_header_length : 4;
    unsigned char ip_TOS;
    unsigned short ip_total_length;
    unsigned short ip_iden;
    unsigned char flag_x : 1;
    unsigned char flag_D : 1;
    unsigned char flag_M : 1;
    unsigned char offset_part_1 : 5;
    unsigned char offset_part_2;
    unsigned char TTL;
    unsigned char ip_protocol;
    unsigned short chk_sum;
    struct in_addr ip_src_add;
    struct in_addr ip_des_add;
    //20bytes
};

struct tcp_header
{
    unsigned short src_port;
    unsigned short des_port;
    unsigned long sqn_num;
    unsigned long ack_num;
    unsigned char offset : 4;
    unsigned char ns : 1;
    unsigned char reserve : 3;
    unsigned char flag_cwr : 1;
    unsigned char flag_ece : 1;
    unsigned char flag_urgent : 1;
    unsigned char flag_ack : 1;
    unsigned char flag_push : 1;
    unsigned char flag_reset : 1;
    unsigned char flag_syn : 1;
    unsigned char flag_fin : 1;
    unsigned short window;
    unsigned short chk_sum;
    unsigned short urgent_point;
    //20bytes
};

void print_ether_header(const unsigned char *pkt_data);
void print_ip_header(const unsigned char *pkt_data);
void print_tcp_header(const unsigned char *pkt_data);
void print_data(const unsigned char *pkt_data);

int main(int argc, char **argv)
{
    pcap_if_t *alldevs = NULL;
    pcap_if_t *dev;
    pcap_t *use_dev;
    char errbuf[BUF_SIZE];
    char FILTER_RULE[BUF_SIZE]="tcp";
    struct bpf_program rule_struct;
    int i,dev_num,res;
    struct pcap_pkthdr *header;
    const unsigned char *pkt_data;

    //port설정 인자값이 있으면 port룰 설정
    //없으면, 모든 패킷 감청
    if (argv[1])
    {
        strcpy(FILTER_RULE, "port ");
        strcat(FILTER_RULE, argv[1]); // FILTER_RULE (port)설정
    }


    if (pcap_findalldevs(&alldevs, errbuf) < 0)
    {
        printf("Device Find Error\n");
        return -1;
    }

    for (dev = alldevs, i = 0; dev != NULL; dev = dev->next)
        printf("%d번 Device : %s (%s)\n", ++i, dev->name,dev->description);

    printf("사용할 디바이스 번호 입력 : ");
    scanf("%d", &dev_num);

    for (dev = alldevs, i = 0; i < dev_num-1;  dev = dev->next,i++);

    if ((use_dev = pcap_open_live(dev->name, SNAPLEN, 1, 1000, errbuf)) == NULL)
    {
        printf("pcap_open ERROR!\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    printf("pcap_open 성공!\n");
    printf("FILTER_RULE : %s\n", FILTER_RULE);
    //////////                    pcap_open_success                ////////////


    if (pcap_compile(use_dev, &rule_struct, FILTER_RULE, 1, NULL) < 0)
    {
        printf("pcap_compile ERROR!\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    if (pcap_setfilter(use_dev, &rule_struct) < 0)
    {
        printf("pcap_setfilter ERROR!\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    pcap_freealldevs(alldevs); //캡처 네트워크를 제외한 네트워크 해제


    while ((res = pcap_next_ex(use_dev, &header, &pkt_data)) >= 0)
    {
        if (res == 0) continue;

        print_ether_header(pkt_data);
        pkt_data += IP_HEADER_JMP;
        print_ip_header(pkt_data);
        pkt_data += TCP_HEADER_JMP;
        print_tcp_header(pkt_data);
        pkt_data += DATA_JMP;
        print_data(pkt_data);
    }

}



///////////////////////////////////print_function///////////////////////////////////////
void print_ether_header(const unsigned char *pkt_data)
{
    struct ether_header *eh;
    eh = (struct ether_header *)pkt_data;
    unsigned short ether_type = ntohs(eh->eth_type);
    if (ether_type == 0x0800) printf("===== IPv4 =====\n");
    printf("Src MAC : ");
    for (int i = 0; i <= 5; i++) printf("%02x ", eh->src_mac.mac_add[i]);
    printf("\nDes MAC : ");
    for (int i = 0; i <= 5; i++)printf("%02x ", eh->des_mac.mac_add[i]);
    printf("\n");
}

void print_ip_header(const unsigned char *pkt_data)
{
    struct ip_header *ih;
    ih = (struct ip_header *)pkt_data;
    if (ih->ip_protocol == 0x06)
    {
        printf("(TCP)");
        printf("Src IP : %s\n",inet_ntoa(ih->ip_src_add));
        printf("(TCP)");
        printf("Des IP : %s\n", inet_ntoa(ih->ip_des_add));
    }
    if (ih->ip_protocol == 0x17)
    {
        printf("(UDP)");
        printf("Src IP : %s\n", inet_ntoa(ih->ip_src_add));
        printf("(UDP)");
        printf("Des IP : %s\n", inet_ntoa(ih->ip_des_add));
    }
}
void print_tcp_header(const unsigned char *pkt_data)
{
    struct tcp_header *th;
    th = (struct tcp_header *)pkt_data;

    printf("Src Port : %d\n", ntohs(th->src_port));
    printf("Des Port : %d\n", ntohs(th->des_port));
}

void print_data(const unsigned char *pkt_data)
{
    printf("Data : \n%s\n",pkt_data);
    printf("====================\n\n");
}
