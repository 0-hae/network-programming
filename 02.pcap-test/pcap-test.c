#include "pcap-test.h"

Param param  = {
	.dev_ = NULL
};

void structuralization(MY_PCAP *mp, const u_char* packet);
void printMP(MY_PCAP *mp);
bool is_tcpip(MY_PCAP *mp);

int main(int argc, char* argv[]) {
	MY_PCAP *mp = (MY_PCAP*)malloc(sizeof(MY_PCAP));
	mp->structuralization = structuralization;
	mp->printMP = printMP;
	mp->is_tcpip = is_tcpip;

	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 0, 1000, errbuf);

	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		u_char* ptr;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		mp->structuralization(mp, packet);
		if(mp->is_tcpip(mp))
			mp->printMP(mp);
		else
			printf("Not a tcp/ip packet\n\n");

		//printf("%u bytes captured\n", header->caplen);
	}

	free(mp);
	pcap_close(pcap);
}

void structuralization(MY_PCAP *mp, const u_char* packet){
	u_char *ptr;
	ptr = (u_char*)packet;
	mp->eth = (struct libnet_ethernet_hdr *) ptr;
	ptr += sizeof(struct libnet_ethernet_hdr);
	mp->ip = (struct libnet_ipv4_hdr *) ptr;
	ptr += sizeof(struct libnet_ipv4_hdr);
	mp->tcp = (struct libnet_tcp_hdr *) ptr;
	ptr += sizeof(struct libnet_tcp_hdr);
	mp->payload = (uint8_t *) ptr;
	mp->payload_len = ntohs(mp->ip->ip_len) - ((mp->ip->ip_hl)*4+(mp->tcp->th_off)*4);
}//ip total len - (ip hdr len - data offset)  

void printMP(MY_PCAP *mp){
	printf("============ ETH ============\n");
	printf("Src MAC : ");
	for(int i=0; i<ETHER_ADDR_LEN;i++){
		printf("%02x ", mp->eth->ether_shost[i]);
	}printf("\nDst MAC : ");
	for(int i=0; i<ETHER_ADDR_LEN;i++){
		printf("%02x ", mp->eth->ether_dhost[i]);
	}printf("\n\n");

	printf("============ IP ============\n");
	printf("Src IP : %s\n", inet_ntoa(mp->ip->ip_src));
	printf("Dst IP : %s\n\n", inet_ntoa(mp->ip->ip_dst));

	printf("============ TCP ============\n");
	printf("Src Port : %d\n", ntohs(mp->tcp->th_sport));
	printf("Dst port : %d\n\n", ntohs(mp->tcp->th_dport));

	printf("============ DATA ============\n");
	printf("payload length : %d\n", mp->payload_len);
	if(mp->payload_len == 0)
		printf("NO DATA\n\n");
	
	else{
		if(mp->payload_len<10){
			for(int i=0;i<mp->payload_len;i++)
				printf("%02x ", mp->payload[i]);
		}else{
			for(int i=0;i<10;i++)
				printf("%02x ", mp->payload[i]);
		}
		printf("\n\n");
	}
}

bool is_tcpip(MY_PCAP *mp){
	if((mp->eth->ether_type == 8)&&(mp->ip->ip_p == 6)) 
		return true;
	else 
		return false;
}