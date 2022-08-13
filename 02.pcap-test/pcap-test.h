#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>

typedef struct MY_PCAP{
    void (*structuralization)(struct MY_PCAP *mp, const u_char* packet);
    void (*printMP)(struct MY_PCAP *mp);
    bool (*is_tcpip)(struct MY_PCAP *mp);

    struct libnet_ethernet_hdr *eth;
	struct libnet_ipv4_hdr *ip;
	struct libnet_tcp_hdr *tcp;
	uint8_t *payload;
    int payload_len;
} MY_PCAP;

typedef struct {
	char* dev_;
} Param;

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}
