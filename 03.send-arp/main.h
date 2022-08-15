#include <cstdio>
#include <pcap.h>
#include <string>
#include "ethhdr.h"
#include "arphdr.h"
#include "get-my-address.h"

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)