#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

#include <string>

std::string get_mac_address();
std::string get_ip_address(char *adapter);