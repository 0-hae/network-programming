#include "get-my-address.h"

using namespace std;

// 출처 : https://muabow.tistory.com/287

string get_mac_address(void) {
    int socket_fd;
    int count_if;

    struct ifreq  *t_if_req;
    struct ifconf  t_if_conf;

    char arr_mac_addr[17] = {0x00, };

    memset(&t_if_conf, 0, sizeof(t_if_conf));

    t_if_conf.ifc_ifcu.ifcu_req = NULL;
    t_if_conf.ifc_len = 0;

    if( (socket_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0 ) {
        return "";
    }

    if( ioctl(socket_fd, SIOCGIFCONF, &t_if_conf) < 0 ) {
        return "";
    }

    if( (t_if_req = (ifreq *)malloc(t_if_conf.ifc_len)) == NULL ) {
        close(socket_fd);
        free(t_if_req);
        return "";

    } else {
        t_if_conf.ifc_ifcu.ifcu_req = t_if_req;
        if( ioctl(socket_fd, SIOCGIFCONF, &t_if_conf) < 0 ) {
            close(socket_fd);
            free(t_if_req);
            return "";
        }

        count_if = t_if_conf.ifc_len / sizeof(struct ifreq);
        for( int idx = 0; idx < count_if; idx++ ) {
            struct ifreq *req = &t_if_req[idx];

            if( !strcmp(req->ifr_name, "lo") ) {
                continue;
            }

            if( ioctl(socket_fd, SIOCGIFHWADDR, req) < 0 ) {
                break;
            }

            sprintf(arr_mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x",
                    (unsigned char)req->ifr_hwaddr.sa_data[0],
                    (unsigned char)req->ifr_hwaddr.sa_data[1],
                    (unsigned char)req->ifr_hwaddr.sa_data[2],
                    (unsigned char)req->ifr_hwaddr.sa_data[3],
                    (unsigned char)req->ifr_hwaddr.sa_data[4],
                    (unsigned char)req->ifr_hwaddr.sa_data[5]);
            break;
        }
    }

    close(socket_fd);
    free(t_if_req);

    return arr_mac_addr;
}
// 출처 : https://stackoverflow.com/questions/1195675/convert-a-char-to-stdstring
string get_ip_address(char *adapter){
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, adapter, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);

	/* display result */
	string str(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	return str;
}