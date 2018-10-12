
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if_arp.h>

#include "logs.h"
#include "options.h"
#include "tap.h"

#define TUN_DEV_NAME "/dev/net/tun"
#define IF_UP_DOWN_SLEEP_US (500 * 1000)

struct in6_ifreq
{
    struct in6_addr ifr6_addr;
    __u32 ifr6_prefixlen;
    unsigned int ifr6_ifindex;
};

static char iface_name[32];

int tap_fd = -1;
static int conf_socket = -1;

#define SUPPORTED_FLAGS (IFF_UP | IFF_BROADCAST | IFF_RUNNING)

uint32_t tap_flags = 0;


void setup_ipv4_data(int socket, unsigned long cmd, struct in_addr * addr, const char* info)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);

    ifr.ifr_addr.sa_family = AF_INET;
    memcpy(&((struct sockaddr_in*)(&ifr.ifr_addr))->sin_addr, addr, sizeof(struct in_addr));
    if (ioctl(socket, cmd, &ifr) < 0)
    {
        U_ERRNO_FATAL("Cannot change IPv4 %s.", info);
    }
}

void renew_ipv6_address()
{
    if (options.ipv6_address_present)
    {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
        if (ioctl(conf_socket, SIOGIFINDEX, &ifr) < 0) {
            U_ERRNO_FATAL("Cannot get interface index.");
        }

        struct in6_ifreq ifr6;
        memset(&ifr6, 0, sizeof(ifr6));
        memcpy(&ifr6.ifr6_addr, &options.ipv6_address, sizeof(options.ipv6_address));
        ifr6.ifr6_prefixlen = options.ipv6_subnet_bits < 0 ? 64 : options.ipv6_subnet_bits;
        ifr6.ifr6_ifindex = ifr.ifr_ifindex;

        if (ioctl(conf_socket, SIOCSIFADDR, &ifr6) < 0) {
            if (errno != EEXIST)
            {
                U_ERRNO_FATAL("Cannot set IPv6 address.");
            }
        }
    }
}

void tap_create()
{
    struct ifreq ifr;
    int err;

    if (tap_fd >= 0)
        return;

    tap_fd = open(TUN_DEV_NAME, O_RDWR);
    if (tap_fd < 0)
        U_ERRNO_FATAL("Cannot open TUN/TAP driver.");

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if (options.iface)
        strncpy(ifr.ifr_name, options.iface, IFNAMSIZ);

    err = ioctl(tap_fd, TUNSETIFF, (void *)&ifr);
    if (err < 0)
        U_ERRNO_FATAL("Cannot create TAP interface.");

    memset(iface_name, 0, sizeof(iface_name));
    strncpy(iface_name, ifr.ifr_name, IFNAMSIZ);

    PRINT_INFO("TAP interface on \"%s\".", iface_name);

    if (options.mac_addr_present)
    {
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
        ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        memcpy(ifr.ifr_hwaddr.sa_data, options.mac_addr, sizeof(options.mac_addr));
	    if (ioctl(tap_fd, SIOCSIFHWADDR, &ifr) < 0) {
            U_ERRNO_FATAL("Cannot setup MAC address.");
        }
    }
    
    int ipv6_socket = -1;
    int ipv4_socket = -1;

    if (options.ipv4_address_present || options.ipv4_netmask_present || options.ipv4_broadcast_present || options.mtu > 0 || !options.ipv6_address_present)
    {
        if ((ipv4_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            U_ERRNO_FATAL("Cannot create socket for IPv4.");
        }
    }

    if (options.mtu > 0)
    {
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
        ifr.ifr_mtu = options.mtu;
		if (ioctl(ipv4_socket, SIOCSIFMTU, &ifr) < 0) {
            U_ERRNO_FATAL("Cannot set interface MTU.");
		}
    }

    if (options.ipv4_address_present)
    {
        setup_ipv4_data(ipv4_socket, SIOCSIFADDR, &options.ipv4_address, "address");
    }

    if (options.ipv4_netmask_present)
    {
        setup_ipv4_data(ipv4_socket, SIOCSIFNETMASK, &options.ipv4_netmask, "netmask");
    }

    if (options.ipv4_broadcast_present)
    {
        setup_ipv4_data(ipv4_socket, SIOCSIFBRDADDR, &options.ipv4_broadcast, "broadcast address");
        tap_flags |= IFF_BROADCAST;
    }

    if (options.ipv6_address_present)
    {
        if ((ipv6_socket = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
            U_ERRNO_FATAL("Cannot create IPv6 socket.");
        }
        conf_socket = ipv6_socket;
        if (ipv4_socket >= 0) close(ipv4_socket);
    }
    else
    {
        conf_socket = ipv4_socket;
    }

    renew_ipv6_address();
}


void tap_delete()
{
    if (tap_fd < 0)
        return;
    close(tap_fd);
    tap_fd = -1;
    close(conf_socket);
    conf_socket = -1;
    PRINT_INFO("TAP interface \"%s\" deleted.", iface_name);
}

static void set_flags()
{
    uint32_t old_flags;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
    
    if (ioctl(conf_socket, SIOCGIFFLAGS, &ifr) < 0)
    {
        U_ERRNO_FATAL("Cannot read interface flags.");
    }
    old_flags = ifr.ifr_flags & ~SUPPORTED_FLAGS;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
    ifr.ifr_flags = old_flags | tap_flags;
    if (ioctl(conf_socket, SIOCSIFFLAGS, &ifr) < 0)
    {
        U_ERRNO_FATAL("Cannot set interface flags.");
    }
}


void tap_set_state(bool up)
{
    char command[256];
    if (tap_fd < 0)
        return;

    if (up)
    {
        tap_flags |= IFF_UP | IFF_RUNNING;
    }
    else
    {
        tap_flags &= ~IFF_UP;
    }

    set_flags();

    if (up)
    {
        renew_ipv6_address();
    }
}
