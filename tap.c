
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

struct in6_ifreq {
    struct in6_addr ifr6_addr;
    __u32 ifr6_prefixlen;
    unsigned int ifr6_ifindex;
};

char iface_name[32];


int tap_fd = -1;
int conf_socket = -1;

#define SUPPORTED_FLAGS (IFF_UP | IFF_BROADCAST | IFF_RUNNING)
uint32_t tap_flags = 0;

#if 0
static void set_ipv4(const char* address, const char* net_mask)
{
	// http://man7.org/linux/man-pages/man7/netdevice.7.html

	struct ifreq req;
	strcpy(req.ifr_ifrn.ifrn_name, todo_name);
	struct sockaddr * addr = &req.ifr_ifru.ifru_addr;
	memset(addr, 0, sizeof(*addr));
	addr->sa_family = AF_INET;
	sa_family_t;
}

static void set_ipv6(const char* address, prefix_len)
{
	// https://stackoverflow.com/questions/8240724/assign-ipv6-address-using-ioctl


	struct in6_ifreq {
	    struct in6_addr addr;
	    uint32_t        prefixlen;
	    unsigned int    ifindex;
	};

    struct in6_ifreq ifr6;
}
#endif

void setup_ipv4_data(int socket, unsigned long cmd, struct in_addr * addr, const char* info)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);

    ifr.ifr_addr.sa_family = AF_INET;
    memcpy(&((struct sockaddr_in*)(&ifr.ifr_addr))->sin_addr, addr, sizeof(struct in_addr));
    if (ioctl(socket, cmd, &ifr) < 0) {
        MY_FATAL("Cannot change IPv4 %s [%d] %s.", info, errno, strerror(errno));
    }
}

static void tap_open()
{
    struct ifreq ifr;
    int err;

    if (tap_fd >= 0)
        return;

    tap_fd = open(TUN_DEV_NAME, O_RDWR);
    if (tap_fd < 0)
        MY_FATAL("Cannot open TUN/TAP driver [%d] %s.", errno, strerror(errno));

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if (options.iface)
        strncpy(ifr.ifr_name, options.iface, IFNAMSIZ);

    err = ioctl(tap_fd, TUNSETIFF, (void *)&ifr);
    if (err < 0)
        MY_FATAL("Cannot create TAP interface [%d] %s.", errno, strerror(errno));

    memset(iface_name, 0, sizeof(iface_name));
    strncpy(iface_name, ifr.ifr_name, IFNAMSIZ);

    MY_INFO("TAP interface on \"%s\".", iface_name);

    if (options.mac_addr_present)
    {
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
        ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        memcpy(ifr.ifr_hwaddr.sa_data, options.mac_addr, sizeof(options.mac_addr));
	    if (ioctl(tap_fd, SIOCSIFHWADDR, &ifr) < 0) {
            MY_FATAL("Cannot setup MAC address [%d] %s.", errno, strerror(errno));
        }
    }
    
    int ipv6_socket = -1;
    int ipv4_socket = -1;

    if (options.ipv4_address_present || options.ipv4_netmask_present || options.ipv4_broadcast_present || options.mtu > 0 || !options.ipv6_address_present)
    {
        if ((ipv4_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            MY_FATAL("YYYY[%d] %s.", errno, strerror(errno));
        }
    }

    if (options.mtu > 0)
    {
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
        ifr.ifr_mtu = options.mtu;
		if (ioctl(ipv4_socket, SIOCSIFMTU, &ifr) < 0) {
            MY_FATAL("Cannot set interface MTU [%d] %s.", errno, strerror(errno));
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
            MY_FATAL("YYYY[%d] %s.", errno, strerror(errno));
        }

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
		if (ioctl(ipv6_socket, SIOGIFINDEX, &ifr) < 0) {
            MY_FATAL("Cannot get interface index [%d] %s.", errno, strerror(errno));
		}

        struct in6_ifreq ifr6;
        memset(&ifr6, 0, sizeof(ifr6));
        memcpy(&ifr6.ifr6_addr, &options.ipv6_address, sizeof(options.ipv6_address));
        ifr6.ifr6_prefixlen = options.ipv6_subnet_bits < 0 ? 128 : options.ipv6_subnet_bits;
        ifr6.ifr6_ifindex = ifr.ifr_ifindex;

		if (ioctl(ipv6_socket, SIOCSIFADDR, &ifr6) < 0) {
            MY_FATAL("Cannot set IPv6 address [%d] %s.", errno, strerror(errno));
		}

        close(ipv6_socket);
    }

    if (ipv4_socket >= 0)
    {
        conf_socket = ipv4_socket;
        if (ipv6_socket >= 0) close(ipv6_socket);
    }
    else
    {
        conf_socket = ipv6_socket;
    }
}


static void tap_close()
{
    if (tap_fd < 0)
        return;
    close(tap_fd);
    tap_fd = -1;
    close(conf_socket);
    conf_socket = -1;
    MY_INFO("TAP interface \"%s\" deleted.", iface_name);
}

static void set_flags()
{
    uint32_t old_flags;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
    
    if (ioctl(conf_socket, SIOCGIFFLAGS, &ifr) < 0)
    {
        MY_FATAL("Cannot read interface flags [%d] %s.", errno, strerror(errno));
    }
    old_flags = ifr.ifr_flags & ~SUPPORTED_FLAGS;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);
    ifr.ifr_flags = old_flags | tap_flags;
    if (ioctl(conf_socket, SIOCSIFFLAGS, &ifr) < 0)
    {
        MY_FATAL("Cannot set interface flags [%d] %s.", errno, strerror(errno));
    }
}


static void tap_up(bool up)
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
}

#if 0

void tap_create()
{
    tap_open();
    tap_up(true);
    is_up = true;
}

void tap_delete()
{
    tap_close();
    is_up = false;
}

void tap_set_state(bool up)
{
    if (is_up != up)
    {
        if (up)
        {
            tap_open();
            tap_up(true);
        }
        else
        {
            tap_close();
        }
        is_up = up;
    }
}


#else

void tap_create()
{
    tap_open();
}

void tap_delete()
{
    tap_close();
}

void tap_set_state(bool up)
{
    tap_up(up);
}

#endif


#if 0

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "logs.h"
#include "pcap.h"

#include "tap.h"

#define TUN_DEV_NAME "/dev/net/tun"
#define READ_ERROR_SLEEP_US (2 * 1000 * 1000)
#define IF_UP_DOWN_SLEEP_US (500 * 1000)

static int tap_fd = -1;
static char if_name[64] = "";
static bool isUp = false;

static int pcap = -1;

void tapAlloc(const char *name)
{
    struct ifreq ifr;
    int err;

    if (tap_fd >= 0)
        return;

    tap_fd = open(TUN_DEV_NAME, O_RDWR);
    if (tap_fd < 0)
        MY_FATAL("Cannot open TUN/TAP driver [%d] %s.", errno, strerror(errno));

    if (pcap <= 0)
    {
        pcap = open("/tmp/slip_decode_tap.pcap", O_WRONLY | O_CREAT | O_TRUNC, 0777);
        if (pcap < 0)
            MY_FATAL("Cannot open pcap output file [%d] %s.", errno, strerror(errno));
        pcapInit(pcap);
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if (name)
        strncpy(ifr.ifr_name, name, IFNAMSIZ);

    err = ioctl(tap_fd, TUNSETIFF, (void *)&ifr);
    if (err < 0)
        MY_FATAL("Cannot create TAP interface [%d] %s.", errno, strerror(errno));

    strcpy(if_name, ifr.ifr_name);

    isUp = false;

    MY_INFO("TAP interface on \"%s\".", if_name);
    pcapLog(pcap, "START");
}

void tapDelete()
{
    if (tap_fd < 0)
        return;
    close(tap_fd);
    tap_fd = -1;
    isUp = false;
    MY_INFO("TAP interface \"%s\" deleted.", if_name);
    pcapLog(pcap, "END");
}

void tapUp(bool up)
{
    up = up || true; // TODO: make it better
    char command[256];
    if (tap_fd < 0 || isUp == up)
        return;
    sprintf(command, "ifconfig %s %s", if_name, up ? "up" : "down");
    int result = system(command);
    if (result == 0)
    {
        MY_INFO("TAP interface is %s.", up ? "up" : "down");
    }
    else
    {
        MY_ERROR("Cannot set TAP interface %s.", up ? "up" : "down");
    }
    isUp = up;
    pcapLog(pcap, up ? "UP" : "DOWN");
    usleep(IF_UP_DOWN_SLEEP_US);
}

void tapWrite(const uint8_t *data, int length)
{
    if (tap_fd < 0)
        MY_ERROR("Unexpected tapWrite.");

    int n = write(tap_fd, data, length);

    if (n < 0)
    {
        MY_ERROR("Write to TAP failed [%d] %s.", errno, strerror(errno));
        pcapLog(pcap, "WRITE ERROR");
        pcapWrite(pcap, data, length, length);
    }
    else if (n < length)
    {
        MY_ERROR("Unfinished write to TAP, requested %d, written %d.", length, n);
        pcapLog(pcap, "CUTTED FRAME");
        pcapWrite(pcap, data, n, length);
    }
    else
    {
        pcapWrite(pcap, data, n, n);
    }
}

int tapRead(uint8_t *data, int bufferSize)
{
    if (tap_fd < 0)
    {
        MY_ERROR("Unexpected tapRead.");
        pcapLog(pcap, "UNEXPECTED READ");
        usleep(READ_ERROR_SLEEP_US);
        return -1;
    }

    int n = read(tap_fd, data, bufferSize);

    if (n < 0)
    {
        MY_ERROR("Read from TAP failed [%d] %s.", errno, strerror(errno));
        pcapLog(pcap, "READ ERROR");
        usleep(READ_ERROR_SLEEP_US);
    }
    else
    {
        pcapWrite(pcap, data, n, n);
    }

    return n;
}

#endif
