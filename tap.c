
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
#include "tap.h"

#define TUN_DEV_NAME "/dev/net/tun"
#define IF_UP_DOWN_SLEEP_US (500 * 1000)

char todo_name[32] =  "dk8";


int tap_fd = -1;
static bool is_up = false;


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

    if (todo_name)
        strncpy(ifr.ifr_name, todo_name, IFNAMSIZ);

    err = ioctl(tap_fd, TUNSETIFF, (void *)&ifr);
    if (err < 0)
        MY_FATAL("Cannot create TAP interface [%d] %s.", errno, strerror(errno));

    strcpy(todo_name, ifr.ifr_name);

    MY_INFO("TAP interface on \"%s\".", todo_name);
}


static void tap_close()
{
    if (tap_fd < 0)
        return;
    close(tap_fd);
    tap_fd = -1;
    MY_INFO("TAP interface \"%s\" deleted.", todo_name);
}


static void tap_up(bool up)
{
    char command[256];
    if (tap_fd < 0)
        return;
    sprintf(command, "ifconfig %s %s", todo_name, up ? "up" : "down");
    int result = system(command);
    if (result == 0)
    {
        MY_INFO("TAP interface is %s.", up ? "up" : "down");
    }
    else
    {
        MY_ERROR("Cannot set TAP interface %s.", up ? "up" : "down");
    }
    usleep(IF_UP_DOWN_SLEEP_US);
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
    if (is_up != up)
    {
        tap_up(up);
        is_up = up;
    }
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
