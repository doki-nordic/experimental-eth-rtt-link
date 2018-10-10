
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <nrfjprog.h>
//#include <nrfjprogdll.h>
#include <jlinkarm_nrf52_nrfjprogdll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <getopt.h>
#include <ctype.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> 

#include "slip.h"
#include "tap.h"

#define JLINK_LIB		"/opt/SEGGER/JLink/libjlinkarm.so.6"

void infloop() { while (1); }

#define exit(x) infloop()


#define app_major_version (0)
#define app_minor_version (1)
#define app_micro_version (0)

static void nrfjprog_callback(const char *msg)
{
#if 0
	fprintf(stderr, "[nrfjprog]: %s\n", msg);
#endif
}

typedef uint8_t u8_t;
typedef uint16_t u16_t;

u16_t crc16_ccitt(u16_t seed, const u8_t *src, size_t len)
{
	for (; len > 0; len--) {
		u8_t e, f;

		e = seed ^ *src++;
		f = e ^ (e << 4);
		seed = (seed >> 8) ^ (f << 8) ^ (f << 3) ^ (f >> 4);
	}

	return seed;
}

int channel_up = -1;
int channel_down = -1;

static bool nrfjprog_init(bool do_exit)
{
	unsigned int i, up, down;
	nrfjprogdll_err_t error;

	error = NRFJPROG_open_dll(JLINK_LIB, nrfjprog_callback, NRF52_FAMILY);
	if (error != SUCCESS)
	{
		fprintf(stderr, "Cannot open JLink library!\n");
		if (do_exit) exit(1); else return false;
	}

	//error = NRFJPROG_connect_to_emu_with_snr(JLINK_SN, JLINKARM_SWD_DEFAULT_SPEED_KHZ);
	error = NRFJPROG_connect_to_emu_without_snr(JLINKARM_SWD_DEFAULT_SPEED_KHZ);
	if (error != SUCCESS)
	{
		fprintf(stderr, "Cannot connect to emmulator!\n");
		if (do_exit) exit(1); else return false;
	}

	error = NRFJPROG_connect_to_device();
	if (error != SUCCESS)
	{
		fprintf(stderr, "Cannot connect to device!\n");
		if (do_exit) exit(1); else return false;
	}
	

	error = NRFJPROG_rtt_start();
	if (error != SUCCESS)
	{
		fprintf(stderr, "Cannot start RTT!\n");
		if (do_exit) exit(1); else return false;
	}

	i = 30;
	while (i--)
	{
		bool rtt_found;

		error = NRFJPROG_rtt_is_control_block_found(&rtt_found);
		if (error != SUCCESS)
		{
			fprintf(stderr, "Cannot check RTT control block status!\n");
		    if (do_exit) exit(1); else return false;
		}

		if (rtt_found)
			break;

		usleep(100 * 1000);
	}

	if (i == 0)
	{
		fprintf(stderr, "RTT Control Block not found!\n");
		if (do_exit) exit(1); else return false;
	}

	error = NRFJPROG_rtt_read_channel_count(&down, &up);
	if (error != SUCCESS)
	{
		fprintf(stderr, "Cannot fetch RTT channel count!\n");
		if (do_exit) exit(1); else return false;
	}

	for (i = 0; (i < up) || (i < down); i++)
	{
		unsigned int size;
		char name[32 + 1];

		if (i < up)
		{
			error = NRFJPROG_rtt_read_channel_info(i, UP_DIRECTION, name, sizeof(name), &size);
			if (error != SUCCESS)
			{
				fprintf(stderr, "Cannot fetch RTT channel info!\n");
        		if (do_exit) exit(1); else return false;
			}

			if (size != 0)
				printf("RTT[%i] UP:\t\"%s\" (size: %u bytes)\n", i, name, size);

            if (strcmp(name, "ETH_RTT") == 0)
            {
                channel_up = i;
            }
		}

		if (i < down)
		{
			error = NRFJPROG_rtt_read_channel_info(i, DOWN_DIRECTION, name, sizeof(name), &size);
			if (error != SUCCESS)
			{
				fprintf(stderr, "Cannot fetch RTT channel info!\n");
        		if (do_exit) exit(1); else return false;
			}

			if (size != 0)
				printf("RTT[%i] DOWN:\t\"%s\" (size: %u bytes)\n", i, name, size);

            if (strcmp(name, "ETH_RTT") == 0)
            {
                channel_down = i;
            }
		}
	}
    return true;
}


static const u8_t reset_frame_data[] = {
	0, 0, 0, 0, 0, 0,            /* dummy destination MAC address */
	0, 0, 0, 0, 0, 0,            /* dummy source MAC address */
	254, 255,                    /* custom eth type */
	216, 33, 105, 148, 78, 111,  /* randomly generated magic payload */
	203, 53, 32, 137, 247, 122,  /* randomly generated magic payload */
	100, 72, 129, 255, 204, 173, /* randomly generated magic payload */
	};


uint8_t buffer[65536];
uint8_t buffer2[2 * 65536];

DecoderContext ctx;

void reset_rtt()
{
    bool ok = false;
    do {
        channel_down = -1;
        channel_up = -1;
        NRFJPROG_rtt_stop();
        NRFJPROG_disconnect_from_device();
        NRFJPROG_disconnect_from_emu();
        NRFJPROG_close_dll();
        usleep(100 * 1000);
        ok = nrfjprog_init(false);
    } while (!ok);
}

#define LOG_NONE  0
#define LOG_ERROR 1
#define LOG_INFO  2
#define LOG_DEBUG 3
#define LOG_NRFJPROG 4

#define OPT_VERBOSE 'v'
#define OPT_IPV4 '4'
#define OPT_IPV6 '6'
#define OPT_MAC 'm'
#define OPT_HELP 'h'
#define OPT_SNR 's'
#define OPT_CLOCKSPEED 'c'
#define OPT_IFACE 'i'
#define OPT_FAMILY 'f'
#define OPT_MTU (0x100 + 0)
#define OPT_VER (0x100 + 1)
#define OPT_POLLTIME (0x100 + 2)
#define OPT_NORTTRETRY (0x100 + 3)
#define OPT_JLINKLIB (0x100 + 4)
#define OPT_IPV4MASK (0x100 + 5)

#define DESC(text) "\0" text
#define END "\0"

int verbose_flag = LOG_ERROR;

#define HELP_OPT_LEN 16
#define _STR2(x) #x
#define STR(x) _STR2(x)

static struct option long_options[] =
{
    {"help"
        DESC("Print this help message")
        END, no_argument, 0, OPT_HELP},
    {"version"
        DESC("Print version information")
        END, no_argument, 0, OPT_VER},
    {"verbose"
        DESC("Set verbosity level:")
        DESC("  0 - disable all messages")
        DESC("  1 - inform only about errors (default)")
        DESC("  2 - prints information (assumed if no argument")
        DESC("      provided)")
        DESC("  3 - prints debugs")
        DESC("  4 - prints debugs and nrfjprogdll messages")
        END, optional_argument, 0, OPT_VERBOSE},
    {"ipv4"
        DESC("IPv4 address. May include netmask bits count at")
        DESC("the end, e.g. 192.168.1.1/24")
        END, required_argument, 0, OPT_IPV4},
    {"ipv4mask"
        DESC("IPv4 network mask")
        END, required_argument, 0, OPT_IPV4MASK},
    {"ipv6"
        DESC("IPv6 address")
        END, required_argument, 0, OPT_IPV6},
    {"mac"
        DESC("MAC address")
        END, required_argument, 0, OPT_MAC},
    {"mtu"
        DESC("Maximum transmission unit")
        END, required_argument, 0, OPT_MTU},
    {"iface"
        DESC("Sets network interface name. Default is tap0 where")
        DESC("0 can be replaced by higher number if needed.")
        END, required_argument, 0, OPT_IFACE},
    {"snr"
        DESC("Selects the debugger with the given serial number")
        DESC("among all those connected to the PC for the")
        DESC("operation.")
        END, required_argument, 0, OPT_SNR},
    {"family"
        DESC("Selects the device family for the operation. Valid")
        DESC("argument options are NRF51, NRF52 and UNKNOWN.")
        END, required_argument, 0, OPT_FAMILY},
    {"clockspeed"
        DESC("Sets the debugger SWD clock speed in kHz")
        DESC("resolution for the operation.")
        END, required_argument, 0, OPT_CLOCKSPEED},
    {"jlinklib"
        DESC("Path to SEGGER J-Link library dll. Default is:")
        DESC("/opt/SEGGER/JLink/libjlinkarm.so.6")
        END, required_argument, 0, OPT_JLINKLIB},
    {"polltime"
        DESC("Interval time in milliseconds for RTT polling loop.")
        END, required_argument, 0, OPT_POLLTIME},
    {"norttretry"
        DESC("Do not rry to recover from RTT errors by restarting")
        DESC("entire process")
        END, no_argument, 0, OPT_NORTTRETRY},
    {0, 0, 0, 0}
};

void print_help()
{
    char line[HELP_OPT_LEN + 10];
    const char* str;
    struct option *opt;

    opt = long_options;
    while (opt->name)
    {
        str = opt->name;
        if (opt->val < 255)
        {
            printf("\n -%c  ", opt->val);
        }
        else
        {
            printf("\n     ");
        }

        strcpy(line, str);

        if (opt->has_arg == optional_argument)
        {
            strcat(line, " [val]");
        }
        else if (opt->has_arg == required_argument)
        {
            strcat(line, " <val>");
        }
        printf("--%-" STR(HELP_OPT_LEN) "s ", line);
        str += strlen(str) + 1;
        do
        {
            printf("%s\n", str);
            printf("       %" STR(HELP_OPT_LEN) "s ", "");
            str += strlen(str) + 1;
        } while (str[0]);
        opt++;
    }
    printf("\n");
}

int show_help = 0;

struct {
    uint32_t verbose;

    bool ipv4_address_present;
    struct in_addr ipv4_address;
    bool ipv4_netmask_present;
    struct in_addr ipv4_netmask;

    bool ipv6_address_present;
    struct in6_addr ipv6_address;
    int ipv6_subnet_bits;

    bool mac_addr_present;
    uint8_t mac_addr[6];

    int mtu;
    const char *iface;

    uint32_t snr;
    device_family_t family;
    uint32_t speed;
    const char* jlink_lib;
    uint32_t poll_time_us;
    bool no_rtt_retry;
} options = {
    .verbose = LOG_ERROR,
    .ipv4_address_present = false,
    .ipv4_netmask_present = false,
    .ipv6_address_present = false,
    .ipv6_subnet_bits = -1,
    .mac_addr_present = false,
    .mtu = -1,
    .iface = NULL,
    .snr = 0,
    .family = UNKNOWN_FAMILY,
    .speed = JLINKARM_SWD_DEFAULT_SPEED_KHZ,
    .jlink_lib = "/opt/SEGGER/JLink/libjlinkarm.so.6",
    .poll_time_us = 5 * 1000,
    .no_rtt_retry = false,
};


uint32_t parse_arg_uint(const char *arg, uint32_t min, uint32_t max)
{
    char* end = NULL;
    uint32_t result = strtoull(arg, &end, 0);
    if (end == NULL || end[0] != '\0')
    {
        fprintf(stderr, "Invalid integer argument '%s'", arg);
        exit(1);
    }
    if (result < min || result > max)
    {
        fprintf(stderr, "Integer argument '%s' out of range [%d-%d]", arg, min, max);
        exit(1);
    }
    return result;
}

int parse_subnet_bits(const char *arg, uint32_t max_bits, const char **address)
{
    static char temp[64];
    char *subnet_start;
    strncpy(temp, arg, sizeof(temp));
    temp[sizeof(temp) - 0] = 0;
    subnet_start = strchr(temp, '/');
    *address = temp;
    if (subnet_start == NULL)
    {
        return -1;
    }
    subnet_start[0] = 0;
    subnet_start++;
    return parse_arg_uint(subnet_start, 0, max_bits);
}

int ci_strcmp(const char* a, const char* b)
{
    while (*a || *b)
    {
        uint8_t ua = (uint8_t)toupper(*a);
        uint8_t ub = (uint8_t)toupper(*b);
        if (ua < ub)
        {
            return -1;
        }
        else if (ua > ub)
        {
            return 1;
        }
        a++;
        b++;
    }
    return 0;
}

void parse_args(int argc, char* argv[])
{
    int c;
    char short_args[3 * sizeof(long_options) / sizeof(long_options[0]) + 1];
    struct option *opt;
    int index;
    const char *arg;

    opt = long_options;
    while (opt->name)
    {
        sprintf(short_args + strlen(short_args), "%c%s", opt->val, (opt->has_arg == no_argument) ? "" : (opt->has_arg == required_argument) ? ":" : "::");
        opt++; 
    }

    do
    {
        int option_index = 0;

        c = getopt_long(argc, argv, short_args, long_options, &option_index);

        arg = optarg;
        while (arg && *arg && (uint8_t)(*arg) <= ' ')
        {
            arg++;
        }

        switch (c)
        {
            case -1:
                break;

            case OPT_HELP:
                print_help();
                exit(0);
                break;

            case OPT_VER:
            {
                uint32_t major = 0;
                uint32_t minor = 0;
                char revision[32] = "0";

                printf("Version:                   %d.%d.%d\n", app_major_version, app_minor_version, app_micro_version);
                printf("Compiled with nrfjprogdll: %d.%d.%d\n", major_version, minor_version, micro_version);

                nrfjprogdll_err_t err = NRFJPROG_open_dll(JLINK_LIB, nrfjprog_callback, NRF52_FAMILY);
                if (err != SUCCESS)
                {
                    fprintf(stderr, "NRFJPROG error %d\n", err);
                    exit(1);
                }
                err = NRFJPROG_dll_version(&major, &minor, revision);
                NRFJPROG_close_dll();
                if (err != SUCCESS)
                {
                    fprintf(stderr, "NRFJPROG error %d\n", err);
                    exit(1);
                }
                printf("Loaded SEGGER J-Link:      %d.%d%s\n", major, minor, revision);

                exit(0);
                break;
            }

            case OPT_VERBOSE:
                if (arg && arg[0])
                {
                    options.verbose = parse_arg_uint(arg, LOG_NONE, LOG_NRFJPROG);
                }
                else
                {
                    options.verbose = LOG_INFO;
                }
                break;

            case OPT_IPV4:
            {
                const char *addr_str;
                int subnet_bits = parse_subnet_bits(arg, 32, &addr_str);

                if (subnet_bits >= 0)
                {
                    uint32_t subnet = (uint32_t)(((uint64_t)0xFFFFFFFF << 32) >> subnet_bits);
                    options.ipv4_netmask_present = true;
                    options.ipv4_netmask.s_addr = htonl(subnet);
                }

                if (inet_pton(AF_INET, addr_str, &options.ipv4_address) <= 0)
                {
                    fprintf(stderr, "Invalid IPv4 address");
                    exit(1);
                }
                options.ipv4_address_present = true;

                break;
            }

            case OPT_IPV4MASK:
                if (inet_pton(AF_INET, arg, &options.ipv4_netmask) <= 0)
                {
                    fprintf(stderr, "Invalid IPv4 netmask");
                    exit(1);
                }
                options.ipv4_netmask_present = true;

                break;

            case OPT_IPV6:
            {
                const char *addr_str;
                int subnet_bits = parse_subnet_bits(arg, 128, &addr_str);

                if (subnet_bits >= 0)
                {
                    options.ipv6_subnet_bits = subnet_bits;
                }

                if (inet_pton(AF_INET6, addr_str, &options.ipv6_address) <= 0)
                {
                    fprintf(stderr, "Invalid IPv6 address");
                    exit(1);
                }

                break;
            }

            case OPT_MAC:
            {
                uint64_t addr;
                char temp[16] = "0x";
                const char* p = arg;
                int i = 2;
                while (*p && i < 15)
                {
                    if ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F'))
                    {
                        temp[i] = *p;
                        i++;
                    }
                    else if ((*p >= 'g' && *p <= 'z') || (*p >= 'g' && *p <= 'z'))
                    {
                        i = 0;
                        break;
                    }
                    p++;
                }
                if (i != 14)
                {
                    fprintf(stderr, "Invalid MAC address");
                    exit(1);
                }
                temp[i] = 0;
                addr = strtoll(temp, NULL, 0);
                options.mac_addr_present = true;
                options.mac_addr[0] = (uint8_t)(addr >> 40);
                options.mac_addr[1] = (uint8_t)(addr >> 32);
                options.mac_addr[2] = (uint8_t)(addr >> 24);
                options.mac_addr[3] = (uint8_t)(addr >> 16);
                options.mac_addr[4] = (uint8_t)(addr >> 8);
                options.mac_addr[5] = (uint8_t)addr;

                break;
            }

            case OPT_MTU:
                options.mtu = parse_arg_uint(arg, 68, 65535);
                break;

            case OPT_IFACE:
                options.iface = strdup(arg);
                break;

            case OPT_SNR:
                options.snr = parse_arg_uint(arg, 1, UINT32_MAX);
                break;

            case OPT_FAMILY:
                if (ci_strcmp("NRF51", arg) == 0)
                {
                    options.family = NRF51_FAMILY;
                }
                else if (ci_strcmp("NRF52", arg) == 0)
                {
                    options.family = NRF52_FAMILY;
                }
                else if (ci_strcmp("UNKNOWN", arg) == 0)
                {
                    options.family = UNKNOWN_FAMILY;
                }
                else
                {
                    fprintf(stderr, "Invalid family name");
                    exit(1);
                }
                break;

            case OPT_CLOCKSPEED:
                options.speed = parse_arg_uint(arg, JLINKARM_SWD_MIN_SPEED_KHZ, JLINKARM_SWD_MAX_SPEED_KHZ);
                break;

            case OPT_JLINKLIB:
                options.jlink_lib = strdup(arg);
                break;

            case OPT_POLLTIME:
                options.poll_time_us = 1000 * parse_arg_uint(arg, 1, 999);
                break;

            case OPT_NORTTRETRY:
                options.no_rtt_retry = true;
                break;

            default:
                fprintf(stderr, "Unexpected error");
                exit(1);
        }
    } while (c >= 0);

    if (optind < argc)
    {
        printf ("Unexpected parameter '%s'\n", argv[optind]);
    }
}

int main(int argc, char* argv[])
{
    parse_args(argc, argv);
    while(1);
    tap_create();

    do
    {
        int pid = fork();
        if (pid < 0)
        {
            return 1;
        }
        else if (pid == 0)
        {
            break;
        }
        else
        {
            int wstatus = 0;
            printf("Child process %d\n", pid);
            pid_t r = waitpid(pid, &wstatus, 0);
            printf("PID %d, %d\n", r, WEXITSTATUS(wstatus));
            usleep(1000 * 1000);
            /*do
            {
                printf("PID %d, 0x%08X\n", r, wstatus);
                usleep(1000 * 1000);
                int r = kill(pid, 0);
                if (r == 0)
                {
                    // running
                    usleep(300 * 1000);
                }
                else if (errno == ESRCH)
                {
                    printf("Child process %d died\n", pid);
                    break;
                }
                else
                {
                    printf("Unexpected error in child process %d\n", pid);
                    return 1;
                }
            } while (1);*/
        }
    }
    while (1);

    uint32_t len;
    nrfjprog_init(true);

    tap_set_state(true);

    int t = time(NULL) + 600;

    slip_decode_init(&ctx);

    printf("BEGIN\n");
    while (time(NULL) < t || 1)
    {
        fd_set rfds;
        struct timeval tv;
        int retval;
        FD_ZERO(&rfds);
        FD_SET(tap_fd, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 5000;
        retval = select(tap_fd + 1, &rfds, NULL, NULL, &tv);
        if (retval < 0)
        {
            perror("select()");
        }
        else if (retval)
        {
            int num = read(tap_fd, buffer, sizeof(buffer) - 2);
            printf("FROM ETH: %d\n", num);
            if (num > 0)
            {
                uint16_t crc = crc16_ccitt(0xFFFF, buffer, num);
                buffer[num] = crc >> 8;
                buffer[num + 1] = crc & 0xFF;
                num = slip_encode(buffer2, buffer, num + 2);
                uint32_t written = 0;
                uint8_t* ptr = buffer2;
                printf("TO RTT:   %d\n", num);
                while (num > 0)
                {
                    nrfjprogdll_err_t err = NRFJPROG_rtt_write(channel_down, ptr, num, &written);
                    if (err != SUCCESS)
                    {
                        printf("RTT WRITE ERROR: %d\n", err);
                        printf("EXITING CHILD\n");
                        return 44;
                        //reset_rtt();
                        //written = 0;
                        //break;
                    }
                    if (written < num)
                    {
                        // TODO: Create write queue (instead of loop) and write remaining data after NRFJPROG_rtt_read if possible
                        // to prevent dead locks when both board and PC are blocked on RTT write.
                        usleep(500);
                    }
                    num -= written;
                    ptr += written;
                }
            }
        }
        len = -1;
        nrfjprogdll_err_t err = NRFJPROG_rtt_read(channel_up, buffer, sizeof(buffer), &len);
        if (err == SUCCESS && len > 0)
        {
            int i;
            printf("FROM RTT: %d\n", len);
            int packets = slip_decode_put(&ctx, buffer, len);
            for (i = 0; i < packets; i++)
            {
                uint8_t* packet;
                int size = slip_decode_read(&ctx, &packet);
                if (size > 2)
                {
                    uint16_t crc = crc16_ccitt(0xFFFF, packet, size - 2);
                    if (packet[size - 2] != (crc >> 8) || packet[size - 1] != (crc & 0xFF))
                    {
                        printf("CRC ERROR exp=%d,%d, got=%d,%d, size=%d\n", (crc >> 8), (crc & 0xFF), packet[size - 2], packet[size - 1], size - 2);
                    }
                    else if (size - 2 == sizeof(reset_frame_data) && 0 == memcmp(packet, reset_frame_data, sizeof(reset_frame_data)))
                    {
                        printf("RESET PACKET\n");
                        tap_set_state(false);
                        tap_set_state(true);
                    }
                    else
                    {
                        printf("TO ETH:   %d\n", size - 2);
                        int written = write(tap_fd, packet, size - 2);
                        if (written < 0)
                        {
                            printf("TAP write error\n");
                        }
                        else if (written != size - 2)
                        {
                            printf("Unexpected error\n");
                        }
                    }
                }
            }
        }
        else if (err != SUCCESS)
        {
            printf("RTT READ ERROR: %d\n", err);
            //reset_rtt();
            printf("EXITING CHILD\n");
            return 44;
        }
    }
    printf("END\n");
    //nrfjprogdll_err_t err = NRFJPROG_rtt_write(channel_down, "123\300", 4, &len);
    //printf("%d %d\n", err, len);


    usleep(1*1000*1000);

    tap_delete();

    NRFJPROG_close_dll();
    return 3;
}
