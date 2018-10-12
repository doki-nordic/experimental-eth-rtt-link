
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <nrfjprog.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <getopt.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <dlfcn.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> 

#include "dyn_nrfjprogdll.h"

#include "options.h"
#include "slip.h"
#include "tap.h"
#include "logs.h"

const char* jlink_lib_def[] = {
    "libjlinkarm.so",
    "/opt/SEGGER/JLink/libjlinkarm.so"
};

void infloop() { while (1); }

//#define exit(x) infloop()

static void nrfjprog_callback(const char *msg)
{
    PRINT_NRFJPROG("%s", msg);
}

uint16_t crc16_ccitt(uint16_t seed, const uint8_t *src, size_t len)
{
	for (; len > 0; len--) {
		uint8_t e, f;

		e = seed ^ *src++;
		f = e ^ (e << 4);
		seed = (seed >> 8) ^ (f << 8) ^ (f << 3) ^ (f >> 4);
	}

	return seed;
}

int channel_up = -1;
int channel_down = -1;


nrfjprogdll_err_t open_jlink(device_family_t family)
{
    int i;
    nrfjprogdll_err_t error;
    const char *error_symbol;

    error_symbol = load_nrfjprogdll(options.nrfjprog_lib);

    if (error_symbol && error_symbol[0])
    {
        U_FATAL("NRFJPROG error: undefined reference to '%s'.\nInvalid nrfjprog library provided.\nSee --nrfjproglib option for help.", error_symbol);
    }
    else if (error_symbol)
    {
        U_FATAL("NRFJPROG error: nrfjprog library cannot be open.\nSee --nrfjproglib option for help.");
    }

    if (options.jlink_lib == NULL)
    {
        for (i = 0; i < sizeof(jlink_lib_def)/sizeof(jlink_lib_def[0]); i++)
        {
            error = NRFJPROG_open_dll(jlink_lib_def[i], nrfjprog_callback, family);
            if (error == SUCCESS)
            {
                options.jlink_lib = jlink_lib_def[i];
                return error;
            }
        }
    }
    else
    {
        error = NRFJPROG_open_dll(options.jlink_lib, nrfjprog_callback, family);
    }

    if (error == JLINKARM_DLL_COULD_NOT_BE_OPENED)
    {
        U_FATAL("NRFJPROG error: J-Link library cannot be open. See --jlinklib option in help.");
    }

    return error;
}

nrfjprogdll_err_t get_jlink_version(uint32_t *major, uint32_t *minor, char *revision)
{
    nrfjprogdll_err_t err = open_jlink(options.family);
    if (err != SUCCESS)
    {
        return err;
    }
    err = NRFJPROG_dll_version(major, minor, revision);
    NRFJPROG_close_dll();
    return err;
}

static bool nrfjprog_init()
{
	unsigned int i, up, down;
	nrfjprogdll_err_t error;

    if (options.family == UNKNOWN_FAMILY)
    {
        error = open_jlink(UNKNOWN_FAMILY);
        if (error != SUCCESS)
        {
            R_FATAL("Cannot open JLink library %d!", error);
        }
        if (options.snr)
        {
            error = NRFJPROG_connect_to_emu_with_snr(options.snr, options.speed);
        }
        else
        {
            error = NRFJPROG_connect_to_emu_without_snr(options.speed);
        }
        if (error != SUCCESS)
        {
            R_FATAL("Cannot connect to emmulator to detect device family!");
        }
        if (!options.snr)
        {
            error = NRFJPROG_read_connected_emu_snr(&options.snr);
            if (error != SUCCESS)
            {
                R_FATAL("Cannot read SNR!");
            }
        }
        error = NRFJPROG_read_device_family(&options.family);
        if (error != SUCCESS)
        {
            R_FATAL("Cannot detect device family!");
        }
        NRFJPROG_close_dll();
    }

	error = open_jlink(options.family);
	if (error != SUCCESS)
	{
		R_FATAL("Cannot open JLink library!");
	}

    if (options.snr)
    {
	    error = NRFJPROG_connect_to_emu_with_snr(options.snr, options.speed);
        PRINT_INFO("snr: %d, speed: %d", options.snr, options.speed);
    }
    else
    {
	    error = NRFJPROG_connect_to_emu_without_snr(options.speed);
        PRINT_INFO("speed: %d", options.speed);
    }

	if (error != SUCCESS)
	{
		R_FATAL("Cannot connect to emmulator!");
	}

	error = NRFJPROG_connect_to_device();
	if (error != SUCCESS)
	{
		R_FATAL("Cannot connect to device!");
	}
	

	error = NRFJPROG_rtt_start();
	if (error != SUCCESS)
	{
		R_FATAL("Cannot start RTT!");
	}

	i = 30;
	while (i--)
	{
		bool rtt_found;

		error = NRFJPROG_rtt_is_control_block_found(&rtt_found);
		if (error != SUCCESS)
		{
			R_FATAL("Cannot check RTT control block status!");
		}

		if (rtt_found)
			break;

		usleep(100 * 1000);
	}

	if (i == 0)
	{
		R_FATAL("RTT Control Block not found!");
	}

	error = NRFJPROG_rtt_read_channel_count(&down, &up);
	if (error != SUCCESS)
	{
		R_FATAL("Cannot fetch RTT channel count!");
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
				PRINT_ERROR("Cannot fetch RTT channel info!");
                continue;
			}

			if (size != 0)
				PRINT_INFO("RTT[%i] UP:\t\"%s\" (size: %u bytes)", i, name, size);

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
				PRINT_ERROR("Cannot fetch RTT channel info!");
                continue;
			}

			if (size != 0)
				PRINT_INFO("RTT[%i] DOWN:\t\"%s\" (size: %u bytes)", i, name, size);

            if (strcmp(name, "ETH_RTT") == 0)
            {
                channel_down = i;
            }
		}
	}

    if (channel_down < 0 || channel_up < 0)
    {
        R_FATAL("Cannot find ethernet RTT channel.");
    }
    return true;
}


static const uint8_t reset_frame_data[] = {
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


#define MAX_WRITE_QUEUE_SIZE (2 * 1024 * 1024)

struct WritePart
{
    struct WritePart *next;
    uint32_t size;
    uint32_t start;
    uint8_t data[1];
};

struct WritePart* queue_start = NULL;
struct WritePart* queue_end = NULL;
uint32_t queue_buffered = 0;

void write_queue()
{
    while (queue_start)
    {
        uint32_t written = 0;
        uint32_t num = queue_start->size - queue_start->start;
        nrfjprogdll_err_t err = NRFJPROG_rtt_write(channel_down, &queue_start->data[queue_start->start], num, &written);
        if (err != SUCCESS)
        {
            R_FATAL("RTT WRITE ERROR: %d", err);
        }
        else if (written == 0)
        {
            return;
        }
        else if (written < num)
        {
            queue_start->start += written;
            return;
        }
        else
        {
            struct WritePart* old_part = queue_start;
            queue_start = queue_start->next;
            queue_buffered -= old_part->size;
            PRINT_DEBUG("Got from queue %d, total %d", old_part->size, queue_buffered);
            free(old_part);
            if (queue_start == NULL)
            {
                queue_end = NULL;
            }
        }
    }
}


void buffered_rtt_write(uint8_t* data, int num)
{
    struct WritePart* item;

    write_queue();

    if (queue_start == NULL)
    {
        uint32_t written = 0;
        nrfjprogdll_err_t err = NRFJPROG_rtt_write(channel_down, data, num, &written);
        if (err != SUCCESS)
        {
            R_FATAL("RTT WRITE ERROR: %d", err);
        }
        else if (written >= num)
        {
            return;
        }
        data += written;
        num -= written;
    }

    while (queue_buffered + num > MAX_WRITE_QUEUE_SIZE && queue_start && queue_start->next)
    {
        item = queue_start->next;
        queue_start->next = queue_start->next->next;
        PRINT_ERROR("Write queue overflow. Removing %d bytes.", item->size);
        queue_buffered -= item->size;
        free(item);
    }

    item = malloc(sizeof(struct WritePart) + num);
    item->next = NULL;
    item->size = num;
    item->start = 0;
    memcpy(item->data, data, num);
    if (queue_end)
    {
        queue_end->next = item;
    }
    else
    {
        queue_start = item;
    }
    queue_end = item;
    queue_buffered += num;
    PRINT_DEBUG("Written to queue %d, total %d", num, queue_buffered);
}

static volatile bool exit_loop = 0;

void my_handler(int s)
{
    PRINT_DEBUG("Caught signal %d in %d (parent %d)",s, getpid(), getppid());
    if (exit_loop)
    {
        PRINT_ERROR("Forcing process to terminate.");
        exit(TERMINATION_EXIT_CODE);
    }
    exit_loop = true;
}

int main(int argc, char* argv[])
{
    parse_args(argc, argv);
    tap_create();

    signal(SIGINT, my_handler);

    if (!options.no_rtt_retry)
    {
        do
        {
            if (exit_loop)
            {
                tap_delete();
                PRINT_INFO("TERMINATED parent process");
                exit(TERMINATION_EXIT_CODE);
            }

            int pid = fork();

            if (pid < 0)
            {
                U_ERRNO_FATAL("Cannot fork process!");
            }
            else if (pid == 0)
            {
                break;
            }
            else
            {
                int wstatus = 0;
                PRINT_INFO("Child process %d", pid);
                pid_t r = waitpid(pid, &wstatus, 0);
                tap_set_state(false);
                PRINT_INFO("PID %d, %d", r, WEXITSTATUS(wstatus));
                if (WEXITSTATUS(wstatus) == TERMINATION_EXIT_CODE && r >= 0)
                {
                    exit_loop = true;
                }
                else if (WEXITSTATUS(wstatus) != RECOVERABLE_EXIT_CODE && r >= 0)
                {
                    exit(wstatus);
                }
                else if (!exit_loop)
                {
                    usleep(1000 * 1000);
                }
            }
        }
        while (true);
    }

    uint32_t len;
    nrfjprog_init(true);

    tap_set_state(true);

    slip_decode_init(&ctx);

    PRINT_INFO("BEGIN");

    while (!exit_loop)
    {
        fd_set rfds;
        struct timeval tv;
        int retval;
        FD_ZERO(&rfds);
        FD_SET(tap_fd, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = options.poll_time_us;
        retval = select(tap_fd + 1, &rfds, NULL, NULL, &tv);
        if (retval < 0)
        {
            perror("select()");
        }
        else if (retval)
        {
            int num = read(tap_fd, buffer, sizeof(buffer) - 2);
            PRINT_INFO("FROM ETH: %d", num);
            if (num > 0)
            {
                uint16_t crc = crc16_ccitt(0xFFFF, buffer, num);
                buffer[num] = crc >> 8;
                buffer[num + 1] = crc & 0xFF;
                num = slip_encode(buffer2, buffer, num + 2);
                uint32_t written = 0;
                PRINT_INFO("TO RTT:   %d", num);
                buffered_rtt_write(buffer2, num);
            }
        }
        len = -1;
        nrfjprogdll_err_t err = NRFJPROG_rtt_read(channel_up, buffer, sizeof(buffer), &len);
        if (err == SUCCESS && len > 0)
        {
            int i;
            PRINT_INFO("FROM RTT: %d", len);
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
                        PRINT_INFO("CRC ERROR exp=%d,%d, got=%d,%d, size=%d", (crc >> 8), (crc & 0xFF), packet[size - 2], packet[size - 1], size - 2);
                    }
                    else if (size - 2 == sizeof(reset_frame_data) && 0 == memcmp(packet, reset_frame_data, sizeof(reset_frame_data)))
                    {
                        PRINT_INFO("RESET PACKET");
                        tap_set_state(false);
                        tap_set_state(true);
                    }
                    else
                    {
                        PRINT_INFO("TO ETH:   %d", size - 2);
                        int written = write(tap_fd, packet, size - 2);
                        if (written < 0)
                        {
                            PRINT_INFO("TAP write error");
                        }
                        else if (written != size - 2)
                        {
                            PRINT_INFO("Unexpected error");
                        }
                    }
                }
            }
        }
        else if (err != SUCCESS)
        {
            R_FATAL("RTT READ ERROR: %d", err);
        }
        write_queue();
    }

    PRINT_INFO("TERMINATED");

    NRFJPROG_close_dll();

    if (options.no_rtt_retry)
    {
        tap_delete();
    }

    return TERMINATION_EXIT_CODE;
}
