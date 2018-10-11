
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

void *nrfjprogdll = NULL;


void load_nrfjprog(const char* lib_path)
{
    if (nrfjprogdll != NULL) return;

    nrfjprogdll = dlopen(lib_path, RTLD_LAZY);
    if (!nrfjprogdll)
    {
        U_FATAL("NRFJPROG error: nrfjprog library cannot be open.\nSee --nrfjproglib option for help.");
    }

    dyn_NRFJPROG_open_dll = dlsym(nrfjprogdll, "NRFJPROG_open_dll");
    dyn_NRFJPROG_dll_version = dlsym(nrfjprogdll, "NRFJPROG_dll_version");
    dyn_NRFJPROG_connect_to_emu_with_snr = dlsym(nrfjprogdll, "NRFJPROG_connect_to_emu_with_snr");
    dyn_NRFJPROG_connect_to_emu_without_snr = dlsym(nrfjprogdll, "NRFJPROG_connect_to_emu_without_snr");
    dyn_NRFJPROG_read_connected_emu_snr = dlsym(nrfjprogdll, "NRFJPROG_read_connected_emu_snr");
    dyn_NRFJPROG_read_device_family = dlsym(nrfjprogdll, "NRFJPROG_read_device_family");
    dyn_NRFJPROG_close_dll = dlsym(nrfjprogdll, "NRFJPROG_close_dll");
    dyn_NRFJPROG_connect_to_device = dlsym(nrfjprogdll, "NRFJPROG_connect_to_device");
    dyn_NRFJPROG_rtt_start = dlsym(nrfjprogdll, "NRFJPROG_rtt_start");
    dyn_NRFJPROG_rtt_is_control_block_found = dlsym(nrfjprogdll, "NRFJPROG_rtt_is_control_block_found");
    dyn_NRFJPROG_rtt_read_channel_count = dlsym(nrfjprogdll, "NRFJPROG_rtt_read_channel_count");
    dyn_NRFJPROG_rtt_read_channel_info = dlsym(nrfjprogdll, "NRFJPROG_rtt_read_channel_info");
    dyn_NRFJPROG_rtt_stop = dlsym(nrfjprogdll, "NRFJPROG_rtt_stop");
    dyn_NRFJPROG_disconnect_from_device = dlsym(nrfjprogdll, "NRFJPROG_disconnect_from_device");
    dyn_NRFJPROG_disconnect_from_emu = dlsym(nrfjprogdll, "NRFJPROG_disconnect_from_emu");
    dyn_NRFJPROG_rtt_write = dlsym(nrfjprogdll, "NRFJPROG_rtt_write");
    dyn_NRFJPROG_rtt_read = dlsym(nrfjprogdll, "NRFJPROG_rtt_read");
}

nrfjprogdll_err_t open_jlink(device_family_t family)
{
    int i;
    nrfjprogdll_err_t error;

    load_nrfjprog(options.nrfjprog_lib);

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

int main(int argc, char* argv[])
{
    parse_args(argc, argv);
    tap_create();

    if (!options.no_rtt_retry)
    {
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
                PRINT_INFO("Child process %d", pid);
                pid_t r = waitpid(pid, &wstatus, 0);
                tap_set_state(false);
                PRINT_INFO("PID %d, %d", r, WEXITSTATUS(wstatus));
                if (WEXITSTATUS(wstatus) != RECOVERABLE_FATAL_CODE)
                {
                    exit(wstatus);
                }
                usleep(1000 * 1000);
            }
        }
        while (1);
    }

    uint32_t len;
    nrfjprog_init(true);

    tap_set_state(true);

    int t = time(NULL) + 600;

    slip_decode_init(&ctx);

    PRINT_INFO("BEGIN");
    while (time(NULL) < t || 1)
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
                uint8_t* ptr = buffer2;
                PRINT_INFO("TO RTT:   %d", num);
                while (num > 0)
                {
                    nrfjprogdll_err_t err = NRFJPROG_rtt_write(channel_down, ptr, num, &written);
                    if (err != SUCCESS)
                    {
                        PRINT_INFO("RTT WRITE ERROR: %d", err);
                        PRINT_INFO("EXITING CHILD");
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
            PRINT_INFO("RTT READ ERROR: %d", err);
            //reset_rtt();
            PRINT_INFO("EXITING CHILD");
            return 44;
        }
    }
    PRINT_INFO("END");
    //nrfjprogdll_err_t err = NRFJPROG_rtt_write(channel_down, "123\300", 4, &len);
    //PRINT_INFO("%d %d", err, len);


    usleep(1*1000*1000);

    tap_delete();

    NRFJPROG_close_dll();
    return 3;
}
