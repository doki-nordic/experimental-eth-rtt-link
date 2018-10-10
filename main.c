
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
#include <nrfjprogdll.h>
//#include <jlinkarm_nrf52_nrfjprogdll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <getopt.h>
#include <ctype.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> 

#include "options.h"
#include "slip.h"
#include "tap.h"
#include "logs.h"

void infloop() { while (1); }

//#define exit(x) infloop()

static void nrfjprog_callback(const char *msg)
{
    if (options.verbose >= LOG_NRFJPROG)
    {
        fprintf(stderr, "%s\n", msg);
    }
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

static bool nrfjprog_init(bool do_exit)
{
	unsigned int i, up, down;
	nrfjprogdll_err_t error;

    if (options.family == UNKNOWN_FAMILY)
    {
	    error = NRFJPROG_open_dll(options.jlink_lib, nrfjprog_callback, UNKNOWN_FAMILY);
        if (error != SUCCESS)
        {
            fprintf(stderr, "Cannot open JLink library!\n");
            if (do_exit) exit(1); else return false;
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
            fprintf(stderr, "Cannot connect to emmulator to detect device family!\n");
            if (do_exit) exit(1); else return false;
        }
        if (!options.snr)
        {
            error = NRFJPROG_read_connected_emu_snr(&options.snr);
            if (error != SUCCESS)
            {
                fprintf(stderr, "Cannot read SNR!\n");
                if (do_exit) exit(1); else return false;
            }
        }
        error = NRFJPROG_read_device_family(&options.family);
        if (error != SUCCESS)
        {
            fprintf(stderr, "Cannot detect device family!\n");
            if (do_exit) exit(1); else return false;
        }
        NRFJPROG_close_dll();
    }

	error = NRFJPROG_open_dll(options.jlink_lib, nrfjprog_callback, options.family);
	if (error != SUCCESS)
	{
		fprintf(stderr, "Cannot open JLink library!\n");
		if (do_exit) exit(1); else return false;
	}

    if (options.snr)
    {
	    error = NRFJPROG_connect_to_emu_with_snr(options.snr, options.speed);
        printf("snr: %d, speed: %d\n", options.snr, options.speed);
    }
    else
    {
	    error = NRFJPROG_connect_to_emu_without_snr(options.speed);
        printf("speed: %d\n", options.speed);
    }

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
                printf("Child process %d\n", pid);
                pid_t r = waitpid(pid, &wstatus, 0);
                tap_set_state(false);
                printf("PID %d, %d\n", r, WEXITSTATUS(wstatus));
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

    printf("BEGIN\n");
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
