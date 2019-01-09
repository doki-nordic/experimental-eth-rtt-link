/*
 * Copyright (c) 2019 Nordic Semiconductor
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

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


#include "options.h"
#include "slip.h"
#include "tap.h"
#include "logs.h"
#include "rtt.h"


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


static uint8_t reset_frame_data[] = {
	0, 0, 0, 0, 0, 0,            /* dummy destination MAC address */
	0, 0, 0, 0, 0, 0,            /* dummy source MAC address */
	254, 255,                    /* custom eth type */
	216, 33, 105, 148, 78, 111,  /* randomly generated magic payload */
	203, 53, 32, 137, 247, 122,  /* randomly generated magic payload */
	100, 72, 129, 255, 204, 173, /* randomly generated magic payload */
	0, 0,                        /* placeholder for CRC */
	};


uint8_t buffer[65536];
uint8_t buffer2[2 * 65536];

DecoderContext ctx;



static volatile bool exit_loop = false;

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

void send_frame_to_rtt(uint8_t * ptr, int num)
{
    uint16_t crc = crc16_ccitt(0xFFFF, ptr, num);
    ptr[num] = crc >> 8;
    ptr[num + 1] = crc & 0xFF;
    num = slip_encode(buffer2, ptr, num + 2);
    PRINT_INFO("TO RTT:   %d", num);
    buffered_rtt_write(buffer2, num);
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
                PRINT_INFO("PID %d, %d, %d", r, WEXITSTATUS(wstatus), wstatus);
                if (WIFSIGNALED(wstatus) && !exit_loop)
                {
                    PRINT_ERROR("Unexpected child %d exit, signal %d", pid, WTERMSIG(wstatus));
                    usleep(1000 * 1000);
                }
                else if (WEXITSTATUS(wstatus) == TERMINATION_EXIT_CODE && r >= 0)
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

    send_frame_to_rtt(reset_frame_data, sizeof(reset_frame_data) - 2);

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
                send_frame_to_rtt(buffer, num);
            }
        }

        len = rtt_read(buffer, sizeof(buffer));
        if (len > 0)
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
                    else if (size == sizeof(reset_frame_data) && 0 == memcmp(packet, reset_frame_data, sizeof(reset_frame_data) - 2))
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
