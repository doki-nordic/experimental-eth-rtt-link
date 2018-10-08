
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
//#include <nrfjprogdll.h>
#include <jlinkarm_nrf52_nrfjprogdll.h>

#include "slip.h"
#include "tap.h"

#define JLINK_LIB		"/opt/SEGGER/JLink/libjlinkarm.so.6"

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

static void nrfjprog_init(void)
{
	unsigned int i, up, down;
	nrfjprogdll_err_t error;

	error = NRFJPROG_open_dll(JLINK_LIB, nrfjprog_callback, NRF52_FAMILY);
	if (error != SUCCESS)
	{
		fprintf(stderr, "Cannot open JLink library!\n");
		exit(1);
	}

	//error = NRFJPROG_connect_to_emu_with_snr(JLINK_SN, JLINKARM_SWD_DEFAULT_SPEED_KHZ);
	error = NRFJPROG_connect_to_emu_without_snr(JLINKARM_SWD_DEFAULT_SPEED_KHZ);
	if (error != SUCCESS)
	{
		fprintf(stderr, "Cannot connect to emmulator!\n");
		exit(1);
	}

	error = NRFJPROG_connect_to_device();
	if (error != SUCCESS)
	{
		fprintf(stderr, "Cannot connect to device!\n");
		exit(1);
	}
	

	error = NRFJPROG_rtt_start();
	if (error != SUCCESS)
	{
		fprintf(stderr, "Cannot start RTT!\n");
		exit(1);
	}

	i = 30;
	while (i--)
	{
		bool rtt_found;

		error = NRFJPROG_rtt_is_control_block_found(&rtt_found);
		if (error != SUCCESS)
		{
			fprintf(stderr, "Cannot check RTT control block status!\n");
			exit(1);
		}

		if (rtt_found)
			break;

		usleep(100 * 1000);
	}

	if (i == 0)
	{
		fprintf(stderr, "RTT Control Block not found!\n");
		exit(1);
	}

	error = NRFJPROG_rtt_read_channel_count(&down, &up);
	if (error != SUCCESS)
	{
		fprintf(stderr, "Cannot fetch RTT channel count!\n");
		exit(1);
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
				exit(1);
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
				exit(1);
			}

			if (size != 0)
				printf("RTT[%i] DOWN:\t\"%s\" (size: %u bytes)\n", i, name, size);

            if (strcmp(name, "ETH_RTT") == 0)
            {
                channel_down = i;
            }
		}
	}
}

uint8_t buffer[65536];
uint8_t buffer2[2 * 65536];

DecoderContext ctx;

int main()
{
    uint32_t len;
    nrfjprog_init();

    tap_create();
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
                        break;
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
    }
    printf("END\n");
    //nrfjprogdll_err_t err = NRFJPROG_rtt_write(channel_down, "123\300", 4, &len);
    //printf("%d %d\n", err, len);


    usleep(1*1000*1000);

    tap_delete();

    NRFJPROG_close_dll();
    return 3;
}
