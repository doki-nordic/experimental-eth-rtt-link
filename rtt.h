#ifndef _rtt_h_
#define _rtt_h_

#include <stdint.h>
#include <stdbool.h>

bool get_jlink_version(uint32_t *major, uint32_t *minor, char *revision);

bool nrfjprog_init();

void write_queue();
void buffered_rtt_write(uint8_t* data, int num);
uint32_t rtt_read(char * data, uint32_t data_len);

#endif
