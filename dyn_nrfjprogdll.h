#ifndef _dyn_load_h_
#define _dyn_load_h_

#define NRFJPROG_open_dll (*dyn_NRFJPROG_open_dll)
#define NRFJPROG_dll_version (*dyn_NRFJPROG_dll_version)
#define NRFJPROG_connect_to_emu_with_snr (*dyn_NRFJPROG_connect_to_emu_with_snr)
#define NRFJPROG_connect_to_emu_without_snr (*dyn_NRFJPROG_connect_to_emu_without_snr)
#define NRFJPROG_read_connected_emu_snr (*dyn_NRFJPROG_read_connected_emu_snr)
#define NRFJPROG_read_device_family (*dyn_NRFJPROG_read_device_family)
#define NRFJPROG_close_dll (*dyn_NRFJPROG_close_dll)
#define NRFJPROG_connect_to_device (*dyn_NRFJPROG_connect_to_device)
#define NRFJPROG_rtt_start (*dyn_NRFJPROG_rtt_start)
#define NRFJPROG_rtt_is_control_block_found (*dyn_NRFJPROG_rtt_is_control_block_found)
#define NRFJPROG_rtt_read_channel_count (*dyn_NRFJPROG_rtt_read_channel_count)
#define NRFJPROG_rtt_read_channel_info (*dyn_NRFJPROG_rtt_read_channel_info)
#define NRFJPROG_rtt_stop (*dyn_NRFJPROG_rtt_stop)
#define NRFJPROG_disconnect_from_device (*dyn_NRFJPROG_disconnect_from_device)
#define NRFJPROG_disconnect_from_emu (*dyn_NRFJPROG_disconnect_from_emu)
#define NRFJPROG_rtt_write (*dyn_NRFJPROG_rtt_write)
#define NRFJPROG_rtt_read (*dyn_NRFJPROG_rtt_read)

#include <nrfjprogdll.h>

#endif
