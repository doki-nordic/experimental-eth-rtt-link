/*
 * Copyright (c) 2019 Nordic Semiconductor
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef _dyn_load_h_
#define _dyn_load_h_

#include <stdbool.h>

#define NRFJPROG_open_dll _DYN_LOAD_MACRO(NRFJPROG_open_dll)
#define NRFJPROG_dll_version _DYN_LOAD_MACRO(NRFJPROG_dll_version)
#define NRFJPROG_connect_to_emu_with_snr _DYN_LOAD_MACRO(NRFJPROG_connect_to_emu_with_snr)
#define NRFJPROG_connect_to_emu_without_snr _DYN_LOAD_MACRO(NRFJPROG_connect_to_emu_without_snr)
#define NRFJPROG_read_connected_emu_snr _DYN_LOAD_MACRO(NRFJPROG_read_connected_emu_snr)
#define NRFJPROG_read_device_family _DYN_LOAD_MACRO(NRFJPROG_read_device_family)
#define NRFJPROG_close_dll _DYN_LOAD_MACRO(NRFJPROG_close_dll)
#define NRFJPROG_connect_to_device _DYN_LOAD_MACRO(NRFJPROG_connect_to_device)
#define NRFJPROG_rtt_set_control_block_address _DYN_LOAD_MACRO(NRFJPROG_rtt_set_control_block_address)
#define NRFJPROG_rtt_start _DYN_LOAD_MACRO(NRFJPROG_rtt_start)
#define NRFJPROG_rtt_is_control_block_found _DYN_LOAD_MACRO(NRFJPROG_rtt_is_control_block_found)
#define NRFJPROG_rtt_read_channel_count _DYN_LOAD_MACRO(NRFJPROG_rtt_read_channel_count)
#define NRFJPROG_rtt_read_channel_info _DYN_LOAD_MACRO(NRFJPROG_rtt_read_channel_info)
#define NRFJPROG_rtt_stop _DYN_LOAD_MACRO(NRFJPROG_rtt_stop)
#define NRFJPROG_disconnect_from_device _DYN_LOAD_MACRO(NRFJPROG_disconnect_from_device)
#define NRFJPROG_disconnect_from_emu _DYN_LOAD_MACRO(NRFJPROG_disconnect_from_emu)
#define NRFJPROG_rtt_write _DYN_LOAD_MACRO(NRFJPROG_rtt_write)
#define NRFJPROG_rtt_read _DYN_LOAD_MACRO(NRFJPROG_rtt_read)

#ifndef _DYN_LOAD_MACRO
#define _DYN_LOAD_MACRO(name) extern (*_dyn_##name)
#endif

#include <nrfjprogdll.h>

#undef _DYN_LOAD_MACRO
#define _DYN_LOAD_MACRO(name) _dyn_##name

char* load_nrfjprogdll(const char* lib_path);

#endif
