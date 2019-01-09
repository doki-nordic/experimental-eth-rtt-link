/*
 * Copyright (c) 2019 Nordic Semiconductor
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdlib.h>
#include <stdbool.h>
#include <dlfcn.h>

#define _DYN_LOAD_MACRO(name) (*_dyn_##name)
#include "dyn_nrfjprogdll.h"


#define LOAD_SYMBOL(name) do { if (!(_dyn_##name = dlsym(dll, #name))) { dlclose(dll); return #name; } } while (0)


static void* nrfjprogdll = NULL;


char* load_nrfjprogdll(const char* lib_path)
{
    void *dll;

    if (nrfjprogdll != NULL) return NULL;

    dll = dlopen(lib_path, RTLD_LAZY);
    if (!dll)
    {
        return "";
    }

    LOAD_SYMBOL(NRFJPROG_open_dll);
    LOAD_SYMBOL(NRFJPROG_dll_version);
    LOAD_SYMBOL(NRFJPROG_connect_to_emu_with_snr);
    LOAD_SYMBOL(NRFJPROG_connect_to_emu_without_snr);
    LOAD_SYMBOL(NRFJPROG_read_connected_emu_snr);
    LOAD_SYMBOL(NRFJPROG_read_device_family);
    LOAD_SYMBOL(NRFJPROG_close_dll);
    LOAD_SYMBOL(NRFJPROG_connect_to_device);
    LOAD_SYMBOL(NRFJPROG_rtt_start);
    LOAD_SYMBOL(NRFJPROG_rtt_is_control_block_found);
    LOAD_SYMBOL(NRFJPROG_rtt_read_channel_count);
    LOAD_SYMBOL(NRFJPROG_rtt_read_channel_info);
    LOAD_SYMBOL(NRFJPROG_rtt_stop);
    LOAD_SYMBOL(NRFJPROG_disconnect_from_device);
    LOAD_SYMBOL(NRFJPROG_disconnect_from_emu);
    LOAD_SYMBOL(NRFJPROG_rtt_write);
    LOAD_SYMBOL(NRFJPROG_rtt_read);

    nrfjprogdll = dll;

    return NULL;
}
