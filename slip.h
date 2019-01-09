/*
 * Copyright (c) 2019 Nordic Semiconductor
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef _SLIP_H_
#define _SLIP_H_

#include <stdint.h>
#include <stdlib.h>

#define SLIP_DECODER_BUFFER_SIZE (256 * 1024)

typedef struct
{
    size_t writeIndex; // where to put data in decoderPut
    size_t readIndex;  // where source data for decoding ended
    // |   temp decoded   |     encoded   |    free     |
    //                    ^readIndex      ^writeIndex   ^SLIP_DECODER_BUFFER_SIZE
    uint8_t buffer[SLIP_DECODER_BUFFER_SIZE];
} DecoderContext;

size_t slip_encode(uint8_t *output, uint8_t *input, size_t length);

void slip_decode_init(DecoderContext *ctx);
size_t slip_decode_put(DecoderContext *ctx, uint8_t *input, size_t length);
size_t slip_decode_read(DecoderContext *ctx, uint8_t **result);

#endif
