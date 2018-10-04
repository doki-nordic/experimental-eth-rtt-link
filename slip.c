#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "logs.h"

#include "slip.h"

#define SLIP_END 0300     /* indicates end of packet */
#define SLIP_ESC 0333     /* indicates byte stuffing */
#define SLIP_ESC_END 0334 /* ESC ESC_END means END data byte */
#define SLIP_ESC_ESC 0335 /* ESC ESC_ESC means ESC data byte */

size_t slip_encode(uint8_t *output, uint8_t *input, size_t length)
{
    uint8_t *begin_of_output = output;
    uint8_t *end_of_input = &input[length];

    *output++ = SLIP_END;

    while (input < end_of_input)
    {
        uint8_t byte = *input++;

        if (byte == SLIP_END)
        {
            *output++ = SLIP_ESC;
            byte = SLIP_ESC_END;
        }
        else if (byte == SLIP_ESC)
        {
            *output++ = SLIP_ESC;
            byte = SLIP_ESC_ESC;
        }

        *output++ = byte;
    }

    *output++ = SLIP_END;

    return output - begin_of_output;
}

void slip_decode_init(DecoderContext *ctx)
{
    ctx->writeIndex = 0;
    ctx->readIndex = 0;
}

size_t slip_decode_put(DecoderContext *ctx, uint8_t *input, size_t length)
{
    size_t result = 0;
    if (ctx->readIndex > 0 && ctx->readIndex < ctx->writeIndex)
    {
        memmove(&ctx->buffer[0], &ctx->buffer[ctx->readIndex], ctx->writeIndex - ctx->readIndex);
    }
    ctx->writeIndex -= ctx->readIndex;
    ctx->readIndex = 0;
    uint8_t *end_of_input = &input[length];
    uint8_t *output = &ctx->buffer[ctx->writeIndex];
    uint8_t *end_of_output = &ctx->buffer[SLIP_DECODER_BUFFER_SIZE];
    while (input < end_of_input && output < end_of_output)
    {
        uint8_t byte = *input++;
        *output++ = byte;
        if (byte == SLIP_END)
        {
            result++;
        }
    }
    if (input < end_of_input)
    {
        MY_ERROR("SLIP decoder buffer overflow. Lost %d bytes.", (int)(end_of_input - input));
    }
    ctx->writeIndex = output - &ctx->buffer[0];
    return result;
}

size_t slip_decode_read(DecoderContext *ctx, uint8_t **result)
{
    uint8_t *input = &ctx->buffer[ctx->readIndex];
    uint8_t *end_of_input = &ctx->buffer[ctx->writeIndex];
    uint8_t *start_of_packet = input;
    uint8_t *end_of_packet = NULL;

    *result = start_of_packet;

    while (input < end_of_input)
    {
        uint8_t byte = *input;
        if (byte == SLIP_END)
        {
            end_of_packet = input;
            break;
        }
        input++;
    }

    if (end_of_packet == NULL)
    {
        return 0;
    }

    ctx->readIndex = end_of_packet - &ctx->buffer[0] + 1;

    uint8_t *output = start_of_packet;
    input = start_of_packet;
    end_of_input = end_of_packet;

    while (input < end_of_input)
    {
        uint8_t byte = *input++;
        if (byte == SLIP_ESC)
        {
            if (input >= end_of_input)
            {
                MY_ERROR("Invalid byte stuffing indicator at the end of packet");
                break;
            }
            else if (*input == SLIP_ESC_END)
            {
                byte = SLIP_END;
            }
            else if (*input == SLIP_ESC_ESC)
            {
                byte = SLIP_ESC;
            }
            else
            {
                MY_ERROR("Invalid byte stuffing indicator \"\\x%02X\"", *input);
            }
            input++;
        }
        *output++ = byte;
    }

    return output - start_of_packet;
}

#if defined(TEST_SLIP)

void test_encoder()
{
    uint8_t input[] = "\300xyz\333uvw\334\335\300--\300";
    uint8_t expected[] = "\300\333\334xyz\333\335uvw\334\335\333\334--\333\334\300";
    uint8_t result[2 * sizeof(input) + 1];
    size_t length = slip_encode(result, input, sizeof(input) - 1);
    if (length != sizeof(expected) - 1 || memcmp(result, expected, sizeof(expected) - 1) != 0)
    {
        MY_FATAL("SLIP decoder self test error");
    }
    else
    {
        MY_INFO("SLIP decoder self test ok");
    }
}

void test_decoder()
{
    typedef struct
    {
        char *input;
        int result;
        int reads;
        char *outputs[6];
    } TestStep;
    DecoderContext ctx;
    TestStep input[] = {
        {NULL},
        {"\333\334xyz\333\335uvw\334\335\333\334--\333\334\300",
         1,
         2,
         {"\300xyz\333uvw\334\335\300--\300", ""}},
        {"abc",
         0,
         1,
         {""}},
        {"abc\333\334",
         0,
         1,
         {""}},
        {"\300xyz",
         1,
         2,
         {"abcabc\300", ""}},
        {"\300one",
         1,
         2,
         {"xyz", ""}},
        {"\300two\300three\300four\300",
         4,
         6,
         {"one", "two", "three", "four", "", ""}},
        {"x\300y\300",
         2,
         0,
         {}},
        {"z\300",
         1,
         4,
         {"x", "y", "z", ""}},
    };

    int i;
    int k;

    for (i = 0; i < sizeof(input) / sizeof(input[0]); i++)
    {
        if (input[i].input == NULL)
        {
            slip_decode_init(&ctx);
            continue;
        }
        int result = slip_decode_put(&ctx, input[i].input, strlen(input[i].input));
        if (result != input[i].result)
            MY_FATAL("Test %d failed", i);
        for (k = 0; k < input[i].reads; k++)
        {
            uint8_t *buffer;
            int count = slip_decode_read(&ctx, &buffer);
            if (count != strlen(input[i].outputs[k]))
                MY_FATAL("Test %d failed", i);
            if (memcmp(input[i].outputs[k], buffer, count) != 0)
                MY_FATAL("Test %d failed", i);
        }
    }
}

int main()
{
    test_decoder();
    test_encoder();
}

#endif
