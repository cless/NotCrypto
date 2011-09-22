/* Copyright (C) 2011 by clueless <clueless@thunked.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/* This code is written from scratch based on RFC 1319.  The substitution table
 * was copied from the reference implementation in RFC 1319, no other code is
 * derived from the reference implementation.  This code is written solely to
 * learn about one way hash functions and MD2 specifically.  This code should
 * never be used in production, or anywhere else.  To the best of my knowledge
 * the implementation is correct but you should assume there are errors in it.
 */

#include <string.h>
#include "md2.h"

// 256 byte table derived from digits of pi as provided by RFC 1319
static const uint8_t sub_table[256] = {
    0x29, 0x2e, 0x43, 0xc9, 0xa2, 0xd8, 0x7c, 0x01,
    0x3d, 0x36, 0x54, 0xa1, 0xec, 0xf0, 0x06, 0x13,
    0x62, 0xa7, 0x05, 0xf3, 0xc0, 0xc7, 0x73, 0x8c,
    0x98, 0x93, 0x2b, 0xd9, 0xbc, 0x4c, 0x82, 0xca,
    0x1e, 0x9b, 0x57, 0x3c, 0xfd, 0xd4, 0xe0, 0x16,
    0x67, 0x42, 0x6f, 0x18, 0x8a, 0x17, 0xe5, 0x12,
    0xbe, 0x4e, 0xc4, 0xd6, 0xda, 0x9e, 0xde, 0x49,
    0xa0, 0xfb, 0xf5, 0x8e, 0xbb, 0x2f, 0xee, 0x7a,
    0xa9, 0x68, 0x79, 0x91, 0x15, 0xb2, 0x07, 0x3f,
    0x94, 0xc2, 0x10, 0x89, 0x0b, 0x22, 0x5f, 0x21,
    0x80, 0x7f, 0x5d, 0x9a, 0x5a, 0x90, 0x32, 0x27,
    0x35, 0x3e, 0xcc, 0xe7, 0xbf, 0xf7, 0x97, 0x03,
    0xff, 0x19, 0x30, 0xb3, 0x48, 0xa5, 0xb5, 0xd1,
    0xd7, 0x5e, 0x92, 0x2a, 0xac, 0x56, 0xaa, 0xc6,
    0x4f, 0xb8, 0x38, 0xd2, 0x96, 0xa4, 0x7d, 0xb6,
    0x76, 0xfc, 0x6b, 0xe2, 0x9c, 0x74, 0x04, 0xf1,
    0x45, 0x9d, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20,
    0x86, 0x5b, 0xcf, 0x65, 0xe6, 0x2d, 0xa8, 0x02,
    0x1b, 0x60, 0x25, 0xad, 0xae, 0xb0, 0xb9, 0xf6,
    0x1c, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7e, 0x0f,
    0x55, 0x47, 0xa3, 0x23, 0xdd, 0x51, 0xaf, 0x3a,
    0xc3, 0x5c, 0xf9, 0xce, 0xba, 0xc5, 0xea, 0x26,
    0x2c, 0x53, 0x0d, 0x6e, 0x85, 0x28, 0x84, 0x09,
    0xd3, 0xdf, 0xcd, 0xf4, 0x41, 0x81, 0x4d, 0x52,
    0x6a, 0xdc, 0x37, 0xc8, 0x6c, 0xc1, 0xab, 0xfa,
    0x24, 0xe1, 0x7b, 0x08, 0x0c, 0xbd, 0xb1, 0x4a,
    0x78, 0x88, 0x95, 0x8b, 0xe3, 0x63, 0xe8, 0x6d,
    0xe9, 0xcb, 0xd5, 0xfe, 0x3b, 0x00, 0x1d, 0x39,
    0xf2, 0xef, 0xb7, 0x0e, 0x66, 0x58, 0xd0, 0xe4,
    0xa6, 0x77, 0x72, 0xf8, 0xeb, 0x75, 0x4b, 0x0a,
    0x31, 0x44, 0x50, 0xb4, 0x8f, 0xed, 0x1f, 0x1a,
    0xdb, 0x99, 0x8d, 0x33, 0x9f, 0x11, 0x83, 0x14};

void md2_init(struct md2_context *ctx)
{
    memset(ctx, 0, sizeof(struct md2_context));
}

// Update the checksum with 1 block worth of data
static void md2_update_checksum(struct md2_context *ctx, const uint8_t *buffer)
{
    for(int i = 0; i < 16; i++)
    {
        uint8_t c = buffer[i];
        ctx->checksum[i] ^= sub_table[c ^ ctx->L];
        ctx->L = ctx->checksum[i];
    }
}

// Update the MD buffer with 1 block worth of data
static void md2_update_mdbuffer(struct md2_context *ctx, const uint8_t *buffer)
{
    for(int i = 0; i < 16; i++)
    {
        ctx->mdbuffer[16 + i] = buffer[i];
        ctx->mdbuffer[32 + i] = buffer[i] ^ ctx->mdbuffer[i];
    }

    uint8_t t = 0;
    for(int i = 0; i < 18; i++)
    {
        for(int j = 0; j < 48; j++)
        {
            t = ctx->mdbuffer[j] ^ sub_table[t];
            ctx->mdbuffer[j] = t;
        }
        t = (t + i) % 256;
    }
    t = 0;
}

static void md2_update_block(struct md2_context *ctx, const uint8_t *buffer)
{
    md2_update_checksum(ctx, buffer);
    md2_update_mdbuffer(ctx, buffer);
}

void md2_update(struct md2_context *ctx, const uint8_t *buffer, size_t len)
{
    // If our context has overflow bytes from the last update then extend those
    // until the overflow buffer has 16 bytes in it so we can process the block
    if(ctx->bufused > 0)
    {
        size_t cpylen = ((16 - ctx->bufused) <= len) ? 16 - ctx->bufused : len;
        memcpy(ctx->buffer + ctx->bufused, buffer, cpylen);
        ctx->bufused += cpylen;
        buffer += cpylen;
        len    -= cpylen;

        if(ctx->bufused == 16)
        {
            md2_update_block(ctx, ctx->buffer);
            ctx->bufused = 0;
              
        }
    }

    // Feed 16 byte blocks into the update function
    while(len >= 16)
    {
        md2_update_block(ctx, buffer);
        len    -= 16;
        buffer += 16;
    }

    // And save any overflow bytes for next update
    if(len > 0)
    {
        memcpy(ctx->buffer, buffer, len);
        ctx->bufused = len;
    }
}

void md2_final(struct md2_context *ctx, uint8_t *hash)
{
    // Apply padding to the internal buffer
    uint8_t pad = 16 - ctx->bufused;
    for(int i = ctx->bufused; i < 16; i++)
    {
        ctx->buffer[i] = pad;
    }

    // Update with the final padded block
    md2_update_block(ctx, ctx->buffer);
    
    // Update mdbuffer with the checksum
    md2_update_mdbuffer(ctx, ctx->checksum);
    
    memcpy(hash, ctx->mdbuffer, 16);
    memset(ctx, 0, sizeof(struct md2_context));
}

void md2(const uint8_t *buffer, size_t len, uint8_t *hash)
{
    struct md2_context ctx;
    md2_init(&ctx);
    md2_update(&ctx, buffer, len);
    md2_final(&ctx, hash);
}
