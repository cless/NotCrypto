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

/* This code is based on the algorithm description in RFC 3174. This code is
 * written solely to learn about one way hash functions and SHA1 specifically.
 * This code should never be used in production, or anywhere else.  To the best
 * of my knowledge the implementation is correct but you should assume there
 * are errors in it.
 */

#include <stdio.h>
#include <string.h>
#include "sha1.h"

// The transformation function building block, correct behavior chosen based
// on the iteration count
static inline uint32_t sha1_func(int t, uint32_t b, uint32_t c, uint32_t d)
{
    if(t < 20)
        return (b & c) | ((~b) & d);
    else if(t < 40)
        return b ^ c ^ d;
    else if(t < 60)
        return (b & c) | (b & d) | (c & d);
    else
        return b ^ c ^ d;
}

// SHA1 constants, again based on iteration count
static inline uint32_t sha1_const(int t)
{
    if(t < 20)
        return 0x5A827999;
    if(t < 40)
      return 0x6ED9EBA1;
    if(t < 60)
      return 0x8F1BBCDC;
    else
      return 0xCA62C1D6;
}

// circular rotate left function
static inline uint32_t sha1_rot(uint32_t x, unsigned int s)
{
    return (x << s) | (x >> (32 - s));
}

// Swap the endianess of any given number, this function is not required on a
// big endian system but this code is designed for X86 systems which are little
// endian
static inline void sha1_endianswap(void *num, size_t len)
{
    uint8_t *bytes = num;
    uint8_t tmp;

    for(size_t i = 0, j = len - 1; i < j; i++, j--)
    {
        tmp = bytes[i];
        bytes[i] = bytes[j];
        bytes[j] = tmp;
    }
}

void sha1_init(struct sha1_context *ctx)
{
    memset(ctx, 0, sizeof(struct sha1_context));
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
}

static void sha1_update_block(struct sha1_context *ctx, const uint8_t *buffer)
{
    uint32_t w_buf[80];
    uint32_t temp;
    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    
    memcpy(w_buf, buffer, 64);
    for(int i = 0, j = 0; i < 16; i++, j += 4)
        sha1_endianswap(&w_buf[i], sizeof(uint32_t));

    for(int t = 16; t < 80; t++)
        w_buf[t] = sha1_rot(w_buf[t - 3] ^ w_buf[t - 8] ^ w_buf[t - 14] ^ w_buf[t - 16] , 1);
    
    for(int t = 0; t < 80; t++)
    {

        temp = sha1_rot(a, 5) + sha1_func(t, b, c, d) + e + w_buf[t] + sha1_const(t);
        e = d;
        d = c;
        c = sha1_rot(b, 30);
        b = a;
        a = temp;
    }
    
    // save the state
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    
    memset(w_buf, 0, 80);
    a = b = c = d = e = 0;
}

void sha1_update(struct sha1_context *ctx, const uint8_t *buffer, size_t len)
{
    ctx->len += len;

    // If our context has overflow bytes from the last update then extend those
    // until the overflow buffer has 64 bytes in it so we can process the block
    if(ctx->bufused > 0)
    {
        size_t cpylen = ((64 - ctx->bufused) <= len) ? 64 - ctx->bufused : len;
        memcpy(ctx->buffer + ctx->bufused, buffer, cpylen);
        ctx->bufused += cpylen;
        buffer += cpylen;
        len    -= cpylen;

        if(ctx->bufused == 64)
        {
            sha1_update_block(ctx, ctx->buffer);
            ctx->bufused = 0;
        }
    }

    // Feed 64 byte blocks into the update function
    while(len >= 64)
    {
        sha1_update_block(ctx, buffer);
        len    -= 64;
        buffer += 64;
    }

    // And save any overflow bytes for next update
    if(len > 0)
    {
        memcpy(ctx->buffer, buffer, len);
        ctx->bufused = len;
    }
}

void sha1_final(struct sha1_context *ctx, uint8_t *hash, int hashtype)
{
    // Apply padding and feed it into the update function
    uint64_t len = ctx->len * 8;
    sha1_endianswap(&len, sizeof(uint64_t));
    size_t padlen = 64 - ((ctx->len + 8) % 64);
    uint8_t padding[64] = {0};
    padding[0] = 0x80;

    sha1_update(ctx, padding, padlen);
    sha1_update(ctx, (uint8_t *)&len, 8);
    
    // Not required on big endian systems
    for(int i = 0; i < 5; i++)
        sha1_endianswap(&ctx->state[i], sizeof(uint32_t));
    
    // Export the hash
    if(hashtype == SHA1_BIN)
        memcpy(hash, ctx->state, 20);
    else
    {
        hash[0] = '\0';
        for(int i = 0; i < 20; i++)
            hash += sprintf((char *)hash, "%02x", ((uint8_t *)ctx->state)[i]);
    }
    memset(ctx, 0, sizeof(struct sha1_context));
}

void sha1(uint8_t *buffer, size_t len, uint8_t *hash, int hashtype)
{
    struct sha1_context ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, buffer, len);
    sha1_final(&ctx, hash, hashtype);
}
