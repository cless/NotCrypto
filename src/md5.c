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

/* This code is written from scratch based on RFC 1321.  The constants are
 * lifted from the reference implementation in RFC 1321, no other code is
 * derived from the reference implementation.  This code is written solely to
 * learn about one way hash functions and MD5 specifically.  This code should
 * never be used in production, or anywhere else.  To the best of my knowledge
 * the implementation is correct but you should assume there are errors in it.
 */

#include <stdio.h>
#include <string.h>
#include "md5.h"

// The 4 'simple' transformation functions
static inline uint32_t md5_func_f(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) | ((~x) & z);
}

static inline uint32_t md5_func_g(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & z) | (y & (~z));
}

static inline uint32_t md5_func_h(uint32_t x, uint32_t y, uint32_t z)
{
    return x ^ y ^ z;
}

static inline uint32_t md5_func_i(uint32_t x, uint32_t y, uint32_t z)
{
    return y ^ (x | (~z));
}

// rotate left function
static inline uint32_t md5_func_rot(uint32_t x, unsigned int s)
{
    return (x << s) | (x >> (32 - s));
}

// Type for the above 'simple' functions
typedef uint32_t (*md5_func)(uint32_t, uint32_t, uint32_t);

// And lastly the actual transformation function that is part of each round
static inline uint32_t md5_func_round(md5_func func, uint32_t a, uint32_t b, uint32_t c,
                                       uint32_t d, uint32_t k, unsigned int s, uint32_t i)
{
    return b + md5_func_rot((a + func(b, c, d) + k + i), s);
}

void md5_init(struct md5_context *ctx)
{
    memset(ctx, 0, sizeof(struct md5_context));
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}

static void md5_update_block(struct md5_context *ctx, const unsigned char *buffer)
{
    // Copy local buffers and states
    uint32_t locbuf[16];
    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    
    memcpy(locbuf, buffer, 64);

    // Round 1
    a = md5_func_round(md5_func_f, a, b, c, d, locbuf[ 0],  7, 0xd76aa478);
    d = md5_func_round(md5_func_f, d, a, b, c, locbuf[ 1], 12, 0xe8c7b756);
    c = md5_func_round(md5_func_f, c, d, a, b, locbuf[ 2], 17, 0x242070db);
    b = md5_func_round(md5_func_f, b, c, d, a, locbuf[ 3], 22, 0xc1bdceee);
    a = md5_func_round(md5_func_f, a, b, c, d, locbuf[ 4],  7, 0xf57c0faf);
    d = md5_func_round(md5_func_f, d, a, b, c, locbuf[ 5], 12, 0x4787c62a);
    c = md5_func_round(md5_func_f, c, d, a, b, locbuf[ 6], 17, 0xa8304613);
    b = md5_func_round(md5_func_f, b, c, d, a, locbuf[ 7], 22, 0xfd469501);
    a = md5_func_round(md5_func_f, a, b, c, d, locbuf[ 8],  7, 0x698098d8);
    d = md5_func_round(md5_func_f, d, a, b, c, locbuf[ 9], 12, 0x8b44f7af);
    c = md5_func_round(md5_func_f, c, d, a, b, locbuf[10], 17, 0xffff5bb1);
    b = md5_func_round(md5_func_f, b, c, d, a, locbuf[11], 22, 0x895cd7be);
    a = md5_func_round(md5_func_f, a, b, c, d, locbuf[12],  7, 0x6b901122);
    d = md5_func_round(md5_func_f, d, a, b, c, locbuf[13], 12, 0xfd987193);
    c = md5_func_round(md5_func_f, c, d, a, b, locbuf[14], 17, 0xa679438e);
    b = md5_func_round(md5_func_f, b, c, d, a, locbuf[15], 22, 0x49b40821);
    
    // Round 2
    a = md5_func_round(md5_func_g, a, b, c, d, locbuf[ 1],  5, 0xf61e2562);
    d = md5_func_round(md5_func_g, d, a, b, c, locbuf[ 6],  9, 0xc040b340);
    c = md5_func_round(md5_func_g, c, d, a, b, locbuf[11], 14, 0x265e5a51);
    b = md5_func_round(md5_func_g, b, c, d, a, locbuf[ 0], 20, 0xe9b6c7aa);
    a = md5_func_round(md5_func_g, a, b, c, d, locbuf[ 5],  5, 0xd62f105d);
    d = md5_func_round(md5_func_g, d, a, b, c, locbuf[10],  9, 0x02441453);
    c = md5_func_round(md5_func_g, c, d, a, b, locbuf[15], 14, 0xd8a1e681);
    b = md5_func_round(md5_func_g, b, c, d, a, locbuf[ 4], 20, 0xe7d3fbc8);
    a = md5_func_round(md5_func_g, a, b, c, d, locbuf[ 9],  5, 0x21e1cde6);
    d = md5_func_round(md5_func_g, d, a, b, c, locbuf[14],  9, 0xc33707d6);
    c = md5_func_round(md5_func_g, c, d, a, b, locbuf[ 3], 14, 0xf4d50d87);
    b = md5_func_round(md5_func_g, b, c, d, a, locbuf[ 8], 20, 0x455a14ed);
    a = md5_func_round(md5_func_g, a, b, c, d, locbuf[13],  5, 0xa9e3e905);
    d = md5_func_round(md5_func_g, d, a, b, c, locbuf[ 2],  9, 0xfcefa3f8);
    c = md5_func_round(md5_func_g, c, d, a, b, locbuf[ 7], 14, 0x676f02d9);
    b = md5_func_round(md5_func_g, b, c, d, a, locbuf[12], 20, 0x8d2a4c8a);
    
    // Round 3
    a = md5_func_round(md5_func_h, a, b, c, d, locbuf[ 5],  4, 0xfffa3942);
    d = md5_func_round(md5_func_h, d, a, b, c, locbuf[ 8], 11, 0x8771f681);
    c = md5_func_round(md5_func_h, c, d, a, b, locbuf[11], 16, 0x6d9d6122);
    b = md5_func_round(md5_func_h, b, c, d, a, locbuf[14], 23, 0xfde5380c);
    a = md5_func_round(md5_func_h, a, b, c, d, locbuf[ 1],  4, 0xa4beea44);
    d = md5_func_round(md5_func_h, d, a, b, c, locbuf[ 4], 11, 0x4bdecfa9);
    c = md5_func_round(md5_func_h, c, d, a, b, locbuf[ 7], 16, 0xf6bb4b60);
    b = md5_func_round(md5_func_h, b, c, d, a, locbuf[10], 23, 0xbebfbc70);
    a = md5_func_round(md5_func_h, a, b, c, d, locbuf[13],  4, 0x289b7ec6);
    d = md5_func_round(md5_func_h, d, a, b, c, locbuf[ 0], 11, 0xeaa127fa);
    c = md5_func_round(md5_func_h, c, d, a, b, locbuf[ 3], 16, 0xd4ef3085);
    b = md5_func_round(md5_func_h, b, c, d, a, locbuf[ 6], 23, 0x04881d05);
    a = md5_func_round(md5_func_h, a, b, c, d, locbuf[ 9],  4, 0xd9d4d039);
    d = md5_func_round(md5_func_h, d, a, b, c, locbuf[12], 11, 0xe6db99e5);
    c = md5_func_round(md5_func_h, c, d, a, b, locbuf[15], 16, 0x1fa27cf8);
    b = md5_func_round(md5_func_h, b, c, d, a, locbuf[ 2], 23, 0xc4ac5665);

    // Round 4
    a = md5_func_round(md5_func_i, a, b, c, d, locbuf[ 0],  6, 0xf4292244);
    d = md5_func_round(md5_func_i, d, a, b, c, locbuf[ 7], 10, 0x432aff97);
    c = md5_func_round(md5_func_i, c, d, a, b, locbuf[14], 15, 0xab9423a7);
    b = md5_func_round(md5_func_i, b, c, d, a, locbuf[ 5], 21, 0xfc93a039);
    a = md5_func_round(md5_func_i, a, b, c, d, locbuf[12],  6, 0x655b59c3);
    d = md5_func_round(md5_func_i, d, a, b, c, locbuf[ 3], 10, 0x8f0ccc92);
    c = md5_func_round(md5_func_i, c, d, a, b, locbuf[10], 15, 0xffeff47d);
    b = md5_func_round(md5_func_i, b, c, d, a, locbuf[ 1], 21, 0x85845dd1);
    a = md5_func_round(md5_func_i, a, b, c, d, locbuf[ 8],  6, 0x6fa87e4f);
    d = md5_func_round(md5_func_i, d, a, b, c, locbuf[15], 10, 0xfe2ce6e0);
    c = md5_func_round(md5_func_i, c, d, a, b, locbuf[ 6], 15, 0xa3014314);
    b = md5_func_round(md5_func_i, b, c, d, a, locbuf[13], 21, 0x4e0811a1);
    a = md5_func_round(md5_func_i, a, b, c, d, locbuf[ 4],  6, 0xf7537e82);
    d = md5_func_round(md5_func_i, d, a, b, c, locbuf[11], 10, 0xbd3af235);
    c = md5_func_round(md5_func_i, c, d, a, b, locbuf[ 2], 15, 0x2ad7d2bb);
    b = md5_func_round(md5_func_i, b, c, d, a, locbuf[ 9], 21, 0xeb86d391);
    
    // save the state
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    
    memset(locbuf, 0, 16);
    a = 0;
    b = 0;
    c = 0;
    d = 0;
}

void md5_update(struct md5_context *ctx, const unsigned char *buffer, size_t len)
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
            md5_update_block(ctx, ctx->buffer);
            ctx->bufused = 0;
        }
    }

    // Feed 64 byte blocks into the update function
    while(len >= 64)
    {
        md5_update_block(ctx, buffer);
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

void md5_final(struct md5_context *ctx, unsigned char *hash, int hashtype)
{
    // Apply padding and feed it into the update function
    uint64_t len = ctx->len * 8;
    size_t padlen = 64 - ((ctx->len + 8) % 64);
    unsigned char padding[64] = {0};
    padding[0] = 0x80;

    md5_update(ctx, padding, padlen);
    md5_update(ctx, (unsigned char *)&len, 8);
    
    // Export the hash
    if(hashtype == MD5_BIN)
    {
        memcpy(hash, (unsigned char *)ctx->state, 16);
    }
    else
    {
        hash[0] = '\0';
        for(int i = 0; i < 16; i++)
            sprintf((char *)hash, "%s%02x", (char *)hash, ((unsigned char *)ctx->state)[i]);
    }
    memset(ctx, 0, sizeof(struct md5_context));
}

void md5(unsigned char *buffer, size_t len, unsigned char *hash, int hashtype)
{
    struct md5_context ctx;
    md5_init(&ctx);
    md5_update(&ctx, buffer, len);
    md5_final(&ctx, hash, hashtype);
}
