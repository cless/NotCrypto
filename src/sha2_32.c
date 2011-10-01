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

/* This code is based on the algorithm description in FIPS PUB 198-3.
 * http://csrc.nist.gov/publications/fips/fips180-3/fips180-3_final.pdf
 * This code is written solely to learn about one way hash functions and SHA2
 * specifically. This code should never be used in production, or anywhere else.
 * To the best of my knowledge the implementation is correct but you should
 * assume there are errors in it. The code of sha2_64.c is almost exactly the
 * same except that it uses 64 bit variables for everything and implements 512
 * and 384 bit hashes.
 */

#include <string.h>
#include "sha2.h"

inline static uint32_t sha2_rot(uint32_t x, int bits)
{
    return (x >> bits) | (x << (32 - bits));
}

// the 6 small transformation functions that are used by the algorithm
inline static uint32_t sha2_func_1(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ ((~x) & z);
}

inline static uint32_t sha2_func_2(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

inline static uint32_t sha2_func_3(uint32_t x)
{
    return sha2_rot(x, 2) ^ sha2_rot(x, 13) ^ sha2_rot(x, 22);
}

inline static uint32_t sha2_func_4(uint32_t x)
{
    return sha2_rot(x, 6) ^ sha2_rot(x, 11) ^ sha2_rot(x, 25);
}

inline static uint32_t sha2_func_5(uint32_t x)
{
    return sha2_rot(x, 7) ^ sha2_rot(x, 18) ^ (x >> 3);
}

inline static uint32_t sha2_func_6(uint32_t x)
{
    return sha2_rot(x, 17) ^ sha2_rot(x, 19) ^ (x >> 10);
}

// Swap the endianess of any given number, this function is not required on a
// big endian system but this code is designed for X86 systems which are little
// endian
static inline void sha2_endianswap(void *num, size_t len)
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

static const uint32_t sha2_const[] = {  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                                        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                                        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
                                        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                                        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
                                        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                                        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
                                        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                                        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
                                        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                                        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 
                                        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                                        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 
                                        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                                        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
                                        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void sha2_256_init(struct sha2_context *ctx)
{
    memset(ctx, 0, sizeof(struct sha2_context));
    
    ctx->ctx_union.b32.state[0] = 0x6a09e667;
    ctx->ctx_union.b32.state[1] = 0xbb67ae85;
    ctx->ctx_union.b32.state[2] = 0x3c6ef372;
    ctx->ctx_union.b32.state[3] = 0xa54ff53a;
    ctx->ctx_union.b32.state[4] = 0x510e527f;
    ctx->ctx_union.b32.state[5] = 0x9b05688c;
    ctx->ctx_union.b32.state[6] = 0x1f83d9ab;
    ctx->ctx_union.b32.state[7] = 0x5be0cd19;
}

void sha2_224_init(struct sha2_context *ctx)
{
    memset(ctx, 0, sizeof(struct sha2_context));
    
    ctx->ctx_union.b32.state[0] = 0xc1059ed8;
    ctx->ctx_union.b32.state[1] = 0x367cd507;
    ctx->ctx_union.b32.state[2] = 0x3070dd17;
    ctx->ctx_union.b32.state[3] = 0xf70e5939;
    ctx->ctx_union.b32.state[4] = 0xffc00b31;
    ctx->ctx_union.b32.state[5] = 0x68581511;
    ctx->ctx_union.b32.state[6] = 0x64f98fa7;
    ctx->ctx_union.b32.state[7] = 0xbefa4fa4;
}

static void sha2_update_block(struct sha2_context *ctx, const uint8_t *buffer)
{
    uint32_t w_buf[64];
    uint32_t lstate[8];
    uint32_t temp[2];

    // Initialize the 'block state'
    memcpy(w_buf, buffer, 16*sizeof(uint32_t));
    for(int i = 0; i < 16; i++)
        sha2_endianswap(&w_buf[i], sizeof(uint32_t));
    for(int i = 16; i < 64; i++)
        w_buf[i] = sha2_func_6(w_buf[i - 2]) + w_buf[i - 7] + sha2_func_5(w_buf[i - 15]) + w_buf[i - 16];

    // Copy the state into a local buffer
    for(int i = 0; i < 8; i++)
        lstate[i] = ctx->ctx_union.b32.state[i];

    // Run over 64 rounds
    for(int i = 0; i < 64; i++)
    {
        temp[0] = lstate[7] + sha2_func_4(lstate[4]) + sha2_func_1(lstate[4], lstate[5], lstate[6]) +
                  sha2_const[i] + w_buf[i];
        temp[1] = sha2_func_3(lstate[0]) + sha2_func_2(lstate[0], lstate[1], lstate[2]);

        lstate[7] = lstate[6];
        lstate[6] = lstate[5];
        lstate[5] = lstate[4];
        lstate[4] = lstate[3] + temp[0];
        lstate[3] = lstate[2];
        lstate[2] = lstate[1];
        lstate[1] = lstate[0];
        lstate[0] = temp[0] + temp[1];
    }

    for(int i = 0; i < 8; i++)
        ctx->ctx_union.b32.state[i] += lstate[i];
}

void sha2_256_update(struct sha2_context *ctx, const uint8_t *buffer, size_t len)
{
    ctx->ctx_union.b32.len += len;

    // If our context has overflow bytes from the last update then extend those
    // until the overflow buffer has 64 bytes in it so we can process the block
    if(ctx->ctx_union.b32.bufused > 0)
    {
        size_t cpylen = ((64 - ctx->ctx_union.b32.bufused) <= len) ? 64 - ctx->ctx_union.b32.bufused : len;
        memcpy(ctx->ctx_union.b32.buffer + ctx->ctx_union.b32.bufused, buffer, cpylen);
        ctx->ctx_union.b32.bufused += cpylen;
        buffer += cpylen;
        len    -= cpylen;

        if(ctx->ctx_union.b32.bufused == 64)
        {
            sha2_update_block(ctx, ctx->ctx_union.b32.buffer);
            ctx->ctx_union.b32.bufused = 0;
        }
    }

    // Feed 64 byte blocks into the update function
    while(len >= 64)
    {
        sha2_update_block(ctx, buffer);
        len    -= 64;
        buffer += 64;
    }

    // And save any overflow bytes for next update
    if(len > 0)
    {
        memcpy(ctx->ctx_union.b32.buffer, buffer, len);
        ctx->ctx_union.b32.bufused = len;
    }
}

void sha2_224_update(struct sha2_context *ctx, const uint8_t *buffer, size_t len)
{
    sha2_256_update(ctx, buffer, len);
}


void sha2_256_final(struct sha2_context *ctx, uint8_t *hash)
{
    // Apply padding and feed it into the update function
    uint64_t len = ctx->ctx_union.b32.len * 8;
    sha2_endianswap(&len, sizeof(uint64_t));
    size_t padlen = 64 - ((ctx->ctx_union.b32.len + 8) % 64);
    uint8_t padding[64] = {0};
    padding[0] = 0x80;

    sha2_256_update(ctx, padding, padlen);
    sha2_256_update(ctx, (uint8_t *)&len, 8);
    
    // Not required on big endian systems
    for(int i = 0; i < 8; i++)
        sha2_endianswap(&ctx->ctx_union.b32.state[i], sizeof(uint32_t));
    
    memcpy(hash, ctx->ctx_union.b32.state, 32);
    memset(ctx, 0, sizeof(struct sha2_context));
}

void sha2_224_final(struct sha2_context *ctx, uint8_t *hash)
{
    // Apply padding and feed it into the update function
    uint64_t len = ctx->ctx_union.b32.len * 8;
    sha2_endianswap(&len, sizeof(uint64_t));
    size_t padlen = 64 - ((ctx->ctx_union.b32.len + 8) % 64);
    uint8_t padding[64] = {0};
    padding[0] = 0x80;

    sha2_256_update(ctx, padding, padlen);
    sha2_256_update(ctx, (uint8_t *)&len, 8);
    
    // Not required on big endian systems
    for(int i = 0; i < 7; i++)
        sha2_endianswap(&ctx->ctx_union.b32.state[i], sizeof(uint32_t));
    
    memcpy(hash, ctx->ctx_union.b32.state, 28);
    memset(ctx, 0, sizeof(struct sha2_context));
}

void sha2_256(const uint8_t *buffer, size_t len, uint8_t *hash)
{
    struct sha2_context ctx;
    sha2_256_init(&ctx);
    sha2_256_update(&ctx, buffer, len);
    sha2_256_final(&ctx, hash);
}

void sha2_224(const uint8_t *buffer, size_t len, uint8_t *hash)
{
    struct sha2_context ctx;
    sha2_224_init(&ctx);
    sha2_224_update(&ctx, buffer, len);
    sha2_224_final(&ctx, hash);
}
