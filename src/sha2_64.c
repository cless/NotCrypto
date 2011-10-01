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
 * The sha384 and sha512 functions work incorrectly for messages with a size
 * larger than 2^64 bits. The code of sha2_32.c is almost exactly the same
 * except that it uses 32 bit variables for everything and implements 256 and
 * 224 bit hashes.
 */

#include <string.h>
#include "sha2.h"

inline static uint64_t sha2_rot(uint64_t x, int bits)
{
    return (x >> bits) | (x << (64 - bits));
}

// the 6 small transformation functions that are used by the algorithm
inline static uint64_t sha2_func_1(uint64_t x, uint64_t y, uint64_t z)
{
    return (x & y) ^ ((~x) & z);
}

inline static uint64_t sha2_func_2(uint64_t x, uint64_t y, uint64_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

inline static uint64_t sha2_func_3(uint64_t x)
{
    return sha2_rot(x, 28) ^ sha2_rot(x, 34) ^ sha2_rot(x, 39);
}

inline static uint64_t sha2_func_4(uint64_t x)
{
    return sha2_rot(x, 14) ^ sha2_rot(x, 18) ^ sha2_rot(x, 41);
}

inline static uint64_t sha2_func_5(uint64_t x)
{
    return sha2_rot(x, 1) ^ sha2_rot(x, 8) ^ (x >> 7);
}

inline static uint64_t sha2_func_6(uint64_t x)
{
    return sha2_rot(x, 19) ^ sha2_rot(x, 61) ^ (x >> 6);
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

static const uint64_t sha2_const[] =
   {0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

void sha2_512_init(struct sha2_context *ctx)
{
    memset(ctx, 0, sizeof(struct sha2_context));
    
    ctx->ctx_union.b64.state[0] = 0x6a09e667f3bcc908;
    ctx->ctx_union.b64.state[1] = 0xbb67ae8584caa73b;
    ctx->ctx_union.b64.state[2] = 0x3c6ef372fe94f82b;
    ctx->ctx_union.b64.state[3] = 0xa54ff53a5f1d36f1;
    ctx->ctx_union.b64.state[4] = 0x510e527fade682d1;
    ctx->ctx_union.b64.state[5] = 0x9b05688c2b3e6c1f;
    ctx->ctx_union.b64.state[6] = 0x1f83d9abfb41bd6b;
    ctx->ctx_union.b64.state[7] = 0x5be0cd19137e2179;
}

void sha2_384_init(struct sha2_context *ctx)
{
    memset(ctx, 0, sizeof(struct sha2_context));
    
    ctx->ctx_union.b64.state[0] = 0xcbbb9d5dc1059ed8;
    ctx->ctx_union.b64.state[1] = 0x629a292a367cd507;
    ctx->ctx_union.b64.state[2] = 0x9159015a3070dd17;
    ctx->ctx_union.b64.state[3] = 0x152fecd8f70e5939;
    ctx->ctx_union.b64.state[4] = 0x67332667ffc00b31;
    ctx->ctx_union.b64.state[5] = 0x8eb44a8768581511;
    ctx->ctx_union.b64.state[6] = 0xdb0c2e0d64f98fa7;
    ctx->ctx_union.b64.state[7] = 0x47b5481dbefa4fa4;
}

static void sha2_update_block(struct sha2_context *ctx, const uint8_t *buffer)
{
    uint64_t w_buf[80];
    uint64_t lstate[8];
    uint64_t temp[2];

    // Initialize the 'block state'
    memcpy(w_buf, buffer, 16*sizeof(uint64_t));
    for(int i = 0; i < 16; i++)
        sha2_endianswap(&w_buf[i], sizeof(uint64_t));
    for(int i = 16; i < 80; i++)
        w_buf[i] = sha2_func_6(w_buf[i - 2]) + w_buf[i - 7] + sha2_func_5(w_buf[i - 15]) + w_buf[i - 16];

    // Copy the state into a local buffer
    for(int i = 0; i < 8; i++)
        lstate[i] = ctx->ctx_union.b64.state[i];

    // Run over 80 rounds
    for(int i = 0; i < 80; i++)
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
        ctx->ctx_union.b64.state[i] += lstate[i];
}

void sha2_512_update(struct sha2_context *ctx, const uint8_t *buffer, size_t len)
{
    ctx->ctx_union.b64.len += len;
    
    // If our context has overflow bytes from the last update then extend those
    // until the overflow buffer has 64 bytes in it so we can process the block
    if(ctx->ctx_union.b64.bufused > 0)
    {
        size_t cpylen = ((128 - ctx->ctx_union.b64.bufused) <= len) ? 128 - ctx->ctx_union.b64.bufused : len;
        memcpy(ctx->ctx_union.b64.buffer + ctx->ctx_union.b64.bufused, buffer, cpylen);
        ctx->ctx_union.b64.bufused += cpylen;
        buffer += cpylen;
        len    -= cpylen;

        if(ctx->ctx_union.b64.bufused == 128)
        {
            sha2_update_block(ctx, ctx->ctx_union.b64.buffer);
            ctx->ctx_union.b64.bufused = 0;
        }
    }

    // Feed 64 byte blocks into the update function
    while(len >= 128)
    {
        sha2_update_block(ctx, buffer);
        len    -= 128;
        buffer += 128;
    }

    // And save any overflow bytes for next update
    if(len > 0)
    {
        memcpy(ctx->ctx_union.b64.buffer, buffer, len);
        ctx->ctx_union.b64.bufused = len;
    }
}

void sha2_384_update(struct sha2_context *ctx, const uint8_t *buffer, size_t len)
{
    sha2_512_update(ctx, buffer, len);
}


void sha2_512_final(struct sha2_context *ctx, uint8_t *hash)
{
    // Apply padding and feed it into the update function
    uint64_t len = ctx->ctx_union.b64.len * 8;
    sha2_endianswap(&len, sizeof(uint64_t));
    size_t padlen = 128 - ((ctx->ctx_union.b64.len + 16) % 128);
    uint8_t padding[128] = {0};
    padding[0] = 0x80;

    sha2_512_update(ctx, padding, padlen);
    sha2_512_update(ctx, padding + 1, 8); // we dont actually support the full 128 bit size yet :(
    sha2_512_update(ctx, (uint8_t *)&len, 8);
    
    // Not required on big endian systems
    for(int i = 0; i < 8; i++)
        sha2_endianswap(&ctx->ctx_union.b64.state[i], sizeof(uint64_t));
    
    memcpy(hash, ctx->ctx_union.b64.state, 64);
    memset(ctx, 0, sizeof(struct sha2_context));
}

void sha2_384_final(struct sha2_context *ctx, uint8_t *hash)
{
    // Apply padding and feed it into the update function
    uint64_t len = ctx->ctx_union.b64.len * 8;
    sha2_endianswap(&len, sizeof(uint64_t));
    size_t padlen = 128 - ((ctx->ctx_union.b64.len + 16) % 128);
    uint8_t padding[128] = {0};
    padding[0] = 0x80;

    sha2_512_update(ctx, padding, padlen);
    sha2_512_update(ctx, padding + 1, 8); // we dont actually support the full 128 bit size yet :(
    sha2_512_update(ctx, (uint8_t *)&len, 8);
    
    // Not required on big endian systems
    for(int i = 0; i < 7; i++)
        sha2_endianswap(&ctx->ctx_union.b64.state[i], sizeof(uint64_t));
    
    memcpy(hash, ctx->ctx_union.b64.state, 48);
    memset(ctx, 0, sizeof(struct sha2_context));
}

void sha2_512(const uint8_t *buffer, size_t len, uint8_t *hash)
{
    struct sha2_context ctx;
    sha2_512_init(&ctx);
    sha2_512_update(&ctx, buffer, len);
    sha2_512_final(&ctx, hash);
}

void sha2_384(const uint8_t *buffer, size_t len, uint8_t *hash)
{
    struct sha2_context ctx;
    sha2_384_init(&ctx);
    sha2_384_update(&ctx, buffer, len);
    sha2_384_final(&ctx, hash);
}
