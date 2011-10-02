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
#ifndef __NOTCRYPTO_SHA2_H_
#define __NOTCRYPTO_SHA2_H_
#include <stddef.h>
#include <stdint.h>

# ifndef NOTCRYPTO_DISABLE_WARNING
#  warning "This code is insecure and should never be used. See README for more information."
# endif

// 32 bit context for SHA2-224 and SHA2-256
struct sha2_context_32bit
{
    uint8_t buffer[64];
    uint32_t state[8];
    size_t bufused;
    uint64_t len;
};

// 64 bit context for SHA2-384 and SHA2-512
struct sha2_context_64bit
{
    uint8_t buffer[128];
    uint64_t state[8];
    size_t bufused;
    uint64_t len; // Should be 128 bits
};

// Unified context to make the API less complex
struct sha2_context
{
    union
    {
        struct sha2_context_32bit b32;
        struct sha2_context_64bit b64;
    } ctx_union;
};

void sha2_256_init(struct sha2_context *ctx);
void sha2_256_update(struct sha2_context *ctx, const uint8_t *buffer, size_t len);
void sha2_256_final(struct sha2_context *ctx, uint8_t *hash);
void sha2_256(const uint8_t *buffer, size_t len, uint8_t *hash);

void sha2_224_init(struct sha2_context *ctx);
void sha2_224_update(struct sha2_context *ctx, const uint8_t *buffer, size_t len);
void sha2_224_final(struct sha2_context *ctx, uint8_t *hash);
void sha2_224(const uint8_t *buffer, size_t len, uint8_t *hash);

void sha2_512_init(struct sha2_context *ctx);
void sha2_512_update(struct sha2_context *ctx, const uint8_t *buffer, size_t len);
void sha2_512_final(struct sha2_context *ctx, uint8_t *hash);
void sha2_512(const uint8_t *buffer, size_t len, uint8_t *hash);

void sha2_384_init(struct sha2_context *ctx);
void sha2_384_update(struct sha2_context *ctx, const uint8_t *buffer, size_t len);
void sha2_384_final(struct sha2_context *ctx, uint8_t *hash);
void sha2_384(const uint8_t *buffer, size_t len, uint8_t *hash);


#endif
