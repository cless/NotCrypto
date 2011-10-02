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
#ifndef __NOTCRYPTO_SHA1_H_
#define __NOTCRYPTO_SHA1_H_

#include <stdint.h>

# ifndef NOTCRYPTO_DISABLE_WARNING
#  warning "This code is insecure and should never be used. See README for more information."
# endif

struct sha1_context
{
    uint8_t buffer[64];
    uint32_t state[5];
    size_t bufused;
    uint64_t len;
};

void sha1_init(struct sha1_context *ctx);
void sha1_update(struct sha1_context *ctx, const uint8_t *buffer, size_t len);
void sha1_final(struct sha1_context *ctx, uint8_t *hash);
void sha1(const uint8_t *buffer, size_t len, uint8_t *hash);

#endif
