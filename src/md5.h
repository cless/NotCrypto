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
#ifndef __NOTCRYPTO_MD5_H_
#define __NOTCRYPTO_MD5_H_

# include <stdint.h>
# include <stddef.h>

# ifndef NOTCRYPTO_DISABLE_WARNING
#  warning "This code is insecure and should never be used. See README for more information."
# endif

struct md5_context
{
    uint8_t buffer[64];
    uint32_t state[4];
    size_t bufused;
    uint64_t len;
};

void md5_init(struct md5_context *ctx);
void md5_update(struct md5_context *ctx, const uint8_t *buffer, size_t len);
void md5_final(struct md5_context *ctx, uint8_t *hash);
void md5(const uint8_t *buffer, size_t len, uint8_t *hash);

#endif
