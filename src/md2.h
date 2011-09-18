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

#ifndef __NOTCRYPTO_MD2_H_
#define __NOTCRYPTO_MD2_H_

#warning "This code is insecure and should never be used. See README for more information."

#define MD2_HEX 0
#define MD2_BIN 1

struct md2_context
{
    unsigned char checksum[16];
    unsigned char mdbuffer[48];
    unsigned char buffer[16];
    unsigned char L;
    size_t bufused;
};

void md2_init(struct md2_context *ctx);
void md2_update(struct md2_context *ctx, const unsigned char *buffer, size_t len);
void md2_final(struct md2_context *ctx, unsigned char *hash, int hashtype);
void md2(unsigned char *buffer, size_t len, unsigned char *hash, int hashtype);

#endif
