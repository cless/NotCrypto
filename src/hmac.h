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
#ifndef __NOTCRYPTO_HMAC_H_
#define __NOTCRYPTO_HMAC_H_
# include <stddef.h>
# include "md2.h"
# include "md5.h"
# include "sha1.h" 
# include "sha2.h"

# ifndef NOTCRYPTO_DISABLE_WARNING
#  warning "This code is insecure and should never be used. See README for more information."
# endif

# define HMAC_IPAD 0x36
# define HMAC_OPAD 0x5C

enum hmac_hashfunctions
{
    HMAC_MD2,
    HMAC_MD5,
    HMAC_SHA1,
    HMAC_SHA2_224,
    HMAC_SHA2_256,
    HMAC_SHA2_384,
    HMAC_SHA2_512
};

typedef void (*hashinit_t)(void *);
typedef void (*hashupdate_t)(void *, const uint8_t *, size_t);
typedef void (*hashfinal_t)(void *, const uint8_t *);

struct hmac_context
{
    int hashtype;
    union
    {
        struct md2_context md2;
        struct md5_context md5;
        struct sha1_context sha1;
        struct sha2_context sha2;
    } hashctx;
    hashinit_t hash_init;
    hashupdate_t hash_update;
    hashfinal_t hash_final;
    uint8_t key[128];    // Make sure to upgrade this when introducing a hash algo with bigger blocksize
    size_t hashsize;
    size_t blocksize;
};

void hmac_init(struct hmac_context *ctx, const uint8_t *key, size_t keylen, int hashtype);
void hmac_update(struct hmac_context *ctx, const uint8_t *buffer, size_t len);
void hmac_final(struct hmac_context *ctx, const uint8_t *mac);
void hmac(const uint8_t *input, size_t inlen, uint8_t *key, size_t keylen, uint8_t *mac, int hashtype);

#endif
