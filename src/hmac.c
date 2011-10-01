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

/* This code is based on the algorithm description in RFC 2104. This code is
 * written solely to learn about HMAC. This code should never be used in
 * production, or anywhere else.  To the best of my knowledge the implementation
 * is correct but you should assume there are errors in it.
 */

#include <string.h>
#include <stdio.h>
#include "hmac.h"

void hmac_makekey(struct hmac_context *ctx, const uint8_t *key, size_t keylen)
{
    if(keylen > ctx->blocksize)
    {
        // Hash the long key
        ctx->hash_init(&ctx->hashctx);
        ctx->hash_update(&ctx->hashctx, key, keylen);
        ctx->hash_final(&ctx->hashctx, ctx->key);
        keylen = ctx->hashsize;
    }
    else
    {
        // copy the short key
        memcpy(ctx->key, key, keylen);
    }
    
    // Pad it with 0 until the blocksize
    memset(ctx->key + keylen, 0, ctx->blocksize - keylen);
}

void hmac_xorkey(struct hmac_context *ctx, uint8_t xorbyte)
{
    for(size_t i = 0; i < ctx->blocksize; i++)
        ctx->key[i] ^= xorbyte;
}

void hmac_init(struct hmac_context *ctx, const uint8_t *key, size_t keylen, int hashtype)
{
    switch(hashtype)
    {
        case HMAC_MD2:
            ctx->blocksize = 16;
            ctx->hashsize  = 16;
            ctx->hash_init   = (hashinit_t)md2_init;
            ctx->hash_update = (hashupdate_t)md2_update;
            ctx->hash_final  = (hashfinal_t)md2_final;
            break;
        case HMAC_MD5:
            ctx->blocksize = 64;
            ctx->hashsize  = 16;
            ctx->hash_init   = (hashinit_t)&md5_init;
            ctx->hash_update = (hashupdate_t)&md5_update;
            ctx->hash_final  = (hashfinal_t)&md5_final;
            break;
        case HMAC_SHA1:
            ctx->blocksize = 64;
            ctx->hashsize  = 20;
            ctx->hash_init   = (hashinit_t)sha1_init;
            ctx->hash_update = (hashupdate_t)sha1_update;
            ctx->hash_final  = (hashfinal_t)sha1_final;
            break;
        case HMAC_SHA2_224:
            ctx->blocksize = 64;
            ctx->hashsize  = 28;
            ctx->hash_init   = (hashinit_t)sha2_224_init;
            ctx->hash_update = (hashupdate_t)sha2_224_update;
            ctx->hash_final  = (hashfinal_t)sha2_224_final;
            break;
        case HMAC_SHA2_256:
            ctx->blocksize = 64;
            ctx->hashsize  = 32;
            ctx->hash_init   = (hashinit_t)sha2_256_init;
            ctx->hash_update = (hashupdate_t)sha2_256_update;
            ctx->hash_final  = (hashfinal_t)sha2_256_final;
            break;
        case HMAC_SHA2_384:
            ctx->blocksize = 128;
            ctx->hashsize  = 48;
            ctx->hash_init   = (hashinit_t)sha2_384_init;
            ctx->hash_update = (hashupdate_t)sha2_384_update;
            ctx->hash_final  = (hashfinal_t)sha2_384_final;
            break;
        case HMAC_SHA2_512:
            ctx->blocksize = 128;
            ctx->hashsize  = 64;
            ctx->hash_init   = (hashinit_t)sha2_512_init;
            ctx->hash_update = (hashupdate_t)sha2_512_update;
            ctx->hash_final  = (hashfinal_t)sha2_512_final;
            break;
    }

    // Prepare the key
    hmac_makekey(ctx, key, keylen);
    hmac_xorkey(ctx, HMAC_IPAD);
    
    // prepare the hash function and feed the key into it
    ctx->hash_init(&ctx->hashctx);
    ctx->hash_update(&ctx->hashctx, ctx->key, ctx->blocksize);

    // Clean up the key
    hmac_xorkey(ctx, HMAC_IPAD);
}


void hmac_update(struct hmac_context *ctx, const uint8_t *buffer, size_t len)
{
    (ctx->hash_update)(&ctx->hashctx, buffer, len);
}

void hmac_final(struct hmac_context *ctx, const uint8_t *mac)
{
    // Calculate the intermediate hash
    uint8_t intermediate[ctx->hashsize];
    ctx->hash_final(&ctx->hashctx, intermediate);
    
    // create the outer hash
    hmac_xorkey(ctx, HMAC_OPAD);
    ctx->hash_init(&ctx->hashctx);
    ctx->hash_update(&ctx->hashctx, ctx->key, ctx->blocksize);
    ctx->hash_update(&ctx->hashctx, intermediate, ctx->hashsize);
    ctx->hash_final(&ctx->hashctx, mac);
}

void hmac(const uint8_t *input, size_t inlen, uint8_t *key, size_t keylen, uint8_t *mac, int hashtype)
{
    struct hmac_context ctx;
    hmac_init(&ctx, key, keylen, hashtype);
    hmac_update(&ctx, input, inlen);
    hmac_final(&ctx, mac);
}

