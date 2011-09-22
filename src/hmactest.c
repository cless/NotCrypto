/* Copyright (C) 2012 by clueless <clueless@thunked.org>
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

/* This code makes me sick, but it has to do
 *
 * Coulnd't find test vectors for HMAC-MD2 and HMAC-SHA1 so I created my own
 * using PHPs hash_hmac() function. Should probably be cross checked with more
 * implementations (not sure what php uses under the hood). The HMAC-SHA1
 * vectors are also compared with PolarSSL hmac_sha1
 * HMAC-MD5 test vectors come from RFC 2104
 */

#include <stdio.h>
#include <string.h>
#include "hmac.h"
#include "hex.h"

#define TEST_INITIALIZER \
{ \
    { \
        "", 0, "", 0, HMAC_MD2, "\x6f\x6e\x03\x12\x23\xb3\x6c\xd2\xa9\x97\x78\x7a\x03\xd1\x6b\xf5", \
        16, "HMAC-MD2 Test 1" \
    }, \
    { \
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 26, "123456789012345678901234567890", 30, HMAC_MD2, "\x10\xad\x2f\x6d\x34\xc6\xd1\xdc\x1b\xfb\xf3\xfa\xaf\x74\xa5\xd5", \
        16, "HMAC-MD2 Test 2" \
    }, \
    { \
        "Hi There", 8, "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 16, \
        HMAC_MD5, "\x92\x94\x72\x7a\x36\x38\xbb\x1c\x13\xf4\x8e\xf8\x15\x8b\xfc\x9d", 16, "HMAC-MD5 Test 1" \
    }, \
    { \
        "what do ya want for nothing?", 28, "Jefe", 4, \
        HMAC_MD5, "\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7\x38", 16, "HMAC-MD5 Test 2" \
    }, \
    { \
        "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD" \
        "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD" \
        "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD" \
        "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD" \
        "\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD", 50, \
        "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA", 16, \
        HMAC_MD5, "\x56\xbe\x34\x52\x1d\x14\x4c\x88\xdb\xb8\xc7\x33\xf0\xe8\xb3\xf6", 16, "HMAC-MD5 Test 3" \
    }, \
    { \
        "", 0, "", 0, HMAC_SHA1, "\xfb\xdb\x1d\x1b\x18\xaa\x6c\x08\x32\x4b\x7d\x64\xb7\x1f\xb7\x63\x70\x69\x0e\x1d", \
        20, "HMAC-SHA1 Test 1" \
    }, \
    { \
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 26, "123456789012345678901234567890", 30, \
        HMAC_SHA1, "\xdd\xd5\x60\x09\x7f\xc7\xe9\xa8\xe3\x2c\xba\x0d\x58\x17\xf4\x6c\x24\x50\x32\x8d", \
        20, "HMAC-SHA1 Test 2" \
    } \
}

struct testentry
{
    char *data;
    size_t datalen;
    char *key;
    size_t keylen;
    int hashtype;
    char *hmac;
    size_t macsize;
    char *name;
};

void printhex(uint8_t *bytes, size_t len)
{
    for(size_t i = 0; i < len; i++)
        printf("%02x", bytes[i]);
}

int main()
{
    struct testentry entries[] = TEST_INITIALIZER; 
    for(size_t i = 0; i < sizeof(entries) / sizeof(struct testentry); i++)
    {
        uint8_t digest[entries[i].macsize];
        char hexdigest[entries[i].macsize * 2 + 1];
        hmac((uint8_t *)entries[i].data, entries[i].datalen, (uint8_t *)entries[i].key,
             entries[i].keylen, digest, entries[i].hashtype);
        hex_encode(hexdigest, digest, entries[i].macsize);
        printf("%s %s ", entries[i].name, hexdigest);
        if(memcmp(digest, entries[i].hmac, entries[i].macsize) == 0)
            printf("OK\n");
        else
        {
            hex_encode(hexdigest, (uint8_t *)entries[i].hmac, entries[i].macsize);
            printf("ERROR EXPECTED %s\n", hexdigest);
        }
    }
}
