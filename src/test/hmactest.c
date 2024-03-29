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
    }, \
    { \
        "Hi There", 8, \
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20, \
        HMAC_SHA2_224, \
        "\x89\x6f\xb1\x12\x8a\xbb\xdf\x19\x68\x32\x10\x7c\xd4\x9d\xf3\x3f" \
        "\x47\xb4\xb1\x16\x99\x12\xba\x4f\x53\x68\x4b\x22", \
        28, "HMAC-SHA2-224 Test 1" \
    }, \
    { \
        "Hi There", 8, \
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20, \
        HMAC_SHA2_256, \
        "\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b" \
        "\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7", \
        32, "HMAC-SHA2-256 Test 1" \
    }, \
    { \
        "Hi There", 8, \
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20, \
        HMAC_SHA2_384, \
        "\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\x25\xf4\xab\x46\x90\x7f" \
        "\x15\xf9\xda\xdb\xe4\x10\x1e\xc6\x82\xaa\x03\x4c\x7c\xeb\xc5\x9c" \
        "\xfa\xea\x9e\xa9\x07\x6e\xde\x7f\x4a\xf1\x52\xe8\xb2\xfa\x9c\xb6", \
        48, "HMAC-SHA2-384 Test 1" \
    }, \
    { \
        "Hi There", 8, \
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20, \
        HMAC_SHA2_512, \
        "\x87\xaa\x7c\xde\xa5\xef\x61\x9d\x4f\xf0\xb4\x24\x1a\x1d\x6c\xb0" \
        "\x23\x79\xf4\xe2\xce\x4e\xc2\x78\x7a\xd0\xb3\x05\x45\xe1\x7c\xde" \
        "\xda\xa8\x33\xb7\xd6\xb8\xa7\x02\x03\x8b\x27\x4e\xae\xa3\xf4\xe4" \
        "\xbe\x9d\x91\x4e\xeb\x61\xf1\x70\x2e\x69\x6c\x20\x3a\x12\x68\x54", \
        64, "HMAC-SHA2-512 Test 1" \
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
