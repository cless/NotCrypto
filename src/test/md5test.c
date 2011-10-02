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

#include <stdio.h>
#include <string.h>
#include "md5.h"
#include "hex.h"

int main()
{
    uint8_t hash[16];
    char hexhash[33];

    uint8_t *test_plain[] = {
        (uint8_t *)"",
        (uint8_t *)"a",
        (uint8_t *)"abc",
        (uint8_t *)"message digest",
        (uint8_t *)"abcdefghijklmnopqrstuvwxyz",
        (uint8_t *)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        (uint8_t *)"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        NULL};

    char *test_hash[] = {
        "d41d8cd98f00b204e9800998ecf8427e",
        "0cc175b9c0f1b6a831c399e269772661",
        "900150983cd24fb0d6963f7d28e17f72",
        "f96b697d7cb7938d525a2f31aaf161d0",
        "c3fcd3d76192e4007dfb496cca67e13b",
        "d174ab98d277d9f5a5611c2c9f419d9f",
        "57edf4a22be3c955ac49da2e2107b67a",
        NULL};

    
    for(int i = 0; test_plain[i] && test_hash[i]; i++)
    {
        md5(test_plain[i], strlen((const char *)test_plain[i]), hash);
        hex_encode(hexhash, hash, 16);
        printf("%s - \"%s\"", hexhash, test_plain[i]);
        if(strcmp(hexhash, test_hash[i]) == 0)
            printf("\n");
        else
            printf("\n  ERROR! Expected %s\n\n", test_hash[i]);
    }
}
