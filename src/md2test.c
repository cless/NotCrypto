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
#include "md2.h"
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
        "8350e5a3e24c153df2275c9f80692773",
        "32ec01ec4a6dac72c0ab96fb34c0b5d1",
        "da853b0d3f88d99b30283a69e6ded6bb",
        "ab4f496bfb2a530b219ff33031fe06b0",
        "4e8ddff3650292ab5a4108c3aa47940b",
        "da33def2a42df13975352846c30338cd",
        "d5976f79d83d3a0dc9806c3c66f3efd8",
        NULL};
    
    for(int i = 0; test_plain[i] && test_hash[i]; i++)
    {
        md2(test_plain[i], strlen((char *)test_plain[i]), hash);
        hex_encode(hexhash, hash, 16);
        printf("%s - \"%s\"", hexhash, test_plain[i]);
        if(strcmp(hexhash, test_hash[i]) == 0)
            printf("\n");
        else
            printf("\n  ERROR! Expected %s\n\n", test_hash[i]);
    }
}
