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
#include "sha1.h"

int main()
{
    char hash[41];

    char *test_plain[] = {
        "",
        "a",
        "abc",
        "message digest",
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        NULL};
    
    char *test_hash[] = {
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
        "a9993e364706816aba3e25717850c26c9cd0d89d",
        "c12252ceda8be8994d5fa0290a47231c1d16aae3",
        "32d10c7b8cf96570ca04ce37f2a19d84240d3a89",
        "761c457bf73b14d27e9e9265c46f4b4dda11f940",
        "50abf5706a150990a08b2c5ea40fa0e585554732",
        NULL};

    
    for(int i = 0; test_plain[i] && test_hash[i]; i++)
    {
        sha1(test_plain[i], strlen(test_plain[i]), hash, SHA1_HEX);
        printf("%s - \"%s\"", hash, test_plain[i]);
        if(strcmp(hash, test_hash[i]) == 0)
            printf("\n");
        else
            printf("\n  ERROR! Expected %s\n\n", test_hash[i]);
    }
}
