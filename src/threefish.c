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

/* This code was implemented fom the Skein 1.3 paper
 * (https://www.schneier.com/skein1.3.pdf). The code is written to be easy to
 * understand and read, this means that no loops are unrolled and the code makes
 * use of rotation and permutation tables.  This code is written solely to learn
 * about block ciphers and threefish specifically. This code should never be
 * used in production, or anywhere else.  To the best of my knowledge this 
 * implementation is correct but you should assume there are errors in it.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "threefish.h"

/* rotation tables */
static const int rot_256_1[2] = {14, 16};
static const int rot_256_2[2] = {52, 57};
static const int rot_256_3[2] = {23, 40};
static const int rot_256_4[2] = { 5, 37};
static const int rot_256_5[2] = {25, 33};
static const int rot_256_6[2] = {46, 12};
static const int rot_256_7[2] = {58, 22};
static const int rot_256_8[2] = {32, 32};
static const int *rot_256[8] = {rot_256_1, rot_256_2, rot_256_3, rot_256_4, rot_256_5, rot_256_6, rot_256_7, rot_256_8}; 
                            
static const int rot_512_1[4] = {46, 36, 19, 37};
static const int rot_512_2[4] = {33, 27, 14, 42};
static const int rot_512_3[4] = {17, 49, 36, 39};
static const int rot_512_4[4] = {44,  9, 54, 56};
static const int rot_512_5[4] = {39, 30, 34, 24};
static const int rot_512_6[4] = {13, 50, 10, 17};
static const int rot_512_7[4] = {25, 29, 39, 43};
static const int rot_512_8[4] = { 8, 35, 56, 22};
static const int *rot_512[8] = {rot_512_1, rot_512_2, rot_512_3, rot_512_4, rot_512_5, rot_512_6, rot_512_7, rot_512_8}; 

static const int rot_1024_1[8] = {24, 13,  8, 47,  8, 17, 22, 37};
static const int rot_1024_2[8] = {38, 19, 10, 55, 49, 18, 23, 52};
static const int rot_1024_3[8] = {33,  4, 51, 13, 34, 41, 59, 17};
static const int rot_1024_4[8] = { 5, 20, 48, 41, 47, 28, 16, 25};
static const int rot_1024_5[8] = {41,  9, 37, 31, 12, 47, 44, 30};
static const int rot_1024_6[8] = {16, 34, 56, 51,  4, 53, 42, 41};
static const int rot_1024_7[8] = {31, 44, 47, 46, 19, 42, 44, 25};
static const int rot_1024_8[8] = { 9, 48, 35, 52, 23, 31, 37, 20};
static const int *rot_1024[8] = {rot_1024_1, rot_1024_2, rot_1024_3, rot_1024_4, rot_1024_5, rot_1024_6, rot_1024_7, rot_1024_8};

/* Permutation tables */
static const int permutations_256[4] = {0, 3, 2, 1};
static const int permutations_512[8] = {2, 1, 4, 7, 6, 5, 0, 3};
static const int permutations_1024[16] = {0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1};

/* several building block functions for the actual algorithm */
static void threefish_subkey(int s, int words, uint64_t *key, uint64_t *tweak, uint64_t *subkey)
{
    for(int i = 0; i < words; i++)
        subkey[i] = key[(s + i) % (words + 1)];

    subkey[words - 3] += tweak[s % 3];
    subkey[words - 2] += tweak[(s + 1) % 3];
    subkey[words - 1] += s;
}

static uint64_t threefish_lrotate(uint64_t x, int n)
{
    return (x << n) | (x >> (64 - n));
}

static uint64_t threefish_rrotate(uint64_t x, int n)
{
    return (x >> n) | (x << (64 - n));
}

static void threefish_mix(int d, int j, const int **table, uint64_t *unmixed, uint64_t *mixed)
{
    mixed[0] = unmixed[0] + unmixed[1];
    mixed[1] = threefish_lrotate(unmixed[1], table[d % 8][j]) ^ mixed[0];
}

static void threefish_unmix(int d, int j, const int **table, uint64_t *mixed, uint64_t *unmixed)
{
    unmixed[1] = threefish_rrotate(mixed[1] ^ mixed[0], table[d % 8][j]);
    unmixed[0] = mixed[0] - unmixed[1];
}

static void threefish_encrypt_internal(int rounds, int words, const int **rot, const int *permutations, uint64_t *key, uint64_t *tweak, uint64_t *ciphertext)
{
    uint64_t subkey[words];
    uint64_t cipheralt[words]; // Alternative buffer for ciphertext (makes permutations easier)
    
    // perform the encryption rounds
    for(int nr = 0; nr < rounds; nr++)
    {
        // Create a new subkey and add it to the state
        if(nr % 4 == 0)
        {
            threefish_subkey(nr / 4, words, key, tweak, subkey);
            for(int nw = 0; nw < words; nw++)
                ciphertext[nw] += subkey[nw];
        }
        
        // Mix the encryption state into the alternate buffer
        for(int nw = 0; nw < words; nw += 2)
            threefish_mix(nr, nw / 2, rot, &ciphertext[nw], &cipheralt[nw]);

        // Permutate the encrytion state from the alternate buffer into the ciphertext buffer
        for(int nw = 0; nw < words; nw++)
            ciphertext[nw] = cipheralt[permutations[nw]];
    }
    // Add the last subkey
    threefish_subkey(rounds / 4, words, key, tweak, subkey);
    for(int nw = 0; nw < words; nw++)
        ciphertext[nw] += subkey[nw];
}

static void threefish_decrypt_internal(int rounds, int words, const int **rot, const int *permutations, uint64_t *key, uint64_t *tweak, uint64_t *ciphertext)
{
    uint64_t subkey[words];
    uint64_t cipheralt[words]; // Alternative buffer for ciphertext (makes permutations easier)
    
    // subtract the last subkey
    threefish_subkey(rounds / 4, words, key, tweak, subkey);
    for(int nw = 0; nw < words; nw++)
        ciphertext[nw] -= subkey[nw];
    
    // perform the decryption rounds
    for(int nr = rounds - 1; nr >= 0; nr--)
    {
        // Reverse permutate the encrytion state into the alternate buffer
        for(int nw = 0; nw < words; nw++)
            cipheralt[permutations[nw]] = ciphertext[nw];
        
        // Unmix the encrytion state from the alt buffer into the ciphertext buffer
        for(int nw = 0; nw < words; nw += 2)
            threefish_unmix(nr, nw / 2, rot, &cipheralt[nw], &ciphertext[nw]);
        
        // Create a new subkey and subtract it from the state
        if(nr % 4 == 0)
        {
            threefish_subkey(nr / 4, words, key, tweak, subkey);
            for(int nw = 0; nw < words; nw++)
                ciphertext[nw] -= subkey[nw];
        }
    }
}


int threefish(int op, size_t blocksize, const uint8_t *inkey, const uint8_t *intweak, uint8_t *plaintext)
{
    int rounds;                 // # of rounds we need
    int words;                  // # of 64 bit words in the plaintext/ciphertext/key
    const int **rot;            // Pointer to the rotation tables (size depends on # words)
    const int *permutations;    // Pointer to the permutation table (size depends on # words again)
    
    // Set the correct parameters based on blocksize
    switch(blocksize)
    {
        case 32:
            rounds = 72;
            words = 4;
            rot = rot_256;
            permutations = permutations_256;
            break;
        case 64:
            rounds = 72;
            words = 8;
            rot = rot_512;
            permutations = permutations_512;
            break;
        case 128:
            rounds = 80;
            words = 16;
            rot = rot_1024;
            permutations = permutations_1024;
            break;
        default:
            return -1;
            break;
    }
    
    // Copy the key and tweak into local buffers we can write to, and cast the plaintext 64 bit words
    uint64_t key[words + 1];
    uint64_t *ciphertext = (uint64_t *)plaintext;
    uint64_t tweak[3];
    memcpy(key, inkey, words * sizeof(uint64_t));
    memcpy(tweak, intweak, 2 * sizeof(uint64_t));
    
    // Create the third tweak word
    tweak[2] = tweak[0] ^ tweak[1];
    
    // And create the extra key word
    key[words] = 0x1BD11BDAA9FC1A22U;
    for(int i = 0; i < words; i++)
        key[words] ^= key[i];
    
    //Pass everything on into the actual encryption/decryption function
    if(op == THREEFISH_ENCRYPT)
        threefish_encrypt_internal(rounds, words, rot, permutations, key, tweak, ciphertext);
    else
        threefish_decrypt_internal(rounds, words, rot, permutations, key, tweak, ciphertext);

    return 0;
}
