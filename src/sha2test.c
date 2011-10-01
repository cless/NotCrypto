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

/* Test vectors for byte oriented messages taken from 
 * http://csrc.nist.gov/groups/STM/cavp/index.html
 */

#include <stdio.h>
#include <string.h>
#include "sha2.h"
#include "hex.h"

struct testdata
{
    size_t size;
    const uint8_t *input;
    const uint8_t *hash;
};

const struct testdata tests224[] =
{
    {0, "", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"},
    {1, "\x84", "3cd36921df5d6963e73739cf4d20211e2d8877c19cff087ade9d0e3a"},
    {2, "\x5c\x7b", "daff9bce685eb831f97fc1225b03c275a6c112e2d6e76f5faf7a36e6"},
    {3, "\x51\xca\x3d", "2c8959023515476e38388abb43599a29876b4b33d56adc06032de3a2"},
    {8, "\x5f\x77\xb3\x66\x48\x23\xc3\x3e", "bdf21ff325f754157ccf417f4855360a72e8fd117d28c8fe7da3ea38"},
    {163, "\xf1\x49\xe4\x1d\x84\x8f\x59\x27\x6c\xfd\xdd\x74\x3b\xaf\xa9\xa9"
          "\x0e\x1e\xe4\xa2\x63\xa1\x18\x14\x2b\x33\xe3\x70\x21\x76\xef\x0a"
          "\x59\xf8\x23\x7a\x1c\xb5\x1b\x42\xf3\xde\xd6\xb2\x02\xd9\xaf\x09"
          "\x97\x89\x8f\xdd\x03\xcf\x60\xbd\xa9\x51\xc5\x14\x54\x7a\x08\x50"
          "\xce\xc2\x54\x44\xae\x2f\x24\xcb\x71\x1b\xfb\xaf\xcc\x39\x56\xc9"
          "\x41\xd3\xde\x69\xf1\x55\xe3\xf8\xb1\x0f\x06\xdb\x5f\x37\x35\x9b"
          "\x77\x2d\xdd\x43\xe1\x03\x5a\x0a\x0d\x3d\xb3\x32\x42\xd5\x84\x30"
          "\x33\x83\x3b\x0d\xd4\x3b\x87\x0c\x6b\xf6\x0e\x8d\xea\xb5\x5f\x31"
          "\x7c\xc3\x27\x3f\x5e\x3b\xa7\x47\xf0\xcb\x65\x05\x0c\xb7\x22\x87"
          "\x96\x21\x0d\x92\x54\x87\x36\x43\x00\x8d\x45\xf2\x9c\xfd\x6c\x5b"
          "\x06\x0c\x9a", "9db6dc3a23abd7b6c3d72c38f4843c7de48a71d0ba91a86b18393e5f"}
};

const struct testdata tests256[] = 
{
    {0, "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {1, "\xd3", "28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1"},
    {2, "\x11\xaf", "5ca7133fa735326081558ac312c620eeca9970d1e70a4b95533d956f072d1f98"},
    {3, "\xb4\x19\x0e", "dff2e73091f6c05e528896c4c831b9448653dc2ff043528f6769437bc7b975c2"},
    {8, "\x57\x38\xc9\x29\xc4\xf4\xcc\xb6", "963bb88f27f512777aab6c8b1a02c70ec0ad651d428f870036e1917120fb48bf"},
    {163, "\x45\x11\x01\x25\x0e\xc6\xf2\x66\x52\x24\x9d\x59\xdc\x97\x4b\x73"
          "\x61\xd5\x71\xa8\x10\x1c\xdf\xd3\x6a\xba\x3b\x58\x54\xd3\xae\x08"
          "\x6b\x5f\xdd\x45\x97\x72\x1b\x66\xe3\xc0\xdc\x5d\x8c\x60\x6d\x96"
          "\x57\xd0\xe3\x23\x28\x3a\x52\x17\xd1\xf5\x3f\x2f\x28\x4f\x57\xb8"
          "\x5c\x8a\x61\xac\x89\x24\x71\x1f\x89\x5c\x5e\xd9\x0e\xf1\x77\x45"
          "\xed\x2d\x72\x8a\xbd\x22\xa5\xf7\xa1\x34\x79\xa4\x62\xd7\x1b\x56"
          "\xc1\x9a\x74\xa4\x0b\x65\x5c\x58\xed\xfe\x0a\x18\x8a\xd2\xcf\x46"
          "\xcb\xf3\x05\x24\xf6\x5d\x42\x3c\x83\x7d\xd1\xff\x2b\xf4\x62\xac"
          "\x41\x98\x00\x73\x45\xbb\x44\xdb\xb7\xb1\xc8\x61\x29\x8c\xdf\x61"
          "\x98\x2a\x83\x3a\xfc\x72\x8f\xae\x1e\xda\x2f\x87\xaa\x2c\x94\x80"
          "\x85\x8b\xec", "3c593aa539fdcdae516cdf2f15000f6634185c88f505b39775fb9ab137a10aa2"}
};

const struct testdata tests384[] = 
{
    {0, "", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"},
    {1, "\xc5", "b52b72da75d0666379e20f9b4a79c33a329a01f06a2fb7865c9062a28c1de860ba432edfd86b4cb1cb8a75b46076e3b1"},
    {2, "\x6e\xce", "53d4773da50d8be4145d8f3a7098ff3691a554a29ae6f652cc7121eb8bc96fd2210e06ae2fa2a36c4b3b3497341e70f0"},
    {3, "\x1f\xa4\xd5", "e4ca4663dff189541cd026dcc056626419028774666f5b379b99f4887c7237bdbd3bea46d5388be0efc2d4b7989ab2c4"},
    {8, "\xde\x60\x27\x5b\xda\xfc\xe4\xb1", 
     "a3d861d866c1362423eb21c6bec8e44b74ce993c55baa2b6640567560ebecdaeda07183dbbbd95e0f522caee5ddbdaf0"},
    {227, "\x62\xc6\xa1\x69\xb9\xbe\x02\xb3\xd7\xb4\x71\xa9\x64\xfc\x0b\xcc"
          "\x72\xb4\x80\xd2\x6a\xec\xb2\xed\x46\x0b\x7f\x50\x01\x6d\xda\xf0"
          "\x4c\x51\x21\x87\x83\xf3\xaa\xdf\xdf\xf5\xa0\x4d\xed\x03\x0d\x7b"
          "\x3f\xb7\x37\x6b\x61\xba\x30\xb9\x0e\x2d\xa9\x21\xa4\x47\x07\x40"
          "\xd6\x3f\xb9\x9f\xa1\x6c\xc8\xed\x81\xab\xaf\x8c\xe4\x01\x6e\x50"
          "\xdf\x81\xda\x83\x20\x70\x37\x2c\x24\xa8\x08\x90\xaa\x3a\x26\xfa"
          "\x67\x57\x10\xb8\xfb\x71\x82\x66\x24\x9d\x49\x6f\x31\x3c\x55\xd0"
          "\xba\xda\x10\x1f\x8f\x56\xee\xcc\xee\x43\x45\xa8\xf9\x8f\x60\xa3"
          "\x66\x62\xcf\xda\x79\x49\x00\xd1\x2f\x94\x14\xfc\xbd\xfd\xeb\x85"
          "\x38\x8a\x81\x49\x96\xb4\x7e\x24\xd5\xc8\x08\x6e\x7a\x8e\xdc\xc5"
          "\x3d\x29\x9d\x0d\x03\x3e\x6b\xb6\x0c\x58\xb8\x3d\x6e\x8b\x57\xf6"
          "\xc2\x58\xd6\x08\x1d\xd1\x0e\xb9\x42\xfd\xf8\xec\x15\x7e\xc3\xe7"
          "\x53\x71\x23\x5a\x81\x96\xeb\x9d\x22\xb1\xde\x3a\x2d\x30\xc2\xab"
          "\xbe\x0d\xb7\x65\x0c\xf6\xc7\x15\x9b\xac\xbe\x29\xb3\xa9\x3c\x92"
          "\x10\x05\x08",
     "0730e184e7795575569f87030260bb8e54498e0e5d096b18285e988d245b6f3486d1f2447d5f85bcbe59d5689fc49425"}
};

const struct testdata tests512[] = 
{
    {0, "",
     "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
     "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
    {1, "\x21",
     "3831a6a6155e509dee59a7f451eb35324d8f8f2df6e3708894740f98fdee2388"
     "9f4de5adb0c5010dfb555cda77c8ab5dc902094c52de3278f35a75ebc25f093a"},
    {2, "\x90\x83",
     "55586ebba48768aeb323655ab6f4298fc9f670964fc2e5f2731e34dfa4b0c09e"
     "6e1e12e3d7286b3145c61c2047fb1a2a1297f36da64160b31fa4c8c2cddd2fb4"},
    {3, "\x0a\x55\xdb", 
     "7952585e5330cb247d72bae696fc8a6b0f7d0804577e347d99bc1b11e52f3849"
     "85a428449382306a89261ae143c2f3fb613804ab20b42dc097e5bf4a96ef919b"},
    {8, "\x6f\x8d\x58\xb7\xca\xb1\x88\x8c",
     "a3941def2803c8dfc08f20c06ba7e9a332ae0c67e47ae57365c243ef40059b11"
     "be22c91da6a80c2cff0742a8f4bcd941bdee0b861ec872b215433ce8dcf3c031"},
    {227, 
     "\x4f\x05\x60\x09\x50\x66\x4d\x51\x90\xa2\xeb\xc2\x9c\x9e\xdb\x89"
     "\xc2\x00\x79\xa4\xd3\xe6\xbc\x3b\x27\xd7\x5e\x34\xe2\xfa\x3d\x02"
     "\x76\x85\x02\xbd\x69\x79\x00\x78\x59\x8d\x5f\xcf\x3d\x67\x79\xbf"
     "\xed\x12\x84\xbb\xe5\xad\x72\xfb\x45\x60\x15\x18\x1d\x95\x87\xd6"
     "\xe8\x64\xc9\x40\x56\x4e\xaa\xfb\x4f\x2f\xea\xd4\x34\x6e\xa0\x9b"
     "\x68\x77\xd9\x34\x0f\x6b\x82\xeb\x15\x15\x88\x08\x72\x21\x3d\xa3"
     "\xad\x88\xfe\xba\x9f\x4f\x13\x81\x7a\x71\xd6\xf9\x0a\x1a\x17\xc4"
     "\x3a\x15\xc0\x38\xd9\x88\xb5\xb2\x9e\xdf\xfe\x2d\x6a\x06\x28\x13"
     "\xce\xdb\xe8\x52\xcd\xe3\x02\xb3\xe3\x3b\x69\x68\x46\xd2\xa8\xe3"
     "\x6b\xd6\x80\xef\xcc\x6c\xd3\xf9\xe9\xa4\xc1\xae\x8c\xac\x10\xcc"
     "\x52\x44\xd1\x31\x67\x71\x40\x39\x91\x76\xed\x46\x70\x00\x19\xa0"
     "\x04\xa1\x63\x80\x6f\x7f\xa4\x67\xfc\x4e\x17\xb4\x61\x7b\xbd\x76"
     "\x41\xaa\xff\x7f\xf5\x63\x96\xba\x8c\x08\xa8\xbe\x10\x0b\x33\xa2"
     "\x0b\x5d\xaf\x13\x4a\x2a\xef\xa5\xe1\xc3\x49\x67\x70\xdc\xf6\xba"
     "\xa4\xf7\xbb",
     "a9db490c708cc72548d78635aa7da79bb253f945d710e5cb677a474efc7c65a2"
     "aab45bc7ca1113c8ce0f3c32e1399de9c459535e8816521ab714b2a6cd200525"}
};

void runtests(char *name, const struct testdata *tests, size_t testsize,
              size_t hashsize, void (*hashfunction)(const uint8_t *, size_t, uint8_t*))
{
    uint8_t hash[hashsize];
    uint8_t hexhash[hashsize*2+1];

    for(int i = 0; i < testsize; i++)
    {
        printf("%s Test #%d\t", name, i+1);
        hashfunction(tests[i].input, tests[i].size, hash);
        hex_encode(hexhash, hash, hashsize);
        if(strcmp(hexhash, tests[i].hash) != 0)
            printf("Failed! Got %s but expected %s\n", hexhash, tests[i].hash);
        else
            printf("OK!\n");
    }
}

int main()
{
    runtests("SHA2-224", tests224, 6, 28, sha2_224);
    runtests("SHA2-256", tests256, 6, 32, sha2_256);
    runtests("SHA2-384", tests384, 6, 48, sha2_384);
    runtests("SHA2-512", tests512, 6, 64, sha2_512);
}
