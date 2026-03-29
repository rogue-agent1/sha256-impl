#!/usr/bin/env python3
"""sha256_impl - Pure Python SHA-256 implementation."""
import sys, struct

K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
]

def _rotr(x, n): return ((x >> n) | (x << (32 - n))) & 0xffffffff

def sha256(message):
    if isinstance(message, str): message = message.encode()
    h0,h1,h2,h3,h4,h5,h6,h7 = 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    msg = bytearray(message)
    length = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56: msg.append(0)
    msg += struct.pack(">Q", length)
    for i in range(0, len(msg), 64):
        w = list(struct.unpack(">16I", msg[i:i+64]))
        for j in range(16, 64):
            s0 = _rotr(w[j-15],7) ^ _rotr(w[j-15],18) ^ (w[j-15]>>3)
            s1 = _rotr(w[j-2],17) ^ _rotr(w[j-2],19) ^ (w[j-2]>>10)
            w.append((w[j-16]+s0+w[j-7]+s1) & 0xffffffff)
        a,b,c,d,e,f,g,h = h0,h1,h2,h3,h4,h5,h6,h7
        for j in range(64):
            S1 = _rotr(e,6) ^ _rotr(e,11) ^ _rotr(e,25)
            ch = (e&f) ^ (~e&g) & 0xffffffff
            t1 = (h+S1+ch+K[j]+w[j]) & 0xffffffff
            S0 = _rotr(a,2) ^ _rotr(a,13) ^ _rotr(a,22)
            maj = (a&b) ^ (a&c) ^ (b&c)
            t2 = (S0+maj) & 0xffffffff
            h,g,f,e,d,c,b,a = g,f,e,(d+t1)&0xffffffff,c,b,a,(t1+t2)&0xffffffff
        h0,h1,h2,h3,h4,h5,h6,h7 = [(x+y)&0xffffffff for x,y in zip([h0,h1,h2,h3,h4,h5,h6,h7],[a,b,c,d,e,f,g,h])]
    return "".join(f"{x:08x}" for x in [h0,h1,h2,h3,h4,h5,h6,h7])

def test():
    assert sha256("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256("hello world") == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    print("sha256_impl: all tests passed")

if __name__ == "__main__":
    test() if "--test" in sys.argv else print("Usage: sha256_impl.py --test")
