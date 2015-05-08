#!/usr/bin/env python

import sys
import gmpy

import nacl
import elligator

from os  import urandom
from struct import pack
from hashlib import sha256
from binascii import hexlify, unhexlify

from M2Crypto import X509

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA


# A simple AES-CTR based CSPRNG, not particularly interesting
class AESPRNG(object):
    def __init__(self, seed):
        key = sha256(seed).digest()
        self.buf      = ''
        self.buf_left = 0
        self.counter  = 0
        self.cipher   = AES.new(key, AES.MODE_ECB)

    def randbytes(self, n):
        ret = ''
        requested = n
        while requested > 0:
            # Grab all unused bytes in the buffer and then refill it
            if requested > self.buf_left:
                ret += self.buf[(16-self.buf_left):]
                requested -= self.buf_left
                # Encrypt the big-endian counter value for
                # the next block of pseudorandom bytes
                self.buf = self.cipher.encrypt(pack('>QQ', 0, self.counter))
                self.counter += 1
                self.buf_left = 16
            # Grab only the bytes we need from the buffer
            else:
                ret += self.buf[(16-self.buf_left):(16-self.buf_left+requested)]
                self.buf_left -= requested
                requested = 0
        return ret

# overwrite some bytes in orig at a specificed offset
def replace_at(orig, replace, offset):
    return orig[0:offset] + replace + orig[offset+len(replace):]

def build_key(bits=2048, e=65537, embed='', pos=1, randfunc=None):
    # generate base key
    rsa = RSA.generate(bits, randfunc)

    # extract modulus as a string
    n_str = unhexlify(str(hex(rsa.n))[2:-1])
    # embed data into the modulus
    n_hex = hexlify(replace_at(n_str, embed, pos))
    n = gmpy.mpz(n_hex, 16)
    p = rsa.p
    # compute a starting point to look for a new q value
    pre_q = n / p
    # use the next prime as the new q value
    q = pre_q.next_prime()
    n = p * q
    phi = (p-1) * (q-1)
    # compute new private exponent
    d = gmpy.invert(e, phi)
    # make sure that p is smaller than q
    if p > q:
        (p, q) = (q, p)
    return RSA.construct((long(n), long(e), long(d), long(p), long(q)))

def recover_seed(key='', modulus=None, pos=1):
    # recreate the master private key from the passphrase
    master = sha256(key).digest()
    # extract the ephemeral representative value from modulus
    # and convert it to the ephemeral Curve25519 public key
    rep = modulus[pos:pos+32]
    pub = elligator.representativetopublic(rep)
    # compute seed with master private and ephemeral public key
    return (nacl.crypto_box_beforenm(pub, master), rep)

if __name__ == "__main__":
    # passphrase and filename as arguments
    # Load an x.509 certificate from a file
    x509 = X509.load_cert(sys.argv[2])
    # Pull the modulus out of the certificate
    orig_modulus = unhexlify(x509.get_pubkey().get_modulus())
    (seed, rep) = recover_seed(key=sys.argv[1], modulus=orig_modulus, pos=80)

    prng = AESPRNG(seed)
    # deterministic key generation from seed 
    rsa = build_key(embed=rep, pos=80, randfunc=prng.randbytes)

    print rsa.exportKey()
