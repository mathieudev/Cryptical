# !/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2016 Hakan Kuesne && Mathieu Devaud
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" This module provides rsa methods. """


from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
from base64 import b64decode


def gen_rsa_keys(bits):
    """Generate an RSA key pair.

    This function generate a RSA key pair with an exponent of 65537 and create
    two PEM files to store them.

    :parameter:
     bits : int
        The key length in bits.

    :return: An RSA key object and two PEM files containing the private key and
    the public key.
    """

    print("Generating RSA key pair, %d bit long modulus" % bits)
    # only accept key of these lengths
    valid_key_length = [3072, 4096, 6144, 8192]

    if bits not in valid_key_length:
        raise AttributeError("You must provide a valid length for the key.")

    try:
        # generate a private and a public rsa key
        new_key = RSA.generate(bits, e=65537)
        # store the public key in a pem format
        pub_key = new_key.publickey()
        # store the private key in a pem format
        priv_key = new_key

        # save private key in a PEM file priv_key.pem
        f = open('priv_key.pem', 'w')
        f.write(new_key.exportKey('PEM'))
        f.close()

        # save public key in a PEM file pub_key.pem
        f = open('pub_key.pem', 'w')
        f.write(new_key.publickey().exportKey('PEM'))
        f.close()

    except ValueError:
        print("[error] RSA key generation failed, key size is too small")
        return False

    print("RSA key pair generated in priv_key.pem and pub_key.pem")

    return priv_key, pub_key


def rsa_encrypt(pub_key, plaintext):
    """Encrypt the plaintext with RSA.

    This function encrypt the plaintext using RSA-OAEP algorithm and public
    key of the recipient.

    :parameter:
     pub_key : RSA key object
        The RSA public key used to encrypt.
     plaintext : string
        Plaintext to encrypt.

    :return: A string, the ciphertext in base64.
    """

    try:
        # create PKCS1 OAEP cipher to perform encryption
        cipherer = PKCS1_OAEP.new(pub_key)
        # encrypt the plaintext
        rsa_ciphertext = cipherer.encrypt(plaintext)
    except ValueError:
        print("[error] RSA encryption failed")
        return False

    # encode the ciphertext in base64
    return rsa_ciphertext.encode('base64')


def rsa_decrypt(priv_key, rsa_ciphertext):
    """Decrypt the RSA ciphertext.

    This function decrypt the ciphertext using RSA-OAEP algorithm and private
    key of the recipient.

    :parameter:
     priv_key : RSA key object
        The RSA private key used to decrypt.
     rsa_ciphertext : string
        Ciphertext to decrypt.

    :return: A string, the plaintext after decryption.
    """

    try:
        # create PKCS1 OAEP cipher to perform decryption
        cipherer = PKCS1_OAEP.new(priv_key)
        # decode then decrypt the ciphertext
        rsa_plaintext = cipherer.decrypt(b64decode(rsa_ciphertext))
    except (ValueError, TypeError):
        print("[error] RSA decryption failed")
        return False

    return rsa_plaintext


def rsa_sign(priv_key, payload):
    """Sign the payload.

    This function sign the payload using RSA-PSS algorithm and private key
    of the source.

    :parameter:
     priv_key : RSA key object
        The rsa private key use to sign the payload.
     payload : string
        The payload to sign.

    :return: A string, the RSA-PSS signature of the payload.
    """

    # prepare the SHA256 hash
    h = SHA256.new()
    # create the SHA256 hash of the payload
    h.update(payload)
    # prepare the PKCS1-PSS signature with the private key
    signer = PKCS1_PSS.new(priv_key)
    # sign the hash
    thesignature = signer.sign(h)

    return thesignature


def rsa_verify_sign(pub_key, rsa_signature, payload):
    """Verify the signature of the payload.

    This function control if the signature is valid for the payload provided
    using using RSA-PSS algorithm and public key of the source.

    :parameter:
     pub_key : RSA key object
        The rsa public key use to verify the signature.
     rsa_signature : string
        The signature of the payload.
     payload : string
        The payload to verify.

    :return: A boolean, true if the signature is verified for the payload or
    false if not.
    """

    # prepare the SHA256 hash
    h = SHA256.new()
    # create the SHA256 hash of the payload
    h.update(payload)
    # prepare the PKCS1-PSS signature with the public key
    verifier = PKCS1_PSS.new(pub_key)

    if verifier.verify(h, rsa_signature):
        sign_ok = True
    else:
        sign_ok = False

    return sign_ok


__author__ = 'Hakan Kuesne and Mathieu Devaud'
__since__ = '2016-05-01'
__date__ = '2016-05-16'
__version__ = '1.0'
__email__ = 'hakan@kusne.ch;mathieu.devaud@hefr.ch'
