#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2016 Hakan Kuesne && Mathieu Devaud
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" This module provides cryptographic tools. """


import base64

from Crypto.Cipher import AES


def gen_aes_key(size):
    """Generates a random AES key.

    This function generate a random AES key from /dev/urandom.

    :parameter:
     size : int
        The key length in bytes, must be 16 (128 bits), 24 (192 bits) or 32 (
        256 bits).

    :return: A string, the random generated AES key.
    """

    valid_key_length = [16, 24, 32]
    if size not in valid_key_length:
        raise AttributeError("You must provide a valid length for the key.")
    urandom = open("/dev/urandom", mode='rb')
    key = urandom.read(size)
    urandom.close()

    return key


def gen_iv(size):
    """Generate a random Initial Vector.

    This function generate a random Initial Vector (IV) from /dev/urandom to
    use with AES in CBC mode.

    :parameter:
     size : int
        The IV length in bytes, must be 8 (64 bits) or 16 (128 bits).

    :raise AttributeError:
            If `size` is too small or to big.

    :return: A string, the random generated IV.
    """

    valid_block_sizes = [8, 16]
    if size not in valid_block_sizes:
        raise AttributeError("You must provide a valid length for the IV.")
    urandom = open("/dev/urandom", mode='rb')
    iv = urandom.read(size)
    urandom.close()

    return iv


def aes_encrypt(blocksize, iv, key, plaintext):
    """Encrypt the plaintext with AES.

    This function encrypt the plaintext using AES algorithm in CBC mode.

    :parameter:
     blocksize : int
        The size of the block of the CBC mode.
     iv : string
        The Initial Vector used in CBC mode.
     key : string
        The symmetric key used to perform AES encryption.
     plaintext : string
        Plaintext to encrypt.

    :return: A string, the ciphertext and the IV in base64.
    """
    if len(key) < 32:
        raise AttributeError("The encryption key must be at "
                             "least 256 bits long.")

    plaintext = pad(blocksize, plaintext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = base64.b64encode(
        iv + cipher.encrypt(plaintext))

    return ciphertext


def aes_decrypt(blocksize, key, ciphertext):
    """Encrypt the plaintext with AES.

    This function encrypt the plaintext using AES algorithm in CBC mode.

    :parameter:
     blocksize : int
        The size of the block of the CBC mode.
     key : string
        The symmetric key used to perform AES decryption.
     ciphertext : string
        Ciphertext to decrypt.

    :return: A string, the plaintext after decryption and removing the padding.
    """

    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:blocksize]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    paddedplaintext = cipher.decrypt(ciphertext[blocksize:])
    plaintext = unpad(paddedplaintext)

    return plaintext


def pad(blocksize, data):
    """Adds PKCS#7 padding.

    This function adds PKCS#7 padding at the end of the last block from
    `data` for a multiple of `blocksize`.

    :parameter:
     blocksize : int
        The size of the block of the CBC mode.
     data : string
        The data to be padded.

    :return: A string, the data padded in PKCS7, must be a multiple of
    `blocksize`.
    """

    length = blocksize - (len(data) % blocksize)
    data += bytes([length]) * length

    return data


def unpad(data):
    """Remove PKCS#7 padding.

    This function remove PKCS#7 padding at the end of the last block from
    `data`.

    :parameter:
     data : string
        The data to be unpadded.

    :return: A string, the data without the PKCS#7 padding.
    """

    array = bytearray()
    array.extend(data)
    array = array[:-(array[-1])]
    return array


__author__ = 'Hakan Kuesne and Mathieu Devaud'
__since__ = '2016-05-01'
__date__ = '2016-05-16'
__version__ = '1.0'
__email__ = 'hakan@kusne.ch;mathieu.devaud@hefr.ch'
