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

""" This module provides files protection methods. """

import tarfile
import os.path
import io
import time
import sys
import tools
import aes
import rsa
from Crypto.PublicKey import RSA

# Use AES block size of 16 bytes
AES_BLOCK_SIZE = 16
AES_KEY_SIZE = 32


def lock_files(files_to_lock, rsa_private_key, rsa_public_key,
               output='archive', secure_delete=False):
    """Lock files.

    This function lock `files_to_lock` in an archive `output` using RSA
    private key `rsa_private_key` and RSA public key `rsa_public_key`.

    :parameter:
     files_to_lock : list
        A list of files to lock.
     rsa_private_key : string
        RSA private key
     rsa_public_key : string
        RSA public key
     output : string
        The output name of the archive. "archive" by default.
     secure_delete : boolean
        True if the user want to securely delete his `files_to_lock`.
    """
    try:
        starttime = time.time()

        #######################################################################
        # Keys generation and importation
        #######################################################################

        # Importe RSA key from PEM
        rsa_private_key = RSA.importKey(open(rsa_private_key).read())
        rsa_public_key = RSA.importKey(open(rsa_public_key).read())

        # Generate AES key and iv
        aes_key = aes.gen_aes_key(AES_KEY_SIZE)
        aes_iv = aes.gen_iv(AES_BLOCK_SIZE)

        encrypted_key = rsa.rsa_encrypt(rsa_public_key, aes_key)

        f = open('cipherkey.lkd', 'w')
        f.write(encrypted_key)
        f.close()

        #######################################################################
        # Encryption and MAC of the files
        #######################################################################

        # Put file in a tar archive
        archive = tools.tarfiles(files_to_lock, 'source.tar')
        archive_data = open(archive, mode='rb')
        raw = archive_data.read()
        archive_data.close()

        # Encrypt the tar file
        cipherdata = \
            aes.aes_encrypt(AES_BLOCK_SIZE, aes_iv, aes_key, raw)

        # Save cipher data
        out = open('encrypted_files.lkd', 'w')
        out.write(str(cipherdata))
        out.close()

        # Tar cipherkeys, cipherfile and mac file toghether
        finalfiles = ['cipherkey.lkd', 'encrypted_files.lkd']
        ciphertar = tools.tarfiles(finalfiles, 'encrypted_files_and_key.lkd')
        f = open(ciphertar, mode='rb')
        ciphertardata = f.read()
        f.close()

        # Sign data with private key
        rsa_signature = rsa.rsa_sign(rsa_private_key, ciphertardata)

        # Save signature
        f = open('encrypted_files_and_key.lkd.sign', 'w')
        f.write(rsa_signature)
        f.close()

        # Archive signed file and signature together
        tools.tarfiles(['encrypted_files_and_key.lkd.sign',
                        'encrypted_files_and_key.lkd'], output+'.lkd')

        # Secure delete temp files
        files_to_delete = ['encrypted_files_and_key.lkd.sign',
                           'encrypted_files.lkd', 'cipherkey.lkd', archive,
                           ciphertar]

        for file in files_to_delete:
            success = tools.secure_delete(file)
            if not success:
                print('Something went wrong during the secure file delete '
                      'of ' + file + ', make sure your erase it manually.')
        # Secure delete sources files
        if secure_delete:
            for file in files_to_lock:
                success = tools.secure_delete(file)
                if not success:
                    print('Something went wrong during the secure file delete '
                          'of ' + file + ', make sure your erase it manually.')
        endtime = time.time()
        elapsedtime = endtime - starttime
        print("The files have been successfuly "
              "locked in %d seconds." % elapsedtime)
    except AttributeError:
        print('A method was called with a false attribute.')
        sys.exit()
    except IOError:
        print('Maybe one of your files does not exist')
        sys.exit()
    except:
        print('An unexpected error occurred when locking files.')
        sys.exit()


# Unlock given file
def unlock_file(cipherfile, rsa_private_key, rsa_public_key):
    """Unlock archive.

    This function unlock an archive `cipherfile` using RSA private key
    `rsa_private_key` and RSA public key `rsa_public_key`.

    :parameter:
     cipherfile : string
        Name of the archive to unlock.
     rsa_private_key : string
        RSA private key
     rsa_public_key : string
        RSA public key
    """
    try:
        starttime = time.time()

        # Importe RSA key from PEM
        rsa_private_key = RSA.importKey(open(rsa_private_key).read())
        rsa_public_key = RSA.importKey(open(rsa_public_key).read())

        # Extract encrypted tar and signature
        tar = tarfile.open(cipherfile)

        for file in tar.getnames():
            tar.extract(file)
        tar.close()

        # Verification of the payload
        archive_data = open('encrypted_files_and_key.lkd.sign', mode='rb')
        raw_signature = archive_data.read()
        archive_data.close()
        archive_data = open('encrypted_files_and_key.lkd', mode='rb')
        raw_files = archive_data.read()
        archive_data.close()
        if not rsa.rsa_verify_sign(rsa_public_key, raw_signature, raw_files):
            print("This file has been corrupted ! Don't use it !")
            # clean tar filed
            files_to_delete = ["encrypted_files_and_key.lkd.sign",
                               "encrypted_files_and_key.lkd"]
            for eachfile in files_to_delete:
                if os.path.isfile(eachfile):
                    tools.secure_delete(eachfile, passes=1)
        else:
            print("This file is authentic !")

            # Extract encrypted files and symetric key
            tar = tarfile.open('encrypted_files_and_key.lkd')

            for eachfile in tar.getnames():
                tar.extract(eachfile)
            tar.close()

            # Decryption of the keys
            archive_data = open('cipherkey.lkd', mode='rb')
            raw = archive_data.read()
            archive_data.close()
            aes_key = rsa.rsa_decrypt(rsa_private_key, raw)

            # Decrypt files
            archive_data = open('encrypted_files.lkd', mode='rb')

            raw_files = archive_data.read()
            archive_data.close()

            bytestar = io.BytesIO(
                str(aes.aes_decrypt(AES_BLOCK_SIZE, aes_key, raw_files)))
            # Untar files
            tar = tarfile.open(fileobj=bytestar)
            for eachfile in tar.getnames():
                tar.extract(eachfile)
            # Delete container related files
            files_to_delete = ["cipherkey.lkd", "encrypted_files_and_key.lkd",
                               "encrypted_files_and_key.lkd.sign",
                               "encrypted_files.lkd", cipherfile]
            for eachfile in files_to_delete:
                tools.secure_delete(eachfile, passes=1)
            endtime = time.time()
            elapsedtime = endtime - starttime
            print("The files have been successfuly "
                  "unlocked in %d seconds." % elapsedtime)
    except AttributeError:
        print('A method was called with a false attribute.')
        sys.exit()
    except:
        print('An unexpected error occurred when unlocking files.')

        files_to_delete = ["cipherkey.lkd", "encrypted_files_and_key.lkd",
                           "encrypted_files_and_key.lkd.sign",
                           "encrypted_files.lkd"]
        for eachfile in files_to_delete:
            if os.path.isfile(eachfile):
                tools.secure_delete(eachfile, passes=1)
        sys.exit()


__author__ = 'Hakan Kuesne and Mathieu Devaud'
__since__ = '2016-05-01'
__date__ = '2016-05-16'
__version__ = '1.0'
__email__ = 'hakan@kusne.ch;mathieu.devaud@hefr.ch'
