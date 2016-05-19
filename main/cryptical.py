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

""" This module provides CLI interface. """


import argparse
from argparse import RawTextHelpFormatter
import sys
import rsa
import locker


if __name__ == "__main__":

    # Configure the Parser
    parser = argparse.ArgumentParser(
        description='Tool to archive securely TOP SECRET files using AES '
                    'symetric algorithm, HMAC mechanism and RSA asymetric '
                    'encryption and signature. A RSA key pair is needed to '
                    'encrypt and sign the archive, if no key pair is available'
                    ', this tool can generate one.',
        formatter_class=RawTextHelpFormatter,
        epilog='Examples of use : \n'
               '   python cryptical --gen 4096\n'
               '   python cryptical --lock file1.txt file2.txt --keys priv.pem'
               ' pub.pem --output mySecretArchive\n'
               '   python cryptical --unlock mySecretArchive.lkd --keys '
               'priv.pem pub.pem')

    # Key generation arg
    parser.add_argument("-g", "--gen",
                        choices=['3072', '4096', '6144', '8192'],
                        help='generate RSA key pair')

    # Key pair files arg
    parser.add_argument("-k", "--keys",
                        nargs=2,
                        type=file,
                        help='private and public RSA keys to use, '
                             'the files have to be in a .pem format and the '
                             'first parameter has to be the private key.')

    # Lock mechanism arg
    parser.add_argument("-l",
                        "--lock",
                        nargs='+',
                        type=file,
                        help='lock file in a secure archive with RSA key pair')

    # Unlock mechanism arg
    parser.add_argument("-u",
                        "--unlock",
                        type=file,
                        help='unlock archive with RSA key pair')

    # Unlock mechanism arg
    parser.add_argument("-o",
                        "--output",
                        help='name of the final archive')

    # Unlock mechanism arg
    parser.add_argument("-d",
                        "--delete",
                        action="store_true",
                        help='use to securely delete the files you want to '
                             'lock')

    # Print help if no args provided
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    # Returns data from the options specified
    args = parser.parse_args()

    # Call RSA key pair generation if args --gen provided
    if args.gen is not None:
        rsa.gen_rsa_keys(int(args.gen))

    # Get RSA key pair if args --keys provided
    elif args.keys is not None:
        rsa_private_key = args.keys[0].name
        print("RSA private key : %s" % rsa_private_key)
        rsa_public_key = args.keys[1].name
        print("RSA public key : %s" % rsa_public_key)

        # Call locking mechanism if args --lock provided
        if args.lock is not None:
            files = []

            for file in args.lock:
                files.append(file.name)
            print("Locking files %s" % files)

            # Secure delete sources files if user use --delete
            if args.delete:
                secure_delete = True
            else:
                secure_delete = False

            # if no name for output, use archive
            if args.output is not None:
                output = str(args.output)
            else:
                output = 'archive'

            locker.lock_files(files, rsa_private_key, rsa_public_key, output,
                              secure_delete)
            print("Files locked in %s.lkd" % output)

        # Call unlocking mechanism if args --unlock provided
        elif args.unlock is not None:
            print("Unlocking archive %s" % args.unlock.name)
            locker.unlock_file(args.unlock.name, rsa_private_key,
                               rsa_public_key)
    else:
        print("Provide RSA key pair or generate them")


__author__ = 'Hakan Kuesne and Mathieu Devaud'
__since__ = '2016-05-01'
__date__ = '2016-05-16'
__version__ = '1.0'
__email__ = 'hakan@kusne.ch;mathieu.devaud@hefr.ch'
