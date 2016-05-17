#!/usr/bin/env python
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

""" This module provides API testing methods. """

from subprocess import call
import os.path
import time
import tarfile
import main.tools


def key_generation():
    """Test API when generating RSA key pair.

    This function test the API when generating a RSA key pair for the user.

    :return: A boolean, True if the test passed and False if the test failed.
    """

    print("[testing] Testing API key generation..")

    call(["python", "../main/cryptical.py", "--gen", "4096"])

    if os.path.isfile("priv_key.pem") and os.path.isfile("pub_key.pem"):
        print("[result] Key generation successful...")
        return True
    else:
        print("[result] Key generation unsuccessful...")
        return False


def normal_case():
    """Test API with normal case.

    This function test the API in a normal case where the files are lock
    then unlock with the right key and no alteration.

    :return: A boolean, True if the test passed and False if the test failed.
    """

    print("[testing] Testing API normal case...")

    # create test files
    file = open("test1.txt", 'w')
    file.write("I'm test1.txt")
    file.close()

    file = open("test2.txt", 'w')
    file.write("I'm test2.txt")
    file.close()

    # lock the files
    call(["python", "../main/cryptical.py", "--lock", "test1.txt",
          "test2.txt", "--keys", "priv_key.pem", "pub_key.pem", "--output",
          "archive"])

    if os.path.isfile("archive.lkd"):
        # archive successfully created then proceed to unlock the archive
        call(["python", "../main/cryptical.py", "--unlock", "archive.lkd",
              "--keys", "priv_key.pem", "pub_key.pem"])

        if os.path.isfile("test1.txt") and os.path.isfile("test2.txt"):
            # archive successfully unlocked
            print("[result] Normal case successful...")
            return True
        else:
            # archive unsuccessfully unlocked
            print("[result] Normal case unsuccessful, "
                  "archive not unlocked ...")
            return False
    else:
        # files unsuccessfully locked
        print("[result] Normal case unsuccessful, archive not created...")
        return False


def wrong_key():
    """Test API with wrong keys.

    This function test the API in a case where the private key to unlock the
    archive is wrong.

    :return: A boolean, True if the test passed and False if the test failed.
    """

    print("[testing] Testing API with wrong private key to unlock...")

    # create test files
    file = open("test1.txt", 'w')
    file.write("I'm test1.txt")
    file.close()

    file = open("test2.txt", 'w')
    file.write("I'm test2.txt")
    file.close()

    # lock files
    call(["python", "../main/cryptical.py", "--lock", "test1.txt",
          "test2.txt", "--keys", "priv_key.pem", "pub_key.pem", "--output",
          "archive"])

    # unlock archive with wrong private key
    call(["python", "../main/cryptical.py", "--unlock", "archive.lkd",
          "--keys", "wrong_priv_key.pem", "pub_key.pem"])

    if os.path.isfile("test1.txt") and os.path.isfile("test2.txt"):
        # archive successfully unlocked
        print("[result] Normal case unsuccessful...")
        return False
    else:
        # archive unsuccessfully unlocked
        print("[result] Normal case successful, archive not unlocked ...")
        return True


def big_file():
    """Test API with bigs files.

    This function test the API in a case where the files to encrypt are 96 MB
    each.

    :return: A boolean, True if the test passed and False if the test failed.
    """

    print("[testing] Testing API with big file...")

    # create test files of 96 MB each
    file = open("test1.txt", 'w')
    file.write("1"*100000000)
    file.close()

    file = open("test2.txt", 'w')
    file.write("2"*100000000)
    file.close()

    start = time.time()

    # lock the files
    call(["python", "../main/cryptical.py", "--lock", "test1.txt",
          "test2.txt", "--keys", "priv_key.pem", "pub_key.pem", "--output",
          "archive"])

    if os.path.isfile("archive.lkd"):
        # archive successfully created then proceed to unlock the archive
        call(["python", "../main/cryptical.py", "--unlock", "archive.lkd",
              "--keys", "priv_key.pem", "pub_key.pem"])

        if os.path.isfile("test1.txt") and os.path.isfile("test2.txt"):
            # archive successfully unlocked
            done = time.time()
            elapsed = done - start
            print("[result] Big file case successful in %d sec ..." % elapsed)
            return True
        else:
            # archive unsuccessfully unlocked
            print("[result] Normal case unsuccessful, "
                  "archive not unlocked ...")
            return False
    else:
        # files unsuccessfully locked
        print("[result] Normal case unsuccessful, archive not created...")
        return False


def unlock_altered_archive():
    """Test API when archive has been altered.

    This function test the API in a case where the archive has been altered.

    :return: A boolean, True if the test passed and False if the test failed.
    """

    print("[testing] Testing API with altered archive...")

    # create test files
    file = open("test1.txt", 'w')
    file.write("I'm test1.txt")
    file.close()

    file = open("test2.txt", 'w')
    file.write("I'm test2.txt")
    file.close()

    # lock the files
    call(["python", "../main/cryptical.py", "--lock", "test1.txt",
          "test2.txt", "--keys", "priv_key.pem", "pub_key.pem", "--output",
          "archive"])

    # Extract encrypted tar and signature
    tar = tarfile.open('archive.lkd')

    for eachfile in tar.getnames():
        tar.extract(eachfile)
    tar.close()

    # alter the archive
    file = open("encrypted_files_and_key.lkd", 'a')
    file.write("I've been hacked\n")
    file.close()

    # Archive signed file and signature together again
    main.tools.tarfiles_named(['encrypted_files_and_key.lkd.sign',
                               'encrypted_files_and_key.lkd'], 'archive.lkd')

    call(["python", "../main/cryptical.py", "--unlock", "archive.lkd",
          "--keys", "priv_key.pem", "pub_key.pem"])

    if os.path.isfile("test1.txt") and os.path.isfile("test2.txt"):
        # archive successfully unlocked
        print("[result] Altered case unsuccessful, archive has been unlocked "
              "when altered")
        return False
    else:
        # archive unsuccessfully unlocked
        print("[result] Altered case successful, archive not unlocked ...")
        return True


if __name__ == "__main__":

    results = []

    if key_generation():
        results.append("OK")
    else:
        results.append("NOK")
    if normal_case():
        results.append("OK")
    else:
        results.append("NOK")
    if wrong_key():
        results.append("OK")
    else:
        results.append("NOK")
    if big_file():
        results.append("OK")
    else:
        results.append("NOK")
    if unlock_altered_archive():
        results.append("OK")
    else:
        results.append("NOK")

    print("\nResults summary --------------------------")
    print("-> Test Case 1 : Key generation  \t| %s |" % results[0])
    print("-> Test Case 2 : Normal case  \t\t| %s |" % results[1])
    print("-> Test Case 3 : Wrong key  \t\t| %s |" % results[2])
    print("-> Test Case 4 : Big file  \t\t\t| %s |" % results[3])
    print("-> Test Case 5 : Altered archive \t| %s |" % results[4])
    print("------------------------------------------")


__author__ = 'Hakan Kuesne and Mathieu Devaud'
__since__ = '2016-05-01'
__date__ = '2016-05-16'
__version__ = '1.0'
__email__ = 'hakan@kusne.ch;mathieu.devaud@hefr.ch'
