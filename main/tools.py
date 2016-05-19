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

""" This module provides tools to ease crypto operations. """


import argparse
import os
import random
import string
import tarfile
import ntpath


def path_leaf(path):
    """Extract file name from path.

    This function extracts the file name in a file path.

    :parameter:
     path : string
        The path of the file.

    :return: A string, the file's name.
    """
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)


def id_generator(size=8, chars=string.ascii_uppercase + string.digits):
    """Generate a random id.

    This function generate a random id containing uppercase and digits.

    :parameter:
     size : int
        The id length in number of chars.
     chars : strings
        The elements to use to create random id.

    :return: A string, the random generated id.
    """

    return ''.join(random.choice(chars) for _ in range(size))


# Takes list of files as argument, put them in tar archive and return it.
def tarfiles(files_list, outname):
    """Create a tar of input files.

    This function create a tar of `files_list` named `outname`.

    :parameter:
     files_list : list
        The id length in number of chars.
     outname : string
        The chars to use to create random id.

    :raise ArgumentError:
            If there is no files in `files_list`.

    :return: A string, the name of the tar file
    """

    if len(files_list) < 1:
        raise argparse.ArgumentError("You must give one or more filenames.")
    filename = outname
    tar = tarfile.open(filename, 'w')
    for name in files_list:
        tar.add(name)
    tar.close()
    return tar.name


# Takes list of files as argument, put them in tar archive and return it.
def tarfiles_withoutpath(files_list, outname):
    """Create a tar of input files.

    This function create a tar of `files_list` named `outname`.

    :parameter:
     files_list : list
        The id length in number of chars.
     outname : string
        The chars to use to create random id.

    :raise ArgumentError:
            If there is no files in `files_list`.

    :return: A string, the name of the tar file
    """

    if len(files_list) < 1:
        raise argparse.ArgumentError("You must give one or more filenames.")
    filename = outname
    tar = tarfile.open(filename, 'w')
    for name in files_list:
        filename = path_leaf(name)
        tar.add(name, arcname=filename)
    tar.close()
    return tar.name


def secure_delete(path, passes=10):
    """Secure way to delete files.

    This function remove sensitive data in a secure way by overwriting data
    `passes` times then deleting the file. This operation can be HEAVY
    depending on file size and the passes number you chose.

    :parameter:
     path : string
        The path of the file to delete.
     passes : int
        The number of passes to overwrite the data.

    :return: A boolean, True is the file has been deleted.
    """

    random.seed()
    with open(path, "wb") as delfile:
        length = delfile.tell()
        for passes in range(passes):
            delfile.seek(0)
            for byte in range(length):
                delfile.write(bytes(random.randrange(256)))

    os.remove(path)

    return True


__author__ = 'Hakan Kuesne and Mathieu Devaud'
__since__ = '2016-05-01'
__date__ = '2016-05-16'
__version__ = '1.0'
__email__ = 'hakan@kusne.ch;mathieu.devaud@hefr.ch'
