#!/usr/bin/python3

import socket
import sys
import struct
import hashlib
import os
import inotify.adapters

SHA256_SIZE = 32
UNSIGNED_LONG_INT_SIZE = 4

# REQUESTS
FILE_UPLOAD_REQUEST = b'F'
FILE_DELETE_REQUEST = b'D'

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 10001)
sock.connect(server_address)
hash_set = {}


def hash_file(fp):
    sha256 = hashlib.sha256()
    with open(fp, 'rb') as f:
        while True:
            data = f.read(4096)
            if not data:
                break

            sha256.update(data)

    return sha256.digest()

def rm_file(fp):
    sock.sendall(struct.pack("!LcL%ds" % len(fp),
                             (UNSIGNED_LONG_INT_SIZE) + len(fp),
                             FILE_DELETE_REQUEST,
                             len(fp),
                             fp.encode()))


def send_file(fp):
    filesize = os.stat(fp).st_size
    filesha = hash_file(fp)
    sock.sendall(struct.pack("!LcL32B%ds" % len(fp),
                             (UNSIGNED_LONG_INT_SIZE * 2) + len(fp) + filesize + SHA256_SIZE,
                             FILE_UPLOAD_REQUEST,
                             len(fp),
                             *bytearray(filesha),
                             fp.encode()))

    with open(fp, 'rb') as f:
        while True:
            #start = f.tell()
            data = f.read(max(1, filesize//64))
            #end = f.tell()
            if not data:
                break

            #sha2.update(data)
            #hash_set[sha2.digest()] = (start, end, fp)

            sock.sendall(data)

    #sha2d = sha2.digest()

    #sock.sendall(struct.pack("!32B", *bytearray(sha2d)))
    #hash_set[sha2d] = fp


# protcol doesn't sync empty folders!
for root, dirs, files in os.walk(sys.argv[1]):
    fps = ([root + "/" + f for f in files])
    for fp in fps:
        if os.access(fp, os.R_OK):
            send_file(fp)

print(hash_set)

i = inotify.adapters.InotifyTree(sys.argv[1])
for event in i.event_gen():

    if event:
        if "IN_CLOSE_WRITE" in event[1] and len(event) >= 4:
            send_file(event[2] + "/" + event[3])
        elif len(event[1]) == 1 and "IN_DELETE" in event[1] and len(event) >= 4:
            rm_file(event[2] + "/" + event[3])



