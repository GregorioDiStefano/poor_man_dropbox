#!/usr/bin/python3

import socket
import sys
import struct
import hashlib
import os
import zlib
import logging
import inotify.adapters

READ_BUFFER = 1 * 1024 * 1024

SHA256_SIZE = 32
UNSIGNED_LONG_INT_SIZE = 4
UNSIGNED_LONG_LONG_INT_SIZE = 8

# REQUESTS
FILE_UPLOAD_REQUEST = b'F'
FILE_DELETE_REQUEST = b'D'
FILE_COPY_REQUEST = b'C'

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 10001)
sock.connect(server_address)
seen_hashes = {}

if os.getenv("DEBUG"):
    l = logging.DEBUG
else:
    l = logging.INFO

logging.basicConfig(level=l)
logger = logging.getLogger('tcpclient')

def hash_file(fp):
    sha256 = hashlib.sha256()

    with open(fp, 'rb') as f:
        while True:
            data = f.read(READ_BUFFER)
            if not data:
                break

            sha256.update(data)

    return sha256.digest()


def rm_file(fp):
    payload_fmt = "!QcL%ds" % len(fp)
    payload_size = struct.calcsize(payload_fmt)
    payload = struct.pack(payload_fmt,
                          payload_size,
                          FILE_DELETE_REQUEST,
                          len(fp),
                          fp.encode())
    sock.sendall(payload)

def send_copy(src, dst):
    payload_fmt = "!QcL%dsL%ds" % (len(src), len(dst))
    payload_size = struct.calcsize(payload_fmt)
    payload = struct.pack(payload_fmt,
                          payload_size,
                          FILE_COPY_REQUEST,
                          len(src),
                          src.encode(),
                          len(dst),
                          dst.encode())
    sock.sendall(payload)

def send_file(fp):
    filesize = os.stat(fp).st_size
    filesha = hash_file(fp)

    logger.info(msg="Sending: {}".format(fp))

    if seen_hashes.get(filesha) and filesize > 0:
        logger.debug(msg="The server has this file, sending 'COPY' command")
        send_copy(seen_hashes.get(filesha), fp)
        return
    else:
        seen_hashes[filesha] = fp

    payload_fmt = "!QcL32s%ds" % len(fp)
    payload_size = struct.calcsize(payload_fmt) + filesize
    payload = struct.pack(payload_fmt,
                          payload_size,
                          FILE_UPLOAD_REQUEST,
                          len(fp),
                          bytearray(filesha),
                          fp.encode())

    sock.sendall(payload)

    with open(fp, 'rb') as f:
        while True:
            data = f.read(READ_BUFFER)
            if not data:
                break

            cdata = zlib.compress(data, zlib.Z_BEST_COMPRESSION)
            sock.sendall(struct.pack("!L%ds" % len(cdata), len(cdata), cdata))
    
# protcol doesn't sync empty folders!
for root, dirs, files in os.walk(sys.argv[1]):
    fps = ([root + "/" + f for f in files])
    for fp in fps:
        if os.access(fp, os.R_OK):
            send_file(fp)

i = inotify.adapters.InotifyTree(sys.argv[1])
for event in i.event_gen():

    if event:
        if "IN_CLOSE_WRITE" in event[1] and len(event) >= 4:
            fp = event[2] + "/" + event[3]
            send_file(fp)
        elif len(event[1]) == 1 and "IN_DELETE" in event[1] and len(event) >= 4:
            fp = event[2] + "/" + event[3]
            rm_file(fp)

