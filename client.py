#!/usr/bin/python3

import socket
import sys
import struct
import hashlib
import os
import time

UNSIGNED_LONG_INT_SIZE = 4

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = ('localhost', 10001)
sock.connect(server_address)

def send_file(fp):
    sha2 = hashlib.sha256()
    path = fp

    filesize = os.stat(path).st_size

    sock.sendall(struct.pack("!LL%ds" % len(path), (UNSIGNED_LONG_INT_SIZE * 2) + len(path) + filesize, len(path), path.encode()))

    print("sending: ", filesize, " bytes")
    with open(path, 'rb') as f:
        while True:
            data = f.read(4096)
            if not data:
                break

            sha2.update(data)
            sock.sendall(data)

    sock.sendall(struct.pack("!32B", *bytearray(sha2.digest())))

for root, dirs, files in os.walk(sys.argv[1]):
    fps = ([root + "/" + f for f in files])
    for fp in fps:
        send_file(fp)


time.sleep(3)
# add inotfiy here
