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
MOVE_REQUEST = b'M'

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


def remove(fp, is_dir):
    payload_fmt = "!QcL%ds" % len(fp)
    payload_size = struct.calcsize(payload_fmt)
    payload = struct.pack(payload_fmt,
                          payload_size,
                          FILE_DELETE_REQUEST,
                          len(fp),
                          fp.encode())
    sock.sendall(payload)

    # remove hash if fp found
    to_delete = None
    for h in seen_hashes:
        if seen_hashes[h] == fp:
            to_delete = h
            break

    try:
        if to_delete:
            logging.debug("Removed hash: {} from seen_hashes".format(to_delete))
            del seen_hashes[to_delete]
    except KeyError:
        logging.warn("failed to remove hash: {}".format(hash))


def _move_or_copy(src, dst, mv):
    request = FILE_COPY_REQUEST

    if mv:
        request = MOVE_REQUEST

    payload_fmt = "!QcL%dsL%ds" % (len(src), len(dst))
    payload_size = struct.calcsize(payload_fmt)
    payload = struct.pack(payload_fmt,
                          payload_size,
                          request,
                          len(src),
                          src.encode(),
                          len(dst),
                          dst.encode())
    sock.sendall(payload)


def send_copy(src, dst):
    _move_or_copy(src, dst, False)


def send_file(fp):
    filesize = os.stat(fp).st_size
    filesha = hash_file(fp)

    logger.info(msg="Sending: {}".format(fp))
    equivalent_file = seen_hashes.get(filesha)

    # if we have already send this hash to the server, the server has this file!
    # so, send over a 'COPY' cmd, and copy the original over with a new filename
    if equivalent_file and equivalent_file != fp and filesize > 0:
        logger.debug(msg="The server has this file, sending 'COPY' command")
        send_copy(seen_hashes.get(filesha), fp)
        return
    else:
        seen_hashes[filesha] = fp

    payload_fmt = "!QcL%ds32s" % len(fp)
    payload_size = struct.calcsize(payload_fmt) + filesize
    payload = struct.pack(payload_fmt,
                          payload_size,
                          FILE_UPLOAD_REQUEST,
                          len(fp),
                          fp.encode(),
                          bytearray(filesha))
    sock.sendall(payload)

    with open(fp, 'rb') as f:
        while True:
            data = f.read(READ_BUFFER)
            if not data:
                break

            cdata = zlib.compress(data, zlib.Z_BEST_COMPRESSION)
            sock.sendall(struct.pack("!L%ds" % len(cdata), len(cdata), cdata))


def move(src, dst, is_dir):
    _move_or_copy(src, dst, True)

    # update location of hash / file dict
    print("hashes: ", seen_hashes)

    if is_dir:
        for h in seen_hashes:
            old_path = seen_hashes[h]
            # go through all files, and update the old dir to the new dir
            if old_path.startswith(src + "/"):
                new_path = dst + "/" + os.path.relpath(old_path, src)
                seen_hashes[h] = new_path

    else:
        # if file, update src/dst
        if seen_hashes.get(src):
            seen_hashes[src] = dst
    print("after hashes: ", seen_hashes)


# KNOWN: protcol doesn't sync empty folders!

for root, dirs, files in os.walk(sys.argv[1]):
    fps = ([root + "/" + f for f in files])
    for fp in fps:
        if os.access(fp, os.R_OK):
            send_file(fp)

i = inotify.adapters.InotifyTree(sys.argv[1])
moves = {}

for event in i.event_gen():
    if event:
        if "IN_CLOSE_WRITE" in event[1] and len(event) >= 4:
            fp = event[2] + "/" + event[3]
            logging.debug(msg="sending new or modified file: {}".format(fp))
            send_file(fp)

        elif "IN_DELETE" in event[1] and len(event) >= 4:
            if "IN_ISDIR" in event[1]:
                is_dir = True
            else:
                is_dir = False

            fp = event[2] + "/" + event[3]
            remove(fp, is_dir)

        elif "IN_MOVED_FROM" in event[1] and len(event) >= 4:
                if "IN_ISDIR" in event[1]:
                    is_dir = True
                else:
                    is_dir = False

                fp = event[2] + "/" + event[3]
                moves[event[0].cookie] = {"dir": is_dir, "src": fp}

        elif "IN_MOVED_TO" in event[1] and len(event) >= 4:
                fp = event[2] + "/" + event[3]
                mv = moves[event[0].cookie]

                is_dir = mv["dir"]
                src = mv["src"]
                dst = fp

                logging.debug(msg="moving (is_dir: {}) from: {} to: {}".format(is_dir, src, dst))
                move(src, dst, is_dir)

