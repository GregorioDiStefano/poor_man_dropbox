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

# SIZES
SHA256_SIZE = 32
UNSIGNED_LONG_INT_SIZE = 4
UNSIGNED_LONG_LONG_INT_SIZE = 8

# REQUESTS
FILE_UPLOAD_REQUEST = b'F'
FILE_DELETE_REQUEST = b'D'
FILE_COPY_REQUEST = b'C'
MOVE_REQUEST = b'M'
FOLDER_CREATE_REQUEST = b'X'

if os.getenv("DEBUG"):
    l = logging.DEBUG
else:
    l = logging.INFO

logging.basicConfig(level=l)
logger = logging.getLogger('tcpclient')


class Client():
    seen_hashes = {}

    def __init__(self, host, port, directory):
        self.host = host
        self.port = port
        self.directory = directory

    def setup(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (self.host, int(self.port))
        self.sock.connect(server_address)

    def hash_file(self, fp):
        sha256 = hashlib.sha256()

        with open(fp, 'rb') as f:
            while True:
                data = f.read(READ_BUFFER)
                if not data:
                    break

                sha256.update(data)
        return sha256.digest()

    def remove(self, fp, is_dir):
        payload_fmt = "!QcL%ds" % len(fp)
        payload_size = struct.calcsize(payload_fmt)
        payload = struct.pack(payload_fmt,
                              payload_size,
                              FILE_DELETE_REQUEST,
                              len(fp),
                              fp.encode())
        self.sock.sendall(payload)

        # remove hash if fp found
        to_delete = None
        for h in self.seen_hashes:
            if self.seen_hashes[h] == fp:
                to_delete = h
                break

        try:
            if to_delete:
                logging.debug("Removed hash: {} from seen_hashes".format(to_delete))
                del self.seen_hashes[to_delete]
        except KeyError:
            logging.warn("failed to remove hash: {}".format(hash))

    # both move and copy operations are similar, only the REQUEST time changes, so we 
    # use this method instead of duplicating the code
    def _move_or_copy(self, src, dst, mv):
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
        self.sock.sendall(payload)

    def send_copy(self, src, dst):
        self._move_or_copy(src, dst, False)

    def send_file(self, fp):
        filesize = os.stat(fp).st_size
        filesha = self.hash_file(fp)

        logger.info("Sending: {}".format(fp))
        equivalent_file = self.seen_hashes.get(filesha)

        # if we have already send this hash to the server, the server has this file!
        # so, send over a 'COPY' cmd, and copy the original over with a new filename
        if equivalent_file and equivalent_file != fp and filesize > 0:
            logger.debug("The server has this file, sending 'COPY' command")
            self.send_copy(self.seen_hashes.get(filesha), fp)
            return
        else:
            self.seen_hashes[filesha] = fp

        payload_fmt = "!QcL%ds32s" % len(fp)
        payload_size = struct.calcsize(payload_fmt) + filesize
        payload = struct.pack(payload_fmt,
                              payload_size,
                              FILE_UPLOAD_REQUEST,
                              len(fp),
                              fp.encode(),
                              bytearray(filesha))
        self.sock.sendall(payload)

        with open(fp, 'rb') as f:
            while True:
                data = f.read(READ_BUFFER)
                if not data:
                    break

                cdata = zlib.compress(data, zlib.Z_BEST_COMPRESSION)
                self.sock.sendall(struct.pack("!L%ds" % len(cdata), len(cdata), cdata))

    def move(self, src, dst, is_dir):
        self._move_or_copy(src, dst, True)

        # update location of hash / file dict

        if is_dir:
            for h in self.seen_hashes:
                old_path = self.seen_hashes[h]
                # go through all files, and update the old dir to the new dir
                if old_path.startswith(src + "/"):
                    new_path = dst + "/" + os.path.relpath(old_path, src)
                    self.seen_hashes[h] = new_path

        else:
            # if file, update src/dst
            if self.seen_hashes.get(src):
                self.seen_hashes[src] = dst

    def make_dir(self, fp):
        payload_fmt = "!QcL%ds" % len(fp)
        payload_size = struct.calcsize(payload_fmt)
        payload = struct.pack(payload_fmt,
                              payload_size,
                              FOLDER_CREATE_REQUEST,
                              len(fp),
                              fp.encode())

        self.sock.sendall(payload)
        logger.info("Creating empty folder: {}".format(fp))


if len(sys.argv) != 2:
    raise SystemExit("please pass an source directory as an argument!")


def crawl_dir_and_send_files(c, fp):
    for root, dirs, files in os.walk(fp):
        if not dirs and not files:
            # empty folder, lets make it.
            c.make_dir(root)

        fps = ([root + "/" + f for f in files])
        for fp in fps:
            if os.access(fp, os.R_OK):
                c.send_file(fp)

if __name__ == "__main__":
    source_dir = sys.argv[1]

    if not os.path.isdir(source_dir):
        raise SystemExit("{} dir. does not exist!".format(source_dir))

    c = Client(os.getenv("HOST", "localhost"),
               int(os.getenv("PORT", 10001)),
               source_dir)
    c.setup()

    crawl_dir_and_send_files(c, source_dir)

    i = inotify.adapters.InotifyTree(sys.argv[1])
    moves = {}

    for event in i.event_gen():
        if event:

            # a new file file is created or modified
            if "IN_CLOSE_WRITE" in event[1] and len(event) >= 4:
                fp = event[2] + "/" + event[3]
                logging.debug("sending new or modified file: {}".format(fp))
                c.send_file(fp)

            # a file is deleted!
            elif "IN_DELETE" in event[1] and len(event) >= 4:
                if "IN_ISDIR" in event[1]:
                    is_dir = True
                else:
                    is_dir = False

                fp = event[2] + "/" + event[3]
                c.remove(fp, is_dir)

            # keep track of file that moved (via cookie)
            elif "IN_MOVED_FROM" in event[1] and len(event) >= 4:
                    if "IN_ISDIR" in event[1]:
                        is_dir = True
                    else:
                        is_dir = False

                    fp = event[2] + "/" + event[3]
                    moves[event[0].cookie] = {"dir": is_dir, "src": fp}

            # once file is finished being moved, we move it.
            elif "IN_MOVED_TO" in event[1] and len(event) >= 4:
                    fp = event[2] + "/" + event[3]
                    mv = moves[event[0].cookie]

                    is_dir = mv["dir"]
                    src = mv["src"]
                    dst = fp

                    logging.debug("moving (is_dir: {}) from: {} to: {}".format(is_dir, src, dst))
                    c.move(src, dst, is_dir)

            # create directory
            elif "IN_CREATE" in event[1] and "IN_ISDIR" in event[1]:
                fp = event[2] + "/" + event[3]
                c.make_dir(fp)

                #also, check if that directory has any content (inotify doesnt tell us!)
                crawl_dir_and_send_files(c, fp)





