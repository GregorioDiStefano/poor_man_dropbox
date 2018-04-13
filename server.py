#!/usr/bin/python3

import sys
import socket
import os
import struct
import io
import logging
import hashlib

UNSIGNED_LONG_INT_SIZE = 4
SHA256_SIZE = 32
COMMAND_SIZE = 1

BUF_SIZE = 1024 * 64

# REQUESTS
FILE_UPLOAD_REQUEST = b'F'
FILE_DELETE_REQUEST = b'D'

if os.getenv("DEBUG"):
    l = logging.DEBUG
else:
    l = logging.INFO

logging.basicConfig(level=l)
logger = logging.getLogger('tcpserver')

class Server:
    def __init__(self, host, port, directory):
        self.host = host
        self.port = port
        self.directory = directory
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn = None

    def setup(self):
        server_address = (self.host, self.port)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(server_address)
        self.sock.listen(1)
        self.conn, _ = self.sock.accept()

    def readInBytes(self, n):
        data_bytes = self.conn.recv(n)
        return io.BytesIO(data_bytes).read(n)

    def checkPath(self, fp, dl_dir):
        if os.path.commonprefix((os.path.realpath(fp),
                                 os.path.realpath(dl_dir))) != os.path.realpath(dl_dir):
            return False
        return True

    def truncateFile(self, dest):
        if os.path.exists(dest):
            os.truncate(dest, 0)

    def writeFile(self, data, dest):
        if not os.path.exists(dest):
            try:
                os.makedirs(os.path.dirname(dest))
            except FileExistsError:
                pass

        with open(dest, "ab") as f:
            f.write(data)

    def rmFile(self, fp):
        fp = "%s/%s" % (self.directory, fp)

        if not self.checkPath(fp, self.directory):
            logging.warn("Path traversal - ignore request.")
            return

        try:
            os.remove(fp)
            logging.info(msg="Deleted: " + fp)
        except FileNotFoundError:
            logging.warn("Tried to delete a non-existing file!")
        except IsADirectoryError:
            logging.warn("Tried to delete a folder!")

    def parseFilePayload(self, fp, size, sha256expected):
        fp = "%s/%s" % (self.directory, fp)

        sha256_calculated = hashlib.sha256()
        bytes_left, total_size = size, size

        def progress(percent):
            print("downloading %s, %d%% complete.." % (fp, percent), end="\r")

        if not self.checkPath(fp, self.directory):
            logging.warn("Path traversal - ignoring file download.")

            # we need to read and discard the rest of the payload..
            while bytes_left > 0:
                read = self.conn.recv(min(BUF_SIZE, bytes_left))
                bytes_left -= len(read)
            return

        self.truncateFile(fp)

        # this should never happen, if it does, there's a bug!
        assert bytes_left >= 0, "bytes left to download is negative! error!"

        # special case, write empty file.
        if bytes_left == 0:
            self.writeFile(bytearray(), fp)
            progress(100)
        else:
            while bytes_left > 0:
                file_payload = self.conn.recv(min(BUF_SIZE, bytes_left))
                data = io.BytesIO(file_payload).read()

                self.writeFile(data, fp)
                sha256_calculated.update(data)
                bytes_left -= len(data)

                progress((total_size-bytes_left)/total_size * 100)

        print()

        if tuple(sha256_calculated.digest()) != sha256expected:
            logging.warn(msg="Ouch! SHA256 verification failed for: " + fp)

    def parseHeader(self):
        data = self.readInBytes(COMMAND_SIZE + (UNSIGNED_LONG_INT_SIZE * 2))

        if len(data) == 0:
            print("Connection closed? Bye!")
            sys.exit(0)

        # make sure we have enough bytes!
        total_payload_size, request_type, filepath_size = struct.unpack("!LcL", data)
        data = self.readInBytes(SHA256_SIZE)
        sha256 = struct.unpack("!32B", data)

        if request_type == FILE_UPLOAD_REQUEST:
            data = self.readInBytes(filepath_size)

            filepath = struct.unpack("!%ds" % filepath_size, data)[0]

            # make sure this works
            filepath = filepath.decode("utf-8")
            file_size = total_payload_size - (UNSIGNED_LONG_INT_SIZE * 2) - filepath_size - SHA256_SIZE

            logging.debug(msg=("Total payload: %s" % repr(total_payload_size),
                               "Filepath size: %s" % repr(filepath_size),
                               "Filepath: %s" % repr(filepath),
                               "File size: %d" % file_size))

            self.parseFilePayload(filepath, file_size, sha256)

        elif request_type == FILE_DELETE_REQUEST:
            data = self.readInBytes(filepath_size)
            filepath = struct.unpack("!%ds" % filepath_size, data)[0]
            filepath = filepath.decode("utf-8")
            self.rmFile(filepath)


if len(sys.argv) != 2:
    raise SystemExit("please pass an empty directory as an argument!")
empty_dir = sys.argv[1]

if os.listdir(empty_dir):
    raise SystemExit("%s is not empty!" % (empty_dir))

s = Server("localhost", 10001, empty_dir)
s.setup()

while True:
    s.parseHeader()
