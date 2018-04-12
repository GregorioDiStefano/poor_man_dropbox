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
BUF_SIZE = 4096

logging.basicConfig(level=logging.DEBUG)
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
        self.sock.bind(server_address)
        self.sock.listen(1)
        self.conn, _ = self.sock.accept()

    def readInBytes(self, n):
        data_bytes = self.conn.recv(n)
        return io.BytesIO(data_bytes).read(n)

    def writeFile(self, data, dest):
        local_file_path = "%s/%s" % (self.directory, str(dest))

        if not os.path.exists(local_file_path):
            try:
                os.makedirs(os.path.dirname(local_file_path))
            except FileExistsError:
                pass

        with open(local_file_path, "ab") as f:
            f.write(data)

    def parseFilePayload(self, fp, size):
        sha256_calculated = hashlib.sha256()
        bytes_left = size
        
        assert bytes_left > 0, "bytes left to download is negative! error!"

        print("bytes_left: ", bytes_left)
        while bytes_left > 0:
            file_payload = self.conn.recv(min(BUF_SIZE, bytes_left))
            data = io.BytesIO(file_payload).read()

            self.writeFile(data, fp)
            sha256_calculated.update(data)
            bytes_left -= len(data)

        sha256bytes = self.conn.recv(32)
        sha256_expected = struct.unpack("!32B", sha256bytes)
        
        if tuple(sha256_calculated.digest()) != sha256_expected:
            logging.warn(msg="Ouch! SHA256 verification failed for: " + fp)

    def parseHeader(self):
        data = self.readInBytes(UNSIGNED_LONG_INT_SIZE * 2)

        if len(data) == 0:
            print("Connection closed? Bye!")
            sys.exit(0)
        
        # make sure we have enough bytes!
        total_payload_size, filepath_size = struct.unpack("!LL", data)
        data = self.readInBytes(filepath_size)

        filepath = struct.unpack("!%ds" % filepath_size, data)[0]
        # make sure this works
        filepath = filepath.decode("utf-8")

        file_size = total_payload_size - (UNSIGNED_LONG_INT_SIZE * 2) - filepath_size

        logging.debug(msg=("Total payload: %s" % repr(total_payload_size),
                      "Filepath size: %s" % repr(filepath_size),
                      "Filepath: %s" % repr(filepath),
                      "File size: %d" % file_size))

        self.parseFilePayload(filepath, file_size)#, data.read())


if len(sys.argv) != 2:
    raise SystemExit("please pass an empty directory as an argument!")
empty_dir = sys.argv[1]

if os.listdir(empty_dir):
    raise SystemExit("%s is not empty!" % (empty_dir))

s = Server("localhost", 10001, empty_dir)
s.setup()

while True:
    s.parseHeader()
    print("done!")
