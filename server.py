#!/usr/bin/python3

import sys
import socket
import os
import struct
import io
import logging
import hashlib
import zlib
from shutil import copyfile, move, rmtree

# SIZES
UNSIGNED_LONG_LONG_INT_SIZE = 8
UNSIGNED_LONG_INT_SIZE = 4
SHA256_SIZE = 32
COMMAND_SIZE = 1

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

    # we get the length of the compressed payload, read it all, and then decompress it
    def readCompressedData(self):
        cdata = bytearray()

        cdata_len = self.readInBytes(UNSIGNED_LONG_INT_SIZE)
        cdata_len = struct.unpack("!L", cdata_len)[0]

        cdata_left = cdata_len

        while cdata_left > 0:
            read = self.readInBytes(cdata_left)
            cdata_left -= len(read)
            cdata += read

        return zlib.decompress(cdata), cdata_len

    # make sure we don't get a milicious request that modifies a file outsides of
    def checkPath(self, fp):
        if os.path.commonprefix((os.path.realpath(fp),
                                 os.path.realpath(self.directory))) != os.path.realpath(self.directory):
            return False
        return True

    def truncateFile(self, dst):
        if os.path.exists(dst):
            os.truncate(dst, 0)

    def make_folder(self, fp):
        dst = "%s/%s" % (self.directory, fp)
        if self.checkPath(dst):
            if not os.path.exists(dst):
                os.makedirs(dst)

    def copyFileAndRename(self, src, dst):
        src = "%s/%s" % (self.directory, src)
        dst = "%s/%s" % (self.directory, dst)

        if self.checkPath(src) and self.checkPath(dst):
            # make dir if it doesn't exist
            dst_folder = os.path.dirname(dst)
            if not os.path.exists(dst):
                try:
                    os.makedirs(dst_folder)
                except FileExistsError:
                    pass

            copyfile(src, dst)

    def moveFileFolder(self, src, dst):
        src = "%s/%s" % (self.directory, src)
        dst = "%s/%s" % (self.directory, dst)

        if self.checkPath(src) and self.checkPath(dst):
            dst_folder = os.path.dirname(dst)
            if not os.path.exists(dst_folder):
                try:
                    os.makedirs(dst_folder)
                except FileExistsError:
                    pass

            move(src, dst)

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

        if not self.checkPath(fp):
            logging.warn("Path traversal - ignore request.")
            return

        is_dir = os.path.isdir(fp)

        try:
            if is_dir:
                rmtree(fp, True)
            else:
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
            if percent == 100:
                print()

        if not self.checkPath(fp):
            logging.warn("Path traversal - ignoring file download.")
            # we need to read and discard the rest of the payload..
            while bytes_left > 0:
                data, _ = self.readCompressedData()
                bytes_left -= len(data)
            return

        self.truncateFile(fp)
        total_cdata_len = 0

        # special case, write empty file.
        if bytes_left == 0:
            self.writeFile(bytearray(), fp)
            progress(100)
        else:
            while bytes_left > 0:
                data, cdata_len = self.readCompressedData()
                total_cdata_len += cdata_len

                self.writeFile(data, fp)
                sha256_calculated.update(data)
                bytes_left -= len(data)

                progress((total_size-bytes_left)/total_size * 100)

        if tuple(sha256_calculated.digest()) != sha256expected:
            logging.warn(msg="Ouch! SHA256 verification failed for: " + fp)

        logging.debug("File size: {}, Data recieved: {}".format(total_size, total_cdata_len))

    # parse header as described in documentation
    def parseHeader(self):
        data = self.readInBytes(UNSIGNED_LONG_LONG_INT_SIZE + COMMAND_SIZE)

        if len(data) == 0:
            print("Connection closed? Bye!")
            sys.exit(0)

        # make sure we have enough bytes!
        total_payload_size, request_type = struct.unpack("!Qc", data)

        if request_type == FILE_UPLOAD_REQUEST:
            data = self.readInBytes(UNSIGNED_LONG_INT_SIZE)
            filepath_size = struct.unpack("!L", data)[0]

            data = self.readInBytes(filepath_size)
            filepath = struct.unpack("!%ds" % filepath_size, data)[0]

            data = self.readInBytes(SHA256_SIZE)
            sha256 = struct.unpack("!32B", data)

            # make sure this works
            filepath = filepath.decode("utf-8")

            # we need to do a little math to determine that actual filesize
            file_size = (total_payload_size
                         - UNSIGNED_LONG_LONG_INT_SIZE
                         - COMMAND_SIZE
                         - UNSIGNED_LONG_INT_SIZE
                         - filepath_size
                         - SHA256_SIZE)

            logging.debug(msg=("Total payload: %s" % repr(total_payload_size),
                               "Filepath size: %s" % repr(filepath_size),
                               "Filepath: %s" % repr(filepath),
                               "File size: %d" % file_size))

            self.parseFilePayload(filepath, file_size, sha256)

        # delete file request
        elif request_type == FILE_DELETE_REQUEST:
            data = self.readInBytes(UNSIGNED_LONG_INT_SIZE)
            filepath_size = struct.unpack("!L", data)[0]

            data = self.readInBytes(filepath_size)
            filepath = struct.unpack("!%ds" % filepath_size, data)[0]
            filepath = filepath.decode()
            self.rmFile(filepath)

        # copy or move file
        elif request_type == FILE_COPY_REQUEST or request_type == MOVE_REQUEST:
            data = self.readInBytes(UNSIGNED_LONG_INT_SIZE)
            src_path_size = struct.unpack("!L", data)[0]
            data = self.readInBytes(src_path_size)
            src_path = struct.unpack("!%ds" % src_path_size, data)[0]

            data = self.readInBytes(UNSIGNED_LONG_INT_SIZE)
            dst_path_size = struct.unpack("!L", data)[0]
            data = self.readInBytes(dst_path_size)
            dst_path = struct.unpack("!%ds" % dst_path_size, data)[0]

            src_path = src_path.decode()
            dst_path = dst_path.decode()

            if request_type == FILE_COPY_REQUEST:
                logging.debug(msg=("Copying {} to {}".format(src_path, dst_path)))
                self.copyFileAndRename(src_path, dst_path)
            else:
                logging.debug(msg=("Moving {} to {}".format(src_path, dst_path)))
                self.moveFileFolder(src_path, dst_path)
        
        elif request_type == FOLDER_CREATE_REQUEST:
            data = self.readInBytes(UNSIGNED_LONG_INT_SIZE)
            folder_path_size = struct.unpack("!L", data)[0]
            data = self.readInBytes(folder_path_size)
            folder_path = struct.unpack("!%ds" % folder_path_size, data)[0]
            folder_path = folder_path.decode()

            logging.debug("Creating folder: {}".format(folder_path))
            self.make_folder(folder_path)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("please pass an empty directory as an argument!")

    empty_dir = sys.argv[1]

    if os.listdir(empty_dir):
        raise SystemExit("%s is not empty!" % (empty_dir))

    s = Server(os.getenv("HOST", "localhost"),
               int(os.getenv("PORT", 10001)),
               empty_dir)

    logger.info("Waiting for client to send a payload to: {}:{}".format(s.host, s.port))
    s.setup()


    while True:
        s.parseHeader()
