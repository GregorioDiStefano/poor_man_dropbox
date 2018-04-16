# poor_man_dropbox

Run the server:

`DEBUG=1 ./server.py dir`

Run the client:

`DEBUG=1 ./client.py src_folder`

If you want to run the server, and accept outside connection: `export HOST=0.0.0.0`

If you want the client to connect to remove host, use the same: `export HOST=192.168.1.22`

- [x] simple binary format
- [x] zlib on-the-fly compression
- [x] path traversal protection
- [x] duplicate file copying instead of re-transmission optimization
- [ ] delta based updated
- [ ] TLS encryption
- [ ] unit tests

Known issues:

- there has been some bugs witnessed in regards to moving folders (might be fixed now?)

---

### BINARY FORMAT

Every header starts with:

    [<payload-size><request-type>]

payload size: *8 bytes*, the entire size of the payload being sent, values : *0 to (2^64)-1*

request type: *1 byte* , the type of request being sent, values: `F` | `C` | `D` | `M`

    'F' indicates *normal file upload*

    'C' indicates *copy instruction*
    
    'M' indicates a file or folder *move*
    
    'D' indicates *delete instruction*

    'X' indicates a new folder must be created

---

A `F` request contains the following extra fields:
    
    [<length-of-filepath><filepath><sha256>]

*length-of-filepath*: 4 bytes, value: length of the filepath

*filepath*: variable amount of bytes, determined from *length-of-filepath*, values: utf-8 encoded filepath

*sha256*: 32 bytes containing sha256 hash of file being upload


The remaining payload can be calculated by simply subtracting <payload-size> from the amount of header bytes recieved.

The reset of payload sent is:

    [<length-of-cdata><cdata>]

*length-of-cdata*: length of zlib compressed payload, value: *0 to (2^32)-1*
*cdata*:           compressed data bytes

--- 

A `C` request contains the following extra fields:
    
    [<length-of-source-filepath><source-filepath><length-of-dst-filepath><dst-filepath>]

*length-of-source-filepath*: 4 bytes, value: length of source filepath

*source-filepath*: same as filepath described above 

*length-of-dest-filepath*: 4 bytes, value: length of destination filepath

*dst-filepath*: same as filepath described above 

--- 

A `M` request is the same as a `C` request, as above, except the server moves a file. 

---

A `D` request contains the following extra fields:
    
    [<length-of-filepath><filepath>]

*length-of-filepath*: 4 bytes, value: length of source filepath

*filepath*: same as filepath described above 

---

A `X` request is the same as a `D` request, as above, except the server creates an empty folder. 


