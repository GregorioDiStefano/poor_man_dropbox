#!/bin/bash
set -u 

#
# A simple testing script that verifies the happy path
#


SOURCE=src
DEST=dst
FAILED=false

function finish {
    if [ $FAILED == true ]; then
        exit 1
    fi

    echo "Cleaning up source and dest files.."
    rm -rf $SOURCE 
    rm -rf $DEST 
}

trap finish INT EXIT

function create_test_files {
    # create test files
    echo "Creating test files..."
    for i in {1..5}
    do
        folder=$(openssl rand -hex 6)
        mkdir ./$SOURCE/"$folder"
        yes "foobar" | tr '\n' '\0' | dd of=./$SOURCE/"$folder"/file_"$i" count=$((4096*i)) 2> /dev/null
    done

    # empty file
    touch "$SOURCE"/empty

    # deeply nested, small file
    mkdir -p ./$SOURCE/tiny/tiny2/tiny3/
    echo -n "1234" > ./$SOURCE/tiny/tiny2/tiny3/tinyfile
    echo -n "1" > ./$SOURCE/very_tiny

    # create one, large test file
    openssl rand $((1024*1024*256)) > ./$SOURCE/large.bin

    echo "Done! the following files were created as source files: "
    echo
   
    printf "%0.s=" {1..55}
    echo
    find "$SOURCE" -type f -printf "%30p\t\t%s bytes\n"
    printf "%0.s=" {1..55}
    echo
    echo
}

if [ ! -d $SOURCE ]; then
    mkdir $SOURCE
else
    # just to make sure we don't do what this guy did: 
    # https://www.independent.co.uk/life-style/gadgets-and-tech/news/man-accidentally-deletes-his-entire-company-with-one-line-of-bad-code-a6984256.html
    rm -rf "${SOURCE:?}"/*
fi

if [ ! -d $DEST ]; then
    mkdir $DEST
else
    rm -rf "${DEST:?}"/*
fi

create_test_files

DEBUG=1 ./server.py $DEST &
sleep 1
./client.py $SOURCE &
sleep 5

kill %1
kill %2

echo "Checking...."

du -a -b $SOURCE | sort -k2 > /tmp/src_content_test
( cd $DEST && du -a -b $SOURCE | sort -k2 > /tmp/dst_content_test )

if diff /tmp/src_content_test /tmp/dst_content_test; then
    echo "PASSED"
else
    echo "FAILED: "
    FAILED=true
    exit 1
fi

if diff -rq $DEST/$SOURCE $SOURCE; then
    echo "PASSED"
else
    echo "FAILED"
    FAILED=true
    exit 1
fi
