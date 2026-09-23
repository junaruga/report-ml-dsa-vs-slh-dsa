OPENSSL_DIR=/home/jaruga/.local/openssl-4.1.0-dev-debug-7194354488

rm -f streaming_sign
gcc -o streaming_sign streaming_sign.c \
    -I${OPENSSL_DIR}/include -L${OPENSSL_DIR}/lib \
    -lcrypto -Wl,-rpath,${OPENSSL_DIR}/lib -Wall
