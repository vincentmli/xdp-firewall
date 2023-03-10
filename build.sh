gcc -o batch batch.c -lbpf
BPF_CLANG=clang BPF_CFLAGS="-g -Wall" go generate
CGO_ENABLED=0 go build .

