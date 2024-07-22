#!/bin/bash -e

cwd=$(git rev-parse --show-toplevel)
cd $cwd

zig build
zig build test
zig build integration
zig build -Doptimize=ReleaseFast

# clone tlsfuzzer repo if don't exists
if [[ ! -d example/tlsfuzzer ]] ; then
    cd example
    git clone https://github.com/tlsfuzzer/tlsfuzzer.git
    python3 -m venv tlsfuzzer
    cd tlsfuzzer
    bin/pip install --pre tlslite-ng
    # to test installation
    # PYTHONPATH=. bin/python scripts/test-invalid-compression-methods.py --help
    cd $cwd
fi
# start server
zig-out/bin/fuzz_server &
# run tlsfuzzer tests on our server
cd example/tlsfuzzer/
../run_tlsfuzzer_tests.sh
# stop server
kill %1

cd $cwd
zig-out/bin/top_sites
zig-out/bin/badssl
zig-out/bin/all_ciphers
