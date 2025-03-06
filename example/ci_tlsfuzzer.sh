#!/bin/bash -e

cwd=$(pwd)
cd $cwd

# clone tlsfuzzer repo if don't exists
if [[ ! -d example/tlsfuzzer ]] ; then
    cd example
    git clone https://github.com/tlsfuzzer/tlsfuzzer.git
    python -m venv tlsfuzzer
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

