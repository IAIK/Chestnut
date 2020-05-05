#!/bin/bash
python3 inject-lib.py $1
LD_LIBRARY_PATH=. $1_patched
