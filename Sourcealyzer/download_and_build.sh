#!/bin/bash

# While this script allows you to download, patch, and build Sourcealyzer, note that this is not sufficient.
# Chestnut requires that all libraries that an application requires are compiled using this modified compiler and the appropriate flags.
# If you want to fully use Sourcealyzer, we recommend to setup a conan environment that builds the compiler, the libraries, and copies them to a sysroot.
# Not doing so will most likely lead to the wrong libraries being used that have not been compiled using Sourcealyzer.

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color


function check_exit_status {
  if [[ ! $? -eq 0 ]]; then
    echo -e "${RED}Error during last command, terminating${NC}"
    exit 1
  fi
}

FOLDER='llvm10'

if [ ! -d $FOLDER ]
then
echo -e "${GREEN}Cloning $APP${NC}"
git clone --branch release/10.x --depth 1 https://github.com/llvm/llvm-project.git llvm10
else
echo -e "${GREEN}$APP already exists${NC}"
fi
check_exit_status

echo -e "${GREEN}Changing directiory and creating build folder${NC}"
# llvm 10 is used as base
cd llvm10 && mkdir build
check_exit_status

echo -e "${GREEN}Patching LLVM${NC}"
patch -p1 < ../sourcealyzer.patch
cd build

echo -e "${GREEN}Running cmake${NC}"
cmake ../llvm -G Ninja -DCMAKE_BUILD_TYPE=Release -DENABLE_EXPERIMENTAL_NEW_PASS_MANAGER=true
check_exit_status

echo -e "${GREEN}Executing ninja${NC}"
ninja
check_exit_status

echo -e "${GREEN}Compiling chestnut.o${NC}"
make -C ../../libchestnut/
check_exit_status
cp ../../libchestnut/chestnut.o bin/


