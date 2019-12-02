#/bin/bash
# Preparing build
./autogen.sh
./configure --target=x86_64 --with-platform=efi
