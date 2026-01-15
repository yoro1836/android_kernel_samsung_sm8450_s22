#!/bin/bash

# Setting Color Font
source "./env.sh"

# OEM Setting
export ANDROID_BUILD_TOP=$(pwd)
export TARGET_PRODUCT=gki
export TARGET_BOARD_PLATFORM=gki
CHIPSET_NAME=waipio

# Introduce Scripts
info "================================================"
info " "
info "          Galaxy S22(Qualcomm) Series Kernel Builder"
info " "
info "================================================"
info "           Import Compiling Script..."
info "================================================"

# Import Compiling Script
./build.sh || exit 1

# Success Compiling
info "================================================"
info "               Success Compiling"
info "================================================"

# Cooking Flashable File
set -x

git clone "https://github.com/yoro1836/AnyKernel3.git"
cp ./out/msm-${CHIPSET_NAME}-${CHIPSET_NAME}-${TARGET_PRODUCT}/dist/Image ./AnyKernel3/
zip ./Yoro_kernel_S22.zip ./AnyKernel/*

set +x
info "        Complete Cooked Flashable File"
info "================================================"
info "             Thank you -@Yoro1836"
info "================================================"
