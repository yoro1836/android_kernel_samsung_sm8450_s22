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

# Download fastbootD patched recovery
for var in "S22 S22+ S22U"
do
    RECOVERY_URL="https://github.com/yoro1836/android_kernel_samsung_sm8450_s22/releases/download/fastbootD/$var"
    RECOVERY_FILE=$(basename "$RECOVERY_URL")
    info "      Downloading FastbootD Patched Recovery for ${var}"
    if [ ! -f "$RECOVERY_FILE" ]; then
        wget -q --show-progress --progress=dot:giga -O "$RECOVERY_FILE" "$RECOVERY_URL"
    fi
done
info "       Complete Download Patched Recovery"
info "================================================"

# Cooking Flashable File
set -x
cp ./out/msm-${CHIPSET_NAME}-${CHIPSET_NAME}-${TARGET_PRODUCT}/dist/boot.img ./
for var in "S22 S22+ S22U"
do
    mv ${var}.img recovery.img
    tar -cvf ${var}_KSUN.tar boot.img recovery.img
done
set +x
info "        Complete Cooked Flashable File"
info "================================================"
info "             Thank you -@Yoro1836"
info "================================================"
