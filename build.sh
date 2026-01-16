#!/bin/bash

# ===============================================================================================================
#
#                                Galaxy S22(Qualcomm) Series Kernel Compiling Script
#
# ===============================================================================================================
#
#   Workflow:
#   1. Fork this kernel repo in your repositories
#   2. Go to the Actions > Select Kernel Build
#   3. Run workflow > Branch: 15 > Run Workflow
#   4. It takes about 30~50mins... (Scamsung Flagship GKI Kernel Source is very huge)
#   5. Workflow Upload Cooked boot.img or Flashable Odin tar file(include FastbootD patched recovery)
#   6. Download file and Flash Cooked file in Odin or FastbootD (If you first, You have to Use Odin)
#
# ===============================================================================================================
#
#   Local:
#   1. clone this kernel repo in your local LinuxPC
#   2. Custom Edit kernel source (If you dont know Kernel Knowledge, I recommend skip this step)
#   3. Open the Terminal > Wrtie and Run This command
#
#                                          ./build.sh
#
#   4. It takes about 30~50mins... (Scamsung Flagship GKI Kernel Source is very huge)
#                 ** Required at least 40~50GB in your local PC Storage **
#   5. Compiler put out Cooked boot.img or Flashable Odin tar file(include FastbootD patched recovery)
#   6. Download file and Flash Cooked file in Odin or FastbootD (If you first, You have to Use Odin)
#
#                                 - Yoro1836 (Thank You for GoRhanHee and Ravindu)
# ===============================================================================================================

# --- FROM env.sh ---
export BLACK='\033[0;30m'
export RED='\033[1;31m'
export UNBOLD_GREEN='\033[0;32m'
export MINT_GREEN='\033[1;92m'
export YELLOW='\033[0;\033m'
export BLUE='\033[0;34m'
export MAGENTA='\033[0;35m'
export CYAN='\033[0;36m'
export BLK='\033[30m'
export GRAY='\033[90m'
export WHITE='\033[0;37m'
export BOLD_WHITE='\033[1;37m'
export LIGHT_YELLOW='\033[1;93m'
export BOLD='\033[1m'
export UNDERLINE='\033[4m'
export RESET='\033[0m'


info() {
    echo -e "${BOLD}${MINT_GREEN}${1}${RESET} ${BOLD}${2}${RESET}"
}

warn() {
    echo -e "${BOLD}${RED}${1}${RESET} ${BOLD}${2}${RESET}" 
}
# -------------------

# --- FROM s22.sh (Intro) ---
# OEM Setting (Preliminary variables from s22.sh - kept for consistency if needed, but build.sh overwrites)
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
# ---------------------------

# --- FROM build.sh ---

info "              Compiling Scripts"
info "================================================"

# Import submodules
set -x
git submodule init && git submodule update --remote
set +x
info "           Success Import Submodule"
info "================================================"

# OEM Setting
set -x
BUILD_TARGET=b0q_gbl_openx
export MODEL=$(echo $BUILD_TARGET | cut -d'_' -f1)
export PROJECT_NAME=${MODEL}
export REGION=$(echo $BUILD_TARGET | cut -d'_' -f2)
export CARRIER=$(echo $BUILD_TARGET | cut -d'_' -f3)
export TARGET_BUILD_VARIANT=user
			
CHIPSET_NAME=waipio

export ANDROID_BUILD_TOP=$(pwd)
export TARGET_PRODUCT=gki
export TARGET_BOARD_PLATFORM=gki

export ANDROID_PRODUCT_OUT=${ANDROID_BUILD_TOP}/out/target/product/${MODEL}
export OUT_DIR=${ANDROID_BUILD_TOP}/out/msm-${CHIPSET_NAME}-${CHIPSET_NAME}-${TARGET_PRODUCT}
export DIST_DIR=${ANDROID_BUILD_TOP}/out/msm-${CHIPSET_NAME}-${CHIPSET_NAME}-${TARGET_PRODUCT}/dist
export MERGE_CONFIG="${ANDROID_BUILD_TOP}/kernel_platform/common/scripts/kconfig/merge_config.sh"

mkdir -p "${ANDROID_BUILD_TOP}/out/msm-${CHIPSET_NAME}-${CHIPSET_NAME}-${TARGET_PRODUCT}/dist"

export KBUILD_EXTRA_SYMBOLS=${ANDROID_BUILD_TOP}/out/vendor/qcom/opensource/mmrm-driver/Module.symvers


export MODNAME=audio_dlkm

export KBUILD_EXT_MODULES="../vendor/qcom/opensource/datarmnet-ext/wlan \
    ../vendor/qcom/opensource/datarmnet/core \
    ../vendor/qcom/opensource/mmrm-driver \
    ../vendor/qcom/opensource/audio-kernel \
    ../vendor/qcom/opensource/camera-kernel \
    ../vendor/qcom/opensource/display-drivers/msm \
    "

set +x
info "             Success OEM Setting"
info "================================================"

# Build Setting
set -x
export GKI_KERNEL_BUILD_OPTIONS="
    SKIP_MRPROPER=1 \
    LTO=thin \
    HERMETIC_TOOLCHAIN=0 \
    KMI_SYMBOL_LIST_STRICT_MODE=0 \
    RECOMPILE_KERNEL=1 \
    ABI_DEFINITION= 
"

# MKBOOTIMG Setting
export MKBOOTIMG_EXTRA_ARGS="
    --os_version 12.0.0 \
    --os_patch_level 2025-08-01 \
    --pagesize 4096 \
"

set +x
info "            Success Build Setting"
info "================================================"

# Import toolchain
TOOLCHAIN_URL="https://github.com/yoro1836/samsung_sm8450_toolchain/releases/download/clang12/toolchain.tar.gz"
TOOLCHAIN_FILE=$(basename "$TOOLCHAIN_URL")
CHECK_DIR="kernel_platform/prebuilts"

if [ -d "$CHECK_DIR" ]; then
    info "Directory '$CHECK_DIR' already exists. Skipping download toolchain."
else
    info "Directory '$CHECK_DIR' not found. Starting download toolchain..."
    if [ ! -f "$TOOLCHAIN_FILE" ]; then
        wget -q --show-progress --progress=dot:giga -O "$TOOLCHAIN_FILE" "$TOOLCHAIN_URL"
    fi
    tar -xzf "$TOOLCHAIN_FILE" -C kernel_platform && rm "$TOOLCHAIN_FILE"
    info "Complete Download."
fi

info "           Success Import Toolchain"
info "================================================"

# Build kernel
( env ${GKI_KERNEL_BUILD_OPTIONS} ${ANDROID_BUILD_TOP}/kernel_platform/build/android/prepare_vendor.sh sec ${TARGET_PRODUCT} || exit 1)
# --------------------

# --- FROM s22.sh (Post-Processing) ---

# Success Compiling
info "================================================"
info "               Success Compiling"
info "================================================"

# Cooking Flashable File
set -x

cp ./out/msm-${CHIPSET_NAME}-${CHIPSET_NAME}-${TARGET_PRODUCT}/dist/Image ./external/AnyKernel3/
zip ./Yoro_kernel_S22.zip ./external/AnyKernel3/*

set +x
info "        Complete Cooked Flashable File"
info "================================================"
info "             Thank you -@Yoro1836"
info "================================================"
