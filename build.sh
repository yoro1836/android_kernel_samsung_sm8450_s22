#!/bin/bash
set -e

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
#                                          ./build.sh [ak3|tar|clean|tcclean|update]
#
#   4. It takes about 30~50mins... (Scamsung Flagship GKI Kernel Source is very huge)
#                 ** Required at least 40~50GB in your local PC Storage **
#   5. Compiler put out Cooked boot.img or Flashable Odin tar file(include FastbootD patched recovery)
#   6. Download file and Flash Cooked file in Odin or FastbootD (If you first, You have to Use Odin)
#
#                                 - Yoro1836 (Thank You for GoRhanHee and Ravindu)
# ===============================================================================================================

# -----------------------------------------------------------------------------
# Configuration & Setup
# -----------------------------------------------------------------------------

function setup_env() {
    echo "Setting up environment..."
    
    # Update submodules to latest
    echo "Updating submodules..."
    git submodule update --init --recursive --remote

    # DIR Setting
    SCRIPT_DIR="$(dirname $(readlink -fq $0))"

    # OEM Setting
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
    
    # KBUILD Setting
    sudo timedatectl set-timezone "Asia/Seoul" || export TZ="Asia/Seoul"
    export KBUILD_BUILD_USER="Yoro1836"
    export KBUILD_BUILD_HOST="AkoTheCow"
    export KBUILD_BUILD_TIMESTAMP=$(date)

    # Kernel Version Customization
    export LOCALVERSION="$VERSION_SUFFIX"

    export ANDROID_PRODUCT_OUT=${ANDROID_BUILD_TOP}/out/target/product/${MODEL}
    export OUT_DIR=${ANDROID_BUILD_TOP}/out/msm-${CHIPSET_NAME}-${CHIPSET_NAME}-${TARGET_PRODUCT}
    export DIST_DIR=${ANDROID_BUILD_TOP}/out/msm-${CHIPSET_NAME}-${CHIPSET_NAME}-${TARGET_PRODUCT}/dist
    export MERGE_CONFIG="${ANDROID_BUILD_TOP}/kernel_platform/common/scripts/kconfig/merge_config.sh"

    mkdir -p "${DIST_DIR}"

    export KBUILD_EXTRA_SYMBOLS=${ANDROID_BUILD_TOP}/out/vendor/qcom/opensource/mmrm-driver/Module.symvers
    export MODNAME=audio_dlkm

    export KBUILD_EXT_MODULES="../vendor/qcom/opensource/datarmnet-ext/wlan \
        ../vendor/qcom/opensource/datarmnet/core \
        ../vendor/qcom/opensource/mmrm-driver \
        ../vendor/qcom/opensource/audio-kernel \
        ../vendor/qcom/opensource/camera-kernel \
        ../vendor/qcom/opensource/display-drivers/msm"

    # CCACHE Setting
    if command -v ccache >/dev/null 2>&1; then
        echo "ccache found! Enabling..."
        export USE_CCACHE=1
        export CCACHE_EXEC=$(command -v ccache)
        export CCACHE_DIR="${ANDROID_BUILD_TOP}/.ccache"
        export CCACHE_COMPILERCHECK=content
        export CCACHE_COMPRESS=1
        export CCACHE_MAXSIZE=10G
        export CCACHE_BASEDIR="${ANDROID_BUILD_TOP}"
        mkdir -p "$CCACHE_DIR"
        ccache -z # Zero stats at start

        # Masquerade clang/gcc to force ccache usage
        local CACHED_BIN_DIR="${ANDROID_BUILD_TOP}/.ccache/bin"
        mkdir -p "$CACHED_BIN_DIR"
        for tool in clang clang++ gcc g++ cc c++; do
            ln -sf "$CCACHE_EXEC" "${CACHED_BIN_DIR}/${tool}"
        done
        export PATH="${CACHED_BIN_DIR}:${PATH}"
        echo "CCache masquerading enabled in ${CACHED_BIN_DIR}"
    else
        echo "ccache not found. Skipping..."
    fi
}

function prepare_toolchain() {
    # MKBOOTIMG Setting
    export MKBOOTIMG_EXTRA_ARGS="
        --os_version 12.0.0 \
        --os_patch_level 2025-08-01 \
        --pagesize 4096
    "

    # Import Samsung toolchain
    local TOOLCHAIN_URL="https://github.com/yoro1836/samsung_sm8450_toolchain/releases/download/clang12/toolchain.tar.gz"
    local TOOLCHAIN_FILE=$(basename "$TOOLCHAIN_URL")
    local CHECK_DIR="kernel_platform/prebuilts"

    if [ -d "$CHECK_DIR" ]; then
        echo "Directory '$CHECK_DIR' already exists. Skipping download toolchain."
    else
        echo "Directory '$CHECK_DIR' not found. Starting download toolchain..."
        if [ ! -f "$TOOLCHAIN_FILE" ]; then
            wget -q --show-progress --progress=dot:giga -O "$TOOLCHAIN_FILE" "$TOOLCHAIN_URL"
        fi
        tar -xzf "$TOOLCHAIN_FILE" -C kernel_platform && rm "$TOOLCHAIN_FILE"
        echo "Complete Download."
    fi
}

# -----------------------------------------------------------------------------
# Build Functions
# -----------------------------------------------------------------------------

function get_common_build_options() {
    echo "
    SKIP_MRPROPER=1 \
    LTO=thin \
    HERMETIC_TOOLCHAIN=0 \
    KMI_SYMBOL_LIST_STRICT_MODE=0 \
    RECOMPILE_KERNEL=1 \
    ABI_DEFINITION= \
    KERNEL_BINARY=Image \
    "
}

function build_kernel() {
    local build_type=$1
    echo "Starting Build for $build_type..."

    local common_options=$(get_common_build_options)

    if [ "$build_type" = "ak3" ]; then
        # GKI Build for AnyKernel3
        # Uses direct build/build.sh call
        export GKI_KERNEL_BUILD_OPTIONS="${common_options} SKIP_VENDOR_BOOT=1"
        # Handle Custom Defconfig Variants
        if [ -z "${DEFCONFIG_VARIANT}" ]; then
            export DEFCONFIG_VARIANT="perf"
        fi

        if [ -n "${DEFCONFIG_VARIANT}" ]; then
            local variant_config="custom_defconfigs/zerox-${DEFCONFIG_VARIANT}_defconfig"
            if [ -f "${variant_config}" ]; then
                echo "Merging variant config: ${variant_config}"
                export POST_DEFCONFIG_CMDS="check_defconfig && ${MERGE_CONFIG} -m \${OUT_DIR}/.config ${ANDROID_BUILD_TOP}/${variant_config}"
            else
                echo "Warning: variant config '${variant_config}' not found!"
            fi
        fi

        # Source CI functions and setup KSU/Patches
        if [ -f ".github/scripts/ci.sh" ]; then
            source .github/scripts/ci.sh
            # setup_ksu relies on KSU_VARIANT being set
            setup_ksu
        else
            echo "Warning: .github/scripts/ci.sh not found, skipping patch application."
        fi
        
        echo "Building Common Kernel..."
        #(
        #    cd kernel_platform
        #    env ${GKI_KERNEL_BUILD_OPTIONS} ./build/build.sh
        #) || { echo "Kernel build failed!"; exit 1; }

        ( 
            env ${GKI_KERNEL_BUILD_OPTIONS} ${ANDROID_BUILD_TOP}/kernel_platform/build/android/prepare_vendor.sh sec ${TARGET_PRODUCT} 
        ) || { echo "Vendor build failed!"; exit 1; }

        
        if [ "$USE_CCACHE" = "1" ]; then
            echo "ccache statistics:"
            ccache -s
        fi
        
    elif [ "$build_type" = "tar" ]; then
        # Odin Tar Build
        # Uses prepare_vendor.sh
        export GKI_KERNEL_BUILD_OPTIONS="${common_options} \
            BUILD_BOOT_IMG=1 \
            MKBOOTIMG_PATH=${ANDROID_BUILD_TOP}/kernel_platform/tools/mkbootimg/mkbootimg.py \
            BOOT_IMAGE_HEADER_VERSION=4"
            
        echo "Building Kernel & Vendor Modules..."
        ( 
            env ${GKI_KERNEL_BUILD_OPTIONS} ${ANDROID_BUILD_TOP}/kernel_platform/build/android/prepare_vendor.sh sec ${TARGET_PRODUCT} 
        ) || { echo "Vendor build failed!"; exit 1; }

        if [ "$USE_CCACHE" = "1" ]; then
            echo "ccache statistics:"
            ccache -s
        fi
    fi
}

function package_ak3() {
    echo "Packaging for AnyKernel3..."
    local image_path="./out/msm-${CHIPSET_NAME}-${CHIPSET_NAME}-${TARGET_PRODUCT}/dist/Image"
    
    if [ ! -f "$image_path" ]; then
        echo "Error: Image not found at $image_path"
        exit 1
    fi

    cp "$image_path" ./external/AnyKernel3/Image
    
    zipname="ZeroX-5.10-$(date +%Y%m%d-%H%M%S)-$(git rev-parse --short HEAD)"

    cd external/AnyKernel3
    zip -r ${zipname}.zip *
    rm Image
    mv ${zipname}.zip ../../
    cd - > /dev/null
    
    echo "Done! Build Complete."
}

function package_tar() {
    echo "Packaging for Odin..."
    local dist_path="./out/msm-${CHIPSET_NAME}-${CHIPSET_NAME}-${TARGET_PRODUCT}/dist"
    
    if [ ! -f "$dist_path/vendor_boot.img" ] || [ ! -f "$dist_path/boot.img" ]; then
        echo "Error: boot.img or vendor_boot.img not found in $dist_path"
        exit 1
    fi

    cp "$dist_path/vendor_boot.img" ./vendor_boot.img
    cp "$dist_path/boot.img" ./boot.img
    
    tar -cvf Galaxy_S22.tar boot.img vendor_boot.img
    
    echo "Done! Build Complete."
}

# -----------------------------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------------------------

function clean_out() {
    echo "Cleaning out directory..."
    rm -rf out device || echo "No need to clean out"
    echo "Cleaned up."
}

function clean_toolchain() {
    echo "Cleaning toolchain..."
    rm -rf kernel_platform/prebuilts* || echo "No need to clean toolchain"
    echo "Toolchain cleaned up."
}

function update_repo() {
    echo "Updating repository..."
    git pull || true
    git submodule update --remote || true
    echo "Updated."
}

function show_usage() {
    echo "Usage: $0 [ak3|tar|clean|tcclean|update]"
    exit 1
}

# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------

if [ "$#" -ne 1 ]; then
    show_usage
fi

case "$1" in
    ak3)
        setup_env
        prepare_toolchain
        build_kernel "ak3"
        package_ak3
        ;;
    tar)
        setup_env
        prepare_toolchain
        build_kernel "tar"
        package_tar
        ;;
    clean)
        clean_out
        ;;
    tcclean)
        clean_toolchain
        ;;
    update)
        update_repo
        ;;
    *)
        show_usage
        ;;
esac
