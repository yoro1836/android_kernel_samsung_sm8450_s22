#!/bin/bash
set -e

# =========================================
#  CI Utility Script for ZeroX Kernel
# =========================================

# Helper functions
log() {
    echo -e "[LOG] $*"
}

error() {
    echo -e "[ERROR] $*"
    # Send error notification if Telegram vars are set
    if [ -n "$TELEGRAM_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        local err_msg="*ZeroX Kernel CI Error* ❌\n\`$*\`"
        send_msg "$err_msg"
        # Try to upload log if exists
        if [ -f "build.log" ]; then
            upload_file "build.log" "Build Log"
        fi
    fi
    exit 1
}

# Environment Prep
prepare_env() {
    log "Freeing up disk space..."
    curl -L -o util_free_space.sh https://raw.githubusercontent.com/apache/arrow/main/ci/scripts/util_free_space.sh
    chmod +x util_free_space.sh
    ./util_free_space.sh || true
    rm -f util_free_space.sh

    log "Installing dependencies..."
    sudo apt-get update
    sudo apt-get install -y build-essential bc bison flex libssl-dev make libncurses5-dev git curl clang lld libelf-dev erofs-utils unzip ccache device-tree-compiler
}

# Patches & Setup
setup_ksu() {
    # Expects KSU_VARIANT to be set
    log "Applying KernelSU Patches..."

    local SUSFS_BRANCH="gki-android12-5.10"
    local SUSFS_DIR="$GITHUB_WORKSPACE/susfs4ksu"
    local SUSFS_PATCHES="$GITHUB_WORKSPACE/patches/susfs"
    local KERNEL_PATCHES="$GITHUB_WORKSPACE/patches"

    pushd kernel_platform/common
    
    curl -LSs "https://raw.githubusercontent.com/pershoot/KernelSU-Next/kernel/setup.sh" | bash -s $SUSFS_BRANCH

    log "Applying SUSFS4KSU Patches (Thanks @linastorvaldz)..."
    git clone --depth=1 -q https://gitlab.com/simonpunk/susfs4ksu -b $SUSFS_BRANCH $SUSFS_DIR
    cp -R $SUSFS_PATCHES/fs/* ./fs
    cp -R $SUSFS_PATCHES/include/* ./include
    patch -p1 < $SUSFS_PATCHES/50_add_susfs_in_${SUSFS_BRANCH}.patch || true
    patch -p1 < $KERNEL_PATCHES/pershoot-susfs-k5.10.patch


    log "Applying Baseband Guard..."
    wget -O- https://github.com/vc-teahouse/Baseband-guard/raw/main/setup.sh | bash
    sed -i '/^config LSM$/,/^help$/{ /^[[:space:]]*default/ { /baseband_guard/! s/selinux/selinux,baseband_guard/ } }' security/Kconfig
    
    log "Applying More Managers Support(Thanks @linastorvaldz)..."
    cd KernelSU-Next
    patch -p1 < $KERNEL_PATCHES/ksun-add-more-managers-support.patch

    popd > /dev/null
}



# Artifact Handling
prepare_artifact() {
    # Expects DEFCONFIG_VARIANT, DATE, SHA to be set
    log "Preparing artifact..."
    
    local zip_file=$(ls ZeroX-5.10*.zip 2>/dev/null | head -n 1)
    
    if [ -z "$zip_file" ]; then
        error "No build artifact found!"
    fi

    # Determine Version (Input or Default)
    local ver="${VERSION:-5.10}"
    
    # Format: ZeroX-[Version]-[Variant]-[Date]-[Hash].zip
    local new_base="ZeroX-${ver}-${DEFCONFIG_VARIANT}-${DATE}-${SHA}"
    local new_name="${new_base}.zip"

    log "Renaming $zip_file to $new_name"
    mv "$zip_file" "$new_name"

    echo "final_name=$new_name" >> $GITHUB_ENV
    echo "artifact_name=$new_base" >> $GITHUB_ENV
}

# Telegram Notifications
send_msg() {
    local message="$1"
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
        -d "chat_id=${TELEGRAM_CHAT_ID}" \
        -d "parse_mode=Markdown" \
        -d "disable_web_page_preview=true" \
        --data-urlencode "text=$message"
}

upload_file() {
    local file="$1"
    local caption="${2:-}"
    
    if [ ! -f "$file" ]; then
        log "File $file not found, skipping upload."
        return
    fi

    log "Uploading $file..."
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendDocument" \
        -F "chat_id=${TELEGRAM_CHAT_ID}" \
        -F "document=@$file" \
        -F "parse_mode=Markdown" \
        -F "caption=$caption"
}

notify_success() {
    local type="$1" # build or release
    local kernel_ver="$2"
    local date="$3"
    local sha="$4"
    local ver="${VERSION:-}" # Optional for release
    
    local msg
    if [ "$type" = "release" ]; then
        msg=$(printf "*ZeroX Kernel Release Success!* 🚀\n\n*Version*: \`${ver}\`\n*Kernel*: \`${kernel_ver}\`\n*Date*: \`${date}\`\n*Hash*: \`${sha}\`")
        send_msg "$msg"
    else
        msg=$(printf "*ZeroX Kernel Build Success!* ⚡️\n\n*Kernel*: \`${kernel_ver}\`\n*Date*: \`${date}\`\n*Hash*: \`${sha}\`")
        
        # Upload all zips in downloads/ or current dir
        local search_dir="${5:-.}"
        local first_file=true
        local files_found=false

        for f in "$search_dir"/*.zip; do
            if [ -e "$f" ]; then
                files_found=true
                if [ "$first_file" = true ]; then
                    upload_file "$f" "$msg"
                    first_file=false
                else
                    upload_file "$f"
                fi
            fi
        done
        
        # If no files found, send just the message
        if [ "$files_found" = false ]; then
            send_msg "$msg"
        fi
    fi
}

notify_failure() {
    local type="$1"
    local msg
    
    if [ -n "$VERSION" ]; then
        msg=$(printf "*ZeroX Kernel ${type^} Failed!* ❌\n\n*Version*: \`${VERSION}\`\n*Variant*: \`${DEFCONFIG_VARIANT}\`\n*Hash*: \`${SHA}\`")
    else
        msg=$(printf "*ZeroX Kernel ${type^} Failed!* ❌\n\n*Variant*: \`${DEFCONFIG_VARIANT}\` \n*Hash*: \`${SHA}\`")
    fi
    
    if [ -f "build.log" ]; then
        upload_file "build.log" "$msg"
    else
        send_msg "$msg"
    fi
}

# =========================================
#  Dispatcher
# =========================================

# Check if the function exists
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if declare -f "$1" > /dev/null; then
        # call arguments verbatim
        "$@"
    else
        echo "Usage: $0 [function_name] [args...]"
        echo "Available functions:"
        declare -F | awk '{print $3}' | grep -v "^_"
        exit 1
    fi
fi
