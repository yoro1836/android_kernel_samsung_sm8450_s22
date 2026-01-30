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
    sudo apt-get install -y build-essential bc bison flex libssl-dev make libncurses5-dev git curl clang lld libelf-dev erofs-utils unzip ccache
}

# Patches & Setup
setup_ksu() {
    # Expects KSU_VARIANT to be set
    log "Applying KernelSU variant: ${KSU_VARIANT}"
    
    pushd kernel_platform/common
    
    if [ "${KSU_VARIANT}" = "ksu" ]; then
        curl -LSs "https://raw.githubusercontent.com/tiann/KernelSU/main/kernel/setup.sh" | bash -
    elif [ "${KSU_VARIANT}" = "ksu-next" ]; then
        curl -LSs "https://raw.githubusercontent.com/KernelSU-Next/KernelSU-Next/next/kernel/setup.sh" | bash -
    else
        log "No KernelSU setup needed for ${KSU_VARIANT}"
    fi

    log "Applying Baseband Guard..."
    wget -O- https://github.com/vc-teahouse/Baseband-guard/raw/main/setup.sh | bash
    sed -i '/^config LSM$/,/^help$/{ /^[[:space:]]*default/ { /baseband_guard/! s/selinux/selinux,baseband_guard/ } }' security/Kconfig
    
    popd > /dev/null
}



# Artifact Handling
prepare_artifact() {
    # Expects KSU_VARIANT, DEFCONFIG_VARIANT, DATE, SHA to be set
    log "Preparing artifact..."
    
    local zip_file=$(ls ZeroX-5.10*.zip 2>/dev/null | head -n 1)
    
    if [ -z "$zip_file" ]; then
        error "No build artifact found!"
    fi

    # Determine Version (Input or Default)
    local ver="${VERSION:-5.10}"
    
    # Format: ZeroX-[Version]-[KSU]-[Variant]-[Date]-[Hash].zip
    local new_base="ZeroX-${ver}-${KSU_VARIANT}-${DEFCONFIG_VARIANT}-${DATE}-${SHA}"
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
        msg=$(printf "*ZeroX Kernel ${type^} Failed!* ❌\n\n*Version*: \`${VERSION}\`\n*KSU*: \`${KSU_VARIANT}\`\n*Variant*: \`${DEFCONFIG_VARIANT}\`\n*Hash*: \`${SHA}\`")
    else
        msg=$(printf "*ZeroX Kernel ${type^} Failed!* ❌\n\n*KSU*: \`${KSU_VARIANT}\`\n*Variant*: \`${DEFCONFIG_VARIANT}\` \n*Hash*: \`${SHA}\`")
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
