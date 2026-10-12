#!/bin/bash
set -e

PKG_SPEC="$1"
if [ -z "$PKG_SPEC" ]; then
    echo "[-] Error: No package specification provided."
    exit 1
fi

echo "[*] Initializing Tripwire Detonation Sandbox for: $PKG_SPEC"

# Setup honeytokens in home directory if configured
mkdir -p "$HOME/.aws" "$HOME/.ssh" "$HOME/.kube"
if [ -f /honeytokens/aws_credentials ]; then
    cp /honeytokens/aws_credentials "$HOME/.aws/credentials"
fi
if [ -f /honeytokens/id_rsa ]; then
    cp /honeytokens/id_rsa "$HOME/.ssh/id_rsa"
    chmod 600 "$HOME/.ssh/id_rsa"
fi
if [ -f /honeytokens/npmrc ]; then
    cp /honeytokens/npmrc "$HOME/.npmrc"
fi
if [ -f /honeytokens/kube_config ]; then
    cp /honeytokens/kube_config "$HOME/.kube/config"
fi

# Initialize clean npm environment
cd /detonation
npm init -y > /dev/null 2>&1

echo "[*] Attaching strace telemetry engine..."
# Trace file operations, process creations, network sockets, and file descriptors
set +e
strace -f -tt -s 512 -e trace=file,process,network,desc -o /trace/raw.trace \
    npm install "$PKG_SPEC" --ignore-scripts=false --audit=false --fund=false
EXIT_CODE=$?
set -e

echo "[*] Detonation finished. Exit code: $EXIT_CODE"
if [ -f /trace/raw.trace ]; then
    LINE_COUNT=$(wc -l < /trace/raw.trace)
    echo "[*] Generated $LINE_COUNT raw syscall trace events."
else
    echo "[-] Warning: No trace output captured."
fi

exit $EXIT_CODE
