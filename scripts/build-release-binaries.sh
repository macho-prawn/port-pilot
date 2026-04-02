#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

xwin_cache_dir="$repo_root/target/.cache"
release_dir="$repo_root/target/release"
windows_target="x86_64-pc-windows-msvc"
darwin_target="x86_64-apple-darwin"

mkdir -p "$xwin_cache_dir"
mkdir -p "$release_dir"

failures=0

log() {
  printf '%s\n' "$*"
}

warn() {
  printf 'warning: %s\n' "$*" >&2
}

have_command() {
  command -v "$1" >/dev/null 2>&1
}

have_rust_target() {
  rustup target list --installed | grep -Fxq "$1"
}

copy_artifact() {
  local source_path="$1"
  local dest_name="$2"

  if [[ ! -f "$source_path" ]]; then
    warn "expected artifact missing: $source_path"
    failures=$((failures + 1))
    return
  fi

  cp "$source_path" "$release_dir/$dest_name"
  log "release artifact: $release_dir/$dest_name"
}

build_linux() {
  log "building Linux amd64 release"
  cargo build --release
  log "linux native artifact: $repo_root/target/release/ports"
  copy_artifact "$repo_root/target/release/ports" "ports-linux-amd64"
}

build_windows() {
  if ! have_rust_target "$windows_target"; then
    warn "missing Rust target: $windows_target"
    failures=$((failures + 1))
    return
  fi

  if have_command cargo-xwin; then
    log "building Windows amd64 release with cargo-xwin"
    env XDG_CACHE_HOME="$xwin_cache_dir" cargo xwin build --release --target "$windows_target"
    log "windows native artifact: $repo_root/target/$windows_target/release/ports.exe"
    copy_artifact "$repo_root/target/$windows_target/release/ports.exe" "ports-windows-amd64.exe"
    return
  fi

  if have_command link.exe; then
    log "building Windows amd64 release with link.exe"
    cargo build --release --target "$windows_target"
    log "windows native artifact: $repo_root/target/$windows_target/release/ports.exe"
    copy_artifact "$repo_root/target/$windows_target/release/ports.exe" "ports-windows-amd64.exe"
    return
  fi

  warn "cannot build $windows_target: install cargo-xwin or provide link.exe"
  failures=$((failures + 1))
}

build_darwin() {
  local darwin_linker="${CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER:-}"
  local darwin_sdk="${SDKROOT:-}"

  if ! have_rust_target "$darwin_target"; then
    warn "missing Rust target: $darwin_target"
    failures=$((failures + 1))
    return
  fi

  if [[ -z "$darwin_sdk" ]] && have_command xcrun; then
    darwin_sdk="$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
  fi

  if [[ -z "$darwin_sdk" ]]; then
    warn "cannot build $darwin_target: set SDKROOT or install xcrun with a macOS SDK"
    failures=$((failures + 1))
    return
  fi

  if [[ ! -d "$darwin_sdk" ]]; then
    warn "cannot build $darwin_target: SDK path does not exist: $darwin_sdk"
    failures=$((failures + 1))
    return
  fi

  if [[ -z "$darwin_linker" ]]; then
    warn "cannot build $darwin_target: set CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER to a Darwin-capable linker"
    failures=$((failures + 1))
    return
  fi

  if [[ ! -x "$darwin_linker" ]] && ! have_command "$darwin_linker"; then
    warn "cannot build $darwin_target: Darwin linker not found: $darwin_linker"
    failures=$((failures + 1))
    return
  fi

  log "building macOS amd64 release"
  env \
    SDKROOT="$darwin_sdk" \
    CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER="$darwin_linker" \
    cargo build --release --target "$darwin_target"
  log "macOS native artifact: $repo_root/target/$darwin_target/release/ports"
  copy_artifact "$repo_root/target/$darwin_target/release/ports" "ports-darwin-amd64"
}

build_linux
build_windows
build_darwin

if (( failures > 0 )); then
  warn "completed with $failures failure(s)"
  exit 1
fi

log "release builds completed with normalized artifacts in $release_dir"
