#!/bin/bash
set -eu

# Sign and optionally notarize macOS binaries (.app, .pkg, .dmg, Mach-O).
# Usage: sign-macos.sh <path>
# Required env: MACOS_SIGNING_IDENTITY, MACOS_CERTIFICATE (base64 .p12), MACOS_CERTIFICATE_PWD.
# Optional: MACOS_ENTITLEMENTS, KEYCHAIN_PASSWORD (random if unset), NOTARIZATION_USERNAME, NOTARIZATION_PASSWORD, NOTARIZATION_TEAM_ID.

SIGN_PATH="$1"
KEYCHAIN_NAME="build.keychain"
if [ -z "${KEYCHAIN_PASSWORD:-}" ]; then
  KEYCHAIN_PASSWORD=$(openssl rand -hex 32)
fi
NOTARY_KEYCHAIN_NAME="notary.keychain"
NOTARY_KEYCHAIN_PATH="${HOME}/Library/Keychains/${NOTARY_KEYCHAIN_NAME}-db"
NOTARY_PROFILE_NAME="release-sign-notarytool-profile"

# Track the default keychain so we can restore it during cleanup if we change it.
PREV_DEFAULT_KEYCHAIN="$(security default-keychain 2>/dev/null || echo "")"
KEYCHAIN_PWD_FILE=""
CERT_PWD_FILE=""
NOTARY_PWD_FILE=""
CERT_FILE=""
cleanup() {
  # Restore the previous default keychain if we changed it.
  if [ -n "${PREV_DEFAULT_KEYCHAIN:-}" ]; then
    security default-keychain -s "$PREV_DEFAULT_KEYCHAIN" 2>/dev/null || true
  fi
  # Delete any temporary keychains we created.
  security delete-keychain "$KEYCHAIN_NAME" 2>/dev/null || true
  security delete-keychain "$NOTARY_KEYCHAIN_NAME" 2>/dev/null || true
  # Remove temporary password and certificate files.
  for f in "$KEYCHAIN_PWD_FILE" "$CERT_PWD_FILE" "$NOTARY_PWD_FILE" "$CERT_FILE"; do
    [ -z "$f" ] && continue
    [ -f "$f" ] || continue
    rm -f "$f"
  done
}
EXIT_CODE=0
TRAP_ERR=0
trap 'TRAP_ERR=$?; cleanup; if [ "$EXIT_CODE" -ne 0 ] 2>/dev/null; then exit "$EXIT_CODE"; else exit "$TRAP_ERR"; fi' EXIT

if [ -z "$SIGN_PATH" ]; then
  echo "Error: Path argument required"
  EXIT_CODE=1; exit 1
fi

if [ ! -e "$SIGN_PATH" ]; then
  echo "Error: Path not found: $SIGN_PATH"
  EXIT_CODE=1; exit 1
fi

# Required for signing (action inputs: macos-signing-identity, macos-certificate, macos-certificate-pwd)
if [ -z "${MACOS_SIGNING_IDENTITY:-}" ]; then echo "Error: macos-signing-identity required" >&2; EXIT_CODE=1; exit 1; fi
if [ -z "${MACOS_CERTIFICATE_PWD:-}" ]; then echo "Error: macos-certificate-pwd required" >&2; EXIT_CODE=1; exit 1; fi
if [ -z "${MACOS_CERTIFICATE:-}" ]; then echo "Error: macos-certificate required (env)" >&2; EXIT_CODE=1; exit 1; fi

# True when all notarization credentials are set; used to gate the optional notarization block below.
notarization_enabled() {
  [ -n "${NOTARIZATION_USERNAME:-}" ] && [ -n "${NOTARIZATION_TEAM_ID:-}" ] && [ -n "${NOTARIZATION_PASSWORD:-}" ]
}
# Passwords to temp files (0600); trim cert password (trailing newline from GitHub UI).
KEYCHAIN_PWD_FILE=$(mktemp -t keychain_pwd.XXXXXX)
CERT_PWD_FILE=$(mktemp -t cert_pwd.XXXXXX)
printf '%s' "$KEYCHAIN_PASSWORD" > "$KEYCHAIN_PWD_FILE"
printf '%s' "$(printf '%s' "$MACOS_CERTIFICATE_PWD" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')" > "$CERT_PWD_FILE"
chmod 600 "$KEYCHAIN_PWD_FILE" "$CERT_PWD_FILE"
unset MACOS_CERTIFICATE_PWD KEYCHAIN_PASSWORD

# Keychain: create, unlock, import cert, set partition list
echo "Setting up keychain and importing certificate..."
security create-keychain -p "$(cat "$KEYCHAIN_PWD_FILE")" "$KEYCHAIN_NAME" || true
security unlock-keychain -p "$(cat "$KEYCHAIN_PWD_FILE")" "$KEYCHAIN_NAME"

# Decode certificate
_cert_tmpdir="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
CERT_FILE=$(TMPDIR="$_cert_tmpdir" mktemp -t cert.XXXXXX)
# Normalize certificate by stripping all whitespace (spaces, tabs, CR, LF) before decoding.
_cert_b64=$(printf '%s' "$MACOS_CERTIFICATE" | tr -d ' \r\n\t')
printf '%s' "$_cert_b64" | base64 --decode > "$CERT_FILE" 2>/dev/null || \
  printf '%s' "$_cert_b64" | base64 -D > "$CERT_FILE" 2>/dev/null || true

if [ ! -s "$CERT_FILE" ]; then
  echo "Error: macos-certificate could not be decoded. Use base64-encoded .p12 contents." >&2
  EXIT_CODE=1; exit 1
fi
_decoded_size=$(wc -c < "$CERT_FILE")
if [ "$_decoded_size" -lt 100 ] || [ "$_decoded_size" -gt 500000 ]; then
  echo "Error: decoded certificate size is ${_decoded_size} bytes; expected ~3300 for .p12. Check base64 secret." >&2
  EXIT_CODE=1; exit 1
fi
# Explicit -f pkcs12 (SecKeychainItemImport is deprecated; format hint can avoid "Unknown format in import")
# Capture stdout/stderr so we don't leak keychain attributes on success; on failure show real error
_import_out=$(mktemp -t security_import.XXXXXX)
_import_exit=0
security import "$CERT_FILE" -f pkcs12 -k "$KEYCHAIN_NAME" -P "$(cat "$CERT_PWD_FILE")" -T /usr/bin/codesign -T /usr/bin/security >"$_import_out" 2>&1 || _import_exit=$?
if [ "$_import_exit" -ne 0 ]; then
  cat "$_import_out" >&2
  rm -f "$_import_out"
  echo "Error: Failed to import certificate into keychain." >&2
  EXIT_CODE=1; exit 1
fi
rm -f "$_import_out"
rm -f "$CERT_FILE"
CERT_FILE=""

security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$(cat "$KEYCHAIN_PWD_FILE")" "$KEYCHAIN_NAME"

# Add our keychain to search list so identity is findable (portable: no mapfile/bash4)
_keychain_list=$(security list-keychains -d user 2>/dev/null)
if ! echo "$_keychain_list" | grep -qF "$KEYCHAIN_NAME"; then
  set --
  while IFS= read -r _kc; do
    [ -z "$_kc" ] && continue
    set -- "$@" "$_kc"
  done <<EOF
$_keychain_list
EOF
  security list-keychains -d user -s "$KEYCHAIN_NAME" "$@" 2>/dev/null || true
fi

sign_item() {
  local item="$1"
  echo "Signing: $item"
  local args=(--force --sign "$MACOS_SIGNING_IDENTITY" --timestamp --options runtime)

  if [ -n "${MACOS_ENTITLEMENTS:-}" ]; then
    if [ -f "$MACOS_ENTITLEMENTS" ]; then
      args+=(--entitlements "$MACOS_ENTITLEMENTS")
    else
      echo "Error: MACOS_ENTITLEMENTS is set to '$MACOS_ENTITLEMENTS' but the file does not exist." >&2
      EXIT_CODE=1; exit 1
    fi
  fi
  if [[ -d "$item" && "$item" == *.app ]]; then
    # Sign nested components inside-out (Apple-recommended; --deep is deprecated and can break notarization).
    # Collect nested .app, .framework, .xpc, .appex, executables, and .dylib/.so, then sort by depth (deepest first).
    local nested_list
    nested_list=$( {
      find "$item" -type d \( -name "*.app" -o -name "*.framework" -o -name "*.xpc" -o -name "*.appex" \) 2>/dev/null
      find "$item" -type f \( -perm -111 -o -name "*.dylib" -o -name "*.so" \) 2>/dev/null
    } | sort -u )
    if [ -n "$nested_list" ]; then
      local depth p
      local sorted_nested
      sorted_nested=$(
        while IFS= read -r p; do
          [ -z "$p" ] && continue
          [ "$p" = "$item" ] && continue
          depth=$(echo "$p" | tr -cd '/' | wc -c | tr -d ' ')
          printf '%06d\x1e%s\n' "$depth" "$p"
        done <<< "$nested_list" | sort -rn -t$'\x1e' -k1,1n | cut -d$'\x1e' -f2-
      )
      while IFS= read -r nested; do
        [ -z "$nested" ] && continue
        sign_item "$nested"
      done <<< "$sorted_nested"
    fi
    codesign "${args[@]}" "$item"
  else
    codesign "${args[@]}" "$item"
  fi
  if ! codesign -v "$item"; then
    echo "Error: codesign verification failed for: $item" >&2
    EXIT_CODE=1; exit 1
  fi
  # For .app bundles, also verify hierarchy (idf-im-ui style)
  if [[ -d "$item" && "$item" == *.app ]]; then
    codesign -v --deep "$item" || { echo "Error: deep verification failed for: $item" >&2; EXIT_CODE=1; exit 1; }
  fi
  echo "Signed: $item"
}

# Returns 0 if file is Mach-O
is_macho() {
  local f="$1"
  [ -f "$f" ] || return 1
  file -b "$f" | grep -qi "Mach-O"
}

collect_macos_artifacts() {
  local path="$1"
  if [ -d "$path" ]; then
    # If the path itself is a .app bundle, emit it (find -mindepth 1 only returns descendants)
    if [[ "$path" == *.app ]]; then
      printf '%s\0' "$path"
    fi
    # .app bundles (signed inside-out recursively in sign_item); -mindepth 1 avoids re-emitting path when it is a .app
    find "$path" -mindepth 1 -type d -name "*.app" -print0
    # .pkg and .dmg
    find "$path" -type f \( -name "*.pkg" -o -name "*.dmg" \) -print0
    # Mach-O binaries not inside a .app (avoid double-signing). Exclude object files (.o) and
    # static libs (.a)—build artifacts, not distributable; Apple rejects notarizing them.
    while IFS= read -r -d '' f; do
      if is_macho "$f" && [[ "$f" != *.app/* ]] && [[ "$f" != *.o ]] && [[ "$f" != *.a ]]; then
        printf '%s\0' "$f"
      fi
    done < <(find "$path" -type f -print0 2>/dev/null)
  elif [ -f "$path" ]; then
    if [[ "$path" == *.pkg ]] || [[ "$path" == *.dmg ]]; then
      printf '%s\0' "$path"
    elif is_macho "$path" && [[ "$path" != *.o ]] && [[ "$path" != *.a ]]; then
      printf '%s\0' "$path"
    fi
  fi
}

notarize_submit() {
  local item="$1"
  local to_submit="$item"
  local zip_file=""
  echo "Notarizing: $item"
  if [[ "$item" == *.app ]] || [[ "$item" == *.pkg ]] || [[ "$item" == *.dmg ]]; then
    to_submit="$item"
  else
    local item_dir zip_name
    item_dir="$(dirname "$item")"
    zip_name="$(basename "$item").zip"
    (cd "$item_dir" && zip -r "$zip_name" "$(basename "$item")")
    zip_file="$item_dir/$zip_name"
    to_submit="$zip_file"
  fi
  set +e
  local out
  out=$(mktemp -t notary.XXXXXX)
  xcrun notarytool submit "$to_submit" --keychain-profile "$NOTARY_PROFILE_NAME" --keychain "$NOTARY_KEYCHAIN_PATH" --wait --timeout 600 2>&1 | tee "$out"
  local status=$?
  [ -n "$zip_file" ] && [ -f "$zip_file" ] && rm -f "$zip_file"
  if [ "$status" -ne 0 ]; then
    local id
    id=$(grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "$out" | head -1)
    rm -f "$out"
    if [ -n "$id" ]; then
      echo "Notarization failed (submission ID: $id). Apple rejection log:" >&2
      xcrun notarytool log "$id" --keychain-profile "$NOTARY_PROFILE_NAME" --keychain "$NOTARY_KEYCHAIN_PATH" >&2
      echo "To re-fetch this log: xcrun notarytool log $id --keychain-profile $NOTARY_PROFILE_NAME --keychain $NOTARY_KEYCHAIN_PATH" >&2
    fi
    EXIT_CODE=$status; set -e; exit $status
  fi
  rm -f "$out"
  set -e
  if [[ "$item" == *.app ]] || [[ "$item" == *.pkg ]] || [[ "$item" == *.dmg ]]; then
    xcrun stapler staple "$item"
  fi
  echo "Notarized: $item"
}

echo "Signing artifacts in: $SIGN_PATH"
SIGNED_ITEMS=()
while IFS= read -r -d '' item; do
  [ -z "$item" ] && continue
  sign_item "$item"
  SIGNED_ITEMS+=("$item")
done < <(collect_macos_artifacts "$SIGN_PATH")

if [ ${#SIGNED_ITEMS[@]} -eq 0 ]; then
  echo "No macOS artifacts (.app, .pkg, .dmg, or Mach-O) found under $SIGN_PATH"
  exit 0
fi

if notarization_enabled; then
  NOTARY_PWD_FILE=$(mktemp -t notary_pwd.XXXXXX)
  printf '%s' "$(printf '%s' "$NOTARIZATION_PASSWORD" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')" > "$NOTARY_PWD_FILE"
  chmod 600 "$NOTARY_PWD_FILE"
  unset NOTARIZATION_PASSWORD
  security create-keychain -p "$(cat "$KEYCHAIN_PWD_FILE")" "$NOTARY_KEYCHAIN_NAME"
  security default-keychain -s "$NOTARY_KEYCHAIN_NAME"
  security unlock-keychain -p "$(cat "$KEYCHAIN_PWD_FILE")" "$NOTARY_KEYCHAIN_NAME"
  # notarytool expects keychain path, not name (e.g. .../notary.keychain-db)
  # Suppress success message (avoids leaking keychain path in logs)
  set +e
  xcrun notarytool store-credentials "$NOTARY_PROFILE_NAME" \
    --apple-id "$NOTARIZATION_USERNAME" \
    --team-id "$NOTARIZATION_TEAM_ID" \
    --keychain "$NOTARY_KEYCHAIN_PATH" < "$NOTARY_PWD_FILE" >/dev/null
  _store_status=$?
  if [ $_store_status -ne 0 ]; then
    xcrun notarytool store-credentials "$NOTARY_PROFILE_NAME" \
      --apple-id "$NOTARIZATION_USERNAME" \
      --team-id "$NOTARIZATION_TEAM_ID" \
      --password "$(cat "$NOTARY_PWD_FILE")" \
      --keychain "$NOTARY_KEYCHAIN_PATH" >/dev/null
    _store_status=$?
  fi
  set -e
  if [ $_store_status -ne 0 ]; then
    echo "Error: Failed to store notarytool credentials." >&2
    EXIT_CODE=$_store_status; exit $_store_status
  fi
  echo "Notarizing signed artifacts..."
  for item in "${SIGNED_ITEMS[@]}"; do
    notarize_submit "$item"
  done
  security default-keychain -s "$KEYCHAIN_NAME"
  security delete-keychain "$NOTARY_KEYCHAIN_NAME" 2>/dev/null || true
fi
echo "Done."
