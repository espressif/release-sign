#!/bin/bash
set -e

# Sign and optionally notarize macOS binaries (.app, .pkg, .dmg, Mach-O) using codesign and notarytool.
# Matches Espressif approach: build.keychain, notarytool store-credentials + --keychain-profile.
# Usage: sign-macos.sh <path>
#
# Required env: MACOS_SIGNING_IDENTITY, MACOS_CERTIFICATE, MACOS_CERTIFICATE_PWD
# Optional: MACOS_ENTITLEMENTS, KEYCHAIN_PASSWORD (if unset, a random keychain password is used)
# Optional (notarization): NOTARIZATION_USERNAME, NOTARIZATION_PASSWORD, NOTARIZATION_TEAM_ID
#
# Credentials are written to temporary files (mode 0600) and read at point of use to avoid
# exposing them in process listings where possible. security(1) -p/-P only accept argv;
# notarytool is fed password via stdin when --password is omitted to avoid argv exposure.

SIGN_PATH="$1"
KEYCHAIN_NAME="build.keychain"
# Normalize to canonical env names so the same secrets work as in Espressif/other signtool scripts
if [ -z "${MACOS_CERTIFICATE}" ] && [ -n "${MACOS_CS_CERTIFICATE}" ]; then MACOS_CERTIFICATE="${MACOS_CS_CERTIFICATE}"; fi
if [ -z "${MACOS_CERTIFICATE_PWD}" ] && [ -n "${MACOS_CS_CERTIFICATE_PWD}" ]; then MACOS_CERTIFICATE_PWD="${MACOS_CS_CERTIFICATE_PWD}"; fi
if [ -z "${KEYCHAIN_PASSWORD}" ] && [ -n "${MACOS_CS_KEYCHAIN_PWD}" ]; then KEYCHAIN_PASSWORD="${MACOS_CS_KEYCHAIN_PWD}"; fi
if [ -z "${MACOS_SIGNING_IDENTITY}" ] && [ -n "${MACOS_CS_IDENTITY_ID}" ]; then MACOS_SIGNING_IDENTITY="${MACOS_CS_IDENTITY_ID}"; fi
# Use KEYCHAIN_PASSWORD from env (e.g. from a secret); if unset, use a random password (no hardcoded default)
if [ -z "${KEYCHAIN_PASSWORD}" ]; then
  KEYCHAIN_PASSWORD=$(openssl rand -hex 32)
fi
NOTARY_KEYCHAIN_NAME="notary.keychain"
NOTARY_PROFILE_NAME="release-sign-notarytool-profile"

# Temporary files for passwords and certificate (0600); wiped and removed on exit to minimize exposure.
KEYCHAIN_PWD_FILE=""
CERT_PWD_FILE=""
NOTARY_PWD_FILE=""
CERT_FILE=""

wipe_and_remove() {
  for f in "$@"; do
    [ -z "$f" ] && continue
    [ -f "$f" ] || continue
    sz=$(wc -c < "$f" 2>/dev/null) && [ -n "$sz" ] && [ "$sz" -gt 0 ] && dd if=/dev/zero of="$f" bs=1 count="$sz" 2>/dev/null || true
    rm -f "$f"
  done
}
trap 'wipe_and_remove "$KEYCHAIN_PWD_FILE" "$CERT_PWD_FILE" "$NOTARY_PWD_FILE" "$CERT_FILE"' EXIT

if [ -z "$SIGN_PATH" ]; then
  echo "Error: Path argument required"
  exit 1
fi

if [ ! -e "$SIGN_PATH" ]; then
  echo "Error: Path not found: $SIGN_PATH"
  exit 1
fi

# Required for signing (exit 1 so callers get a consistent non-zero status)
if [ -z "${MACOS_SIGNING_IDENTITY}" ]; then echo "Error: MACOS_SIGNING_IDENTITY (or MACOS_CS_IDENTITY_ID) environment variable required" >&2; exit 1; fi
if [ -z "${MACOS_CERTIFICATE}" ] && { [ -z "${MACOS_CERTIFICATE_FILE}" ] || [ ! -r "${MACOS_CERTIFICATE_FILE}" ]; }; then
  echo "Error: MACOS_CERTIFICATE (or MACOS_CS_CERTIFICATE) or readable MACOS_CERTIFICATE_FILE required" >&2; exit 1
fi
if [ -z "${MACOS_CERTIFICATE_PWD}" ]; then echo "Error: MACOS_CERTIFICATE_PWD (or MACOS_CS_CERTIFICATE_PWD) environment variable required" >&2; exit 1; fi

# True when all notarization credentials are set; used to gate the optional notarization block below.
notarization_enabled() {
  [ -n "${NOTARIZATION_USERNAME}" ] && [ -n "${NOTARIZATION_TEAM_ID}" ] && [ -n "${NOTARIZATION_PASSWORD}" ]
}
if notarization_enabled; then
  echo "Notarization enabled (NOTARIZATION_* credentials provided)"
fi

# Write passwords to temp files (0600) so we don't pass them on the command line longer than necessary.
KEYCHAIN_PWD_FILE=$(mktemp -t keychain_pwd.XXXXXX)
CERT_PWD_FILE=$(mktemp -t cert_pwd.XXXXXX)
printf '%s' "$KEYCHAIN_PASSWORD" > "$KEYCHAIN_PWD_FILE"
printf '%s' "$MACOS_CERTIFICATE_PWD" > "$CERT_PWD_FILE"
chmod 600 "$KEYCHAIN_PWD_FILE" "$CERT_PWD_FILE"
unset MACOS_CERTIFICATE_PWD KEYCHAIN_PASSWORD
# NOTARIZATION_PASSWORD written to temp file only when setting up notary below

# Reuse or create build keychain (do not delete on exit; other steps may rely on it)
# Note: security(1) has no option to read -p/-P from file or stdin; password may appear in argv (macOS often masks in ps).
echo "Setting up keychain and importing certificate..."
security list-keychains | grep -q "$KEYCHAIN_NAME" || security create-keychain -p "$(cat "$KEYCHAIN_PWD_FILE")" "$KEYCHAIN_NAME"
security default-keychain -s "$KEYCHAIN_NAME"
security unlock-keychain -p "$(cat "$KEYCHAIN_PWD_FILE")" "$KEYCHAIN_NAME"

# Write .p12 to a restrictive temp file (prefer RUNNER_TEMP on GitHub Actions) so it is never world-readable.
_cert_tmpdir="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
CERT_FILE=$(TMPDIR="$_cert_tmpdir" mktemp -t cert.XXXXXX)
# Prefer certificate from file (avoids GitHub Actions env truncation of multi-line base64); otherwise use env.
if [ -n "${MACOS_CERTIFICATE_FILE}" ] && [ -r "${MACOS_CERTIFICATE_FILE}" ]; then
  _cert_raw=$(cat "$MACOS_CERTIFICATE_FILE")
else
  _cert_raw=$(printf '%s' "$MACOS_CERTIFICATE")
fi
unset MACOS_CERTIFICATE
_cert_trimmed=$(printf '%s' "$_cert_raw" | tr -d '\n\r \t')
_cert_trimmed="${_cert_trimmed#$'\xef\xbb\xbf'}"
# Keep only base64 alphabet so multi-line or spaced pastes work without user steps.
CERT_DATA=$(printf '%s' "$_cert_trimmed" | sed 's/[^A-Za-z0-9+/=]//g')
_decode_to_file() {
  local data="$1" out="$2"
  printf '%s' "$data" | base64 -D > "$out" 2>/dev/null && [ -s "$out" ] && return 0
  printf '%s' "$data" | base64 --decode > "$out" 2>/dev/null && [ -s "$out" ] && return 0
  return 1
}
# PKCS#12 (.p12) is ASN.1 DER; it starts with SEQUENCE (0x30) then length. Accept any 0x30-starting blob with reasonable size.
_is_pkcs12() {
  local f="$1"
  [ -s "$f" ] || return 1
  [ "$(wc -c < "$f" 2>/dev/null)" -ge 12 ] || return 1
  local first_hex; first_hex=$(head -c 1 "$f" 2>/dev/null | xxd -p 2>/dev/null | tr -d '\n')
  [ "$first_hex" = "30" ] && return 0
  return 1
}
if _decode_to_file "$CERT_DATA" "$CERT_FILE"; then
  if ! _is_pkcs12 "$CERT_FILE"; then
    # Decoded content is not .p12; try double base64 (secret was base64(base64(.p12)))
    _double="$CERT_FILE.double"
    if cat "$CERT_FILE" | base64 -D > "$_double" 2>/dev/null && [ -s "$_double" ] && _is_pkcs12 "$_double"; then
      mv "$_double" "$CERT_FILE"
    elif cat "$CERT_FILE" | base64 --decode > "$_double" 2>/dev/null && [ -s "$_double" ] && _is_pkcs12 "$_double"; then
      mv "$_double" "$CERT_FILE"
    else
      rm -f "$_double"
    fi
  fi
else
  printf '%s' "$_cert_raw" > "$CERT_FILE"
fi
if [ ! -s "$CERT_FILE" ]; then
  echo "Error: MACOS_CERTIFICATE produced an empty file. Use base64-encoded .p12 contents." >&2
  rm -f "$CERT_FILE"
  exit 1
fi
if ! _is_pkcs12 "$CERT_FILE"; then
  echo "Error: MACOS_CERTIFICATE is not valid .p12 (PKCS#12). Use the base64-encoded contents of your .p12 file." >&2
  rm -f "$CERT_FILE"
  exit 1
fi
chmod 600 "$CERT_FILE"
if ! security import "$CERT_FILE" -k "$KEYCHAIN_NAME" -P "$(cat "$CERT_PWD_FILE")" -T /usr/bin/codesign -T /usr/bin/security 2>&1; then
  echo "Error: Certificate import failed. Check that MACOS_CERTIFICATE_PWD matches the .p12 password." >&2
  rm -f "$CERT_FILE"
  exit 1
fi
rm -f "$CERT_FILE"

security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$(cat "$KEYCHAIN_PWD_FILE")" "$KEYCHAIN_NAME" 2>/dev/null || true

sign_item() {
  local item="$1"
  echo "Signing: $item"
  local args=(--force --sign "$MACOS_SIGNING_IDENTITY" --timestamp --options runtime)

  if [ -n "$MACOS_ENTITLEMENTS" ]; then
    if [ -f "$MACOS_ENTITLEMENTS" ]; then
      args+=(--entitlements "$MACOS_ENTITLEMENTS")
    else
      echo "Error: MACOS_ENTITLEMENTS is set to '$MACOS_ENTITLEMENTS' but the file does not exist." >&2
      exit 1
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
    exit 1
  fi
  echo "Successfully signed: $item"
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
    # Mach-O binaries not inside a .app (avoid double-signing)
    while IFS= read -r -d '' f; do
      if is_macho "$f" && [[ "$f" != *.app/* ]]; then
        printf '%s\0' "$f"
      fi
    done < <(find "$path" -type f -print0 2>/dev/null)
  elif [ -f "$path" ]; then
    if [[ "$path" == *.pkg ]] || [[ "$path" == *.dmg ]]; then
      printf '%s\0' "$path"
    elif is_macho "$path"; then
      printf '%s\0' "$path"
    fi
  fi
}

notarize_submit() {
  local item="$1"
  local to_submit="$item"
  local zip_file=""
  if [[ "$item" == *.app ]] || [[ "$item" == *.pkg ]] || [[ "$item" == *.dmg ]]; then
    to_submit="$item"
  else
    local item_dir
    local zip_name
    item_dir="$(dirname "$item")"
    zip_name="$(basename "$item").zip"
    (cd "$item_dir" && zip -r "$zip_name" "$(basename "$item")")
    zip_file="$item_dir/$zip_name"
    to_submit="$zip_file"
  fi
  echo "Notarizing: $to_submit"
  set +e
  xcrun notarytool submit "$to_submit" --keychain-profile "$NOTARY_PROFILE_NAME" --wait
  local notary_status=$?
  [ -n "$zip_file" ] && [ -f "$zip_file" ] && rm -f "$zip_file"
  set -e
  if [ $notary_status -ne 0 ]; then
    echo "Notarization failed for $to_submit"
    exit $notary_status
  fi
  if [[ "$item" == *.app ]] || [[ "$item" == *.pkg ]] || [[ "$item" == *.dmg ]]; then
    echo "Stapling: $item"
    xcrun stapler staple "$item"
  fi
  echo "Successfully notarized: $item"
}

echo "=== Signing macOS artifacts in: $SIGN_PATH ==="

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
  echo "=== Setting up notary credentials ==="
  NOTARY_PWD_FILE=$(mktemp -t notary_pwd.XXXXXX)
  printf '%s' "$NOTARIZATION_PASSWORD" > "$NOTARY_PWD_FILE"
  chmod 600 "$NOTARY_PWD_FILE"
  unset NOTARIZATION_PASSWORD
  security create-keychain -p "$(cat "$KEYCHAIN_PWD_FILE")" "$NOTARY_KEYCHAIN_NAME"
  security default-keychain -s "$NOTARY_KEYCHAIN_NAME"
  security unlock-keychain -p "$(cat "$KEYCHAIN_PWD_FILE")" "$NOTARY_KEYCHAIN_NAME"
  set +e
  # Prefer stdin so password is not in process argv; fallback to --password if stdin is not read (e.g. TTY-only prompt)
  xcrun notarytool store-credentials "$NOTARY_PROFILE_NAME" \
    --apple-id "$NOTARIZATION_USERNAME" \
    --team-id "$NOTARIZATION_TEAM_ID" \
    --keychain "$NOTARY_KEYCHAIN_NAME" < "$NOTARY_PWD_FILE"
  store_credentials_status=$?
  if [ $store_credentials_status -ne 0 ]; then
    xcrun notarytool store-credentials "$NOTARY_PROFILE_NAME" \
      --apple-id "$NOTARIZATION_USERNAME" \
      --team-id "$NOTARIZATION_TEAM_ID" \
      --password "$(cat "$NOTARY_PWD_FILE")" \
      --keychain "$NOTARY_KEYCHAIN_NAME"
    store_credentials_status=$?
  fi
  set -e
  if [ $store_credentials_status -ne 0 ]; then
    echo "Error: Failed to store notarytool credentials in keychain '$NOTARY_KEYCHAIN_NAME'."
    exit $store_credentials_status
  fi
  echo "=== Notarizing signed artifacts ==="
  for item in "${SIGNED_ITEMS[@]}"; do
    notarize_submit "$item"
  done
  # Clean up the temporary notary keychain; it was only needed for storing credentials and notarytool submit.
  security default-keychain -s "$KEYCHAIN_NAME"
  security delete-keychain "$NOTARY_KEYCHAIN_NAME" 2>/dev/null || true
else
  echo "Skipping notarization (NOTARIZATION_USERNAME, NOTARIZATION_TEAM_ID, NOTARIZATION_PASSWORD not all set)."
fi

echo "=== macOS signing complete ==="
