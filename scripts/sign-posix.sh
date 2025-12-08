#!/bin/bash
set -e

# Sign Windows files using Azure Key Vault and Jsign
# Usage: sign-linux.sh <path>

SIGN_PATH="$1"

if [ -z "$SIGN_PATH" ]; then
  echo "Error: Path argument required"
  exit 1
fi

if [ ! -e "$SIGN_PATH" ]; then
  echo "Error: Path not found: $SIGN_PATH"
  exit 1
fi

# Required environment variables
: "${JSIGN_JAR:?JSIGN_JAR environment variable required}"
: "${AZURE_TOKEN:?AZURE_TOKEN environment variable required}"
: "${KEYVAULT_URI:?KEYVAULT_URI environment variable required}"
: "${CERT_NAME:?CERT_NAME environment variable required}"
: "${DIGEST_ALG:=SHA-256}"

# Optional
CERTCHAIN_ARG=""
if [ -n "$CERT_CHAIN" ]; then
  CERTCHAIN_FILE="${GITHUB_WORKSPACE:-/tmp}/certchain.p7b"
  echo "$CERT_CHAIN" > "$CERTCHAIN_FILE"
  CERTCHAIN_ARG="-certchain $CERTCHAIN_FILE"
  echo "Using certificate chain file"
fi

# Sign a Windows file with Jsign
sign_windows_file() {
  local file="$1"
  echo "Signing: $file"
  java -jar "$JSIGN_JAR" \
    --storetype AZUREKEYVAULT \
    --keystore "$KEYVAULT_URI" \
    --storepass "$AZURE_TOKEN" \
    --alias "$CERT_NAME" \
    --alg "$DIGEST_ALG" \
    --tsaurl http://timestamp.digicert.com \
    --tsretries 3 \
    --tsretrywait 10 \
    "$file"
  echo "Successfully signed: $file"
}

# Sign a JAR file with jarsigner
sign_jar_file() {
  local file="$1"
  echo "Signing JAR: $file"
  jarsigner \
    -J-cp -J"$JSIGN_JAR" \
    -J--add-modules -Jjava.sql \
    -providerClass net.jsign.jca.JsignJcaProvider \
    -providerArg "$KEYVAULT_URI" \
    -keystore NONE \
    -storetype AZUREKEYVAULT \
    -storepass "$AZURE_TOKEN" \
    -tsa http://timestamp.digicert.com \
    $CERTCHAIN_ARG \
    "$file" \
    "$CERT_NAME"
  echo "Successfully signed: $file"
}

# Verify a signed file
verify_file() {
  local file="$1"
  echo "Verifying: $file"
  if [[ "$file" == *.jar ]]; then
    jarsigner -verify -verbose "$file" || true
  else
    java -jar "$JSIGN_JAR" extract "$file" || true
  fi
}

echo "=== Signing files in: $SIGN_PATH ==="

# Sign Windows files
if [ -d "$SIGN_PATH" ]; then
  while IFS= read -r -d '' file; do
    sign_windows_file "$file"
  done < <(find "$SIGN_PATH" -type f \( -name "*.exe" -o -name "*.dll" -o -name "*.cat" -o -name "*.sys" -o -name "*.msi" -o -name "*.ps1" \) -print0)
elif [ -f "$SIGN_PATH" ] && [[ ! "$SIGN_PATH" == *.jar ]]; then
  sign_windows_file "$SIGN_PATH"
fi

# Sign JAR files
if [ -d "$SIGN_PATH" ]; then
  while IFS= read -r -d '' file; do
    sign_jar_file "$file"
  done < <(find "$SIGN_PATH" -type f -name "*.jar" -print0)
elif [ -f "$SIGN_PATH" ] && [[ "$SIGN_PATH" == *.jar ]]; then
  sign_jar_file "$SIGN_PATH"
fi

echo "=== Verifying signatures ==="

# Verify all signed files
if [ -d "$SIGN_PATH" ]; then
  while IFS= read -r -d '' file; do
    verify_file "$file"
  done < <(find "$SIGN_PATH" -type f \( -name "*.exe" -o -name "*.dll" -o -name "*.cat" -o -name "*.sys" -o -name "*.msi" -o -name "*.ps1" -o -name "*.jar" \) -print0)
elif [ -f "$SIGN_PATH" ]; then
  verify_file "$SIGN_PATH"
fi

echo "=== Signing complete ==="

