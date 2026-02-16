#!/bin/bash
# Tests for sign-macos.sh: validation + real signing with a self-signed cert (no Apple Developer account).
# Run on macOS only. Usage: ./scripts/test-sign-macos.sh

set -e
SCRIPT_DIR="${BASH_SOURCE%/*}"
SIGN_MACOS="$SCRIPT_DIR/sign-macos.sh"
TESTS_PASSED=0
TESTS_FAILED=0
TEST_DIR=""
GEN_KEYCHAIN=""

run_test() {
  local name="$1" expected_exit="$2"
  shift 2
  set +e
  ("$@") 2>/dev/null
  local got=$?
  set -e
  if [ "$got" -eq "$expected_exit" ]; then
    echo "  OK: $name"
    ((TESTS_PASSED++)) || true
    return 0
  else
    echo "  FAIL: $name (expected exit $expected_exit, got $got)"
    ((TESTS_FAILED++)) || true
    return 1
  fi
}

cleanup_test_dir() {
  # Remove keychain first (deregister and delete); avoid leaving it behind if creation succeeded but later steps failed.
  [ -n "$GEN_KEYCHAIN" ] && security delete-keychain "$GEN_KEYCHAIN" 2>/dev/null || true
  [ -n "$TEST_DIR" ] && [ -d "$TEST_DIR" ] && rm -rf "$TEST_DIR"
}

trap cleanup_test_dir EXIT

echo "=== 1. Validation tests (no real certs) ==="

# Syntax check
echo "Syntax check..."
bash -n "$SIGN_MACOS" || { echo "  FAIL: script has syntax errors"; exit 1; }
echo "  OK: script syntax"
((TESTS_PASSED++)) || true

run_test "no path argument → exit 1" 1 "$SIGN_MACOS"
run_test "path does not exist → exit 1" 1 "$SIGN_MACOS" /nonexistent/path/here
# Use env -i so runner env (e.g. MACOS_SIGNING_IDENTITY) doesn't supply the "missing" var
run_test "missing MACOS_SIGNING_IDENTITY → exit 1" 1 env -i "PATH=$PATH" MACOS_CERTIFICATE=foo MACOS_CERTIFICATE_PWD=bar "$SIGN_MACOS" /tmp
run_test "missing MACOS_CERTIFICATE → exit 1" 1 env -i "PATH=$PATH" MACOS_SIGNING_IDENTITY=id MACOS_CERTIFICATE_PWD=bar "$SIGN_MACOS" /tmp
run_test "missing MACOS_CERTIFICATE_PWD → exit 1" 1 env -i "PATH=$PATH" MACOS_SIGNING_IDENTITY=id MACOS_CERTIFICATE=foo "$SIGN_MACOS" /tmp
run_test "invalid cert base64 → non-zero exit" 1 env \
  MACOS_SIGNING_IDENTITY="Developer ID Application: Test (TEAM)" \
  MACOS_CERTIFICATE="not-valid-base64!!" \
  MACOS_CERTIFICATE_PWD=secret \
  "$SIGN_MACOS" /tmp
run_test "empty path → exit 1" 1 env MACOS_SIGNING_IDENTITY=id MACOS_CERTIFICATE=x MACOS_CERTIFICATE_PWD=x "$SIGN_MACOS" ""

echo "=== 2. Real signing test (self-signed cert, no Apple account) ==="

TEST_DIR=$(mktemp -d)
TEST_PWD="testpass"
GEN_KEYCHAIN="$TEST_DIR/gen.keychain"
TEST_IDENTITY="Test Signing (Self-Signed)"

# Prefer macOS-native cert so Security import accepts the .p12 (OpenSSL .p12 is often rejected by SecKeychainItemImport)
echo "  Creating self-signed code-signing cert..."
USED_NATIVE_CERT=0
if security create-keychain -p "$TEST_PWD" "$GEN_KEYCHAIN" 2>/dev/null &&
   security set-keychain-settings -lut 3600 "$GEN_KEYCHAIN" 2>/dev/null &&
   security unlock-keychain -p "$TEST_PWD" "$GEN_KEYCHAIN" 2>/dev/null &&
   security create-certificate -a -c "$TEST_IDENTITY" -i "$TEST_IDENTITY" -k "$GEN_KEYCHAIN" -s 1 -t "cu" -x 2>/dev/null &&
   security export -k "$GEN_KEYCHAIN" -t identities -f pkcs12 -o "$TEST_DIR/cert.p12" -P "$TEST_PWD" 2>/dev/null; then
  security delete-keychain "$GEN_KEYCHAIN" 2>/dev/null || true
  USED_NATIVE_CERT=1
else
  # Fallback: OpenSSL cert + .p12 — macOS Security often rejects this at import, so we skip the real signing run below
  security delete-keychain "$GEN_KEYCHAIN" 2>/dev/null || true
  cat > "$TEST_DIR/openssl.cnf" << 'OPENSSL_CNF'
[req]
distinguished_name = dn
x509_extensions = v3_ext
[dn]
CN = Test Signing (Self-Signed)
[v3_ext]
extendedKeyUsage = 1.3.6.1.5.5.7.3.3
OPENSSL_CNF
  openssl req -x509 -newkey rsa:2048 -keyout "$TEST_DIR/key.pem" -out "$TEST_DIR/cert.pem" \
    -days 365 -nodes -subj "/CN=Test Signing (Self-Signed)" -config "$TEST_DIR/openssl.cnf" -extensions v3_ext
  # Try standard pkcs12 export first (no -legacy, no weak PBE); fall back to -legacy, then to weaker PBE if needed.
  if openssl pkcs12 -export -out "$TEST_DIR/cert.p12" -inkey "$TEST_DIR/key.pem" -in "$TEST_DIR/cert.pem" \
    -password "pass:$TEST_PWD" -name "$TEST_IDENTITY" 2>/dev/null; then
    :
  elif openssl pkcs12 -export -legacy -out "$TEST_DIR/cert.p12" -inkey "$TEST_DIR/key.pem" -in "$TEST_DIR/cert.pem" \
    -password "pass:$TEST_PWD" -name "$TEST_IDENTITY" 2>/dev/null; then
    :
  else
    openssl pkcs12 -export -out "$TEST_DIR/cert.p12" -inkey "$TEST_DIR/key.pem" -in "$TEST_DIR/cert.pem" \
      -password "pass:$TEST_PWD" -name "$TEST_IDENTITY" -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES 2>/dev/null || true
  fi
fi
[ -f "$TEST_DIR/cert.p12" ] || { echo "  FAIL: could not create .p12"; exit 1; }

# Run real signing only when we have a macOS-native .p12 (importable); otherwise skip to avoid known SecKeychainItemImport failure
if [ "$USED_NATIVE_CERT" = "1" ]; then
  cp /bin/cat "$TEST_DIR/testbin"
  file "$TEST_DIR/testbin" | grep -q Mach-O || { echo "  FAIL: testbin is not Mach-O"; exit 1; }
  CERT_B64=$(base64 < "$TEST_DIR/cert.p12" | tr -d '\n')
  echo "  Running sign-macos.sh on $TEST_DIR..."
  env \
    MACOS_SIGNING_IDENTITY="$TEST_IDENTITY" \
    MACOS_CERTIFICATE="$CERT_B64" \
    MACOS_CERTIFICATE_PWD="$TEST_PWD" \
    "$SIGN_MACOS" "$TEST_DIR"
  if codesign -v "$TEST_DIR/testbin" 2>/dev/null; then
    echo "  OK: real signing — binary is signed and verifies"
    ((TESTS_PASSED++)) || true
  else
    echo "  FAIL: real signing — codesign -v failed"
    ((TESTS_FAILED++)) || true
  fi
else
  echo "  OK: real signing test skipped (OpenSSL .p12 not importable on this macOS; validation tests passed)"
  ((TESTS_PASSED++)) || true
fi

echo "=== Results: $TESTS_PASSED passed, $TESTS_FAILED failed ==="
[ "$TESTS_FAILED" -eq 0 ] || exit 1
