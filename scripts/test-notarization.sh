#!/bin/bash
set -euo pipefail

# Tests notarization timeout plumbing and prevents stapling rejected DMGs.
# Run on macOS only. Usage: ./scripts/test-notarization.sh

SCRIPT_DIR="${BASH_SOURCE%/*}"
SIGN_MACOS="$SCRIPT_DIR/sign-macos.sh"
TESTS_PASSED=0
TESTS_FAILED=0

run_case() {
	local case_name="$1"
	local timeout="$2"
	local notary_status="$3"
	local expected_exit="$4"
	local test_dir="$5"
	local fake_bin="$test_dir/bin"
	local input_dir="$test_dir/input"
	local log_file="$test_dir/xcrun.log"

	mkdir -p "$fake_bin" "$input_dir" "$test_dir/home/Library/Keychains"
	touch "$input_dir/test.dmg"

	cat > "$fake_bin/security" <<'FAKE_SECURITY'
#!/bin/bash
case "$1" in
default-keychain)
	printf '"%s/original.keychain-db"\n' "$TEST_DIR"
	;;
list-keychains)
	;;
*)
	;;
esac
FAKE_SECURITY

	cat > "$fake_bin/codesign" <<'FAKE_CODESIGN'
#!/bin/bash
exit 0
FAKE_CODESIGN

	cat > "$fake_bin/xcrun" <<'FAKE_XCRUN'
#!/bin/bash
printf '%s\n' "$*" >> "$XCRUN_LOG"
if [ "$1" = "notarytool" ] && [ "$2" = "submit" ]; then
	printf 'Submission ID received\n  id: 11111111-1111-1111-1111-111111111111\n'
	printf 'Processing complete\n  status: %s\n' "$NOTARY_STATUS"
	exit 0
fi
if [ "$1" = "notarytool" ] && [ "$2" = "log" ]; then
	printf '{"status":"%s"}\n' "$NOTARY_STATUS"
	exit 0
fi
if [ "$1" = "stapler" ] && [ "$2" = "staple" ]; then
	touch "$STAPLE_MARKER"
fi
FAKE_XCRUN

	chmod +x "$fake_bin/security" "$fake_bin/codesign" "$fake_bin/xcrun"

	local certificate
	certificate="$(printf '%200s' '' | tr ' ' x | base64 | tr -d '\n')"
	local status
	set +e
	(
		export HOME="$test_dir/home"
		export PATH="$fake_bin:$PATH"
		export TEST_DIR="$test_dir"
		export XCRUN_LOG="$log_file"
		export STAPLE_MARKER="$test_dir/stapled"
		export NOTARY_STATUS="$notary_status"
		export MACOS_SIGNING_IDENTITY="Test Signing (Self-Signed)"
		export MACOS_CERTIFICATE="$certificate"
		export MACOS_CERTIFICATE_PWD=test-password
		export NOTARIZATION_USERNAME=test@example.com
		export NOTARIZATION_PASSWORD=test-app-password
		export NOTARIZATION_TEAM_ID=TEAMID
		export NOTARIZATION_TIMEOUT="$timeout"
		"$SIGN_MACOS" "$input_dir"
	)
	status=$?
	set -e

	if [ "$status" -ne "$expected_exit" ]; then
		echo "  FAIL: $case_name (expected exit $expected_exit, got $status)"
		((TESTS_FAILED++)) || true
		return 1
	fi

	if ! grep -q -- "--timeout $timeout" "$log_file"; then
		echo "  FAIL: $case_name (timeout $timeout was not passed to notarytool)"
		((TESTS_FAILED++)) || true
		return 1
	fi

	if [ "$notary_status" = "Accepted" ] && [ ! -f "$test_dir/stapled" ]; then
		echo "  FAIL: $case_name (accepted DMG was not stapled)"
		((TESTS_FAILED++)) || true
		return 1
	fi

	if [ "$notary_status" != "Accepted" ] && [ -f "$test_dir/stapled" ]; then
		echo "  FAIL: $case_name (rejected DMG was stapled)"
		((TESTS_FAILED++)) || true
		return 1
	fi

	echo "  OK: $case_name"
	((TESTS_PASSED++)) || true
}

if [ "$(uname -s)" != "Darwin" ]; then
	echo "This test must run on macOS."
	exit 1
fi

echo "=== Notarization tests ==="
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

run_case "uses the default timeout and staples accepted DMG" 600 Accepted 0 "$TEST_ROOT/default"
run_case "uses a custom timeout and staples accepted DMG" 60m Accepted 0 "$TEST_ROOT/custom"
run_case "does not staple an invalid DMG" 60m Invalid 1 "$TEST_ROOT/invalid"

echo "=== Results: $TESTS_PASSED passed, $TESTS_FAILED failed ==="
[ "$TESTS_FAILED" -eq 0 ]
