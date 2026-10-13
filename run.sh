#!/bin/sh
# Build bitwig-license, run its tests, and demonstrate the format end to end.
#
# The demo writes a file in the real framing with a freshly generated key, so it
# needs no Bitwig license. verify rejects that file, which is the correct result
# and is shown rather than hidden: the signature is Ed25519 against a key the
# client does not hold.
set -eu

cd "$(dirname "$0")"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

echo "== build =="
go build ./...
echo "build ok"

echo
echo "== vet =="
go vet ./...
echo "vet ok"

echo
echo "== gofmt =="
unformatted="$(gofmt -l internal cmd)"
if [ -n "$unformatted" ]; then
    echo "these files are not gofmt-clean:" >&2
    echo "$unformatted" >&2
    exit 1
fi
echo "gofmt clean"

echo
echo "== tests =="
go test ./...
echo

echo "== demo: the public material recovered from the client =="
go build -o "$WORK/bitwig-license" ./cmd/bitwig-license
"$WORK/bitwig-license" keys

echo
echo "== demo: a file in the real framing =="
"$WORK/bitwig-license" synth -o "$WORK/sample.activation"

echo
echo "-- explain --"
"$WORK/bitwig-license" explain "$WORK/sample.activation"

echo
echo "-- verify --"
# synth signs with its own key, so this must fail. A success here would mean the
# verifier ignores which key signed the file, which would be a real bug.
if "$WORK/bitwig-license" verify "$WORK/sample.activation"; then
    echo "FAIL: verify accepted a file signed by a key that is not Bitwig's" >&2
    exit 1
else
    echo "verify rejected the foreign signature, as it should"
fi

echo
echo "all checks passed"
