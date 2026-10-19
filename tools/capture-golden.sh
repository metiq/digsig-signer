#!/usr/bin/env bash
# Re-captures the golden files in tests/DigSig.Tests/TestData from the ORIGINAL DigSig application.
# The original is not part of this repository; bring your own copy and a Java 8 runtime:
#
#   tools/capture-golden.sh /path/to/digsig-signer-1.3.7.jar /path/to/java8/bin/java
#
# It generates the fictional test certificates, runs the original once per certificate (it reads
# ./application.properties), and records its responses. Port 8443 must be free.
set -euo pipefail

JAR=$(realpath "$1")
JAVA=${2:-java}
REPO=$(cd "$(dirname "$0")/.." && pwd)
DATA="$REPO/tests/DigSig.Tests/TestData"
WORK=$(mktemp -d)
JAVA_PID=
trap '[ -n "$JAVA_PID" ] && kill "$JAVA_PID" 2>/dev/null; rm -rf "$WORK"' EXIT

dotnet run "$REPO/tools/make-test-pki.cs" -- "$WORK"
cp "$WORK/test-leaf.pfx" "$WORK/kibs.pfx" "$DATA/"

start() { # $1 = directory with application.properties
  # Dates in /certificate are rendered in the JVM's zone; the tests expect Skopje time.
  (cd "$1" && exec "$JAVA" -Duser.timezone=Europe/Skopje -jar "$JAR" >"$1/java.log" 2>&1) &
  JAVA_PID=$!
  for _ in $(seq 1 60); do curl -sk -o /dev/null https://localhost:8443/certificate && return 0; sleep 1; done
  echo "the original did not start, see $1/java.log" >&2; exit 1
}
stop() { kill "$JAVA_PID" 2>/dev/null || true; wait "$JAVA_PID" 2>/dev/null || true; sleep 2; }

G="$DATA/golden"; rm -rf "$G"; mkdir -p "$G"
start "$WORK/test-leaf"
curl -sk -D "$G/cert.headers" -o "$G/cert.json" https://localhost:8443/certificate -H "Origin: https://portal.example.mk"
for f in "$DATA"/in/*.xml; do
  n=$(basename "$f" .xml)
  curl -sk -D "$G/$n.headers" -o "$G/$n.signed.xml" -X POST https://localhost:8443/signature \
    -H "Content-Type: application/xml" -H "Origin: https://portal.example.mk" --data-binary @"$f"
done
curl -sk -D "$G/preflight.headers" -o /dev/null -X OPTIONS https://localhost:8443/signature -H "Origin: https://portal.example.mk" \
  -H "Access-Control-Request-Method: POST" -H "Access-Control-Request-Headers: content-type,x-foo"
stop

G="$DATA/golden-kibs"; rm -rf "$G"; mkdir -p "$G"
start "$WORK/kibs"
curl -sk -o "$G/cert.json" https://localhost:8443/certificate
curl -sk -o "$G/01-basic.signed.xml" -X POST https://localhost:8443/signature -H "Content-Type: application/xml" --data-binary @"$DATA/in/01-basic.xml"
stop

echo "Golden files updated in $DATA"
