#!/bin/bash
#
# Scanner container entrypoint.
#
# Contract with the Runner:
#   argv  : <tool> <validated args...>
#   stdout: JSON (array or NDJSON) — the API parses this
#   stderr: diagnostics, never mixed into stdout
#   exit  : the tool's own status; 127 when the tool is not installed
#
# Rules:
#  - every user-controlled value arrives through "$@" and is always quoted, so
#    nothing can be word-split or re-interpreted as shell syntax;
#  - stderr is preserved (it is the only place a failure explains itself);
#  - a missing tool exits 127 so the Runner reports `unavailable` instead of an
#    empty result;
#  - no output file is written outside /tmp (the container is read-only).
set -uo pipefail

TOOL_NAME="${1:-}"
shift || true

if [ -z "${TOOL_NAME}" ]; then
    echo "usage: scanner-runner <tool> [args...]" >&2
    exit 64
fi

if ! command -v "${TOOL_NAME}" >/dev/null 2>&1; then
    echo "scanner-runner: tool not installed: ${TOOL_NAME}" >&2
    exit 127
fi

# Emit a JSON array from a JSON/NDJSON stdout stream, preserving records.
normalise_json() {
    python3 - <<'PY'
import json
import sys

raw = sys.stdin.read().strip()
if not raw:
    print("[]")
    sys.exit(0)

try:
    parsed = json.loads(raw)
    print(json.dumps(parsed if isinstance(parsed, list) else [parsed]))
    sys.exit(0)
except json.JSONDecodeError:
    pass

records = []
for line in raw.splitlines():
    line = line.strip()
    if not line or line[0] not in "{[":
        continue
    try:
        records.append(json.loads(line))
    except json.JSONDecodeError:
        continue

print(json.dumps(records))
PY
}

case "${TOOL_NAME}" in
    nmap)
        nmap "$@" -oX - 2>&1 >/tmp/nmap.xml | cat >&2
        python3 - <<'PY'
import json
import xml.etree.ElementTree as ET

try:
    root = ET.parse('/tmp/nmap.xml').getroot()
except Exception as exc:  # noqa: BLE001 - reported to stderr
    raise SystemExit(f"nmap output was not valid XML: {exc}")

results = []
for host in root.findall('.//host'):
    address = host.find('.//address')
    ip = address.get('addr', '') if address is not None else ''
    for port in host.findall('.//port'):
        state = port.find('state')
        if state is None or state.get('state') != 'open':
            continue
        service = port.find('service')
        results.append({
            'ip': ip,
            'port': int(port.get('portid', 0)),
            'protocol': port.get('protocol', ''),
            'service': service.get('name', '') if service is not None else '',
            'product': service.get('product', '') if service is not None else '',
            'version': service.get('version', '') if service is not None else '',
        })

print(json.dumps(results))
PY
        ;;

    httpx)
        httpx "$@" -json | normalise_json
        ;;

    whatweb)
        whatweb "$@" --log-json=/tmp/whatweb.json >/dev/null
        python3 - <<'PY'
import json

try:
    with open('/tmp/whatweb.json') as handle:
        payload = json.load(handle)
except Exception:
    payload = []

print(json.dumps(payload))
PY
        ;;

    dnsrecon)
        dnsrecon "$@" -j /tmp/dnsrecon.json >/dev/null
        python3 - <<'PY'
import json

try:
    with open('/tmp/dnsrecon.json') as handle:
        payload = json.load(handle)
except Exception:
    payload = []

print(json.dumps(payload))
PY
        ;;

    subfinder | amass | theharvester | gau | katana | nuclei)
        "${TOOL_NAME}" "$@" | normalise_json
        ;;

    waybackurls)
        "${TOOL_NAME}" "$@" | python3 -c '
import json, sys
print(json.dumps([line.strip() for line in sys.stdin if line.strip()]))
'
        ;;

    hakrawler)
        "${TOOL_NAME}" "$@" | normalise_json
        ;;

    dirsearch)
        # Writes its JSON report to a file; /tmp is the only writable path.
        dirsearch "$@" >/dev/null
        cat /tmp/dirsearch.json 2>/dev/null || echo '[]'
        ;;

    ffuf)
        ffuf "$@" >/dev/null
        cat /tmp/ffuf.json 2>/dev/null || echo '[]'
        ;;

    wapiti)
        wapiti "$@" >/dev/null
        cat /tmp/wapiti.json 2>/dev/null || echo '[]'
        ;;

    nikto)
        nikto "$@" 2>/dev/null | python3 -c '
import json, sys
raw = sys.stdin.read().strip()
try:
    print(json.dumps(json.loads(raw)))
except json.JSONDecodeError:
    # Nikto can prefix a banner before the JSON body.
    start = raw.find("{")
    try:
        print(json.dumps(json.loads(raw[start:]) if start >= 0 else []))
    except json.JSONDecodeError:
        print("[]")
'
        ;;

    sslscan | testssl)
        "${TOOL_NAME}" "$@" | normalise_json
        ;;

    *)
        # Never execute an unknown tool, even if it happens to exist in PATH.
        echo "scanner-runner: tool is not supported by this image: ${TOOL_NAME}" >&2
        exit 126
        ;;
esac
