#!/bin/bash
set -e

TOOL_NAME="$1"
shift || true

case "${TOOL_NAME}" in
    nmap)
        nmap $@ -oX /dev/stdout 2>/dev/null | python3 -c "
import sys, xml.etree.ElementTree as ET
import json
tree = ET.parse(sys.stdin)
root = tree.getroot()
results = []
for host in root.findall('.//host'):
    ip = host.find('.//address').get('addr', '') if host.find('.//address') is not None else ''
    ports = []
    for port in host.findall('.//port'):
        state = port.find('state').get('state', '') if port.find('state') is not None else ''
        if state == 'open':
            ports.append({
                'port': int(port.get('portid', 0)),
                'protocol': port.get('protocol', ''),
                'service': port.find('service').get('name', '') if port.find('service') is not None else ''
            })
    if ports:
        results.extend(ports)
        if ip:
            results.append({'ip': ip, 'ports': ports})
print(json.dumps(results))
"
        ;;
    httpx)
        httpx $@ -json 2>/dev/null
        ;;
    whatweb)
        whatweb $@ --log-json=/dev/stdout 2>/dev/null
        ;;
    dnsrecon)
        python3 -c "
import dns.resolver, json, sys
target = '$1'
results = {'records': {}, 'target': target}
for qtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']:
    try:
        answers = dns.resolver.resolve(target, qtype)
        results['records'][qtype] = [str(r) for r in answers]
    except:
        pass
print(json.dumps(results))
" 2>/dev/null
        ;;
    subfinder)
        subfinder -d "$1" -silent -json 2>/dev/null
        ;;
    amass)
        amass enum -d "$1" -json /dev/stdout 2>/dev/null || echo '[]'
        ;;
    theharvester)
        theHarvester -d "$1" -b all -f /dev/stdout 2>/dev/null || echo '{"hosts":[]}'
        ;;
    dirsearch)
        dirsearch -u "$1" --format=json -o /tmp/ds.json 2>/dev/null && cat /tmp/ds.json 2>/dev/null || echo '[]'
        ;;
    ffuf)
        ffuf -u "$1/FUZZ" -w /wordlists/common.txt -json -o /dev/stdout 2>/dev/null || echo '[]'
        ;;
    katana)
        katana -u "$1" -silent -json 2>/dev/null || echo '[]'
        ;;
    hakrawler)
        echo "$1" | hakrawler -json 2>/dev/null | head -200 || echo '[]'
        ;;
    gau)
        gau "$1" --json 2>/dev/null || echo '[]'
        ;;
    waybackurls)
        waybackpy -u "$1" -known 2>/dev/null || echo '[]'
        ;;
    nuclei)
        nuclei -u "$1" -json -silent 2>/dev/null || echo '[]'
        ;;
    nikto)
        nikto -h "$1" -Format json 2>/dev/null || echo '{"vulnerabilities":[]}'
        ;;
    wapiti)
        wapiti -u "$1" --json-output /dev/stdout 2>/dev/null || echo '[]'
        ;;
    sslscan)
        sslscan --no-color --json=/dev/stdout "$1" 2>/dev/null || echo '[]'
        ;;
    testssl)
        testssl --jsonfile /dev/stdout "$1" 2>/dev/null || echo '[]'
        ;;
    *)
        echo "{\"error\": \"Unknown tool: ${TOOL_NAME}\"}"
        exit 1
        ;;
esac
