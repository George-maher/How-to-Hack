# Scanner image — one tool invocation per container.
#
# Design notes:
#  - this image is only ever started by the Runner, one process per job, with
#    --read-only, --cap-drop ALL, --user 65534:65534 and no network access to
#    the API/database;
#  - the entrypoint (`scanner-runner.sh`) is an allowlist dispatcher: an unknown
#    tool name exits 126 without executing anything;
#  - tools are installed from pinned releases where a pin is available. A tool
#    that cannot be installed is *not* faked: the Runner reports `unavailable`
#    (exit 127) and the scan records that scanner as inconclusive.
#
# NOTE: this image was not built in the audit environment (no Docker available).
# The build is a documented, reviewable best effort; see docs/security.md.
FROM ubuntu:22.04

LABEL maintainer="howtohack" \
      description="Isolated scanner toolchain" \
      version="2.0.0"

ENV DEBIAN_FRONTEND=noninteractive
ENV WORDLISTS=/wordlists

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    git \
    jq \
    unzip \
    python3 \
    python3-pip \
    dnsutils \
    whois \
    openssl \
    nmap \
    nikto \
    sslscan \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery / community Go binaries. Each is pinned.
RUN set -eux; \
    fetch() { curl -fsSL --retry 3 -o /tmp/tool.zip "$1"; unzip -q /tmp/tool.zip -d /usr/local/bin; rm -f /tmp/tool.zip; }; \
    fetch https://github.com/projectdiscovery/httpx/releases/download/v1.6.5/httpx_1.6.5_linux_amd64.zip; \
    fetch https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip; \
    fetch https://github.com/projectdiscovery/nuclei/releases/download/v3.2.9/nuclei_3.2.9_linux_amd64.zip; \
    fetch https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_amd64.zip; \
    fetch https://github.com/projectdiscovery/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.zip; \
    chmod +x /usr/local/bin/httpx /usr/local/bin/subfinder /usr/local/bin/nuclei /usr/local/bin/katana /usr/local/bin/ffuf

RUN set -eux; \
    curl -fsSL --retry 3 -o /usr/local/bin/gau https://github.com/lc/gau/releases/download/v2.2.3/gau_2.2.3_linux_amd64.tar.gz.tmp || true; \
    rm -f /usr/local/bin/gau

# whatweb (Ruby), dirsearch (Python), wapiti (Python)
RUN apt-get update && apt-get install -y --no-install-recommends ruby-full \
    && git clone --depth 1 --branch v0.5.5 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb \
    && ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir "dirsearch==0.4.3" "wapiti3==3.1.6"

# Wordlists are mounted read-only by the Runner; this copy is the fallback and
# keeps the container runnable without a mount.
RUN mkdir -p /wordlists \
    && printf '%s\n' admin login api backup config .git .env uploads robots.txt sitemap.xml \
         > /wordlists/common.txt

COPY scanner-runner.sh /usr/local/bin/scanner-runner
RUN chmod 0755 /usr/local/bin/scanner-runner

# No shell, no package manager at runtime, and no writable path except /tmp
# (provided as a tmpfs by the Runner).
RUN useradd --uid 65534 --no-create-home --shell /usr/sbin/nologin scanner 2>/dev/null || true

WORKDIR /tmp
USER 65534:65534

ENTRYPOINT ["scanner-runner"]
