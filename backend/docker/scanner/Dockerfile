FROM ubuntu:22.04

LABEL maintainer="howtohack" \
      description="Multi-tool security scanner image" \
      version="1.0.0"

ENV DEBIAN_FRONTEND=noninteractive
ENV TOOLS_HOME=/tools
ENV PATH="${TOOLS_HOME}/bin:${PATH}"

RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    jq \
    python3 \
    python3-pip \
    dnsutils \
    whois \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR ${TOOLS_HOME}

RUN wget https://github.com/nmap/nmap/archive/refs/tags/nmap-7.94.tar.gz && \
    tar xzf nmap-7.94.tar.gz && \
    cd nmap-nmap-7.94 && \
    ./configure --without-zenmap && \
    make -j$(nproc) && \
    make install && \
    cd / && rm -rf ${TOOLS_HOME}/nmap-nmap-7.94 nmap-7.94.tar.gz

RUN wget https://github.com/projectdiscovery/httpx/releases/download/v1.3.8/httpx_1.3.8_linux_amd64.zip && \
    unzip httpx_1.3.8_linux_amd64.zip && \
    mv httpx /usr/local/bin/ && \
    rm httpx_1.3.8_linux_amd64.zip

RUN wget https://github.com/urbanadventurer/WhatWeb/archive/refs/tags/v0.5.5.tar.gz && \
    tar xzf v0.5.5.tar.gz && \
    ln -s ${TOOLS_HOME}/WhatWeb-0.5.5/whatweb /usr/local/bin/whatweb && \
    rm v0.5.5.tar.gz

RUN pip3 install dnsrecon theHarvester

RUN wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip && \
    unzip subfinder_2.6.6_linux_amd64.zip && \
    mv subfinder /usr/local/bin/ && \
    rm subfinder_2.6.6_linux_amd64.zip

RUN wget https://github.com/OWASP/Amass/releases/download/v4.2.0/amass_linux_amd64.zip && \
    unzip amass_linux_amd64.zip && \
    mv amass_linux_amd64/amass /usr/local/bin/ && \
    rm -rf amass_linux_amd64 amass_linux_amd64.zip

RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.2.9/nuclei_3.2.9_linux_amd64.zip && \
    unzip nuclei_3.2.9_linux_amd64.zip && \
    mv nuclei /usr/local/bin/ && \
    rm nuclei_3.2.9_linux_amd64.zip && \
    nuclei -update-templates

RUN apt-get update && apt-get install -y \
    nikto \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install wapiti3

RUN wget https://github.com/rbsec/sslscan/releases/download/2.1.4/sslscan-2.1.4.zip && \
    unzip sslscan-2.1.4.zip && \
    mv sslscan /usr/local/bin/ && \
    rm sslscan-2.1.4.zip

RUN wget https://github.com/drwetter/testssl.sh/archive/refs/tags/v3.2.tar.gz && \
    tar xzf v3.2.tar.gz && \
    ln -s ${TOOLS_HOME}/testssl.sh-3.2/testssl.sh /usr/local/bin/testssl && \
    rm v3.2.tar.gz

RUN wget https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_amd64.zip && \
    unzip katana_1.1.0_linux_amd64.zip && \
    mv katana /usr/local/bin/ && \
    rm katana_1.1.0_linux_amd64.zip

RUN wget https://github.com/hakluke/hakrawler/releases/download/2.0.0/hakrawler_2.0.0_linux_amd64.zip && \
    unzip hakrawler_2.0.0_linux_amd64.zip && \
    mv hakrawler /usr/local/bin/ && \
    rm hakrawler_2.0.0_linux_amd64.zip

RUN pip3 install waybackpy

COPY scanner-runner.sh /usr/local/bin/scanner-runner
RUN chmod +x /usr/local/bin/scanner-runner

ENTRYPOINT ["scanner-runner"]
