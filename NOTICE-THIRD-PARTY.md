# Third-Party Notices

This product contains software components licensed by third parties.
The following is a summary of the third-party components used in
HowToHack and their respective license information.

## PHP / Composer Dependencies

See `backend/composer.json` for the complete list of dependencies.

| Package | License |
|---------|---------|
| laravel/framework | MIT |
| laravel/tinker | MIT |
| fakerphp/faker | MIT |
| dompdf/dompdf | LGPL-2.1+ |
| laravel/pail | MIT |
| laravel/pint | MIT |
| laravel/sail | MIT |
| mockery/mockery | BSD-3-Clause |
| nunomaduro/collision | MIT |
| phpunit/phpunit | BSD-3-Clause |

## JavaScript / npm Dependencies

See `frontend/package.json` for the complete list of dependencies.

| Package | License |
|---------|---------|
| react | MIT |
| react-dom | MIT |
| react-router-dom | MIT |
| vite | MIT |
| typescript | Apache-2.0 |
| eslint | MIT |
| @vitejs/plugin-react | MIT |

## External Security Tools

These tools are used via Docker containers and are not incorporated
into the HowToHack source code.

| Tool | License |
|------|---------|
| nmap | NPSL (custom open source) |
| nuclei | MIT |
| nikto | GPL-2.0 |
| wapiti | Apache-2.0 |
| whatweb | GPL-2.0 |
| theHarvester | GPL-2.0 |
| subfinder | MIT |
| amass | Apache-2.0 |
| httpx | MIT |
| katana | MIT |
| ffuf | MIT |
| dnsrecon | GPL-2.0 |
| sslscan | GPL-3.0 |
| testssl.sh | GPL-2.0 |
| hakrawler | MIT |
| gau | MIT |

## Docker Images

| Image | License |
|-------|---------|
| php:8.2-fpm | PHP License |
| node:20-alpine | MIT |
| postgres:16-alpine | PostgreSQL License |
| redis:7-alpine | BSD-3-Clause |
| ubuntu:22.04 | Various |

---

This document is provided for informational purposes only. The licenses
noted above are believed to be accurate as of the time of publication.
Please refer to the individual package documentation for the most current
license information.
