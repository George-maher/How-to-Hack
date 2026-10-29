/**
 * The scanner registry.
 *
 * Every executable the Runner is allowed to start is declared here, with a
 * fixed image and a fixed argv builder. A job names a tool; it cannot name a
 * binary, add a flag, mount a volume, set an environment variable or choose an
 * image. That is the difference between "a job interface" and "remote command
 * execution".
 *
 * The API keeps a mirror of the names/intrusiveness in
 * backend/app/Scanners/RunnerToolRegistry.php; test/registry-parity.test.mjs
 * asserts the two agree.
 */

export const INTRUSIVENESS = Object.freeze({ PASSIVE: 'passive', ACTIVE: 'active' });

/**
 * Every value that reaches argv passes through here first.
 *
 * There is no shell in this path, but a scanner parses its own argv: a "host"
 * of `--script=evil` would be obeyed as an option. Refusing to build the argv
 * at all is the only safe answer.
 */
export class UnsafeTargetError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UnsafeTargetError';
  }
}

/** @param {unknown} value */
function clean(value) {
  const text = String(value ?? '');

  if (text === '' || text.length > 2048) {
    throw new UnsafeTargetError('the target value is empty or too long');
  }

  if (/[\u0000-\u001f\u007f\s]/.test(text)) {
    throw new UnsafeTargetError('the target value contains whitespace or control characters');
  }

  if (text.startsWith('-')) {
    throw new UnsafeTargetError('the target value would be parsed as a command-line flag');
  }

  return text;
}

/** Absolute http(s) URL with no userinfo and no fragment. */
function urlFor({ url, host, port }) {
  const raw = typeof url === 'string' && url !== '' ? url : `https://${clean(host)}:${Number(port) || 443}/`;

  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new UnsafeTargetError('the target URL is not a valid absolute URL');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new UnsafeTargetError('the target URL must use http or https');
  }

  if (parsed.username || parsed.password) {
    throw new UnsafeTargetError('the target URL must not contain credentials');
  }

  parsed.hash = '';

  return parsed.toString();
}

function hostOnly({ host }) {
  return clean(host);
}

/**
 * @typedef {object} ToolDefinition
 * @property {string} intrusiveness
 * @property {string} description
 * @property {number} timeoutMs
 * @property {(target: { host: string, url: string, port: number }) => string[]} argv
 */

/** @type {Record<string, ToolDefinition>} */
export const TOOLS = Object.freeze({
  nmap: {
    intrusiveness: INTRUSIVENESS.ACTIVE,
    description: 'Service and version detection against the approved ports',
    timeoutMs: 300_000,
    argv: ({ host }) => ['-sV', '-Pn', '--top-ports', '200', '-oX', '-', hostOnly({ host })],
  },
  httpx: {
    intrusiveness: INTRUSIVENESS.PASSIVE,
    description: 'HTTP probing: status, title, technologies',
    timeoutMs: 120_000,
    argv: (target) => ['-silent', '-json', '-status-code', '-title', '-tech-detect', urlFor(target)],
  },
  whatweb: {
    intrusiveness: INTRUSIVENESS.PASSIVE,
    description: 'Technology fingerprinting',
    timeoutMs: 120_000,
    argv: (target) => ['--no-errors', '--log-json=/tmp/whatweb.json', '-a', '1', urlFor(target)],
  },
  dnsrecon: {
    intrusiveness: INTRUSIVENESS.ACTIVE,
    description: 'DNS record enumeration',
    timeoutMs: 120_000,
    argv: (target) => ['-d', hostOnly(target), '-t', 'std', '-j', '/tmp/dnsrecon.json'],
  },
  subfinder: {
    intrusiveness: INTRUSIVENESS.PASSIVE,
    description: 'Passive subdomain discovery',
    timeoutMs: 120_000,
    argv: (target) => ['-d', hostOnly(target), '-silent', '-json'],
  },
  amass: {
    intrusiveness: INTRUSIVENESS.ACTIVE,
    description: 'Attack-surface mapping',
    timeoutMs: 300_000,
    argv: (target) => ['enum', '-passive', '-d', hostOnly(target), '-json', '/tmp/amass.json'],
  },
  theharvester: {
    intrusiveness: INTRUSIVENESS.PASSIVE,
    description: 'OSINT collection for the target domain',
    timeoutMs: 180_000,
    argv: (target) => ['-d', hostOnly(target), '-b', 'duckduckgo', '-f', '/tmp/theharvester'],
  },
  dirsearch: {
    intrusiveness: INTRUSIVENESS.ACTIVE,
    description: 'Directory and file brute force',
    timeoutMs: 300_000,
    argv: (target) => [
      '-u', urlFor(target),
      '-w', '/wordlists/common.txt',
      '--format=json',
      '-o', '/tmp/dirsearch.json',
      '--quiet',
    ],
  },
  ffuf: {
    intrusiveness: INTRUSIVENESS.ACTIVE,
    description: 'Content discovery with a fixed wordlist',
    timeoutMs: 300_000,
    argv: (target) => [
      '-u', `${urlFor(target).replace(/\/$/, '')}/FUZZ`,
      '-w', '/wordlists/common.txt',
      '-mc', '200,204,301,302,307,401,403',
      '-of', 'json',
      '-o', '/tmp/ffuf.json',
      '-s',
    ],
  },
  katana: {
    intrusiveness: INTRUSIVENESS.ACTIVE,
    description: 'Crawling for endpoints and parameters',
    timeoutMs: 180_000,
    argv: (target) => ['-u', urlFor(target), '-d', '3', '-json', '-silent', '-rl', '20'],
  },
  hakrawler: {
    intrusiveness: INTRUSIVENESS.ACTIVE,
    description: 'Crawler for URLs and JS endpoints',
    timeoutMs: 180_000,
    argv: (target) => ['-url', urlFor(target), '-d', '3', '-json'],
  },
  gau: {
    intrusiveness: INTRUSIVENESS.PASSIVE,
    description: 'Known URLs from public archives',
    timeoutMs: 120_000,
    argv: (target) => ['--json', hostOnly(target)],
  },
  waybackurls: {
    intrusiveness: INTRUSIVENESS.PASSIVE,
    description: 'URLs from the Wayback Machine',
    timeoutMs: 120_000,
    argv: (target) => [hostOnly(target)],
  },
  nuclei: {
    intrusiveness: INTRUSIVENESS.ACTIVE,
    description: 'Template-based vulnerability checks (no exploit templates)',
    timeoutMs: 420_000,
    argv: (target) => [
      '-u', urlFor(target),
      '-jsonl',
      '-silent',
      '-severity', 'info,low,medium,high,critical',
      '-exclude-tags', 'dos,fuzz,intrusive',
      '-rate-limit', '20',
      '-no-interactsh',
    ],
  },
  nikto: {
    intrusiveness: INTRUSIVENESS.ACTIVE,
    description: 'Web server misconfiguration checks',
    timeoutMs: 300_000,
    argv: (target) => ['-h', urlFor(target), '-Format', 'json', '-output', '-', '-nointeractive'],
  },
  wapiti: {
    intrusiveness: INTRUSIVENESS.ACTIVE,
    description: 'Web application vulnerability scan (no exploitation)',
    timeoutMs: 420_000,
    argv: (target) => ['-u', urlFor(target), '-f', 'json', '-o', '/tmp/wapiti.json', '--flush-session'],
  },
  sslscan: {
    intrusiveness: INTRUSIVENESS.PASSIVE,
    description: 'TLS configuration inspection',
    timeoutMs: 120_000,
    argv: (target) => ['--xml=-', `${hostOnly(target)}:${Number(target.port) || 443}`],
  },
  testssl: {
    intrusiveness: INTRUSIVENESS.PASSIVE,
    description: 'TLS/SSL cipher and protocol testing',
    timeoutMs: 180_000,
    argv: (target) => ['--jsonfile', '/tmp/testssl.json', '--quiet', `${hostOnly(target)}:${Number(target.port) || 443}`],
  },
});

export const TOOL_NAMES = Object.freeze(Object.keys(TOOLS));

/** @returns {ToolDefinition | null} */
export function getTool(name) {
  if (typeof name !== 'string' || !Object.prototype.hasOwnProperty.call(TOOLS, name)) {
    return null;
  }
  return TOOLS[name];
}

/** Public catalogue for GET /tools: no images, no argv. */
export function catalogue() {
  return TOOL_NAMES.map((name) => ({
    name,
    intrusiveness: TOOLS[name].intrusiveness,
    description: TOOLS[name].description,
    timeout_ms: TOOLS[name].timeoutMs,
  }));
}
