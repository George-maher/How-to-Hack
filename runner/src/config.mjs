/**
 * Configuration is read once, validated at boot, and then frozen.
 *
 * A runner that starts with a weak secret, a host network or a root container
 * user is worse than no runner: it looks isolated and is not. So every unsafe
 * value is a startup error, not a warning.
 */

const DEFAULTS = Object.freeze({
  port: 8080,
  host: '0.0.0.0',
  secretMinLength: 32,
  clockSkewSeconds: 300,
  maxBodyBytes: 64 * 1024,
  maxConcurrentJobs: 2,
  maxTimeoutMs: 600_000,
  defaultTimeoutMs: 120_000,
  maxOutputBytes: 256 * 1024,
  scannerNetwork: 'scanner-net',
  containerUser: '65534:65534',
  image: 'howtohack/scanner:latest',
  memoryMb: 512,
  cpus: 1,
  pidsLimit: 256,
  wordlistMount: '/opt/howtohack/wordlists:/wordlists:ro',
});

/** Names the runner must never place a scanner container on. */
const FORBIDDEN_NETWORKS = new Set(['host', 'bridge', 'default', 'none']);

export class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
  }
}

function int(value, fallback, field) {
  if (value === undefined || value === '') return fallback;
  const parsed = Number.parseInt(String(value), 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new ConfigError(`${field} must be a non-negative integer`);
  }
  return parsed;
}

/**
 * @param {Record<string, string | undefined>} env
 */
export function loadConfig(env = process.env) {
  const secret = env.RUNNER_SECRET ?? '';

  if (secret.length < DEFAULTS.secretMinLength) {
    throw new ConfigError(
      `RUNNER_SECRET must be at least ${DEFAULTS.secretMinLength} characters; refusing to start.`,
    );
  }

  const scannerNetwork = env.RUNNER_SCANNER_NETWORK ?? DEFAULTS.scannerNetwork;
  if (FORBIDDEN_NETWORKS.has(scannerNetwork)) {
    throw new ConfigError(
      `RUNNER_SCANNER_NETWORK may not be "${scannerNetwork}": scanners need their own isolated network.`,
    );
  }

  const containerUser = env.RUNNER_CONTAINER_USER ?? DEFAULTS.containerUser;
  if (containerUser === 'root' || containerUser.startsWith('0:') || containerUser === '0') {
    throw new ConfigError('RUNNER_CONTAINER_USER may not be root.');
  }

  const config = {
    port: int(env.RUNNER_PORT, DEFAULTS.port, 'RUNNER_PORT'),
    host: env.RUNNER_HOST ?? DEFAULTS.host,
    secret,
    clockSkewSeconds: int(env.RUNNER_CLOCK_SKEW_SECONDS, DEFAULTS.clockSkewSeconds, 'RUNNER_CLOCK_SKEW_SECONDS'),
    maxBodyBytes: int(env.RUNNER_MAX_BODY_BYTES, DEFAULTS.maxBodyBytes, 'RUNNER_MAX_BODY_BYTES'),
    maxConcurrentJobs: int(env.RUNNER_MAX_CONCURRENT, DEFAULTS.maxConcurrentJobs, 'RUNNER_MAX_CONCURRENT'),
    maxTimeoutMs: int(env.RUNNER_MAX_TIMEOUT_MS, DEFAULTS.maxTimeoutMs, 'RUNNER_MAX_TIMEOUT_MS'),
    defaultTimeoutMs: int(env.RUNNER_DEFAULT_TIMEOUT_MS, DEFAULTS.defaultTimeoutMs, 'RUNNER_DEFAULT_TIMEOUT_MS'),
    maxOutputBytes: int(env.RUNNER_MAX_OUTPUT_BYTES, DEFAULTS.maxOutputBytes, 'RUNNER_MAX_OUTPUT_BYTES'),
    scannerNetwork,
    containerUser,
    image: env.RUNNER_IMAGE ?? DEFAULTS.image,
    memoryMb: int(env.RUNNER_MEMORY_MB, DEFAULTS.memoryMb, 'RUNNER_MEMORY_MB'),
    cpus: Number.parseFloat(env.RUNNER_CPUS ?? String(DEFAULTS.cpus)),
    pidsLimit: int(env.RUNNER_PIDS_LIMIT, DEFAULTS.pidsLimit, 'RUNNER_PIDS_LIMIT'),
    wordlistMount: env.RUNNER_WORDLIST_MOUNT ?? DEFAULTS.wordlistMount,
    dockerBin: env.RUNNER_DOCKER_BIN ?? 'docker',
    logLevel: env.LOG_LEVEL ?? 'info',
  };

  if (!Number.isFinite(config.cpus) || config.cpus <= 0) {
    throw new ConfigError('RUNNER_CPUS must be a positive number');
  }

  if (config.maxConcurrentJobs < 1) {
    throw new ConfigError('RUNNER_MAX_CONCURRENT must be at least 1');
  }

  if (config.maxTimeoutMs > 3_600_000) {
    throw new ConfigError('RUNNER_MAX_TIMEOUT_MS may not exceed one hour');
  }

  return Object.freeze(config);
}

export const CONFIG_DEFAULTS = DEFAULTS;
