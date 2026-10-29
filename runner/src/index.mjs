#!/usr/bin/env node
/**
 * Runner entrypoint.
 *
 * Refuses to start on an unsafe configuration (short secret, host networking,
 * root container user) rather than starting in a degraded security posture.
 */

import { loadConfig, ConfigError } from './config.mjs';
import { DockerExecutor } from './executor.mjs';
import { createRunnerServer, RUNNER_VERSION } from './server.mjs';

let config;

try {
  config = loadConfig(process.env);
} catch (error) {
  if (error instanceof ConfigError) {
    process.stderr.write(`runner: refusing to start: ${error.message}\n`);
    process.exit(1);
  }
  throw error;
}

const logger = {
  info: (message) => process.stdout.write(`${new Date().toISOString()} INFO ${message}\n`),
  warn: (message) => process.stdout.write(`${new Date().toISOString()} WARN ${message}\n`),
  error: (message) => process.stderr.write(`${new Date().toISOString()} ERROR ${message}\n`),
};

const executor = new DockerExecutor({ config, logger });
const server = createRunnerServer({ config, executor, logger });

server.listen(config.port, config.host, () => {
  logger.info(
    `runner ${RUNNER_VERSION} listening on ${config.host}:${config.port} ` +
      `(network=${config.scannerNetwork}, max_concurrent=${config.maxConcurrentJobs})`,
  );
});

const shutdown = (signal) => {
  logger.info(`received ${signal}; shutting down`);
  server.close(() => process.exit(0));
  // Give in-flight jobs a moment to be killed by their own timeouts.
  setTimeout(() => process.exit(0), 5000).unref();
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
