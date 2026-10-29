#!/usr/bin/env node
/**
 * Fixture runner for http_pinning_test.php.
 *
 * Starts two HTTP fixtures on the SAME port on 127.0.0.1 and 127.0.0.2 (so the
 * only way to reach one or the other is the pinned literal), plus a redirect
 * target and, where the host supports it, an ::1 fixture. Then runs the PHP
 * test with `php` (or $PHP_BIN) and forwards its exit code.
 *
 *   node backend/tests/Standalone/http_pinning.mjs
 *
 * Nothing outside the loopback interface is contacted.
 */
import http from 'node:http';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const script = path.join(here, 'http_pinning_test.php');
const phpBin = process.env.PHP_BIN || 'php';

const listen = (server, address) =>
  new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, address, () => resolve(server.address().port));
  });

const body = (res, text, status = 200, headers = {}) => {
  res.writeHead(status, { 'content-type': 'text/plain', ...headers });
  res.end(text);
};

const makeServer = (label, redirectTo) =>
  http.createServer((req, res) => {
    if (req.url === '/redirect' && redirectTo) {
      body(res, `redirecting from ${label}`, 302, { location: redirectTo() });
      return;
    }
    body(res, label);
  });

const servers = [];
const closeAll = () => Promise.all(servers.map((s) => new Promise((r) => s.close(r))));

// A redirect target on its own port, so the 30x destination is unambiguous.
const redirectServer = http.createServer((req, res) => body(res, 'REDIRECT-TARGET'));
const redirectPort = await listen(redirectServer, '127.0.0.1');
servers.push(redirectServer);

// A and B share a port; only the pinned address distinguishes them.
const a = makeServer('ADDRESS-A', () => `http://redirect.test:${redirectPort}/`);
const b = makeServer('ADDRESS-B');
const port = await listen(a, '127.0.0.1');
servers.push(a);

// Binding the same port on 127.0.0.2 (all of 127/8 is loopback on Linux) is
// what makes the pin observable rather than merely configured.
try {
  await new Promise((resolve, reject) => {
    b.once('error', reject);
    b.listen(port, '127.0.0.2', resolve);
  });
  servers.push(b);
} catch (error) {
  console.error(`fixtures: could not bind 127.0.0.2:${port} — ${error.code}`);
  await closeAll();
  process.exit(1);
}

// Optional IPv6 fixture; skipped when the host has no ::1.
let v6Port = 0;
const v6 = makeServer('ADDRESS-V6');
try {
  v6Port = await listen(v6, '::1');
  servers.push(v6);
} catch {
  v6Port = 0;
}

console.log(
  `fixtures: A=127.0.0.1:${port} B=127.0.0.2:${port} redirect=127.0.0.1:${redirectPort} v6=${v6Port || 'unavailable'}`,
);

const child = spawn(phpBin, [script], {
  stdio: 'inherit',
  env: {
    ...process.env,
    PIN_TEST_PORT: String(port),
    PIN_TEST_REDIRECT_PORT: String(redirectPort),
    PIN_TEST_V6_PORT: String(v6Port),
  },
});

const code = await new Promise((resolve) => {
  child.on('close', resolve);
  child.on('error', (error) => {
    console.error(`could not start "${phpBin}": ${error.message}`);
    console.error('Set PHP_BIN to a PHP 8.2+ binary, or run without an interpreter to skip.');
    resolve(2);
  });
});

await closeAll();
process.exit(code ?? 1);
