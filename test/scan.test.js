import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { scan, normaliseBaseUrl } from '../src/scan.js';
import { envKeys } from '../src/checks.js';

const run = promisify(execFile);
const CLI = fileURLToPath(new URL('../bin/cli.js', import.meta.url));
const SECRET = 'sk_live_51SuperSecretValue';

const VULNERABLE = {
  '/.env': `# app config\nDATABASE_URL=postgres://user:pw@db/app\nSTRIPE_KEY=${SECRET}\nexport DEBUG=false\n`,
  '/.git/config': '[core]\n\trepositoryformatversion = 0\n',
  '/.git/HEAD': 'ref: refs/heads/main\n',
  '/.DS_Store': Buffer.from([0, 0, 0, 1, 0x42, 0x75, 0x64, 0x31, 0, 0, 16, 0]),
  '/backup.zip': Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0, 0, 0]),
  '/dump.sql': 'CREATE TABLE users (id int);\nINSERT INTO users VALUES (1);\n',
  '/id_rsa': '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n',
};

const SPA_HTML = '<!doctype html><html><head><title>App</title></head><body><div id="root"></div></body></html>';

function listen(handler) {
  return new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(0, '127.0.0.1', () => resolve({ server, url: `http://127.0.0.1:${server.address().port}` }));
  });
}

const servers = {};

before(async () => {
  servers.vulnerable = await listen((req, res) => {
    const body = VULNERABLE[req.url];
    if (body === undefined) return res.writeHead(404).end('Not found');
    res.writeHead(200).end(body);
  });
  servers.spa = await listen((req, res) => res.writeHead(200, { 'content-type': 'text/html' }).end(SPA_HTML));
  servers.textCatchAll = await listen((req, res) => res.writeHead(200).end('OK=1\n'));
  servers.redirect = await listen((req, res) => res.writeHead(302, { location: '/login' }).end());
  servers.clean = await listen((req, res) => res.writeHead(404).end('Not found'));
  servers.subpath = await listen((req, res) => {
    if (req.url === '/app/.env') return res.writeHead(200).end('API_KEY=abc\n');
    res.writeHead(404).end();
  });
});

after(() => Object.values(servers).forEach(({ server }) => server.close()));

test('detects exposed files with the right severity', async () => {
  const { findings } = await scan(servers.vulnerable.url);
  const byPath = Object.fromEntries(findings.map((f) => [f.path, f]));
  assert.equal(byPath['/.env'].severity, 'critical');
  assert.match(byPath['/.env'].detail, /3 variables exposed \(DATABASE_URL, STRIPE_KEY, DEBUG\)/);
  assert.equal(byPath['/.git/config'].severity, 'high');
  assert.ok(byPath['/.git/HEAD']);
  assert.ok(byPath['/.DS_Store']);
  assert.ok(byPath['/backup.zip']);
  assert.ok(byPath['/dump.sql']);
  assert.ok(byPath['/id_rsa']);
  assert.equal(findings.length, 7);
  assert.equal(findings[0].severity, 'critical', 'findings are sorted by severity');
});

test('never reports secret values', async () => {
  const result = await scan(servers.vulnerable.url);
  assert.ok(!JSON.stringify(result).includes(SECRET));
  assert.ok(!JSON.stringify(result).includes('user:pw'));
});

test('single-page apps that answer every path with index.html are not flagged', async () => {
  const { findings } = await scan(servers.spa.url);
  assert.deepEqual(findings, []);
});

test('a non-HTML catch-all response is recognised through the baseline probe', async () => {
  const { findings } = await scan(servers.textCatchAll.url);
  assert.deepEqual(findings, []);
});

test('redirects are not treated as exposures', async () => {
  const { findings } = await scan(servers.redirect.url);
  assert.deepEqual(findings, []);
});

test('scans relative to a sub-path', async () => {
  const { findings } = await scan(`${servers.subpath.url}/app`);
  assert.deepEqual(findings.map((f) => f.path), ['/.env']);
});

test('envKeys returns names only and skips comments', () => {
  assert.deepEqual(envKeys('# c\nA=1\n\nexport B_2 = "x"\nnot a var\n'), ['A', 'B_2']);
});

test('normaliseBaseUrl adds https and a trailing slash', () => {
  assert.equal(normaliseBaseUrl('example.com').href, 'https://example.com/');
  assert.equal(normaliseBaseUrl('http://example.com/app?x=1').href, 'http://example.com/app/');
  assert.throws(() => normaliseBaseUrl('ftp://example.com'), /Unsupported protocol/);
});

test('CLI exits 1 on findings, prints no secrets and supports --json', async () => {
  await assert.rejects(run('node', [CLI, servers.vulnerable.url]), (error) => {
    assert.equal(error.code, 1);
    assert.match(error.stdout, /CRITICAL.*\/\.env/);
    assert.ok(!error.stdout.includes(SECRET));
    return true;
  });
  await assert.rejects(run('node', [CLI, servers.vulnerable.url, '--json']), (error) => {
    const report = JSON.parse(error.stdout);
    assert.equal(report.reports[0].findings.length, 7);
    return true;
  });
});

test('CLI respects --fail-on', async () => {
  // Only low-severity .DS_Store and nothing else → passes with the default threshold.
  const dsOnly = await listen((req, res) => {
    if (req.url === '/.DS_Store') return res.writeHead(200).end(VULNERABLE['/.DS_Store']);
    res.writeHead(404).end();
  });
  try {
    const { stdout } = await run('node', [CLI, dsOnly.url]);
    assert.match(stdout, /LOW/);
    await assert.rejects(run('node', [CLI, dsOnly.url, '--fail-on', 'low']), { code: 1 });
  } finally {
    dsOnly.server.close();
  }
});

test('CLI exits 0 for a clean site and 2 for an unreachable one or bad usage', async () => {
  const { stdout } = await run('node', [CLI, servers.clean.url]);
  assert.match(stdout, /No exposed files found/);
  await assert.rejects(run('node', [CLI, 'http://127.0.0.1:1', '--timeout', '2000']), { code: 2 });
  await assert.rejects(run('node', [CLI]), { code: 2 });
  await assert.rejects(run('node', [CLI, 'example.com', '--fail-on', 'nope']), { code: 2 });
});
