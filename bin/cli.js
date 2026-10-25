#!/usr/bin/env node
import { appendFileSync, readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { scan, DEFAULT_CHECKS, SEVERITIES } from '../src/scan.js';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

const HELP = `exposure-check ${pkg.version}
Check your own websites for publicly served secrets: .env files, .git
directories, private keys, database dumps and backups.

Usage:
  exposure-check <url> [<url>...] [options]

Options:
  --fail-on <level>     Exit with code 1 if a finding is at least this severe:
                        low, medium, high or critical (default: medium)
  --json                Print results as JSON
  --header "Name: v"    Add a request header (repeatable), e.g. for preview auth
  --timeout <ms>        Per-request timeout (default: 10000)
  --concurrency <n>     Parallel requests per site (default: 6)
  --list                List every path that is checked and exit
  -v, --version         Print the version
  -h, --help            Show this help

Exit codes:
  0  nothing found at or above --fail-on
  1  exposures found
  2  usage error or a site could not be reached

Only scan sites you own or are authorised to test.`;

const COLORS = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code, text) => (COLORS ? `\x1b[${code}m${text}\x1b[0m` : text);
const SEVERITY_STYLE = { critical: '1;31', high: '31', medium: '33', low: '36' };

function fail(message) {
  console.error(`exposure-check: ${message}\nRun "exposure-check --help" for usage.`);
  process.exit(2);
}

let parsed;
try {
  parsed = parseArgs({
    allowPositionals: true,
    options: {
      'fail-on': { type: 'string', default: 'medium' },
      json: { type: 'boolean', default: false },
      header: { type: 'string', multiple: true, default: [] },
      timeout: { type: 'string', default: '10000' },
      concurrency: { type: 'string', default: '6' },
      list: { type: 'boolean', default: false },
      version: { type: 'boolean', short: 'v', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
  });
} catch (error) {
  fail(error.message);
}

const { values, positionals } = parsed;

if (values.help) {
  console.log(HELP);
  process.exit(0);
}
if (values.version) {
  console.log(pkg.version);
  process.exit(0);
}
if (values.list) {
  for (const check of DEFAULT_CHECKS) console.log(`${check.severity.padEnd(8)} ${check.path}  (${check.title})`);
  process.exit(0);
}

const failOn = values['fail-on'].toLowerCase();
if (!SEVERITIES.includes(failOn)) fail(`--fail-on must be one of: ${SEVERITIES.join(', ')}`);
const timeout = Number(values.timeout);
const concurrency = Number(values.concurrency);
if (!Number.isInteger(timeout) || timeout <= 0) fail('--timeout must be a positive integer');
if (!Number.isInteger(concurrency) || concurrency <= 0) fail('--concurrency must be a positive integer');

const headers = {};
for (const header of values.header) {
  const index = header.indexOf(':');
  if (index < 1) fail(`invalid --header "${header}", expected "Name: value"`);
  headers[header.slice(0, index).trim()] = header.slice(index + 1).trim();
}

const targets = positionals.flatMap((arg) => arg.split(/[\s,]+/)).filter(Boolean);
if (targets.length === 0) fail('give at least one URL to check');

const threshold = SEVERITIES.indexOf(failOn);
const reports = [];
let unreachable = false;

for (const target of targets) {
  try {
    reports.push(await scan(target, { timeout, concurrency, headers }));
  } catch (error) {
    unreachable = true;
    reports.push({ target, error: error.message, findings: [], errors: [] });
  }
}

const failing = reports.flatMap((r) => r.findings).filter((f) => SEVERITIES.indexOf(f.severity) >= threshold);

if (values.json) {
  console.log(JSON.stringify({ version: pkg.version, failOn, reports }, null, 2));
} else {
  for (const report of reports) {
    console.log(`\n${paint('1', report.target)}`);
    if (report.error) {
      console.log(`  ${paint('31', '!')} ${report.error}`);
      continue;
    }
    if (report.findings.length === 0) {
      console.log(`  ${paint('32', '✓')} No exposed files found (${report.checked} paths checked)`);
    }
    for (const finding of report.findings) {
      const label = paint(SEVERITY_STYLE[finding.severity], finding.severity.toUpperCase().padEnd(8));
      console.log(`  ${label} ${finding.path}  ${finding.title}: ${finding.detail}`);
    }
    if (report.errors.length > 0) {
      console.log(paint('2', `  ${report.errors.length} path(s) could not be checked (${report.errors[0].error})`));
    }
  }
  if (failing.length > 0) {
    console.log(`\n${paint('31', `✖ ${failing.length} exposure(s) at or above "${failOn}".`)} Remove these files from the web root and rotate any exposed secrets.`);
  }
}

if (process.env.GITHUB_STEP_SUMMARY) {
  const rows = reports.flatMap((r) =>
    r.error ? [`| ${r.target} | error | ${r.error} |`] : r.findings.map((f) => `| ${f.url} | ${f.severity} | ${f.title}: ${f.detail} |`),
  );
  const summary = rows.length
    ? `### exposure-check found ${rows.length} issue(s)\n\n| URL | Severity | Finding |\n| --- | --- | --- |\n${rows.join('\n')}\n`
    : `### exposure-check: no exposed files found ✅\n\nChecked: ${targets.join(', ')}\n`;
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary);
}

process.exit(unreachable ? 2 : failing.length > 0 ? 1 : 0);
