import { DEFAULT_CHECKS, SEVERITIES } from './checks.js';

const MAX_BYTES = 64 * 1024;
const USER_AGENT = 'exposure-check (+https://github.com/skdas20/exposure-check)';

async function readLimited(response, limit = MAX_BYTES) {
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  while (size < limit) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    size += value.length;
  }
  await reader.cancel().catch(() => {});
  const bytes = new Uint8Array(Math.min(size, limit));
  let offset = 0;
  for (const chunk of chunks) {
    const slice = chunk.subarray(0, bytes.length - offset);
    bytes.set(slice, offset);
    offset += slice.length;
    if (offset >= bytes.length) break;
  }
  return bytes;
}

async function fetchPath(baseUrl, path, { timeout, headers }) {
  const url = new URL(path.replace(/^\//, ''), baseUrl);
  const response = await fetch(url, {
    method: 'GET',
    redirect: 'manual', // a redirect (e.g. to a login page) is not an exposure
    headers: { 'user-agent': USER_AGENT, ...headers },
    signal: AbortSignal.timeout(timeout),
  });
  const bytes = await readLimited(response);
  return { url: url.href, status: response.status, bytes, text: new TextDecoder().decode(bytes) };
}

function sameBody(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const index = next++;
      results[index] = await fn(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

export function normaliseBaseUrl(input) {
  const url = new URL(/^[a-z]+:\/\//i.test(input) ? input : `https://${input}`);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error(`Unsupported protocol: ${url.protocol}`);
  if (!url.pathname.endsWith('/')) url.pathname += '/';
  url.search = '';
  url.hash = '';
  return url;
}

/**
 * Scans one site for publicly served sensitive files.
 *
 * @param {string} target - Base URL, e.g. "https://example.com" or "example.com/app".
 * @param {object} [options]
 * @param {number} [options.timeout=10000] - Per-request timeout in ms.
 * @param {number} [options.concurrency=6] - Parallel requests.
 * @param {Record<string,string>} [options.headers] - Extra request headers.
 * @param {Array} [options.checks] - Checks to run (defaults to DEFAULT_CHECKS).
 * @returns {Promise<{target: string, findings: Array, errors: Array, checked: number}>}
 */
export async function scan(target, options = {}) {
  const { timeout = 10000, concurrency = 6, headers = {}, checks = DEFAULT_CHECKS } = options;
  const baseUrl = normaliseBaseUrl(target);

  // A random path tells us what the server returns for files that don't exist.
  // If a check returns the exact same body, it's a catch-all page, not a file.
  let baseline = null;
  try {
    const probe = await fetchPath(baseUrl, `/exposure-check-${Math.random().toString(36).slice(2)}.txt`, { timeout, headers });
    if (probe.status === 200) baseline = probe.bytes;
  } catch (error) {
    throw new Error(`Could not reach ${baseUrl.href}: ${error.cause?.code || error.message}`);
  }

  const findings = [];
  const errors = [];
  await mapLimit(checks, concurrency, async (check) => {
    try {
      const response = await fetchPath(baseUrl, check.path, { timeout, headers });
      if (response.status !== 200 || response.bytes.length === 0) return;
      if (baseline && sameBody(response.bytes, baseline)) return;
      const detail = check.detect(response);
      if (detail) {
        findings.push({ severity: check.severity, title: check.title, path: check.path, url: response.url, detail });
      }
    } catch (error) {
      errors.push({ path: check.path, error: error.name === 'TimeoutError' ? 'timed out' : error.message });
    }
  });

  findings.sort((a, b) => SEVERITIES.indexOf(b.severity) - SEVERITIES.indexOf(a.severity) || a.path.localeCompare(b.path));
  return { target: baseUrl.href, findings, errors, checked: checks.length };
}

export { DEFAULT_CHECKS, SEVERITIES };
