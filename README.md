<div align="center">

# exposure-check

**Is your website serving its `.env` file to the whole internet? Find out in one command.**

`exposure-check` scans your deployed site for publicly accessible secrets: `.env` files, `.git` folders, private keys, database dumps and backups. Run it from your terminal, or as a GitHub Action after every deploy.

[![CI](https://github.com/skdas20/exposure-check/actions/workflows/ci.yml/badge.svg)](https://github.com/skdas20/exposure-check/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](package.json)
[![Node.js 18+](https://img.shields.io/badge/node-%3E%3D18-339933?logo=node.js&logoColor=white)](https://nodejs.org)

</div>

```console
$ npx github:skdas20/exposure-check https://my-app.example.com

https://my-app.example.com/
  CRITICAL /.env        Environment file: 2 variables exposed (MONGODB_URI, GEMINI_API_KEY)
  HIGH     /.git/config Git repository metadata: the .git directory is served, so the full source and history can be downloaded

✖ 2 exposure(s) at or above "medium". Remove these files from the web root and rotate any exposed secrets.
```

> Only scan sites you own or are authorised to test.

## Why this exists

A very common deployment mistake is serving the **whole project directory** as static files: a `StaticFiles` / `express.static` / nginx root pointed at the repo, or a build that copies `.env` into the public folder. Everything looks fine in the browser, but `https://your-site/.env` hands out your database password and API keys, and bots scan for exactly that path within hours.

This tool was built after finding exactly that bug in a real FastAPI app: the static mount at `/` served the repository root, including `.env`. `exposure-check` catches it in seconds, and in CI it catches it before the leak goes unnoticed.

## Features

- **40 high-signal checks**: `.env` variants, `.git` and `.hg` metadata, SSH and TLS private keys, `.npmrc` tokens, AWS credentials, `.htpasswd`, WordPress config backups, SQL dumps, ZIP and tar.gz backups, `docker-compose.yml`, `.DS_Store`, `phpinfo()` and Apache `server-status` pages. Run `--list` to see them all.
- **No false positives from single-page apps**: Vercel, Netlify and most SPA hosts answer every path with `200 index.html`. Every check verifies the file's actual content (dotenv lines, `[core]`, ZIP magic bytes, `BEGIN PRIVATE KEY`…) and compares against a random-path baseline.
- **Never prints your secrets**: for `.env` files it reports only the variable *names*.
- **CI-friendly**: exit codes, `--fail-on` severity threshold, `--json` output, and a GitHub Actions job summary.
- **Zero dependencies**: a single small Node.js package using built-in `fetch`.

## Usage

### Command line

Requires Node.js 18 or newer.

```bash
npx github:skdas20/exposure-check https://example.com

# several sites, JSON output, fail only on high or critical findings
npx github:skdas20/exposure-check example.com app.example.com --json --fail-on high

# a protected preview deployment
npx github:skdas20/exposure-check https://preview.example.com --header "Authorization: Bearer $TOKEN"
```

| Option | Default | Description |
| --- | --- | --- |
| `--fail-on <level>` | `medium` | Exit 1 when a finding is at least `low`, `medium`, `high` or `critical` |
| `--json` | off | Machine-readable output |
| `--header "Name: value"` | none | Extra request header (repeatable) |
| `--timeout <ms>` | `10000` | Per-request timeout |
| `--concurrency <n>` | `6` | Parallel requests per site |
| `--list` | | Print every path that is checked |

**Exit codes:** `0` nothing found at or above `--fail-on` · `1` exposures found · `2` usage error or site unreachable.

### GitHub Action

Check your production site after every deploy, or on a schedule:

```yaml
name: Exposure check
on:
  deployment_status:
  schedule:
    - cron: "0 6 * * *"   # daily
  workflow_dispatch:

jobs:
  exposure-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - uses: skdas20/exposure-check@v0
        with:
          urls: https://example.com https://api.example.com
          fail-on: medium
```

| Input | Default | Description |
| --- | --- | --- |
| `urls` | required | URLs separated by spaces, commas or new lines |
| `fail-on` | `medium` | Minimum severity that fails the step |
| `headers` | none | `Name: value` per line, e.g. for preview protection |
| `timeout` | `15000` | Per-request timeout in ms |

Findings are also written to the job summary.

### As a library

```js
// npm install github:skdas20/exposure-check
import { scan } from 'exposure-check';

const { findings } = await scan('https://example.com');
for (const f of findings) console.log(f.severity, f.path, f.detail);
```

## FAQ

### How do I check if my `.env` file is publicly accessible?

Run `npx github:skdas20/exposure-check https://your-site.com`. It requests `/.env` and common variants (`.env.local`, `.env.production`, `backend/.env`…) and confirms that the response really is a dotenv file, not your app's HTML fallback page. You can also run `curl -i https://your-site.com/.env`, but on single-page-app hosts a `200` response is usually just `index.html`, and that's exactly the false positive this tool filters out.

### My `.env` was exposed. What now?

1. **Rotate every secret in it immediately** (database passwords, API keys, tokens). Removing the file is not enough: assume it has already been copied.
2. Stop serving it: serve only your build output (e.g. `dist/`, `public/`) instead of the project root, and keep `.env` out of the deployed artifact.
3. Add `.env` to `.gitignore` and remove it from git history if it was committed (`git filter-repo`, or GitHub's guide on removing sensitive data).
4. Add `exposure-check` to CI so it can't silently come back.

### Is my `.git` folder exposed?

If `/.git/config` or `/.git/HEAD` is reachable, anyone can reconstruct your entire repository, including history and any secrets ever committed. `exposure-check` reports it as **high**. Block dot-directories in your web server, or deploy build artifacts instead of a git checkout.

### Does it work with Vercel, Netlify, Render, Railway, Cloudflare Pages?

Yes. It only makes plain HTTPS requests to your public URL, and it's designed to ignore the catch-all `index.html` responses those platforms return for unknown paths.

### Is this a full security scanner?

No. It answers one question quickly and reliably: "is my deployment serving files it shouldn't?" For broader testing, look at tools like OWASP ZAP or nuclei, and for secrets committed to git, gitleaks or trufflehog.

## How detection works

1. Request a random, non-existent path to learn what the site returns for missing files.
2. Request each known-sensitive path (no redirects followed, at most 64 KB read).
3. Report a path only if it returns `200`, differs from the baseline response, and its content matches the file type's signature.

## Contributing

New checks are very welcome: each one is a few lines in [`src/checks.js`](src/checks.js) plus a test. See [CONTRIBUTING.md](CONTRIBUTING.md). If this tool saved you from a leak, **a ⭐ helps others find it.**

## License

[MIT](LICENSE) © [Sumit Kumar Das](https://github.com/skdas20)
