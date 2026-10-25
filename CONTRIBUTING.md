# Contributing

Thanks for helping make deployments safer!

## Adding a check

Most contributions are new checks, and each one is small:

1. Add an entry to `DEFAULT_CHECKS` in [`src/checks.js`](src/checks.js) using `envFile`, `textMatch` or `binaryMatch`.
2. Make the detection **content-based**: match something only the real file contains (a header line, magic bytes, a known key). Never rely on the status code alone, because single-page apps return `200` for every path.
3. Pick a severity: `critical` (credentials or data), `high` (source code or password hashes), `medium` (config or info leaks that may contain secrets) or `low` (metadata).
4. Add a test in [`test/scan.test.js`](test/scan.test.js): one response that should match and, ideally, one look-alike that shouldn't.
5. Never include secret *values* in the `detail` message.

## Development

```bash
git clone https://github.com/skdas20/exposure-check.git
cd exposure-check
npm test                          # Node.js 18+, no install needed
node bin/cli.js https://your-own-site.example
```

There are no dependencies, and we'd like to keep it that way.

## Ground rules

- Only test against sites you own or are authorised to test.
- Keep PRs focused, and describe how you tested them.
- Be kind. See the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
