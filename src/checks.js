// Each check names a path to request and a `detect` function that inspects the
// response. Detection always looks at the content itself: single-page apps
// often answer every path with 200 and index.html, so a status code alone
// proves nothing.

const textDecoder = new TextDecoder('utf-8', { fatal: false });

export const SEVERITIES = ['low', 'medium', 'high', 'critical'];

function asText(bytes) {
  return textDecoder.decode(bytes);
}

function looksLikeHtml(text) {
  return /^\s*(<!doctype html|<html|<head|<body|<\?xml)/i.test(text) || /<\/(html|body|div|script)>/i.test(text);
}

function startsWith(bytes, signature) {
  if (bytes.length < signature.length) return false;
  return signature.every((byte, i) => bytes[i] === byte);
}

const ENV_LINE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=/;

// Returns the variable names in a dotenv-style file, never the values.
export function envKeys(text) {
  const keys = [];
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*(#|$)/.test(line)) continue;
    const match = line.match(ENV_LINE);
    if (match) keys.push(match[1]);
  }
  return keys;
}

function envFile(path, severity = 'critical') {
  return {
    path,
    severity,
    title: 'Environment file',
    detect({ text }) {
      if (looksLikeHtml(text)) return null;
      const keys = envKeys(text);
      // Require mostly KEY=value lines so random text files don't match.
      const lines = text.split(/\r?\n/).filter((line) => !/^\s*(#|$)/.test(line));
      if (keys.length === 0 || keys.length < lines.length * 0.6) return null;
      const shown = keys.slice(0, 8).join(', ') + (keys.length > 8 ? `, +${keys.length - 8} more` : '');
      return `${keys.length} variable${keys.length === 1 ? '' : 's'} exposed (${shown})`;
    },
  };
}

function textMatch(path, severity, title, pattern, describe) {
  return {
    path,
    severity,
    title,
    detect({ text }) {
      if (looksLikeHtml(text) && !pattern.html) return null;
      return pattern.test(text) ? describe : null;
    },
  };
}

function binaryMatch(path, severity, title, signature, describe) {
  return {
    path,
    severity,
    title,
    detect({ bytes }) {
      return startsWith(bytes, signature) ? describe : null;
    },
  };
}

const ZIP = [0x50, 0x4b, 0x03, 0x04];
const GZIP = [0x1f, 0x8b];
const SQL = /\b(CREATE TABLE|INSERT INTO|DROP TABLE)\b/i;
const PRIVATE_KEY = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;

export const DEFAULT_CHECKS = [
  // Environment files
  envFile('/.env'),
  envFile('/.env.local'),
  envFile('/.env.production'),
  envFile('/.env.prod'),
  envFile('/.env.development'),
  envFile('/.env.backup'),
  envFile('/.env.bak'),
  envFile('/.env.old'),
  envFile('/backend/.env'),
  envFile('/api/.env'),
  envFile('/server/.env'),

  // Version control metadata: lets anyone download your source and history
  textMatch('/.git/config', 'high', 'Git repository metadata', /^\s*\[core\]/m, 'the .git directory is served, so the full source and history can be downloaded'),
  textMatch('/.git/HEAD', 'high', 'Git repository metadata', /^ref: refs\//, 'the .git directory is served, so the full source and history can be downloaded'),
  textMatch('/.hg/hgrc', 'high', 'Mercurial repository metadata', /^\s*\[paths\]/m, 'the .hg directory is served'),

  // Credentials and keys
  textMatch('/.npmrc', 'critical', 'npm credentials', /_authToken\s*=/, 'npm auth token exposed'),
  textMatch('/.aws/credentials', 'critical', 'AWS credentials', /aws_access_key_id\s*=/i, 'AWS access keys exposed'),
  textMatch('/id_rsa', 'critical', 'SSH private key', PRIVATE_KEY, 'private key exposed'),
  textMatch('/id_ed25519', 'critical', 'SSH private key', PRIVATE_KEY, 'private key exposed'),
  textMatch('/.ssh/id_rsa', 'critical', 'SSH private key', PRIVATE_KEY, 'private key exposed'),
  textMatch('/server.key', 'critical', 'TLS private key', PRIVATE_KEY, 'private key exposed'),
  textMatch('/privkey.pem', 'critical', 'TLS private key', PRIVATE_KEY, 'private key exposed'),
  textMatch('/.htpasswd', 'high', 'Password file', /^[^\s:#<]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|[A-Za-z0-9./]{13}$)/m, 'password hashes exposed'),
  textMatch('/.vscode/sftp.json', 'high', 'Editor deployment config', /"(password|privateKeyPath|passphrase)"\s*:/, 'SFTP deployment credentials exposed'),
  textMatch('/wp-config.php.bak', 'critical', 'WordPress config backup', /DB_PASSWORD/, 'database credentials exposed'),
  textMatch('/wp-config.php~', 'critical', 'WordPress config backup', /DB_PASSWORD/, 'database credentials exposed'),
  textMatch('/wp-config.php.save', 'critical', 'WordPress config backup', /DB_PASSWORD/, 'database credentials exposed'),

  // Configuration that often embeds secrets
  textMatch('/docker-compose.yml', 'medium', 'Docker Compose file', /^services\s*:/m, 'service configuration exposed; check it for inline secrets'),
  textMatch('/docker-compose.yaml', 'medium', 'Docker Compose file', /^services\s*:/m, 'service configuration exposed; check it for inline secrets'),
  textMatch('/config/database.yml', 'high', 'Database config', /^\s*(password|username)\s*:/m, 'database configuration exposed'),

  // Database dumps and backups
  textMatch('/dump.sql', 'critical', 'Database dump', SQL, 'SQL dump exposed'),
  textMatch('/backup.sql', 'critical', 'Database dump', SQL, 'SQL dump exposed'),
  textMatch('/database.sql', 'critical', 'Database dump', SQL, 'SQL dump exposed'),
  textMatch('/db.sql', 'critical', 'Database dump', SQL, 'SQL dump exposed'),
  binaryMatch('/backup.zip', 'high', 'Site backup', ZIP, 'ZIP archive exposed'),
  binaryMatch('/site.zip', 'high', 'Site backup', ZIP, 'ZIP archive exposed'),
  binaryMatch('/www.zip', 'high', 'Site backup', ZIP, 'ZIP archive exposed'),
  binaryMatch('/backup.tar.gz', 'high', 'Site backup', GZIP, 'gzip archive exposed'),

  // Information leaks
  binaryMatch('/.DS_Store', 'low', 'macOS folder metadata', [0x00, 0x00, 0x00, 0x01, 0x42, 0x75, 0x64, 0x31], 'reveals file and folder names'),
  textMatch('/server-status', 'medium', 'Apache server status', Object.assign(/Apache Server Status/i, { html: true }), 'live request and client information exposed'),
  textMatch('/phpinfo.php', 'medium', 'phpinfo() page', Object.assign(/<title>phpinfo\(\)<\/title>/i, { html: true }), 'PHP configuration and environment exposed'),
];
