const crypto = require('crypto');

const CN_URLS = [
  'https://bannedbook.github.io/fanqiang/vsp-cn.py',
  'https://raw.githubusercontent.com/bannedbook/fanqiang/master/docs/vsp-cn.py',
];

const EN_URLS = [
  'https://bannedbook.github.io/fanqiang/vsp-en.py',
  'https://raw.githubusercontent.com/bannedbook/fanqiang/master/docs/vsp-en.py',
  'https://gitlab.com/bobmolen/cloud/raw/master/vsp-en.py',
  'https://storage.googleapis.com/jwnews/vsp-en.py',
];

const DEFAULT_URLS = [...CN_URLS, ...EN_URLS];

const DEFAULT_USER_AGENT = 'NekoBox/Android/6.5.0 (Prefer ClashMeta Format)';
const KEY = Buffer.from('36KeAARKZuKF39N9LFyycLUyKMhZDq0B', 'utf8');
const IV = Buffer.from('36KeAARKZuKF39N9', 'utf8');
const NODE_LINE_RE = /^(vmess|vless|trojan|ss|ssr|hysteria2?|tuic|wireguard):\/\//i;

function parseUrlsFromEnv() {
  const raw = (process.env.SUB_URLS || '').trim();
  if (!raw) return DEFAULT_URLS;
  return raw.split(',').map((v) => v.trim()).filter(Boolean);
}

function parseUrlsFromRegion(region = 'cn') {
  const r = String(region || '').toLowerCase();
  if (r === 'en') return EN_URLS;
  if (r === 'cn') return CN_URLS;
  return DEFAULT_URLS;
}

function normalizeBase64(input) {
  let x = String(input || '').trim().replace(/\s+/g, '');
  x = x.replace(/-/g, '+').replace(/_/g, '/');
  const mod = x.length % 4;
  if (mod) x += '='.repeat(4 - mod);
  return x;
}

function decodeBase64Text(input) {
  return Buffer.from(normalizeBase64(input), 'base64');
}

function aesDecryptVsp(cipherText) {
  const encrypted = decodeBase64Text(cipherText);
  if (!encrypted.length || encrypted.length % 16 !== 0) {
    throw new Error(`cipher length invalid: ${encrypted.length}`);
  }
  const decipher = crypto.createDecipheriv('aes-256-cbc', KEY, IV);
  const plain = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return plain.toString('utf8');
}

function extractBase64Candidates(text) {
  const candidates = new Set();
  const trimmed = String(text || '').trim();
  if (trimmed) candidates.add(trimmed);

  const found = String(text || '').match(/[A-Za-z0-9+/_=-]{200,}/g) || [];
  for (const f of found) candidates.add(f);

  return [...candidates];
}

function extractNodeLines(text) {
  return String(text || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => NODE_LINE_RE.test(line));
}

function parsePlainOrEncrypted(text) {
  const raw = String(text || '').trim();
  if (!raw) throw new Error('empty payload');

  const directNodes = extractNodeLines(raw);
  if (directNodes.length) {
    return {
      mode: 'plain',
      plainText: raw,
      nodes: directNodes,
    };
  }

  const candidates = extractBase64Candidates(raw);
  for (const c of candidates) {
    try {
      const decrypted = aesDecryptVsp(c).trim();
      const nodes = extractNodeLines(decrypted);
      if (nodes.length) {
        return {
          mode: 'aes',
          plainText: decrypted,
          nodes,
        };
      }
    } catch (_) {
      // try next decoder
    }

    try {
      const decoded = decodeBase64Text(c).toString('utf8').trim();
      const nodes = extractNodeLines(decoded);
      if (nodes.length) {
        return {
          mode: 'base64',
          plainText: decoded,
          nodes,
        };
      }
    } catch (_) {
      // try next candidate
    }
  }

  throw new Error(`unable to parse payload; candidates=${candidates.length}`);
}

async function fetchText(url, userAgent = DEFAULT_USER_AGENT) {
  const resp = await fetch(url, {
    headers: {
      'user-agent': userAgent,
      accept: '*/*',
    },
  });

  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status} ${resp.statusText}`);
  }

  return await resp.text();
}

async function fetchAndDecrypt({ urls, userAgent }) {
  const errors = [];

  for (const url of urls) {
    try {
      const rawText = await fetchText(url, userAgent);
      const parsed = parsePlainOrEncrypted(rawText);
      return {
        sourceUrl: url,
        ...parsed,
      };
    } catch (err) {
      errors.push({
        url,
        error: String((err && err.message) || err),
      });
    }
  }

  const detail = errors.map((e) => `${e.url}: ${e.error}`).join('; ');
  throw new Error(`all sources failed: ${detail}`);
}

module.exports = {
  DEFAULT_URLS,
  CN_URLS,
  EN_URLS,
  DEFAULT_USER_AGENT,
  parseUrlsFromEnv,
  parseUrlsFromRegion,
  parsePlainOrEncrypted,
  fetchAndDecrypt,
};
