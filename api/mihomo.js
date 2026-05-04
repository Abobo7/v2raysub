const {
  parseUrlsFromEnv,
  parseUrlsFromRegion,
  DEFAULT_USER_AGENT,
  fetchAndDecrypt,
} = require('../lib/subscription');
const { generateMihomoConfig } = require('../lib/mihomo');

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', '*');
    return res.status(204).end();
  }

  if (req.method !== 'GET') {
    return res.status(405).json({ ok: false, error: 'method not allowed' });
  }

  try {
    const queryUrls = String(req.query.urls || '').trim();
    const queryUrl = String(req.query.url || '').trim();
    const region = String(req.query.region || process.env.SUB_REGION || 'cn').trim().toLowerCase();
    const fronting = String(req.query.fronting || '').trim();
    const format = String(req.query.format || 'yaml').toLowerCase();

    const urls = queryUrls
      ? queryUrls.split(',').map((v) => v.trim()).filter(Boolean)
      : queryUrl
      ? [queryUrl]
      : (process.env.SUB_URLS ? parseUrlsFromEnv() : parseUrlsFromRegion(region));

    const userAgent = String(req.query.ua || process.env.SUB_USER_AGENT || DEFAULT_USER_AGENT).trim();

    const result = await fetchAndDecrypt({ urls, userAgent });

    const config = generateMihomoConfig(result.nodes, {
      fronting,
      sourceUrl: result.sourceUrl,
    });

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cache-Control', 's-maxage=300, stale-while-revalidate=600');
    res.setHeader('X-Source-Url', result.sourceUrl);
    res.setHeader('X-Decrypt-Mode', result.mode);
    res.setHeader('X-Total-Nodes', String(result.nodes.length));
    res.setHeader('X-Parsed-Proxies', String(config.parsedNodes.length));
    res.setHeader('X-Fronting', fronting || 'none');

    if (format === 'json') {
      return res.status(200).json({
        ok: true,
        sourceUrl: result.sourceUrl,
        mode: result.mode,
        fronting: fronting || null,
        totalNodes: result.nodes.length,
        proxyCount: config.parsedNodes.length,
        proxies: config.proxies,
        yaml: config.yaml,
      });
    }

    res.setHeader('Content-Type', 'text/yaml; charset=utf-8');
    return res.status(200).send(config.yaml);
  } catch (err) {
    return res.status(500).json({
      ok: false,
      error: String((err && err.message) || err),
    });
  }
};
