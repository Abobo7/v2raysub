module.exports = function handler(req, res) {
  res.status(200).json({
    ok: true,
    service: 'v2raysub-decrypt-api',
    endpoint: '/api/decrypt',
  });
};