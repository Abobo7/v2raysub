const NODE_LINE_RE = /^(vmess|vless|trojan|ss|ssr|hysteria2?|tuic|wireguard):\/\//i;

function b64Decode(s) {
  let str = String(s || '').trim().replace(/\s/g, '');
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  const mod = str.length % 4;
  if (mod) str += '='.repeat(4 - mod);
  return Buffer.from(str, 'base64').toString('utf8');
}

function parseAddr(line, prefix) {
  const rest = line.slice(prefix.length);
  const atIdx = rest.indexOf('@');
  if (atIdx < 0) throw new Error(`invalid ${prefix} url: missing @`);
  const userinfo = rest.slice(0, atIdx);
  const afterAt = rest.slice(atIdx + 1);

  const hashIdx = afterAt.indexOf('#');
  const name = hashIdx >= 0 ? decodeURIComponent(afterAt.slice(hashIdx + 1)) : '';

  const addrPart = hashIdx >= 0 ? afterAt.slice(0, hashIdx) : afterAt;
  const queryIdx = addrPart.indexOf('?');
  const hostPort = queryIdx >= 0 ? addrPart.slice(0, queryIdx) : addrPart;
  const queryStr = queryIdx >= 0 ? addrPart.slice(queryIdx + 1) : '';

  const ipv6Bracket = hostPort.lastIndexOf(']');
  let server, port;
  if (hostPort.startsWith('[') && ipv6Bracket >= 0) {
    server = hostPort.slice(1, ipv6Bracket);
    const colonAfter = hostPort.indexOf(':', ipv6Bracket + 1);
    port = colonAfter >= 0 ? parseInt(hostPort.slice(colonAfter + 1)) || 443 : 443;
  } else {
    const lastColon = hostPort.lastIndexOf(':');
    if (lastColon < 0) throw new Error(`invalid ${prefix} url: missing port`);
    server = hostPort.slice(0, lastColon);
    port = parseInt(hostPort.slice(lastColon + 1)) || 443;
  }

  const params = new URLSearchParams(queryStr);

  return { userinfo, server, port, name, params };
}

function parseVmess(line) {
  const b64 = line.slice('vmess://'.length);
  let json;
  try {
    json = JSON.parse(b64Decode(b64));
  } catch (_) {
    throw new Error('invalid vmess base64');
  }

  const name = String(json.ps || '').trim();
  const server = String(json.add || '').trim();
  const port = parseInt(json.port) || 443;
  const uuid = String(json.id || '').trim();
  const alterId = parseInt(json.aid) || 0;
  const network = String(json.net || 'tcp').trim().toLowerCase();
  const path = String(json.path || '').trim();
  const host = String(json.host || '').trim();
  const tls = String(json.tls || '').trim() === 'tls';
  const sni = String(json.sni || '').trim();
  const type = String(json.type || 'none').trim().toLowerCase();

  if (!server || !uuid) throw new Error('vmess missing required fields');

  return {
    protocol: 'vmess',
    name: name || server,
    server,
    port,
    uuid,
    alterId,
    network: network || 'tcp',
    path: path || '/',
    host: host || '',
    tls,
    sni: sni || '',
    type,
  };
}

function parseVless(line) {
  const { userinfo: uuid, server, port, name, params } = parseAddr(line, 'vless://');
  const network = params.get('type') || 'tcp';

  return {
    protocol: 'vless',
    name: name || server,
    server,
    port,
    uuid,
    network,
    path: params.get('path') || '',
    host: params.get('host') || '',
    tls: params.get('security') === 'tls' || params.get('security') === 'reality',
    sni: params.get('sni') || '',
    flow: params.get('flow') || '',
    fp: params.get('fp') || '',
  };
}

function parseTrojan(line) {
  const { userinfo: password, server, port, name, params } = parseAddr(line, 'trojan://');
  const network = params.get('type') || 'tcp';

  return {
    protocol: 'trojan',
    name: name || server,
    server,
    port,
    password,
    network,
    path: params.get('path') || '',
    host: params.get('host') || '',
    tls: true,
    sni: params.get('sni') || server,
  };
}

function parseSS(line) {
  const rest = line.slice('ss://'.length);
  const hashIdx = rest.indexOf('#');
  const name = hashIdx >= 0 ? decodeURIComponent(rest.slice(hashIdx + 1)) : '';
  const basePart = hashIdx >= 0 ? rest.slice(0, hashIdx) : rest;

  let userinfo, addr;
  const atIdx = basePart.lastIndexOf('@');

  if (atIdx >= 0) {
    userinfo = basePart.slice(0, atIdx);
    addr = basePart.slice(atIdx + 1);
  } else {
    const decoded = b64Decode(basePart);
    const atIdx2 = decoded.lastIndexOf('@');
    if (atIdx2 < 0) throw new Error('invalid ss url');
    userinfo = decoded.slice(0, atIdx2);
    addr = decoded.slice(atIdx2 + 1);
  }

  let method, password;
  try {
    const decoded = b64Decode(userinfo);
    if (decoded.includes(':')) {
      const colonIdx = decoded.indexOf(':');
      method = decoded.slice(0, colonIdx);
      password = decoded.slice(colonIdx + 1);
    } else {
      throw new Error('not base64 userinfo');
    }
  } catch (_) {
    const colonIdx = userinfo.indexOf(':');
    if (colonIdx < 0) throw new Error('invalid ss userinfo');
    method = userinfo.slice(0, colonIdx);
    password = userinfo.slice(colonIdx + 1);
  }

  const ipv6Bracket = addr.lastIndexOf(']');
  let server, port;
  if (addr.startsWith('[') && ipv6Bracket >= 0) {
    server = addr.slice(1, ipv6Bracket);
    const colonAfter = addr.indexOf(':', ipv6Bracket + 1);
    port = colonAfter >= 0 ? parseInt(addr.slice(colonAfter + 1)) || 8388 : 8388;
  } else {
    const lastColon = addr.lastIndexOf(':');
    if (lastColon < 0) throw new Error('invalid ss url: missing port');
    server = addr.slice(0, lastColon);
    port = parseInt(addr.slice(lastColon + 1)) || 8388;
  }

  return {
    protocol: 'ss',
    name: name || server,
    server,
    port,
    cipher: method,
    password,
    network: 'tcp',
  };
}

function parseHysteria2(line) {
  const prefix = line.startsWith('hysteria2://') ? 'hysteria2://' : 'hysteria://';
  const { userinfo: auth, server, port, name, params } = parseAddr(line, prefix);

  const authParam = params.get('auth');
  const password = authParam || auth;

  return {
    protocol: 'hysteria2',
    name: name || server,
    server,
    port,
    password,
    sni: params.get('sni') || server,
    skipCertVerify: params.get('insecure') === '1',
    network: 'udp',
  };
}

function parseTuic(line) {
  const { userinfo, server, port, name, params } = parseAddr(line, 'tuic://');
  const colonIdx = userinfo.indexOf(':');
  const uuid = colonIdx >= 0 ? userinfo.slice(0, colonIdx) : userinfo;
  const password = colonIdx >= 0 ? userinfo.slice(colonIdx + 1) : '';

  const alpnRaw = params.get('alpn');
  const alpn = alpnRaw ? alpnRaw.split(',').map(function (s) { return s.trim(); }).filter(Boolean) : ['h3'];

  return {
    protocol: 'tuic',
    name: name || server,
    server,
    port,
    uuid,
    password,
    sni: params.get('sni') || server,
    congestionController: params.get('congestion_control') || 'bbr',
    alpn: alpn,
    network: 'tcp',
    tls: true,
  };
}

function parseWireguard(line) {
  const b64 = line.slice('wireguard://'.length);
  let decoded;
  try {
    decoded = b64Decode(b64);
  } catch (_) {
    throw new Error('invalid wireguard url');
  }

  const lines = decoded.split('\n');
  let server = '', port = 51820, privateKey = '', publicKey = '', address = '', name = '';

  for (var i = 0; i < lines.length; i++) {
    var l = lines[i].trim();
    var eqIdx = l.indexOf('=');
    if (eqIdx < 0) continue;
    var key = l.slice(0, eqIdx).trim().toLowerCase();
    var value = l.slice(eqIdx + 1).trim();

    if (key === 'endpoint') {
      var parts = value.split(':');
      server = parts[0];
      if (parts[1]) port = parseInt(parts[1]) || 51820;
    } else if (key === 'privatekey') {
      privateKey = value;
    } else if (key === 'publickey') {
      publicKey = value;
    } else if (key === 'address') {
      address = value;
    } else if (key === '#') {
      name = value;
    }
  }

  if (!server) throw new Error('wireguard missing endpoint');

  return {
    protocol: 'wireguard',
    name: name || server || 'wg',
    server: server,
    port,
    privateKey,
    publicKey,
    address,
    network: 'udp',
  };
}

function parseNodeLine(line) {
  var trimmed = String(line || '').trim();
  if (!trimmed) return null;

  var match = trimmed.match(NODE_LINE_RE);
  if (!match) return null;

  var proto = match[1].toLowerCase();

  try {
    switch (proto) {
      case 'vmess': return parseVmess(trimmed);
      case 'vless': return parseVless(trimmed);
      case 'trojan': return parseTrojan(trimmed);
      case 'ss': return parseSS(trimmed);
      case 'hysteria':
      case 'hysteria2': return parseHysteria2(trimmed);
      case 'tuic': return parseTuic(trimmed);
      case 'wireguard': return parseWireguard(trimmed);
      default: return null;
    }
  } catch (_) {
    return null;
  }
}

function yamlVal(v) {
  if (v === null || v === undefined) return '';
  var s = String(v);
  if (s === '') return '';
  if (/[{}[\]&*!>|#@`"'%:,]/.test(s) || /^[\s-]/.test(s) || /\s$/.test(s) || /:\s/.test(s) || s === 'true' || s === 'false' || s === 'null' || s === 'yes' || s === 'no' || s === 'on' || s === 'off' || /^\d/.test(s) && /[^\d.]/.test(s)) {
    return JSON.stringify(s);
  }
  return s;
}

function nodeToMihomoProxy(parsed, options) {
  var opts = options || {};
  var fronting = opts.fronting || '';
  var hostHeader = parsed.host || parsed.server;
  var target = fronting || parsed.server;

  var proxy = {
    name: parsed.name,
    type: parsed.protocol === 'hysteria' ? 'hysteria2' : parsed.protocol,
    server: target,
    port: parsed.port,
  };

  switch (parsed.protocol) {
    case 'vmess':
      proxy.uuid = parsed.uuid;
      proxy.alterId = parsed.alterId;
      proxy.cipher = 'auto';
      break;
    case 'vless':
      proxy.uuid = parsed.uuid;
      if (parsed.flow) proxy.flow = parsed.flow;
      break;
    case 'trojan':
      proxy.password = parsed.password;
      break;
    case 'ss':
      proxy.cipher = parsed.cipher;
      proxy.password = parsed.password;
      break;
    case 'hysteria':
    case 'hysteria2':
      proxy.password = parsed.password;
      if (parsed.sni) proxy.sni = parsed.sni;
      if (parsed.skipCertVerify) proxy['skip-cert-verify'] = true;
      break;
    case 'tuic':
      proxy.uuid = parsed.uuid;
      proxy.password = parsed.password;
      if (parsed.sni) proxy.sni = parsed.sni;
      if (parsed.congestionController) proxy['congestion-controller'] = parsed.congestionController;
      if (parsed.alpn && parsed.alpn.length) proxy.alpn = parsed.alpn;
      break;
    case 'wireguard':
      proxy['private-key'] = parsed.privateKey;
      proxy['public-key'] = parsed.publicKey;
      if (parsed.address) proxy.ip = parsed.address;
      break;
  }

  var net = parsed.network || 'tcp';
  if (net === 'httpupgrade') net = 'ws';
  if (net !== 'tcp' || parsed.protocol === 'hysteria2' || parsed.protocol === 'wireguard') {
    proxy.network = net;
  }

  if (net === 'ws' && (parsed.path || fronting)) {
    proxy.wsOpts = {
      path: parsed.path || '/',
      v2rayHttpUpgrade: true,
    };
    if (fronting) {
      proxy.wsOpts.headers = { Host: parsed.server };
    } else if (parsed.host) {
      proxy.wsOpts.headers = { Host: parsed.host };
    }
  }

  if (net === 'h2' && (parsed.path || parsed.host || fronting)) {
    proxy.h2Opts = {
      path: parsed.path || '/',
      host: [fronting ? parsed.server : (parsed.host || parsed.server)],
    };
  }

  if (net === 'grpc') {
    proxy.grpcOpts = {
      serviceName: parsed.path || parsed.host || '',
    };
  }

  if (parsed.tls || parsed.protocol === 'trojan') {
    proxy.tls = true;
    var serverName = parsed.sni || parsed.host || parsed.server;
    if (serverName) proxy.servername = serverName;
  }

  if (parsed.protocol === 'trojan' && parsed.sni) {
    proxy.sni = parsed.sni;
  }

  return proxy;
}

function proxyToYAMLLines(proxy, indent) {
  var sp = ' '.repeat(indent >= 0 ? indent : 2);
  var sp2 = ' '.repeat((indent >= 0 ? indent : 2) + 2);
  var sp3 = ' '.repeat((indent >= 0 ? indent : 2) + 4);
  var lines = [];

  lines.push(sp + '- name: ' + yamlVal(proxy.name));
  lines.push(sp2 + 'type: ' + yamlVal(proxy.type));
  lines.push(sp2 + 'server: ' + yamlVal(proxy.server));
  lines.push(sp2 + 'port: ' + proxy.port);

  if (proxy.type === 'vmess') {
    lines.push(sp2 + 'udp: true');
    lines.push(sp2 + 'uuid: ' + yamlVal(proxy.uuid));
    lines.push(sp2 + 'alterId: ' + proxy.alterId);
    lines.push(sp2 + 'cipher: auto');
  } else if (proxy.type === 'vless') {
    lines.push(sp2 + 'udp: true');
    lines.push(sp2 + 'uuid: ' + yamlVal(proxy.uuid));
    if (proxy.flow) lines.push(sp2 + 'flow: ' + yamlVal(proxy.flow));
  } else if (proxy.type === 'trojan') {
    lines.push(sp2 + 'udp: true');
    lines.push(sp2 + 'password: ' + yamlVal(proxy.password));
  } else if (proxy.type === 'ss') {
    lines.push(sp2 + 'udp: true');
    lines.push(sp2 + 'cipher: ' + yamlVal(proxy.cipher));
    lines.push(sp2 + 'password: ' + yamlVal(proxy.password));
  } else if (proxy.type === 'hysteria2') {
    lines.push(sp2 + 'password: ' + yamlVal(proxy.password));
    if (proxy.sni) lines.push(sp2 + 'sni: ' + yamlVal(proxy.sni));
    if (proxy['skip-cert-verify']) lines.push(sp2 + 'skip-cert-verify: true');
  } else if (proxy.type === 'tuic') {
    lines.push(sp2 + 'uuid: ' + yamlVal(proxy.uuid));
    lines.push(sp2 + 'password: ' + yamlVal(proxy.password));
    if (proxy.sni) lines.push(sp2 + 'sni: ' + yamlVal(proxy.sni));
    if (proxy['congestion-controller']) lines.push(sp2 + 'congestion-controller: ' + yamlVal(proxy['congestion-controller']));
    if (proxy.alpn && proxy.alpn.length) {
      lines.push(sp2 + 'alpn:');
      for (var ai = 0; ai < proxy.alpn.length; ai++) lines.push(sp3 + '- ' + yamlVal(proxy.alpn[ai]));
    }
  } else if (proxy.type === 'wireguard') {
    lines.push(sp2 + 'private-key: ' + yamlVal(proxy['private-key']));
    lines.push(sp2 + 'public-key: ' + yamlVal(proxy['public-key']));
    if (proxy.ip) lines.push(sp2 + 'ip: ' + yamlVal(proxy.ip));
  }

  if (proxy.network) {
    lines.push(sp2 + 'network: ' + yamlVal(proxy.network));
  }

  if (proxy.wsOpts) {
    lines.push(sp2 + 'ws-opts:');
    lines.push(sp3 + 'path: ' + yamlVal(proxy.wsOpts.path));
    if (proxy.wsOpts.headers && proxy.wsOpts.headers.Host) {
      lines.push(sp3 + 'headers:');
      lines.push(' '.repeat((indent >= 0 ? indent : 2) + 6) + 'Host: ' + yamlVal(proxy.wsOpts.headers.Host));
    }
    if (proxy.wsOpts.v2rayHttpUpgrade) {
      lines.push(sp3 + 'v2ray-http-upgrade: true');
    }
  }

  if (proxy.h2Opts) {
    lines.push(sp2 + 'h2-opts:');
    lines.push(sp3 + 'path: ' + yamlVal(proxy.h2Opts.path));
    if (proxy.h2Opts.host && proxy.h2Opts.host.length) {
      lines.push(sp3 + 'host:');
      for (var hi = 0; hi < proxy.h2Opts.host.length; hi++) lines.push(sp3 + '  - ' + yamlVal(proxy.h2Opts.host[hi]));
    }
  }

  if (proxy.grpcOpts) {
    lines.push(sp2 + 'grpc-opts:');
    lines.push(sp3 + 'grpc-service-name: ' + yamlVal(proxy.grpcOpts.serviceName));
  }

  if (proxy.tls) {
    lines.push(sp2 + 'tls: true');
    if (proxy.servername) lines.push(sp2 + 'servername: ' + yamlVal(proxy.servername));
  }

  if (proxy.sni && proxy.type === 'trojan') {
    lines.push(sp2 + 'sni: ' + yamlVal(proxy.sni));
  }

  return lines;
}

function formatDate(date) {
  var y = date.getFullYear();
  var m = String(date.getMonth() + 1).padStart(2, '0');
  var d = String(date.getDate()).padStart(2, '0');
  return y + '-' + m + '-' + d;
}

function generateMihomoYAML(proxies, meta) {
  var metaObj = meta || {};
  var sourceUrl = metaObj.sourceUrl || '';
  var fronting = metaObj.fronting || '';
  var now = new Date();
  var today = formatDate(now);

  var lines = [];

  lines.push('# Import this into FlClash/Mihomo.');
  if (sourceUrl) {
    lines.push('# Source subscription fetched on ' + today + ' from ' + sourceUrl);
  }
  if (fronting) {
    lines.push('# VMESS fronting host switched to ' + fronting + ' on ' + today + '.');
  }
  lines.push('');

  lines.push('mixed-port: 7890');
  lines.push('mode: rule');
  lines.push('log-level: info');
  lines.push('allow-lan: false');
  lines.push('ipv6: true');
  lines.push('unified-delay: true');
  lines.push('');

  lines.push('geodata-mode: true');
  lines.push('geo-auto-update: true');
  lines.push('geo-update-interval: 24');
  lines.push('');

  lines.push('dns:');
  lines.push('  enable: true');
  lines.push('  ipv6: true');
  lines.push('  respect-rules: true');
  lines.push('  enhanced-mode: fake-ip');
  lines.push('  default-nameserver:');
  lines.push('    - 223.5.5.5');
  lines.push('    - 119.29.29.29');
  lines.push('  proxy-server-nameserver:');
  lines.push('    - 223.5.5.5');
  lines.push('    - 119.29.29.29');
  lines.push('  nameserver:');
  lines.push('    - 223.5.5.5');
  lines.push('    - 119.29.29.29');
  lines.push('  nameserver-policy:');
  lines.push('    "geosite:private,cn":');
  lines.push('      - 223.5.5.5');
  lines.push('      - 119.29.29.29');
  lines.push('  fallback:');
  lines.push('    - https://1.1.1.1/dns-query');
  lines.push('    - https://dns.google/dns-query');
  lines.push('  fallback-filter:');
  lines.push('    geoip: true');
  lines.push('    geoip-code: CN');
  lines.push('    geosite:');
  lines.push('      - gfw');
  lines.push('');

  lines.push('proxies:');
  for (var i = 0; i < proxies.length; i++) {
    var proxyLines = proxyToYAMLLines(proxies[i], 2);
    for (var j = 0; j < proxyLines.length; j++) lines.push(proxyLines[j]);
  }
  lines.push('');

  var proxyNames = [];
  for (var k = 0; k < proxies.length; k++) proxyNames.push(proxies[k].name);

  lines.push('proxy-groups:');
  lines.push('  - name: AUTO');
  lines.push('    type: url-test');
  lines.push('    proxies:');
  for (var m = 0; m < proxyNames.length; m++) lines.push('      - ' + yamlVal(proxyNames[m]));
  lines.push('    url: https://cp.cloudflare.com/generate_204');
  lines.push('    interval: 300');
  lines.push('    timeout: 10000');
  lines.push('    lazy: false');
  lines.push('    expected-status: 204');
  lines.push('    tolerance: 50');
  lines.push('');

  lines.push('  - name: PROXY');
  lines.push('    type: select');
  lines.push('    proxies:');
  lines.push('      - AUTO');
  for (var n = 0; n < proxyNames.length; n++) lines.push('      - ' + yamlVal(proxyNames[n]));
  lines.push('      - DIRECT');
  lines.push('');

  lines.push('rules:');
  lines.push('  - GEOSITE,private,DIRECT');
  lines.push('  - GEOSITE,cn,DIRECT');
  lines.push('  - GEOIP,CN,DIRECT,no-resolve');
  lines.push('  - MATCH,PROXY');

  return lines.join('\n') + '\n';
}

function generateMihomoConfig(nodeLines, options) {
  var opts = options || {};
  var fronting = opts.fronting || '';
  var sourceUrl = opts.sourceUrl || '';

  var parsedNodes = [];
  for (var i = 0; i < nodeLines.length; i++) {
    var parsed = parseNodeLine(nodeLines[i]);
    if (parsed) parsedNodes.push(parsed);
  }

  var proxies = [];
  for (var j = 0; j < parsedNodes.length; j++) {
    proxies.push(nodeToMihomoProxy(parsedNodes[j], { fronting: fronting }));
  }

  var yaml = generateMihomoYAML(proxies, { sourceUrl: sourceUrl, fronting: fronting });

  return { yaml: yaml, proxies: proxies, parsedNodes: parsedNodes };
}

module.exports = {
  parseNodeLine: parseNodeLine,
  nodeToMihomoProxy: nodeToMihomoProxy,
  generateMihomoYAML: generateMihomoYAML,
  generateMihomoConfig: generateMihomoConfig,
};
