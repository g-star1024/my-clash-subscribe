const fs = require('fs');
const https = require('https');

// ----------------------------- 工具函数 -----------------------------
function base64Decode(str) {
    try {
        let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4) b64 += '=';
        return Buffer.from(b64, 'base64').toString('utf-8');
    } catch (e) {
        return null;
    }
}

function isValidPort(port) {
    const p = parseInt(port);
    return Number.isInteger(p) && p > 0 && p <= 65535;
}

function isValidServer(server) {
    if (!server || typeof server !== 'string') return false;
    server = server.trim();
    // 简单域名或IPv4/IPv6校验（宽松）
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$/;
    return ipv4Regex.test(server) || domainRegex.test(server);
}

function sanitizeName(raw, fallback) {
    let name = raw || fallback;
    name = name.replace(/[&\*\{\}\[\]\|\\\<\>\?\:\/]/g, '').trim();
    if (name.length === 0) name = fallback;
    return name;
}

function isNonEmptyString(str) {
    return str && typeof str === 'string' && str.trim().length > 0;
}

// 严格去重（保留第一个，后续重复加序号）
function deduplicateProxyNames(proxies) {
    const nameCount = new Map();
    const result = [];
    for (const p of proxies) {
        let finalName = p.name;
        if (nameCount.has(finalName)) {
            const count = nameCount.get(finalName);
            nameCount.set(finalName, count + 1);
            finalName = `${finalName}-${count + 1}`;
        } else {
            nameCount.set(finalName, 1);
        }
        result.push({ ...p, name: finalName });
    }
    return result;
}

// ----------------------------- 各协议严格解析 -----------------------------

function parseVmess(uri) {
    if (!uri.startsWith('vmess://')) return null;
    const b64 = uri.slice(8);
    const decoded = base64Decode(b64);
    if (!decoded) return null;
    let cfg;
    try {
        cfg = JSON.parse(decoded);
    } catch (e) {
        return null;
    }

    // 必需字段检查
    const server = cfg.add || cfg.host;
    const port = cfg.port ? parseInt(cfg.port) : null;
    const uuid = cfg.id || cfg.uuid;
    if (!isValidServer(server) || !isValidPort(port) || !isNonEmptyString(uuid)) {
        return null;
    }

    const proxy = {
        name: sanitizeName(cfg.ps || cfg.remark, 'vmess'),
        type: 'vmess',
        server: server,
        port: port,
        uuid: uuid,
        alterId: cfg.aid !== undefined ? parseInt(cfg.aid) : (cfg.alterId !== undefined ? parseInt(cfg.alterId) : 0),
        cipher: cfg.security || cfg.scy || 'auto',
        tls: cfg.tls === 'tls' || cfg.tls === true || (cfg.tls && cfg.tls !== 'none'),
        'skip-cert-verify': cfg.allowInsecure === true || cfg.allowInsecure === '1',
        network: cfg.net || cfg.type || 'tcp',
    };

    // network 只允许合法类型
    const allowedNetworks = ['tcp', 'ws', 'grpc', 'h2', 'http'];
    if (!allowedNetworks.includes(proxy.network)) proxy.network = 'tcp';

    // 传输层特定字段
    if (proxy.network === 'ws') {
        if (cfg.path) proxy['ws-path'] = cfg.path;
        if (cfg.host) proxy['ws-headers'] = { Host: cfg.host };
    }
    if (proxy.network === 'grpc' && cfg.path) {
        proxy['grpc-service-name'] = cfg.path;
    }
    if (proxy.network === 'http' && cfg.path) {
        proxy['http-path'] = cfg.path;
    }
    if (cfg.sni) proxy.servername = cfg.sni;
    else if (cfg.host && proxy.tls) proxy.servername = cfg.host;

    return proxy;
}

function parseVless(uri) {
    if (!uri.startsWith('vless://')) return null;
    let url;
    try {
        url = new URL(uri);
    } catch (e) {
        return null;
    }

    const server = url.hostname;
    const port = parseInt(url.port);
    const uuid = url.username;
    if (!isValidServer(server) || !isValidPort(port) || !isNonEmptyString(uuid)) {
        return null;
    }

    const params = url.searchParams;
    const security = params.get('security') || 'none';
    const type = params.get('type') || 'tcp';
    const flow = params.get('flow') || '';
    const encryption = params.get('encryption') || 'none';
    const sni = params.get('sni') || params.get('host') || server;
    const allowInsecure = params.get('allowInsecure') === '1';
    const host = params.get('host') || '';
    const path = params.get('path') || '';

    // Reality 特殊校验：必须同时有 public-key 和 short-id
    if (security === 'reality') {
        const pbk = params.get('pbk');
        const sid = params.get('sid');
        if (!isNonEmptyString(pbk) || !isNonEmptyString(sid)) {
            return null; // 不完整 Reality 丢弃
        }
    }

    const allowedNetworks = ['tcp', 'ws', 'grpc', 'h2', 'http'];
    const finalNetwork = allowedNetworks.includes(type) ? type : 'tcp';

    const proxy = {
        name: sanitizeName(decodeURIComponent(url.hash.slice(1)), 'vless'),
        type: 'vless',
        server: server,
        port: port,
        uuid: uuid,
        flow: flow,
        encryption: encryption !== 'none' ? encryption : undefined,
        tls: security === 'tls' || security === 'reality',
        'skip-cert-verify': allowInsecure,
        servername: sni,
        network: finalNetwork,
    };
    // 清理 undefined 字段
    if (proxy.encryption === undefined) delete proxy.encryption;

    if (finalNetwork === 'ws') {
        if (path) proxy['ws-path'] = path;
        if (host) proxy['ws-headers'] = { Host: host };
    }
    if (finalNetwork === 'grpc' && path) {
        proxy['grpc-service-name'] = path;
    }
    if (security === 'reality') {
        proxy['reality-opts'] = {
            'public-key': params.get('pbk'),
            'short-id': params.get('sid')
        };
    }
    return proxy;
}

function parseTrojan(uri) {
    if (!uri.startsWith('trojan://')) return null;
    let url;
    try {
        url = new URL(uri);
    } catch (e) {
        return null;
    }

    const server = url.hostname;
    const port = parseInt(url.port);
    const password = url.username;
    if (!isValidServer(server) || !isValidPort(port) || !isNonEmptyString(password)) {
        return null;
    }

    const params = url.searchParams;
    const sni = params.get('sni') || params.get('peer') || server;
    const allowInsecure = params.get('allowInsecure') === '1' || params.get('skip-cert-verify') === '1';
    const type = params.get('type') || 'tcp';
    const host = params.get('host') || '';
    const path = params.get('path') || '';

    const allowedNetworks = ['tcp', 'ws', 'grpc', 'h2', 'http'];
    const finalNetwork = allowedNetworks.includes(type) ? type : 'tcp';

    const proxy = {
        name: sanitizeName(decodeURIComponent(url.hash.slice(1)), 'trojan'),
        type: 'trojan',
        server: server,
        port: port,
        password: password,
        udp: true,
        tls: true,
        'skip-cert-verify': allowInsecure,
        sni: sni,
        network: finalNetwork,
    };
    if (finalNetwork === 'ws') {
        if (path) proxy['ws-path'] = path;
        if (host) proxy['ws-headers'] = { Host: host };
    }
    if (finalNetwork === 'grpc' && path) {
        proxy['grpc-service-name'] = path;
    }
    return proxy;
}

function parseShadowsocks(uri) {
    if (!uri.startsWith('ss://')) return null;
    let parts = uri.slice(5);
    let name = '';
    const hashIndex = parts.indexOf('#');
    if (hashIndex !== -1) {
        name = decodeURIComponent(parts.slice(hashIndex + 1));
        parts = parts.slice(0, hashIndex);
    }
    let method = '', password = '', server = '', port = null;
    const atIndex = parts.indexOf('@');
    if (atIndex !== -1) {
        const methodPass = parts.slice(0, atIndex);
        const serverPort = parts.slice(atIndex + 1);
        if (methodPass.includes(':')) {
            [method, password] = methodPass.split(':');
        } else {
            const decoded = base64Decode(methodPass);
            if (decoded && decoded.includes(':')) {
                [method, password] = decoded.split(':');
            } else return null;
        }
        const [s, p] = serverPort.split(':');
        server = s;
        port = parseInt(p);
    } else {
        // 全 base64 形式
        const decoded = base64Decode(parts);
        if (!decoded || !decoded.includes('@')) return null;
        const [methodPass, serverPort] = decoded.split('@');
        if (methodPass.includes(':')) {
            [method, password] = methodPass.split(':');
        } else {
            const decodedMp = base64Decode(methodPass);
            if (decodedMp && decodedMp.includes(':')) {
                [method, password] = decodedMp.split(':');
            } else return null;
        }
        const [s, p] = serverPort.split(':');
        server = s;
        port = parseInt(p);
    }
    if (!isValidServer(server) || !isValidPort(port) || !isNonEmptyString(method) || !isNonEmptyString(password)) {
        return null;
    }
    return {
        name: sanitizeName(name, 'ss'),
        type: 'ss',
        server: server,
        port: port,
        cipher: method,
        password: password,
        udp: true,
    };
}

// ----------------------------- 主处理流程 -----------------------------
function urisToProxies(uris) {
    const proxies = [];
    for (const uri of uris) {
        let proxy = null;
        if (uri.startsWith('vmess://')) proxy = parseVmess(uri);
        else if (uri.startsWith('vless://')) proxy = parseVless(uri);
        else if (uri.startsWith('trojan://')) proxy = parseTrojan(uri);
        else if (uri.startsWith('ss://')) proxy = parseShadowsocks(uri);
        if (proxy) proxies.push(proxy);
    }
    return proxies;
}

function generateClashYaml(proxies) {
    if (!proxies.length) {
        return '# No valid proxies after strict validation.\n';
    }
    let yaml = `# Clash 配置文件 (严格格式自动生成)\n# 生成时间: ${new Date().toUTCString()}\n# 源订阅: roosterkid/openproxylist\n\n`;
    yaml += 'proxies:\n';
    for (const p of proxies) {
        yaml += `  - name: "${p.name}"\n`;
        yaml += `    type: ${p.type}\n`;
        yaml += `    server: ${p.server}\n`;
        yaml += `    port: ${p.port}\n`;

        if (p.type === 'vmess') {
            yaml += `    uuid: ${p.uuid}\n`;
            yaml += `    alterId: ${p.alterId}\n`;
            yaml += `    cipher: ${p.cipher}\n`;
            yaml += `    tls: ${p.tls}\n`;
            if (p['skip-cert-verify']) yaml += `    skip-cert-verify: true\n`;
            yaml += `    network: ${p.network}\n`;
            if (p['ws-path']) yaml += `    ws-path: ${p['ws-path']}\n`;
            if (p['ws-headers']) {
                yaml += `    ws-headers:\n`;
                for (const [k, v] of Object.entries(p['ws-headers'])) {
                    yaml += `      ${k}: ${v}\n`;
                }
            }
            if (p.servername) yaml += `    servername: ${p.servername}\n`;
        } else if (p.type === 'vless') {
            yaml += `    uuid: ${p.uuid}\n`;
            if (p.flow) yaml += `    flow: ${p.flow}\n`;
            if (p.encryption) yaml += `    encryption: ${p.encryption}\n`;
            yaml += `    tls: ${p.tls}\n`;
            if (p['skip-cert-verify']) yaml += `    skip-cert-verify: true\n`;
            if (p.servername) yaml += `    servername: ${p.servername}\n`;
            yaml += `    network: ${p.network}\n`;
            if (p['ws-path']) yaml += `    ws-path: ${p['ws-path']}\n`;
            if (p['ws-headers']) yaml += `    ws-headers:\n      Host: ${p['ws-headers'].Host}\n`;
            if (p['grpc-service-name']) yaml += `    grpc-service-name: ${p['grpc-service-name']}\n`;
            if (p['reality-opts']) {
                yaml += `    reality-opts:\n`;
                yaml += `      public-key: ${p['reality-opts']['public-key']}\n`;
                yaml += `      short-id: ${p['reality-opts']['short-id']}\n`;
            }
        } else if (p.type === 'trojan') {
            yaml += `    password: ${p.password}\n`;
            yaml += `    udp: true\n`;
            yaml += `    tls: true\n`;
            if (p.sni) yaml += `    sni: ${p.sni}\n`;
            if (p['skip-cert-verify']) yaml += `    skip-cert-verify: true\n`;
            yaml += `    network: ${p.network}\n`;
            if (p['ws-path']) yaml += `    ws-path: ${p['ws-path']}\n`;
            if (p['ws-headers']) yaml += `    ws-headers:\n      Host: ${p['ws-headers'].Host}\n`;
            if (p['grpc-service-name']) yaml += `    grpc-service-name: ${p['grpc-service-name']}\n`;
        } else if (p.type === 'ss') {
            yaml += `    cipher: ${p.cipher}\n`;
            yaml += `    password: ${p.password}\n`;
            yaml += `    udp: true\n`;
        }
        yaml += '\n';
    }
    return yaml;
}

async function fetchAndConvert() {
    const url = 'https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/V2RAY_BASE64.txt';
    return new Promise((resolve, reject) => {
        https.get(url, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                const lines = data.split(/\r?\n/);
                const allUris = [];
                for (const line of lines) {
                    if (!line.trim()) continue;
                    const decoded = base64Decode(line);
                    if (decoded) {
                        const subLines = decoded.split(/\r?\n/);
                        for (const sub of subLines) {
                            const trimmed = sub.trim();
                            if (trimmed && (trimmed.startsWith('vmess://') || trimmed.startsWith('vless://') || trimmed.startsWith('trojan://') || trimmed.startsWith('ss://'))) {
                                allUris.push(trimmed);
                            }
                        }
                    } else {
                        if (line.startsWith('vmess://') || line.startsWith('vless://') || line.startsWith('trojan://') || line.startsWith('ss://')) {
                            allUris.push(line);
                        }
                    }
                }
                let proxies = urisToProxies(allUris);
                proxies = deduplicateProxyNames(proxies);
                const yaml = generateClashYaml(proxies);
                fs.writeFileSync('clash.yaml', yaml, 'utf8');
                console.log(`✅ 严格转换完成，有效节点数: ${proxies.length}`);
                resolve();
            });
        }).on('error', reject);
    });
}

fetchAndConvert().catch(err => {
    console.error('❌ 转换失败:', err);
    process.exit(1);
});
