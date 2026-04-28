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

function sanitizeName(raw, fallback) {
    let name = raw || fallback;
    name = name.replace(/[&\*\{\}\[\]\|\\\<\>\?\:\/]/g, '').trim();
    return name.length ? name : fallback;
}

// 解析 vmess://
function parseVmess(uri) {
    if (!uri.startsWith('vmess://')) return null;
    const b64 = uri.slice(8);
    const decoded = base64Decode(b64);
    if (!decoded) return null;
    try {
        const cfg = JSON.parse(decoded);
        return {
            name: sanitizeName(cfg.ps || cfg.remark, 'vmess'),
            type: 'vmess',
            server: cfg.add || cfg.host,
            port: parseInt(cfg.port) || 443,
            uuid: cfg.id || cfg.uuid,
            alterId: cfg.aid !== undefined ? parseInt(cfg.aid) : (cfg.alterId || 0),
            cipher: cfg.security || cfg.scy || 'auto',
            tls: cfg.tls === 'tls' || cfg.tls === true || (cfg.tls && cfg.tls !== 'none'),
            'skip-cert-verify': cfg.allowInsecure === true || cfg.allowInsecure === '1',
            network: cfg.net || cfg.type || 'tcp',
            'ws-path': cfg.path || undefined,
            'ws-headers': cfg.host ? { Host: cfg.host } : undefined,
            servername: cfg.sni || (cfg.host && cfg.tls ? cfg.host : undefined)
        };
    } catch (e) { return null; }
}

// 解析 vless://
function parseVless(uri) {
    if (!uri.startsWith('vless://')) return null;
    try {
        const url = new URL(uri);
        return {
            name: sanitizeName(decodeURIComponent(url.hash.slice(1)), 'vless'),
            type: 'vless',
            server: url.hostname,
            port: parseInt(url.port) || 443,
            uuid: url.username,
            flow: url.searchParams.get('flow') || '',
            encryption: url.searchParams.get('encryption') || 'none',
            tls: url.searchParams.get('security') === 'tls' || url.searchParams.get('security') === 'reality',
            'skip-cert-verify': url.searchParams.get('allowInsecure') === '1',
            servername: url.searchParams.get('sni') || url.searchParams.get('host') || url.hostname,
            network: url.searchParams.get('type') || 'tcp',
            'ws-path': url.searchParams.get('path') || undefined,
            'ws-headers': url.searchParams.get('host') ? { Host: url.searchParams.get('host') } : undefined,
            realityOpts: url.searchParams.get('security') === 'reality' ? {
                'public-key': url.searchParams.get('pbk'),
                'short-id': url.searchParams.get('sid')
            } : undefined
        };
    } catch (e) { return null; }
}

// 解析 trojan://
function parseTrojan(uri) {
    if (!uri.startsWith('trojan://')) return null;
    try {
        const url = new URL(uri);
        return {
            name: sanitizeName(decodeURIComponent(url.hash.slice(1)), 'trojan'),
            type: 'trojan',
            server: url.hostname,
            port: parseInt(url.port) || 443,
            password: url.username,
            udp: true,
            tls: true,
            'skip-cert-verify': url.searchParams.get('allowInsecure') === '1' || url.searchParams.get('skip-cert-verify') === '1',
            sni: url.searchParams.get('sni') || url.searchParams.get('peer') || url.hostname,
            network: url.searchParams.get('type') || 'tcp',
            'ws-path': url.searchParams.get('path') || undefined,
            'ws-headers': url.searchParams.get('host') ? { Host: url.searchParams.get('host') } : undefined
        };
    } catch (e) { return null; }
}

// 解析 ss://
function parseShadowsocks(uri) {
    if (!uri.startsWith('ss://')) return null;
    try {
        let parts = uri.slice(5);
        let name = '';
        const hashIndex = parts.indexOf('#');
        if (hashIndex !== -1) {
            name = decodeURIComponent(parts.slice(hashIndex + 1));
            parts = parts.slice(0, hashIndex);
        }
        let atIndex = parts.indexOf('@');
        let methodPass = '', serverPort = '';
        if (atIndex !== -1) {
            methodPass = parts.slice(0, atIndex);
            serverPort = parts.slice(atIndex + 1);
        } else {
            const decodedMaybe = base64Decode(parts);
            if (decodedMaybe && decodedMaybe.includes('@')) {
                const arr = decodedMaybe.split('@');
                methodPass = arr[0];
                serverPort = arr[1];
            } else return null;
        }
        let method = '', password = '';
        if (methodPass.includes(':')) {
            [method, password] = methodPass.split(':');
        } else {
            const decodedMp = base64Decode(methodPass);
            if (decodedMp && decodedMp.includes(':')) {
                [method, password] = decodedMp.split(':');
            } else return null;
        }
        const [server, portStr] = serverPort.split(':');
        const port = parseInt(portStr) || 8388;
        return {
            name: sanitizeName(name, 'ss'),
            type: 'ss',
            server: server,
            port: port,
            cipher: method,
            password: password,
            udp: true
        };
    } catch (e) { return null; }
}

function urisToProxies(uris) {
    const proxies = [];
    for (const uri of uris) {
        let proxy = null;
        if (uri.startsWith('vmess://')) proxy = parseVmess(uri);
        else if (uri.startsWith('vless://')) proxy = parseVless(uri);
        else if (uri.startsWith('trojan://')) proxy = parseTrojan(uri);
        else if (uri.startsWith('ss://')) proxy = parseShadowsocks(uri);
        if (proxy && proxy.server && proxy.port) proxies.push(proxy);
    }
    return proxies;
}

function generateClashYaml(proxies) {
    if (!proxies.length) return '# 未解析到任何有效节点\n';
    let yaml = `# Clash 配置文件 (自动更新)\n# 生成时间: ${new Date().toUTCString()}\n# 源订阅: roosterkid/openproxylist\n\n`;
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
                for (const [k, v] of Object.entries(p['ws-headers'])) yaml += `      ${k}: ${v}\n`;
            }
            if (p.servername) yaml += `    servername: ${p.servername}\n`;
        } else if (p.type === 'vless') {
            yaml += `    uuid: ${p.uuid}\n`;
            if (p.flow) yaml += `    flow: ${p.flow}\n`;
            if (p.encryption !== 'none') yaml += `    encryption: ${p.encryption}\n`;
            yaml += `    tls: ${p.tls}\n`;
            if (p['skip-cert-verify']) yaml += `    skip-cert-verify: true\n`;
            if (p.servername) yaml += `    servername: ${p.servername}\n`;
            yaml += `    network: ${p.network}\n`;
            if (p['ws-path']) yaml += `    ws-path: ${p['ws-path']}\n`;
            if (p['ws-headers']) yaml += `    ws-headers:\n      Host: ${p['ws-headers'].Host}\n`;
            if (p.realityOpts && p.realityOpts['public-key']) {
                yaml += `    reality-opts:\n      public-key: ${p.realityOpts['public-key']}\n`;
                if (p.realityOpts['short-id']) yaml += `      short-id: ${p.realityOpts['short-id']}\n`;
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
        } else if (p.type === 'ss') {
            yaml += `    cipher: ${p.cipher}\n`;
            yaml += `    password: ${p.password}\n`;
            yaml += `    udp: true\n`;
        }
        yaml += '\n';
    }
    return yaml;
}

// ---------- 主流程 ----------
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
                        const uris = decoded.split(/\r?\n/);
                        for (const u of uris) {
                            const trimmed = u.trim();
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
                const proxies = urisToProxies(allUris);
                const yaml = generateClashYaml(proxies);
                fs.writeFileSync('clash.yaml', yaml, 'utf8');
                console.log(`✅ 转换完成，共生成 ${proxies.length} 个节点。`);
                resolve();
            });
        }).on('error', reject);
    });
}

fetchAndConvert().catch(err => {
    console.error('❌ 转换失败:', err);
    process.exit(1);
});
