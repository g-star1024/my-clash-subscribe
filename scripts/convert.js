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

// 去重函数（关键）
function deduplicateProxyNames(proxies) {
    const nameCount = new Map();
    for (const p of proxies) {
        const originalName = p.name;
        if (nameCount.has(originalName)) {
            nameCount.set(originalName, nameCount.get(originalName) + 1);
            p.name = `${originalName}-${nameCount.get(originalName)}`;
        } else {
            nameCount.set(originalName, 1);
        }
    }
    return proxies;
}

// 以下 parseVmess, parseVless, parseTrojan, parseShadowsocks 函数保持不变
// （为了节省篇幅，这里省略，直接使用你之前提供的完整内容）
// ...（请将你原有的各 parse 函数原样粘贴在此处）...

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
        // ...（后面原来的生成逻辑保持不变）...
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
                let proxies = urisToProxies(allUris);
                proxies = deduplicateProxyNames(proxies);   // 👈 关键行
                const yaml = generateClashYaml(proxies);
                fs.writeFileSync('clash.yaml', yaml, 'utf8');
                console.log(`✅ 转换完成，共生成 ${proxies.length} 个唯一节点。`);
                resolve();
            });
        }).on('error', reject);
    });
}

fetchAndConvert().catch(err => {
    console.error('❌ 转换失败:', err);
    process.exit(1);
});
