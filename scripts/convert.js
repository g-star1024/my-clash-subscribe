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

// 去重函数：给重复的名字加上序号 -1, -2, -3...
function deduplicateProxyNames(proxies) {
    const nameCount = new Map();
    const result = [];
    for (const p of proxies) {
        const originalName = p.name;
        let finalName = originalName;
        if (nameCount.has(originalName)) {
            const count = nameCount.get(originalName);
            nameCount.set(originalName, count + 1);
            finalName = `${originalName}-${count + 1}`;
        } else {
            nameCount.set(originalName, 1);
        }
        result.push({ ...p, name: finalName });
    }
    return result;
}

// ----------------------------- 解析各协议 -----------------------------
function parseVmess(uri) {
    if (!uri.startsWith('vmess://')) return null;
    const b64 = uri.slice(8);
    const decoded = base64Decode(b64);
    if (!decoded) return null;
    try {
        const cfg = JSON.parse(decoded);
        const proxy = {
            name: sanitizeName(cfg.ps || cfg.remark || "vmess-node", "vmess"),
            type: "vmess",
            server: cfg.add || cfg.host || "",
            port: parseInt(cfg.port) || 443,
            uuid: cfg.id || cfg.uuid || "",
            alterId: cfg.aid !== undefined ? parseInt(cfg.aid) : (cfg.alterId || 0),
            cipher: cfg.security || cfg.scy || "auto",
            tls: cfg.tls === "tls" || cfg.tls === true || (cfg.tls && cfg.tls !== "none") || false,
            "skip-cert-verify": cfg.allowInsecure === true || cfg.allowInsecure === "1" || false,
            network: cfg.net || cfg.type || "tcp",
        };
        if (proxy.network === "ws") {
            if (cfg.path) proxy["ws-path"] = cfg.path;
            if (cfg.host) proxy["ws-headers"] = { Host: cfg.host };
        }
        if (proxy.network === "grpc" && cfg.path) proxy["grpc-service-name"] = cfg.path;
        if (proxy.network === "http" && cfg.path) proxy["http-path"] = cfg.path;
        if (cfg.sni) proxy.servername = cfg.sni;
        else if (cfg.host && proxy.tls) proxy.servername = cfg.host;
        return proxy;
    } catch (e) {
        return null;
    }
}

function parseVless(uri) {
    if (!uri.startsWith('vless://')) return null;
    try {
        const url = new URL(uri);
        const name = decodeURIComponent(url.hash.substring(1)) || "vless-node";
        const server = url.hostname;
        const port = parseInt(url.port) || 443;
        const uuid = url.username;
        const params = url.searchParams;
        const security = params.get('security') || "none";
        const sni = params.get('sni') || params.get('host') || server;
        const allowInsecure = params.get('allowInsecure') === "1";
        const type = params.get('type') || "tcp";
        const host = params.get('host') || "";
        const path = params.get('path') || "";
        const flow = params.get('flow') || "";
        const encryption = params.get('encryption') || "none";
        
        // ----- 关键修改：Reality 完整性校验 -----
        if (security === "reality") {
            const pbk = params.get('pbk');
            const sid = params.get('sid');
            // 必须同时存在有效的 public-key 和 short-id，否则丢弃该节点
            if (!pbk || !sid || pbk.trim() === "" || sid.trim() === "") {
                console.warn(`丢弃不完整的 Reality 节点: ${name} (缺少 public-key 或 short-id)`);
                return null;
            }
        }
        
        const proxy = {
            name: sanitizeName(name, "vless"),
            type: "vless",
            server: server,
            port: port,
            uuid: uuid,
            flow: flow,
            "skip-cert-verify": allowInsecure,
            tls: security === "tls" || security === "reality",
            network: type,
            servername: sni || (security === "tls" ? server : ""),
        };
        if (encryption !== "none") proxy.encryption = encryption;
        
        // 只有通过校验的 Reality 才会添加 realityOpts
        if (security === "reality") {
            const pbk = params.get('pbk');
            const sid = params.get('sid');
            proxy.realityOpts = {
                "public-key": pbk,
                "short-id": sid
            };
        }
        
        if (type === "ws" && path) proxy["ws-path"] = path;
        if (type === "ws" && host) proxy["ws-headers"] = { Host: host };
        if (type === "grpc" && path) proxy["grpc-service-name"] = path;
        return proxy;
    } catch (e) {
        return null;
    }
}

function parseTrojan(uri) {
    if (!uri.startsWith('trojan://')) return null;
    try {
        const url = new URL(uri);
        const name = decodeURIComponent(url.hash.substring(1)) || "trojan-node";
        const server = url.hostname;
        const port = parseInt(url.port) || 443;
        const password = url.username;
        const params = url.searchParams;
        const sni = params.get('sni') || params.get('peer') || server;
        const allowInsecure = params.get('allowInsecure') === "1" || params.get('skip-cert-verify') === "1";
        const type = params.get('type') || "tcp";
        const host = params.get('host') || "";
        const path = params.get('path') || "";
        const proxy = {
            name: sanitizeName(name, "trojan"),
            type: "trojan",
            server: server,
            port: port,
            password: password,
            udp: true,
            "skip-cert-verify": allowInsecure,
            tls: true,
            sni: sni,
            network: type,
        };
        if (type === "ws") {
            if (path) proxy["ws-path"] = path;
            if (host) proxy["ws-headers"] = { Host: host };
        }
        if (type === "grpc" && path) proxy["grpc-service-name"] = path;
        return proxy;
    } catch (e) {
        return null;
    }
}

function parseShadowsocks(uri) {
    if (!uri.startsWith('ss://')) return null;
    try {
        let parts = uri.substring(5);
        let name = "";
        let hashIndex = parts.indexOf('#');
        if (hashIndex !== -1) {
            name = decodeURIComponent(parts.substring(hashIndex + 1));
            parts = parts.substring(0, hashIndex);
        }
        let atIndex = parts.indexOf('@');
        let serverPort = "", methodPass = "";
        if (atIndex !== -1) {
            methodPass = parts.substring(0, atIndex);
            serverPort = parts.substring(atIndex + 1);
        } else {
            const decodedMaybe = base64Decode(parts);
            if (decodedMaybe && decodedMaybe.includes('@')) {
                const arr = decodedMaybe.split('@');
                methodPass = arr[0];
                serverPort = arr[1];
            } else return null;
        }
        let method = "", password = "";
        if (methodPass.includes(':')) {
            const mp = methodPass.split(':');
            method = mp[0];
            password = mp[1];
        } else {
            const decodedMp = base64Decode(methodPass);
            if (decodedMp && decodedMp.includes(':')) {
                const mp = decodedMp.split(':');
                method = mp[0];
                password = mp[1];
            } else return null;
        }
        const [server, portStr] = serverPort.split(':');
        const port = parseInt(portStr) || 8388;
        return {
            name: sanitizeName(name, "ss-node"),
            type: "ss",
            server: server,
            port: port,
            cipher: method,
            password: password,
            udp: true,
        };
    } catch (e) {
        return null;
    }
}

function urisToProxies(uris) {
    const proxies = [];
    for (const uri of uris) {
        let proxy = null;
        if (uri.startsWith("vmess://")) proxy = parseVmess(uri);
        else if (uri.startsWith("vless://")) proxy = parseVless(uri);
        else if (uri.startsWith("trojan://")) proxy = parseTrojan(uri);
        else if (uri.startsWith("ss://")) proxy = parseShadowsocks(uri);
        if (proxy && proxy.server && proxy.port) {
            proxies.push(proxy);
        }
    }
    return proxies;
}

function generateClashYaml(proxies) {
    if (!proxies.length) {
        return "# 未解析到有效节点，请稍后重试或检查源格式\n";
    }
    let yaml = `# Clash 配置文件 (自动更新)\n# 生成时间: ${new Date().toUTCString()}\n# 源订阅: roosterkid/openproxylist\n\n`;
    yaml += "proxies:\n";
    for (const p of proxies) {
        yaml += `  - name: "${p.name}"\n`;
        yaml += `    type: ${p.type}\n`;
        yaml += `    server: ${p.server}\n`;
        yaml += `    port: ${p.port}\n`;

        if (p.type === "vmess") {
            yaml += `    uuid: ${p.uuid}\n`;
            if (p.alterId !== undefined) yaml += `    alterId: ${p.alterId}\n`;
            yaml += `    cipher: ${p.cipher}\n`;
            if (p.tls !== undefined) yaml += `    tls: ${p.tls}\n`;
            if (p["skip-cert-verify"]) yaml += `    skip-cert-verify: true\n`;
            yaml += `    network: ${p.network}\n`;
            if (p["ws-path"]) yaml += `    ws-path: ${p["ws-path"]}\n`;
            if (p["ws-headers"]) {
                yaml += `    ws-headers:\n`;
                for (const [k, v] of Object.entries(p["ws-headers"])) {
                    yaml += `      ${k}: ${v}\n`;
                }
            }
            if (p.servername) yaml += `    servername: ${p.servername}\n`;
        }
        else if (p.type === "vless") {
            yaml += `    uuid: ${p.uuid}\n`;
            if (p.flow) yaml += `    flow: ${p.flow}\n`;
            if (p.encryption && p.encryption !== "none") yaml += `    encryption: ${p.encryption}\n`;
            yaml += `    tls: ${p.tls}\n`;
            if (p["skip-cert-verify"]) yaml += `    skip-cert-verify: true\n`;
            if (p.servername) yaml += `    servername: ${p.servername}\n`;
            yaml += `    network: ${p.network}\n`;
            if (p["ws-path"]) yaml += `    ws-path: ${p["ws-path"]}\n`;
            if (p["ws-headers"]) yaml += `    ws-headers:\n      Host: ${p["ws-headers"].Host}\n`;
            if (p["grpc-service-name"]) yaml += `    grpc-service-name: ${p["grpc-service-name"]}\n`;
            // 只有完整的 realityOpts 才会输出
            if (p.realityOpts) {
                yaml += `    reality-opts:\n`;
                yaml += `      public-key: ${p.realityOpts["public-key"]}\n`;
                yaml += `      short-id: ${p.realityOpts["short-id"]}\n`;
            }
        }
        else if (p.type === "trojan") {
            yaml += `    password: ${p.password}\n`;
            yaml += `    udp: true\n`;
            yaml += `    tls: true\n`;
            if (p.sni) yaml += `    sni: ${p.sni}\n`;
            if (p["skip-cert-verify"]) yaml += `    skip-cert-verify: true\n`;
            yaml += `    network: ${p.network}\n`;
            if (p["ws-path"]) yaml += `    ws-path: ${p["ws-path"]}\n`;
            if (p["ws-headers"]) yaml += `    ws-headers:\n      Host: ${p["ws-headers"].Host}\n`;
        }
        else if (p.type === "ss") {
            yaml += `    cipher: ${p.cipher}\n`;
            yaml += `    password: ${p.password}\n`;
            yaml += `    udp: true\n`;
        }
        yaml += `\n`;
    }
    return yaml;
}

// ----------------------------- 主流程 -----------------------------
async function fetchAndConvert() {
    const url = "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/V2RAY_BASE64.txt";
    return new Promise((resolve, reject) => {
        https.get(url, (res) => {
            let data = "";
            res.on("data", chunk => data += chunk);
            res.on("end", () => {
                const lines = data.split(/\r?\n/);
                const allUris = [];
                for (const line of lines) {
                    if (!line.trim()) continue;
                    const decoded = base64Decode(line);
                    if (decoded) {
                        const uris = decoded.split(/\r?\n/);
                        for (const u of uris) {
                            const trimmed = u.trim();
                            if (trimmed && (trimmed.startsWith("vmess://") || trimmed.startsWith("vless://") || trimmed.startsWith("trojan://") || trimmed.startsWith("ss://"))) {
                                allUris.push(trimmed);
                            }
                        }
                    } else {
                        if (line.startsWith("vmess://") || line.startsWith("vless://") || line.startsWith("trojan://") || line.startsWith("ss://")) {
                            allUris.push(line);
                        }
                    }
                }
                let proxies = urisToProxies(allUris);
                proxies = deduplicateProxyNames(proxies);
                const yaml = generateClashYaml(proxies);
                fs.writeFileSync("clash.yaml", yaml, "utf8");
                console.log(`✅ 转换完成，共生成 ${proxies.length} 个唯一节点。`);
                resolve();
            });
        }).on("error", reject);
    });
}

fetchAndConvert().catch(err => {
    console.error("❌ 转换失败:", err);
    process.exit(1);
});
