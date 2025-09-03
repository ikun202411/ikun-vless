import { connect } from 'cloudflare:sockets';

//🔧 参数调节
//CONNECT_TIMEOUT_MS
//如果你发现 Worker 日志里频繁报 timeout 或 CPU 使用过高，可以适当调小（如 1500ms）。
//如果目标服务器响应较慢，可以调大（如 5000ms），但可能增加 Worker 占用。
//WS_BATCH_SIZE
//现在是 10 条消息合并一次写入，减少了系统调用，但批次越大，单次处理越重。
//如果感觉 CPU 占用高，可以改成 5；如果带宽利用率低，可以改成 20。

// ==================== 可调参数 ====================
const CONNECT_TIMEOUT_MS = 3000; // TCP 连接超时（毫秒）
const WS_BATCH_SIZE = 10;         // WS->Socket 合并消息数量，可根据负载调整

// ==================== 配置管理 ====================
class Config {
  constructor(env, url) {
    this.userId = env?.USER_ID || '123456';
    this.uuid = env?.UUID || 'aaa6b096-1165-4bbe-935c-99f4ec902d02';
    this.nodeName = env?.NODE_NAME || 'IKUN-Vless';
    this.fallbackDomain = env?.FALLBACK_DOMAIN || 'example.com';
    
    this.bestIPs = this.parseList(env?.BEST_IPS) || [
      'developers.cloudflare.com',
      'ip.sb', 
      'www.visa.cn',
      'ikun.glimmer.cf.090227.xyz'
    ];
    
    this.proxyIP = url?.searchParams.get('proxyip') || env?.PROXY_IP || 'sjc.o00o.ooo:443';
    
    // SOCKS5 配置 (支持 socks5://user:pass@host:port 格式)
    this.socks5URI = env?.SOCKS5_URI || 'socks5://123:123@54.193.123.84:1080';
    this.globalSocks5 = String(env?.GLOBAL_SOCKS5 || 'false').toLowerCase() === 'true';
    this.socks5Config = this.parseSocks5URI(this.socks5URI);
    
    // 存储原始环境变量用于显示
    this.env = env;
    
    // 预处理 UUID 为字节数组
    this.uuidBytes = new Uint8Array(
      this.uuid.replace(/-/g, '').match(/.{2}/g).map(x => parseInt(x, 16))
    );
  }
  
  parseList(val) {
    return typeof val === 'string' ? val.split('\n').filter(Boolean) : val;
  }
  
  parseSocks5URI(uri) {
    if (!uri || !uri.startsWith('socks5://')) {
      return null;
    }
    
    try {
      const withoutProtocol = uri.slice(9);
      if (withoutProtocol.includes('@')) {
        const [credentials, hostPort] = withoutProtocol.split('@');
        const [user, pass] = credentials.split(':');
        const [host, port = '1080'] = hostPort.split(':');
        return { host, port: parseInt(port), user, pass };
      } else {
        const [host, port = '1080'] = withoutProtocol.split(':');
        return { host, port: parseInt(port), user: '', pass: '' };
      }
    } catch (error) {
      console.error('Invalid SOCKS5 URI format:', uri);
      return null;
    }
  }
  
  hasSocks5() { return !!this.socks5Config; }
  hasProxyIP() { return !!this.proxyIP; }
}

// ==================== SOCKS5 连接实现 ====================
async function connectViaSocks5(targetHost, targetPort, config) {
  if (!config.hasSocks5()) throw new Error('SOCKS5 not configured');
  
  const socks5 = config.socks5Config;
  const socket = connect({ hostname: socks5.host, port: socks5.port });
  await socket.opened;
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  
  try {
    await writer.write(new Uint8Array([5, 2, 0, 2]));
    const authResponse = (await reader.read()).value;
    if (authResponse[0] !== 5) throw new Error('Invalid SOCKS5 response');
    
    if (authResponse[1] === 2 && socks5.user) {
      const userBytes = new TextEncoder().encode(socks5.user);
      const passBytes = new TextEncoder().encode(socks5.pass);
      await writer.write(new Uint8Array([1, userBytes.length, ...userBytes, passBytes.length, ...passBytes]));
      const credResponse = (await reader.read()).value;
      if (credResponse[1] !== 0) throw new Error('SOCKS5 authentication failed');
    } else if (authResponse[1] !== 0) {
      throw new Error('SOCKS5 authentication method not supported');
    }
    
    const domainBytes = new TextEncoder().encode(targetHost);
    await writer.write(new Uint8Array([5, 1, 0, 3, domainBytes.length, ...domainBytes, targetPort >> 8, targetPort & 0xff]));
    const connectResponse = (await reader.read()).value;
    if (connectResponse[1] !== 0) throw new Error('SOCKS5 connection failed');
    
    writer.releaseLock();
    reader.releaseLock();
    return socket;
  } catch (error) {
    try { writer.releaseLock(); reader.releaseLock(); } catch {}
    socket.close();
    throw error;
  }
}

// ==================== 连接管理 ====================
async function fastConnect(hostname, port, config) {
  const attempts = [];
  if (config.globalSocks5 && config.hasSocks5()) {
    attempts.push(() => connectViaSocks5(hostname, port, config));
  } else {
    attempts.push(() => connect({ hostname, port }));
    if (config.hasSocks5()) attempts.push(() => connectViaSocks5(hostname, port, config));
    if (config.hasProxyIP()) {
      const [proxyHost, proxyPort = port] = config.proxyIP.split(':');
      attempts.push(() => connect({ hostname: proxyHost, port: +proxyPort }));
    }
  }
  if (attempts.length === 0) throw new Error('No connection methods available');
  for (const attempt of attempts) {
    try {
      const socket = await Promise.race([
        attempt(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), CONNECT_TIMEOUT_MS))
      ]);
      await socket.opened;
      return socket;
    } catch (error) {
      console.error('Connection attempt failed:', error.message);
      continue;
    }
  }
  throw new Error('All connection attempts failed');
}

// ==================== 协议处理 ====================
function parseVlessHeader(buffer) {
  const view = new DataView(buffer.buffer);
  const uuid = buffer.slice(1, 17);
  const optLen = buffer[17];
  const portIdx = 18 + optLen + 1;
  const port = view.getUint16(portIdx);
  const addrType = buffer[portIdx + 2];
  let addr, addrLen, addrIdx = portIdx + 3;
  switch (addrType) {
    case 1: addr = buffer.slice(addrIdx, addrIdx + 4).join('.'); addrLen = 4; break;
    case 2: addrLen = buffer[addrIdx++]; addr = new TextDecoder().decode(buffer.slice(addrIdx, addrIdx + addrLen)); break;
    case 3:
      addrLen = 16;
      const parts = [];
      for (let i = 0; i < 8; i++) parts.push(view.getUint16(addrIdx + i * 2).toString(16));
      addr = parts.join(':');
      break;
    default: throw new Error('Invalid address type');
  }
  return { uuid, port, address: addr, addressType: addrType, initialData: buffer.slice(addrIdx + addrLen) };
}

// ==================== 数据传输 ====================
async function streamTransfer(ws, socket, initialData) {
  const writer = socket.writable.getWriter();
  ws.send(new Uint8Array([0, 0]));
  if (initialData?.length > 0) await writer.write(initialData);
  await Promise.allSettled([
    (async () => {
      const queue = [];
      let processing = false;
      ws.addEventListener('message', async ({ data }) => {
        queue.push(new Uint8Array(data));
        if (!processing) {
          processing = true;
          while (queue.length > 0) {
            const batch = queue.splice(0, WS_BATCH_SIZE);
            const merged = new Uint8Array(batch.reduce((acc, arr) => acc + arr.length, 0));
            let offset = 0;
            for (const arr of batch) { merged.set(arr, offset); offset += arr.length; }
            try { await writer.write(merged); await new Promise(r => setTimeout(r, 0)); } catch { break; }
          }
          processing = false;
        }
      });
      ws.addEventListener('close', () => { try { writer.close(); } catch {} });
    })(),
    socket.readable.pipeTo(new WritableStream({
      write: chunk => { try { ws.send(chunk); } catch { ws.close(); } },
      abort: () => { ws.close(); }
    }))
  ]);
  socket.closed.then(() => { try { ws.close(); } catch {} });
}

// ==================== WebSocket 处理 ====================
async function handleWebSocket(request, config) {
  const protocol = request.headers.get('sec-websocket-protocol');
  if (!protocol) return new Response('Bad Request', { status: 400 });
  const protocolData = Uint8Array.from(atob(protocol.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  const { uuid, port, address, addressType, initialData } = parseVlessHeader(protocolData);
  if (!uuid.every((b, i) => b === config.uuidBytes[i])) return new Response('Unauthorized', { status: 403 });
  const socket = await fastConnect(addressType === 3 ? `[${address}]` : address, port, config);
  const [client, server] = new WebSocketPair();
  server.accept();
  streamTransfer(server, socket, initialData);
  return new Response(null, { status: 101, webSocket: client });
}

// ==================== 页面生成 ====================
function generateHTML(config, host) {
  const escapeHtml = (str) => str.replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
  const proxyInfo = config.hasProxyIP() ? config.proxyIP : '未配置';
  const socks5Info = config.hasSocks5() ? `${config.socks5Config.host}:${config.socks5Config.port}` : '未配置';
  const globalSocks5Info = config.globalSocks5 ? '✅ 启用' : '❌ 未启用';
  const globalSocks5EnvValue = config.env?.GLOBAL_SOCKS5 || 'undefined';
  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VLESS Enhanced</title>
<style>body{font-family:'Segoe UI',sans-serif;margin:0;padding:20px;background:#f5f5f5}.container{max-width:800px;margin:0 auto;background:white;padding:30px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}h1{text-align:center;margin-bottom:30px}h3{border-bottom:2px solid #e0e0e0;padding-bottom:10px}.info{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:20px;margin-bottom:30px}.item{padding:15px;background:#f8f9fa;border-radius:8px;border-left:4px solid #007bff}.label{font-weight:bold;margin-bottom:5px}.box{display:flex;align-items:center;gap:10px;margin-bottom:20px}.text{flex:1;padding:12px;border:1px solid #ddd;border-radius:6px;background:#f8f9fa;font-family:monospace;font-size:14px;word-break:break-all}.btn{padding:12px 20px;background:#007bff;color:white;border:none;border-radius:6px;cursor:pointer}.btn:hover{background:#0056b3}.btn.ok{background:#28a745}</style></head>
<body><div class="container">
<h1>🚀 VLESS Enhanced</h1>
<div class="info">
<div class="item"><div class="label">节点名称</div><div class="value">${escapeHtml(config.nodeName)}</div></div>
<div class="item"><div class="label">用户ID</div><div class="value">${escapeHtml(config.userId)}</div></div>
<div class="item"><div class="label">代理IP</div><div class="value">${escapeHtml(proxyInfo)}</div></div>
<div class="item"><div class="label">SOCKS5代理</div><div class="value">${escapeHtml(socks5Info)}</div></div>
<div class="item"><div class="label">全局SOCKS5</div><div class="value">${escapeHtml(globalSocks5Info)} (值: ${escapeHtml(globalSocks5EnvValue)})</div></div>
<div class="item"><div class="label">回落域名</div><div class="value">${escapeHtml(config.fallbackDomain)}</div></div>
</div>
<h3>订阅链接</h3>
<div class="box"><div class="text" id="s">https://${escapeHtml(host)}/${escapeHtml(config.userId)}/vless</div><button class="btn" onclick="copyText('s', this)">复制</button></div>
<h3>节点链接</h3>
<div class="box"><div class="text" id="n">vless://${escapeHtml(config.uuid)}@${escapeHtml(config.bestIPs[0] || host)}:443?encryption=none&security=tls&type=ws&host=${escapeHtml(host)}&sni=${escapeHtml(host)}&path=%2F%3Fed%3D2560#${escapeHtml(config.nodeName)}</div><button class="btn" onclick="copyText('n', this)">复制</button></div>
</div><script>function copyText(id,btn){navigator.clipboard.writeText(document.getElementById(id).textContent).then(()=>{const t=btn.textContent;btn.textContent='✓';btn.classList.add('ok');setTimeout(()=>{btn.textContent=t;btn.classList.remove('ok')},1000)})}</script></body></html>`;
}

function generateVlessConfig(host, config) {
  return [...config.bestIPs, `${host}:443`].map(ip => {
    const [addr, port = 443] = ip.split(':');
    return `vless://${config.uuid}@${addr}:${port}?encryption=none&security=tls&type=ws&host=${host}&sni=${host}&path=%2F%3Fed%3D2560#${config.nodeName}`;
  }).join('\n');
}

// ==================== 主入口 ====================
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const config = new Config(env, url);
    const host = request.headers.get('Host');
    try {
      if (request.headers.get('Upgrade') === 'websocket') return await handleWebSocket(request, config);
      switch (url.pathname) {
        case `/${config.userId}`:
          return new Response(generateHTML(config, host), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
        case `/${config.userId}/vless`:
          return new Response(generateVlessConfig(host, config), { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
        case '/':
          const fallbackUrl = new URL(request.url);
          fallbackUrl.hostname = config.fallbackDomain;
          return fetch(new Request(fallbackUrl, request));
        default:
          return new Response('Not Found', { status: 404 });
      }
    } catch (error) {
      console.error('Error:', error);
      return new Response(`Error: ${error.message}`, { status: 500 });
    }
  }
};
