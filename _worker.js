import { connect } from 'cloudflare:sockets';

/*
使用说明（中文）—— 请完整阅读

环境变量（在 Cloudflare Worker 面板绑定）：
- USERID / userid         : 订阅用的用户 ID（路由 /<USERID>）
- UUID   / uuid           : VLESS 用户 UUID（用于校验）
- URL    / url            : 仅用于替代原代码中 example.com 的回退目标（非 websocket 回退），如果未设置则回退到 example.com
- BESTIPS / bestips       : 多个 bestip，支持换行或逗号分隔；每个 bestip 会生成一条 vless 节点（顺序保留）
- PROXYIP / proxyip       : 可选的回退 proxyip，格式 host:port
- SOCKS5 / socks5         : 可选的 socks5 设置，支持多种格式：
                            - user:pass@host:port
                            - socks5://user:pass@host:port
                            - socks://dXNlcjpwYXNzd29yZA==@host:port （如果 user 部分为 base64，会尝试解码）
- GSOCKS5 / gsocks5       : 全局 socks5 请求开关（"true"/"false"）。**仅在显式请求时才会尝试开启**（env / query / path / 代码改动）。
                            若请求开启全局 socks5，但无可用 socks5 配置或 socks5 连接失败，脚本会自动关闭全局 socks（降级为普通顺序：直连 -> socks5 回退 -> proxyip 回退）。

路由与行为要点：
- **仅当访问** https://<部署域名>/<USERID> **返回订阅信息**（纯文本：每行一条 vless:// 链接；BESTIPS 中每个 bestip 一行，且始终包含部署域名作为一条节点）。
- /<USERID>/vless 返回相同的纯文本节点列表（兼容）。
- 非 websocket 且非上述两条路径：回退到 env.URL（若未设置则回退到 example.com）。
- WebSocket 主逻辑（UUID 校验、VLESS 头解析、DNS over DoH、连接顺序）保持原样：默认顺序 直连 -> socks5 回退 -> proxyip 回退；若显式请求全局 socks5，会优先尝试 socks5，失败时自动降级。
*/

/* ===================== 实现代码 ===================== */

export default {
  async fetch(req, env) {
    // ------------------- 1. 读取并规范化环境变量 -------------------
    const USER_ID = env?.USERID || env?.USER_ID || env?.userid || 'ikun';
    const UUID = (env?.UUID || env?.uuid || '4ba0eec8-25e1-4ab3-b188-fd8a70b53984').toLowerCase();
    const NODE_NAME = env?.NODE_NAME || env?.NODENAME || 'IKUN-vless';
    const PUBLIC_URL = env?.URL || env?.url || 'example.com';

    // BESTIPS 支持换行或逗号分隔
    const BESTIPS_RAW = env?.BESTIPS || env?.bestips || env?.BEST_IPS || [
      'ip.sb',
      'www.visa.com',
      'developers.cloudflare.com',
      'ikun.glimmer.cf.090227.xyz'
    ];
    const BESTIPS = String(BESTIPS_RAW)
      .split(/\r?\n|,/)
      .map(s => s.trim())
      .filter(Boolean);

    const PROXY_IP_ENV = env?.PROXYIP || env?.proxyip || '';
    const SOCKS5_ENV = env?.SOCKS5 || env?.socks5 || '';
    const GSOCKS5_ENV = String(env?.GSOCKS5 || env?.gsocks5 || 'false').toLowerCase() === 'true';

    // 预处理 UUID 为字节数组（用于校验）
    let uuidBytes;
    try {
      const hex = UUID.replace(/-/g, '');
      uuidBytes = new Uint8Array(hex.match(/.{2}/g).map(x => parseInt(x, 16)));
      if (uuidBytes.length !== 16) throw new Error('invalid uuid');
    } catch {
      uuidBytes = new Uint8Array(16);
    }

    // -------------------  解析请求 URL / Query / Path（公共信息） -------------------
    const urlObj = new URL(req.url);
    const reqHost = urlObj.hostname; // 部署域名（请求 Host），**作为 sni/host**
    const q = urlObj.searchParams;
    const defaultPort = 443;
    const pathCandidate = urlObj.pathname.slice(1) || null; // 用于从 path 解析 socks5

    // ------------------- socks5 字符串解析函数 -------------------
    function parseSocksString(s) {
      if (!s) return null;
      try {
        let input = String(s).trim();
        if (input.includes('=') && !/^socks5?:\/\//i.test(input)) input = input.slice(input.indexOf('=') + 1);

        // 支持多种协议前缀：socks5:// socks:// s5:// gs5:// gsocks5://
        if (/^socks5?:\/\//i.test(input)) {
          if (input.toLowerCase().startsWith('socks5://')) input = input.slice(9);
          else input = input.slice(8);
        } else if (/^socks:\/\//i.test(input)) {
          input = input.slice(8);
        } else if (input.toLowerCase().startsWith('s5://')) {
          input = input.slice(5);
        } else if (input.toLowerCase().startsWith('gs5://')) {
          input = input.slice(6);
        } else if (input.toLowerCase().startsWith('gsocks5://')) {
          input = input.slice(10);
        } else if (input.toLowerCase().startsWith('gsocks://')) {
          input = input.slice(9);
        }

        let user = '', pass = '';
        let hostPort = input;
        if (input.includes('@')) {
          const [userPart, serverPart] = input.split('@');
          if (/^[A-Za-z0-9+/=]+$/.test(userPart) && !userPart.includes(':')) {
            try {
              const dec = atob(userPart);
              if (dec.includes(':')) [user, pass] = dec.split(':');
              else { user = dec; pass = ''; }
            } catch {
              if (userPart.includes(':')) [user, pass] = userPart.split(':');
              else user = userPart;
            }
          } else {
            if (userPart.includes(':')) [user, pass] = userPart.split(':');
            else user = userPart;
          }
          hostPort = serverPart;
        }
        const [host, portRaw] = hostPort.split(':');
        const port = portRaw ? parseInt(portRaw, 10) : 1080;
        return { host, port, user, pass, raw: s };
      } catch {
        return null;
      }
    }

    // -------------------  从 Query / Path / Env 决定 socks5 与 gsocks 请求意图 -------------------
    // 支持多种 query 名称：s5 / socks5 (提供 socks 配置但不自动开全局)
    // 以及 gs5 / gsocks5 (用于请求开启全局，并且可能携带 socks 字符串)
    let socksParamQuery = null;
    let requestedGlobalQuery = false;
    let socksSourceIsGs = false; // 记录 socks 字符串是否来自 gs5/gsocks5（query 或 path）

    // 1) 首先优先查找非全局的 socks 参数（s5 或 socks5）
    if (q.has('s5')) socksParamQuery = q.get('s5');
    else if (q.has('socks5')) socksParamQuery = q.get('socks5');

    // 2) 如果没有找到非全局 socks 参数，再检查 gs5/gsocks5（它们可能携带 socks 字符串，也可能仅为 true）
    if (!socksParamQuery) {
      if (q.has('gs5')) {
        const v = q.get('gs5');
        if (v && v.toLowerCase() !== 'true' && v.toLowerCase() !== 'false') {
          socksParamQuery = v;
          socksSourceIsGs = true; // 来源是 gs5，记下标志
        }
        requestedGlobalQuery = true;
      } else if (q.has('gsocks5')) {
        const v = q.get('gsocks5');
        if (v && v.toLowerCase() !== 'true' && v.toLowerCase() !== 'false') {
          socksParamQuery = v;
          socksSourceIsGs = true; // 来源是 gsocks5
        }
        requestedGlobalQuery = true;
      }
    } else {
      // 如果已有 s5/socks5 参数，但同时也传了 gs5/gsocks5 -> 那也算请求开启全局（如果 gs* 存在）
      if (q.has('gs5') || q.has('gsocks5')) requestedGlobalQuery = true;
      // 注意：如果同时传了 s5= 和 gs5=xxx 的极端情况，上面的逻辑优先选 s5=（非全局）
    }

    // 解析 path 中的 s5 / socks5 / gs5 / gsocks5
    let socksFromPath = null;
    let pathGlobalActivate = false;
    if (pathCandidate) {
      const low = pathCandidate.toLowerCase();
      if (low.includes('gs5=')) {
        const idx = pathCandidate.toLowerCase().indexOf('gs5=');
        const raw = decodeURIComponent(pathCandidate.slice(idx));
        const maybe = raw.split('=')[1] || null;
        if (maybe) socksFromPath = maybe;
        pathGlobalActivate = true;
        socksSourceIsGs = true; // 来源为 gs5
      } else if (low.includes('gsocks5=')) {
        const idx = pathCandidate.toLowerCase().indexOf('gsocks5=');
        const raw = decodeURIComponent(pathCandidate.slice(idx));
        const maybe = raw.split('=')[1] || null;
        if (maybe) socksFromPath = maybe;
        pathGlobalActivate = true;
        socksSourceIsGs = true; // 来源为 gsocks5
      } else if (low.includes('s5=')) {
        const idx = pathCandidate.toLowerCase().indexOf('s5=');
        const raw = decodeURIComponent(pathCandidate.slice(idx));
        const maybe = raw.split('=')[1] || null;
        if (maybe) socksFromPath = maybe;
      } else if (low.includes('socks5=')) {
        const idx = pathCandidate.toLowerCase().indexOf('socks5=');
        const raw = decodeURIComponent(pathCandidate.slice(idx));
        const maybe = raw.split('=')[1] || null;
        if (maybe) socksFromPath = maybe;
      } else if (/^gs5:\/\//i.test(pathCandidate)) {
        pathGlobalActivate = true;
        socksFromPath = pathCandidate.replace(/^gs5:\/\//i, '');
        socksSourceIsGs = true;
      } else if (/^gsocks5:\/\//i.test(pathCandidate)) {
        pathGlobalActivate = true;
        socksFromPath = pathCandidate.replace(/^gsocks5:\/\//i, '');
        socksSourceIsGs = true;
      } else if (/^s5:\/\//i.test(pathCandidate)) {
        socksFromPath = pathCandidate.replace(/^s5:\/\//i, '');
      } else if (/^socks5:\/\//i.test(pathCandidate)) {
        socksFromPath = pathCandidate.replace(/^socks5:\/\//i, '');
      } else if (pathCandidate.includes('@') && pathCandidate.toLowerCase().includes('socks')) {
        const p = pathCandidate.toLowerCase().indexOf('socks');
        const seg = pathCandidate.slice(p);
        const idx = seg.indexOf('@');
        if (idx > 0) socksFromPath = seg;
      }
    }

    // 最终 socks 原始字符串 优先级 Query(s5/socks5) > Path (s5/socks5/gs5/gsocks5) > Env
    const socksRawFinal = socksParamQuery || socksFromPath || SOCKS5_ENV || null;
    const socks5 = parseSocksString(socksRawFinal);

    // gsocks5 现在兼容 ?gs5 and ?gsocks5，也支持 env GSOCKS5；pathGlobalActivate 也会生效
    const gsocksQuery = q.get('gs5') || q.get('gsocks5') || null;
    const requestedGlobal = GSOCKS5_ENV || requestedGlobalQuery || (gsocksQuery && gsocksQuery.toLowerCase() === 'true') || pathGlobalActivate;
    // 初始决定 globalSocks：只有“请求开启”且存在 socks5 配置才允许初始为 true
    let globalSocks = Boolean(requestedGlobal && socks5);

    const PROXY_IP = q.get('proxyip') || PROXY_IP_ENV || null;

    // ------------------- 构造 vless path 片段（包含 proxyip 与 s5/gs5） -------------------
    function buildPathForVless(query) {
      const parts = [];
      const proxy = query.get('proxyip') || PROXY_IP;
      // 兼容 query 参数名 s5 / socks5 / gs5 / gsocks5；并根据 socksSourceIsGs 决定使用 s5= 或 gs5=
      const s5val = query.get('s5') || query.get('socks5') || socksRawFinal;
      if (proxy) parts.push('proxyip=' + encodeURIComponent(proxy));
      if (s5val) {
        if (socksSourceIsGs) {
          parts.push('gs5=' + encodeURIComponent(s5val)); // 当 socks 来自 gs5 时，使用 gs5= 保留“全局”语义
        } else {
          parts.push('s5=' + encodeURIComponent(s5val));
        }
      }
      return '/?' + parts.join('&');
    }

    // ------------------- WebSocket 代理主逻辑（优先处理 WebSocket） -------------------
    if (req.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
      const [client, ws] = Object.values(new WebSocketPair());
      ws.accept();

      let remote = null, udpWriter = null, isDNS = false;

      // socks5 连接函数
      const socks5Connect = async (s5, targetHost, targetPort) => {
        if (!s5 || !s5.host) throw new Error('no-socks5-config');
        const s = connect({ hostname: s5.host, port: s5.port });
        await s.opened;
        const w = s.writable.getWriter();
        const r = s.readable.getReader();
        try {
          if (s5.user) {
            await w.write(new Uint8Array([5, 2, 0, 2]));
          } else {
            await w.write(new Uint8Array([5, 1, 0]));
          }
          const auth = (await r.read()).value;
          if (!auth || auth[0] !== 5) throw new Error('s5bad');
          if (auth[1] === 2 && s5.user) {
            const ub = new TextEncoder().encode(s5.user);
            const pb = new TextEncoder().encode(s5.pass || '');
            await w.write(new Uint8Array([1, ub.length, ...ub, pb.length, ...pb]));
            const cred = (await r.read()).value;
            if (!cred || cred[1] !== 0) throw new Error('s5auth');
          } else if (auth[1] !== 0 && !(auth[1] === 2 && s5.user)) {
            throw new Error('s5noauth');
          }
          const domain = new TextEncoder().encode(targetHost);
          await w.write(new Uint8Array([5, 1, 0, 3, domain.length, ...domain, targetPort >> 8, targetPort & 255]));
          const cresp = (await r.read()).value;
          if (!cresp || cresp[1] !== 0) throw new Error('s5fail');
          w.releaseLock(); r.releaseLock();
          return s;
        } catch (e) {
          try { w.releaseLock(); r.releaseLock(); } catch {}
          try { s.close(); } catch {}
          throw e;
        }
      };

      // WebSocket 消息流入管道
      new ReadableStream({
        start(ctrl) {
          ws.addEventListener('message', e => {
            if (e.data instanceof ArrayBuffer || ArrayBuffer.isView(e.data)) {
              ctrl.enqueue(e.data);
            } else if (typeof e.data === 'string') {
              try {
                const bin = Uint8Array.from(atob(e.data.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
                ctrl.enqueue(bin.buffer);
              } catch {}
            }
          });
          ws.addEventListener('close', () => { try { remote?.close(); } catch {} ; ctrl.close(); });
          ws.addEventListener('error', () => { try { remote?.close(); } catch {} ; ctrl.error(); });

          const early = req.headers.get('sec-websocket-protocol');
          if (early) {
            try {
              ctrl.enqueue(Uint8Array.from(atob(early.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)).buffer);
            } catch {}
          }
        }
      }).pipeTo(new WritableStream({
        async write(data) {
          if (isDNS) return udpWriter?.write(data);

          if (remote) {
            const w = remote.writable.getWriter();
            await w.write(data);
            w.releaseLock();
            return;
          }

          if (data.byteLength < 24) return;

          // UUID 校验（字节比较）
          const uuidRecv = new Uint8Array(data.slice(1, 17));
          for (let i = 0; i < 16; i++) {
            if (uuidRecv[i] !== uuidBytes[i]) return;
          }

          // 解析 VLESS 头
          const view = new DataView(data);
          const optLen = view.getUint8(17);
          const cmd = view.getUint8(18 + optLen);
          if (cmd !== 1 && cmd !== 2) return;

          let pos = 19 + optLen;
          const port = view.getUint16(pos);
          const type = view.getUint8(pos + 2);
          pos += 3;

          let addr = '';
          if (type === 1) {
            addr = `${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
            pos += 4;
          } else if (type === 2) {
            const len = view.getUint8(pos++);
            addr = new TextDecoder().decode(data.slice(pos, pos + len));
            pos += len;
          } else if (type === 3) {
            const parts = [];
            for (let i = 0; i < 8; i++, pos += 2) parts.push(view.getUint16(pos).toString(16));
            addr = parts.join(':');
          } else return;

          const header = new Uint8Array([data[0], 0]);
          const payload = data.slice(pos);

          // DNS over DoH（cmd==2 && port==53）
          if (cmd === 2) {
            if (port !== 53) return;
            isDNS = true;

            let sent = false;
            const { readable, writable } = new TransformStream({
              transform(chunk, ctrl) {
                for (let i = 0; i < chunk.byteLength;) {
                  const len = new DataView(chunk.slice(i, i + 2)).getUint16(0);
                  ctrl.enqueue(chunk.slice(i + 2, i + 2 + len));
                  i += 2 + len;
                }
              }
            });

            readable.pipeTo(new WritableStream({
              async write(query) {
                try {
                  const resp = await fetch('https://1.1.1.1/dns-query', {
                    method: 'POST',
                    headers: { 'content-type': 'application/dns-message' },
                    body: query
                  });
                  if (ws.readyState === 1) {
                    const result = new Uint8Array(await resp.arrayBuffer());
                    ws.send(new Uint8Array([ ...(sent ? [] : header), result.length >> 8, result.length & 0xff, ...result ]));
                    sent = true;
                  }
                } catch {}
              }
            }));

            udpWriter = writable.getWriter();
            return udpWriter.write(payload);
          }

          // ====== 连接策略（直连 -> socks5 回退 -> proxyip 回退；若 requested 全局 socks，则优先尝试） ======
          let sock = null;

          // 若请求开启 globalSocks（且上面已初步判断有 socks5），优先尝试
          if (globalSocks) {
            try {
              sock = await socks5Connect(socks5, addr, port);
            } catch (e) {
              // 全局 socks5 失败：自动关闭 globalSocks，并降级到普通顺序（允许 proxyip 兜底）
              try { sock && sock.close(); } catch {}
              sock = null;
              globalSocks = false;
            }
          }

          // 普通顺序（如果未建立连接）
          if (!sock) {
            // 1) 直连
            try {
              const s = connect({ hostname: addr, port });
              await s.opened;
              sock = s;
            } catch (e) {
              try { sock && sock.close(); } catch {}
              sock = null;
            }

            // 2) socks5 回退（若有配置）
            if (!sock && socks5) {
              try {
                sock = await socks5Connect(socks5, addr, port);
              } catch (e) {
                try { sock && sock.close(); } catch {}
                sock = null;
              }
            }

            // 3) proxyip 回退（若提供）
            if (!sock && PROXY_IP) {
              try {
                const [ph, pp] = PROXY_IP.split(':');
                const s = connect({ hostname: ph, port: +pp || port });
                await s.opened;
                sock = s;
              } catch (e) {
                try { sock && sock.close(); } catch {}
                sock = null;
              }
            }
          }

          if (!sock) return;

          // 成功：写入 payload 并将远端返回通过 ws 发回
          remote = sock;
          const w = sock.writable.getWriter();
          await w.write(payload);
          w.releaseLock();

          let sent = false;
          sock.readable.pipeTo(new WritableStream({
            write(chunk) {
              if (ws.readyState === 1) {
                ws.send(sent ? chunk : new Uint8Array([ ...header, ...new Uint8Array(chunk) ]));
                sent = true;
              }
            },
            close: () => ws.readyState === 1 && ws.close(),
            abort: () => ws.readyState === 1 && ws.close()
          })).catch(() => {});
        }
      })).catch(() => {});

      return new Response(null, { status: 101, webSocket: client });
    }

    // ------------------- 订阅接口 -------------------
    // GET /USER_ID 返回纯文本订阅（每行一条 vless 链接）
    if (req.method === 'GET' && urlObj.pathname === `/${USER_ID}`) {
      const pathForVless = buildPathForVless(q);
      const bestList = Array.from(BESTIPS);
      if (!bestList.includes(reqHost)) bestList.push(reqHost);
      const sniHost = reqHost;

      const vlessLines = bestList.map(ip => {
        let addr = ip;
        let port = defaultPort;
        if (ip.includes(':')) {
          const parts = ip.split(':');
          addr = parts[0];
          port = parts[1] || defaultPort;
        }
        return `vless://${UUID}@${addr}:${port}?encryption=none&security=tls&sni=${encodeURIComponent(sniHost)}&allowInsecure=1&type=ws&host=${encodeURIComponent(sniHost)}&path=${encodeURIComponent(pathForVless)}#${encodeURIComponent(NODE_NAME)}`;
      }).join('\n');

      return new Response(vlessLines, { status: 200, headers: { 'content-type': 'text/plain; charset=utf-8' } });
    }

    //  非 websocket 且非订阅路由：回退到 PUBLIC_URL 或 example.com -------------------
    const fallback = new URL(req.url);
    fallback.hostname = PUBLIC_URL || 'example.com';
    return fetch(new Request(fallback, req));
  }
};
