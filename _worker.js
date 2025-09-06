import { connect } from 'cloudflare:sockets';
export default {
  async fetch(req, env) {
    const USER_ID = env?.USERID || env?.USER_ID || env?.userid || 'ikun';
    const UUID = (env?.UUID || env?.uuid || '4ba0eec8-25e1-4ab3-b188-fd8a70b53984').toLowerCase();
    const NODE_NAME = env?.NODE_NAME || env?.NODENAME || 'IKUN-vless';
    const PUBLIC_URL = env?.URL || env?.url || 'example.com';
    const BESTIPS_RAW = env?.BESTIPS || env?.bestips || env?.BEST_IPS || [
      'ip.sb',
      'www.visa.com',
      'developers.cloudflare.com'
    ];
    const BESTIPS = String(BESTIPS_RAW).split(/\r?\n|,/).map(s => s.trim()).filter(Boolean);
    const PROXY_IP_ENV = env?.PROXYIP || env?.proxyip || '';
    const SOCKS5_ENV = env?.SOCKS5 || env?.socks5 || '';
    const GSOCKS5_ENV = String(env?.GSOCKS5 || env?.gsocks5 || 'false').toLowerCase() === 'true';
    let uuidBytes;
    try {
      const hex = UUID.replace(/-/g, '');
      uuidBytes = new Uint8Array(hex.match(/.{2}/g).map(x => parseInt(x, 16)));
      if (uuidBytes.length !== 16) throw new Error('invalid uuid');
    } catch {
      uuidBytes = new Uint8Array(16);
    }

    const urlObj = new URL(req.url);
    const reqHost = urlObj.hostname;
    const q = urlObj.searchParams;
    const defaultPort = 443;

    const pathRaw = decodeURIComponent(urlObj.pathname.slice(1) || '');

    // 允许的四种写法标志
    let socksFrom = null;            
    let isGlobalByPath = false;      
    let originScheme = null;        
    // 仅：/socks5=user:pass@host:port  （不全局）
    if (pathRaw.startsWith('socks5=')) {
      socksFrom = parseSocksString(pathRaw.slice('socks5='.length));
      originScheme = 'socks5-param';
    }
    // 仅：/socks://BASE64@host:port   （全局）
    else if (pathRaw.startsWith('socks://')) {
      socksFrom = parseSocksString(pathRaw.slice('socks://'.length), /*isBase64User=*/true);
      isGlobalByPath = true;
      originScheme = 'socks';
    }
    // 仅：/socks5://user:pass@host:port  （全局）
    else if (pathRaw.startsWith('socks5://')) {
      socksFrom = parseSocksString(pathRaw.slice('socks5://'.length));
      isGlobalByPath = true;
      originScheme = 'socks5';
    }

    // 仅：/?socks5=user:pass@host:port  （不全局）
    let socksFromQuery = null;
    if (q.has('socks5')) {
      socksFromQuery = parseSocksString(q.get('socks5'));
      if (socksFromQuery) originScheme = 'socks5-param';
    }

    // 最终 socks 字符串来源：Query 优先于 Path，再优先于 Env
    const socksFinal = socksFromQuery || socksFrom || (SOCKS5_ENV ? parseSocksString(SOCKS5_ENV) : null);
    let globalSocks = Boolean((isGlobalByPath || GSOCKS5_ENV) && socksFinal);
    const PROXY_IP = q.get('proxyip') || PROXY_IP_ENV || '';

    function parseSocksString(input, isBase64User = false) {
      if (!input) return null;
      try {
        let user = '', pass = '', host = '', port = 1080;
        let left = String(input).trim();

        // 期望格式： [user[:pass]]@host:port
        if (!left.includes('@')) return null;
        const [userPart, serverPart] = left.split('@');

        if (isBase64User) {
          // /socks://BASE64(user:pass)@host:port
          const dec = atob(userPart);
          const idx = dec.indexOf(':');
          if (idx >= 0) { user = dec.slice(0, idx); pass = dec.slice(idx + 1); }
          else { user = dec; pass = ''; }
        } else {
          // 普通 user[:pass]
          const idx = userPart.indexOf(':');
          if (idx >= 0) { user = userPart.slice(0, idx); pass = userPart.slice(idx + 1); }
          else { user = userPart; pass = ''; }
        }

        const sp = serverPart.split(':');
        host = sp[0];
        port = sp[1] ? parseInt(sp[1], 10) : 1080;
        if (!host || Number.isNaN(port)) return null;

        return { host, port, user, pass, raw: input };
      } catch {
        return null;
      }
    }

    if (req.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
      const [client, ws] = Object.values(new WebSocketPair());
      ws.accept();

      let remote = null;
      let udpWriter = null;
      let isDNS = false;

      const socks5Connect = async (s5, targetHost, targetPort) => {
        if (!s5 || !s5.host) throw new Error('no-socks5-config');
        const s = connect({ hostname: s5.host, port: s5.port });
        await s.opened;
        const w = s.writable.getWriter();
        const r = s.readable.getReader();
        try {
          if (s5.user) {
            await w.write(new Uint8Array([5, 2, 0, 2])); // no-auth & user/pass
          } else {
            await w.write(new Uint8Array([5, 1, 0]));    // no-auth
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
          await w.write(new Uint8Array([5, 1, 0, 3, domain.length, ...domain, targetPort >> 8, targetPort & 0xff]));
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

      new ReadableStream({
        start(controller) {
          ws.addEventListener('message', e => {
            if (e.data instanceof ArrayBuffer || ArrayBuffer.isView(e.data)) {
              controller.enqueue(e.data);
            } else if (typeof e.data === 'string') {
              try {
                const bin = Uint8Array.from(atob(e.data.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
                controller.enqueue(bin.buffer);
              } catch {}
            }
          });
          ws.addEventListener('close', () => { try { remote?.close(); } catch {} ; controller.close(); });
          ws.addEventListener('error', () => { try { remote?.close(); } catch {} ; controller.error(); });

          const early = req.headers.get('sec-websocket-protocol');
          if (early) {
            try {
              controller.enqueue(Uint8Array.from(atob(early.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)).buffer);
            } catch {}
          }
        }
      }).pipeTo(new WritableStream({
        async write(chunk) {
          if (isDNS) { return udpWriter?.write(chunk); }

          if (remote) {
            const w = remote.writable.getWriter();
            await w.write(chunk);
            w.releaseLock();
            return;
          }

          if (chunk.byteLength < 24) return;

          const uuidRecv = new Uint8Array(chunk.slice(1, 17));
          for (let i = 0; i < 16; i++) if (uuidRecv[i] !== uuidBytes[i]) return;

          const view = new DataView(chunk);
          const optLen = view.getUint8(17);
          const cmd = view.getUint8(18 + optLen);
          if (cmd !== 1 && cmd !== 2) return;

          let pos = 19 + optLen;
          const port = view.getUint16(pos);
          const addrType = view.getUint8(pos + 2);
          pos += 3;

          let addr = '';
          if (addrType === 1) {
            addr = `${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
            pos += 4;
          } else if (addrType === 2) {
            const len = view.getUint8(pos++);
            addr = new TextDecoder().decode(chunk.slice(pos, pos + len));
            pos += len;
          } else if (addrType === 3) {
            const parts = [];
            for (let i = 0; i < 8; i++, pos += 2) parts.push(view.getUint16(pos).toString(16));
            addr = parts.join(':');
          } else return;

          const header = new Uint8Array([chunk[0], 0]);
          const payload = chunk.slice(pos);

          // UDP DNS（DoH）
          if (cmd === 2) {
            if (port !== 53) return;
            isDNS = true;

            let sent = false;
            const { readable, writable } = new TransformStream({
              transform(buf, ctrl) {
                for (let i = 0; i < buf.byteLength;) {
                  const len = new DataView(buf.slice(i, i + 2)).getUint16(0);
                  ctrl.enqueue(buf.slice(i + 2, i + 2 + len));
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

          let sock = null;

          if (globalSocks) {
            try {
              sock = await socks5Connect(socksFinal, addr, port);
            } catch {
              try { sock?.close(); } catch {}
              sock = null;
              globalSocks = false; // 降级
            }
          }

          if (!sock) {
            try {
              const s = connect({ hostname: addr, port });
              await s.opened;
              sock = s;
            } catch { try { sock?.close(); } catch {}; sock = null; }

            if (!sock && socksFinal) {
              try {
                sock = await socks5Connect(socksFinal, addr, port);
              } catch { try { sock?.close(); } catch {}; sock = null; }
            }
            if (!sock && PROXY_IP) {
              try {
                const [ph, pp] = PROXY_IP.split(':');
                const s = connect({ hostname: ph, port: +pp || port });
                await s.opened;
                sock = s;
              } catch { try { sock?.close(); } catch {}; sock = null; }
            }
          }

          if (!sock) return;

          // 首包 + 回流
          remote = sock;
          const w = sock.writable.getWriter();
          await w.write(payload);
          w.releaseLock();

          let sent = false;
          sock.readable.pipeTo(new WritableStream({
            write(chunk2) {
              if (ws.readyState === 1) {
                ws.send(sent ? chunk2 : new Uint8Array([ ...header, ...new Uint8Array(chunk2) ]));
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

    if (req.method === 'GET' && urlObj.pathname === `/${USER_ID}`) {
      const bestList = Array.from(BESTIPS);
      if (!bestList.includes(reqHost)) bestList.push(reqHost);
      const sniHost = reqHost;

      const pathForVless = buildPathForVless();

      function buildPathForVless() {
        const parts = [];
        if (PROXY_IP) parts.push('proxyip=' + encodeURIComponent(PROXY_IP));

        if (socksFinal) {
          if (isGlobalByPath || GSOCKS5_ENV) {
            if (originScheme === 'socks') {
              return '/' + (parts.length ? `?${parts.join('&')}` : '') + `socks://${encodeURIComponent(btoa(`${socksFinal.user || ''}${socksFinal.user !== undefined ? ':' : ''}${socksFinal.pass || ''}`))}@${socksFinal.host}:${socksFinal.port}`;
            } else {
              const creds = encodeURIComponent(`${socksFinal.user || ''}${socksFinal.user !== undefined ? ':' : ''}${socksFinal.pass || ''}`);
              const suffix = `socks5://${creds}@${socksFinal.host}:${socksFinal.port}`;
              return '/' + (parts.length ? `?${parts.join('&')}` : '') + suffix;
            }
          } else {
            const creds = encodeURIComponent(`${socksFinal.user || ''}${socksFinal.user !== undefined ? ':' : ''}${socksFinal.pass || ''}`);
            parts.push('socks5=' + `${creds}@${socksFinal.host}:${socksFinal.port}`);
          }
        }

        return '/?' + parts.join('&');
      }

      const lines = BESTIPS.map(ip => {
        let addr = ip, port = defaultPort;
        if (ip.includes(':')) {
          const seg = ip.split(':');
          addr = seg[0]; port = seg[1] || defaultPort;
        }
        return `vless://${UUID}@${addr}:${port}?encryption=none&security=tls&sni=${encodeURIComponent(sniHost)}&allowInsecure=1&type=ws&host=${encodeURIComponent(sniHost)}&path=${encodeURIComponent(pathForVless)}#${encodeURIComponent(NODE_NAME)}`;
      }).join('\n');

      return new Response(lines, { status: 200, headers: { 'content-type': 'text/plain; charset=utf-8' } });
    }

    const fallback = new URL(req.url);
    fallback.hostname = PUBLIC_URL || 'example.com';
    return fetch(new Request(fallback, req));
  }
};
