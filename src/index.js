// ===== Utilitários gerais =====

function b64urlToBytes(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  const bin = atob(b64 + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function bytesToB64url(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function concatBytes(...arrs) {
  const len = arrs.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const a of arrs) { out.set(a, offset); offset += a.length; }
  return out;
}

async function checkPinWithLockout(request, env) {
  if (!env.APP_PIN) return { ok: true, locked: false };
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  const lockKey = 'lock:' + ip;

  const locked = await env.CLIENTS_KV.get(lockKey);
  if (locked) return { ok: false, locked: true };

  const pin = request.headers.get('x-app-pin') || '';
  if (pin === env.APP_PIN) {
    // Só escreve no KV se realmente houver algo a limpar (evita gastar
    // quota de escrita em cada pedido bem-sucedido, que é o caso comum).
    const failKey = 'fails:' + ip;
    const hasFailRecord = await env.CLIENTS_KV.get(failKey);
    if (hasFailRecord) {
      await env.CLIENTS_KV.delete(failKey).catch(() => {});
    }
    return { ok: true, locked: false };
  }

  const failKey = 'fails:' + ip;
  const current = parseInt((await env.CLIENTS_KV.get(failKey)) || '0', 10) + 1;
  if (current >= 5) {
    await env.CLIENTS_KV.put(lockKey, '1', { expirationTtl: 900 }); // 15 min de bloqueio
    await env.CLIENTS_KV.delete(failKey).catch(() => {});
  } else {
    await env.CLIENTS_KV.put(failKey, String(current), { expirationTtl: 900 });
  }
  return { ok: false, locked: false };
}

function unauthorized(locked) {
  return new Response(JSON.stringify({ error: locked ? 'locked' : 'unauthorized' }), {
    status: locked ? 429 : 401,
    headers: { 'Content-Type': 'application/json' }
  });
}

function daysUntilUTC(dateStr, todayUTC) {
  const [y, m, d] = dateStr.split('-').map(Number);
  const targetUTC = Date.UTC(y, m - 1, d);
  return Math.round((targetUTC - todayUTC) / 86400000);
}

// ===== Web Push (RFC 8291 + VAPID), implementado com Web Crypto =====

async function hmacSha256(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, msgBytes);
  return new Uint8Array(sig);
}

async function deriveWebPushKeys(ecdhSecret, authSecret, uaPublic, asPublic, salt) {
  const te = new TextEncoder();
  const info1 = concatBytes(te.encode('WebPush: info\0'), uaPublic, asPublic);
  const prkKey = await hmacSha256(authSecret, ecdhSecret);
  const ikm = (await hmacSha256(prkKey, concatBytes(info1, new Uint8Array([1])))).slice(0, 32);

  const prk = await hmacSha256(salt, ikm);
  const cek = (await hmacSha256(prk, concatBytes(te.encode('Content-Encoding: aes128gcm\0'), new Uint8Array([1])))).slice(0, 16);
  const nonce = (await hmacSha256(prk, concatBytes(te.encode('Content-Encoding: nonce\0'), new Uint8Array([1])))).slice(0, 12);
  return { cek, nonce };
}

function buildAes128gcmHeader(salt, recordSize, keyid) {
  const rs = new Uint8Array(4);
  new DataView(rs.buffer).setUint32(0, recordSize, false);
  return concatBytes(salt, rs, new Uint8Array([keyid.length]), keyid);
}

async function getVapidPrivateCryptoKey(env) {
  const pub = b64urlToBytes(env.VAPID_PUBLIC_KEY);
  const x = pub.slice(1, 33);
  const y = pub.slice(33, 65);
  const d = b64urlToBytes(env.VAPID_PRIVATE_KEY);
  const jwk = { kty: 'EC', crv: 'P-256', d: bytesToB64url(d), x: bytesToB64url(x), y: bytesToB64url(y), ext: true };
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}

async function createVapidJWT(audience, subject, privateKey) {
  const header = { typ: 'JWT', alg: 'ES256' };
  const payload = { aud: audience, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: subject };
  const te = new TextEncoder();
  const encHeader = bytesToB64url(te.encode(JSON.stringify(header)));
  const encPayload = bytesToB64url(te.encode(JSON.stringify(payload)));
  const unsigned = `${encHeader}.${encPayload}`;
  const sigBuf = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, te.encode(unsigned));
  return `${unsigned}.${bytesToB64url(new Uint8Array(sigBuf))}`;
}

async function sendWebPush(subscription, payloadObj, env) {
  const p256dh = b64urlToBytes(subscription.keys.p256dh);
  const authSecret = b64urlToBytes(subscription.keys.auth);

  const ephemeralKeyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPublicRaw = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey));

  const subscriberPublicKey = await crypto.subtle.importKey('raw', p256dh, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const sharedSecret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: subscriberPublicKey }, ephemeralKeyPair.privateKey, 256));

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const { cek, nonce } = await deriveWebPushKeys(sharedSecret, authSecret, p256dh, asPublicRaw, salt);

  const plaintext = new TextEncoder().encode(JSON.stringify(payloadObj));
  const padded = concatBytes(plaintext, new Uint8Array([2]));
  const cekKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, cekKey, padded));

  const body = concatBytes(buildAes128gcmHeader(salt, 4096, asPublicRaw), ciphertext);

  const url = new URL(subscription.endpoint);
  const audience = `${url.protocol}//${url.host}`;
  const vapidPrivateKey = await getVapidPrivateCryptoKey(env);
  const jwt = await createVapidJWT(audience, 'mailto:admin@validades.app', vapidPrivateKey);

  return fetch(subscription.endpoint, {
    method: 'POST',
    headers: {
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      'TTL': '86400',
      'Authorization': `vapid t=${jwt}, k=${env.VAPID_PUBLIC_KEY}`
    },
    body
  });
}

async function subKeyFor(endpoint) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(endpoint));
  return 'sub:' + bytesToB64url(new Uint8Array(hash)).slice(0, 24);
}

async function sendToAllSubscriptions(env, payload) {
  const list = await env.CLIENTS_KV.list({ prefix: 'sub:' });
  let sent = 0, removed = 0, failed = 0;
  for (const k of list.keys) {
    const raw = await env.CLIENTS_KV.get(k.name);
    if (!raw) continue;
    const sub = JSON.parse(raw);
    try {
      const res = await sendWebPush(sub, payload, env);
      if (res.status === 404 || res.status === 410) {
        await env.CLIENTS_KV.delete(k.name);
        removed++;
      } else if (res.ok) {
        sent++;
      } else {
        failed++;
      }
    } catch (e) {
      failed++;
    }
  }
  return { sent, removed, failed, total: list.keys.length };
}

// ===== Verificação diária (Cron) =====

async function checkExpiringAndNotify(env) {
  const data = await env.CLIENTS_KV.get('clients');
  const clientList = data ? JSON.parse(data) : [];
  const now = new Date();
  const todayUTC = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());

  const expiringTomorrow = clientList.filter(c => daysUntilUTC(c.date, todayUTC) === 1);
  if (expiringTomorrow.length === 0) return { sent: 0, reason: 'nenhum cliente a expirar amanhã' };

  const todayKey = now.toISOString().slice(0, 10);
  const guardKey = 'notif_sent:' + todayKey;
  if (await env.CLIENTS_KV.get(guardKey)) return { sent: 0, reason: 'já enviado hoje' };

  const names = expiringTomorrow.map(c => c.name).slice(0, 5).join(', ');
  const extra = expiringTomorrow.length > 5 ? ` e mais ${expiringTomorrow.length - 5}` : '';
  const payload = {
    title: `${expiringTomorrow.length} cliente(s) a expirar amanhã`,
    body: `${names}${extra}`
  };

  const result = await sendToAllSubscriptions(env, payload);
  await env.CLIENTS_KV.put(guardKey, '1', { expirationTtl: 172800 });
  return result;
}

// ===== Worker =====

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/api/clients') {
      if (request.method === 'GET') {
        const auth = await checkPinWithLockout(request, env);
        if (!auth.ok) return unauthorized(auth.locked);
        const data = await env.CLIENTS_KV.get('clients');
        return new Response(data || '[]', { headers: { 'Content-Type': 'application/json' } });
      }
      if (request.method === 'POST') {
        const auth = await checkPinWithLockout(request, env);
        if (!auth.ok) return unauthorized(auth.locked);
        let body;
        try { body = await request.json(); } catch (e) {
          return new Response(JSON.stringify({ error: 'invalid json' }), { status: 400 });
        }
        if (!Array.isArray(body)) return new Response(JSON.stringify({ error: 'expected array' }), { status: 400 });
        await env.CLIENTS_KV.put('clients', JSON.stringify(body));
        return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
      }
      return new Response('Method not allowed', { status: 405 });
    }

    if (path === '/api/subscribe' && request.method === 'POST') {
      const auth = await checkPinWithLockout(request, env);
      if (!auth.ok) return unauthorized(auth.locked);
      let sub;
      try { sub = await request.json(); } catch (e) {
        return new Response(JSON.stringify({ error: 'invalid json' }), { status: 400 });
      }
      if (!sub || !sub.endpoint || !sub.keys) {
        return new Response(JSON.stringify({ error: 'invalid subscription' }), { status: 400 });
      }
      const key = await subKeyFor(sub.endpoint);
      await env.CLIENTS_KV.put(key, JSON.stringify(sub));
      return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
    }

    // Endpoint manual para testar já, sem esperar pela verificação diária.
    if (path === '/api/test-push') {
      const auth = await checkPinWithLockout(request, env);
      if (!auth.ok) return unauthorized(auth.locked);
      const result = await sendToAllSubscriptions(env, {
        title: 'Teste — Validades',
        body: 'Se estás a ver isto, as notificações estão a funcionar.'
      });
      return new Response(JSON.stringify(result), { headers: { 'Content-Type': 'application/json' } });
    }

    return env.ASSETS.fetch(request);
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(checkExpiringAndNotify(env));
  }
};
