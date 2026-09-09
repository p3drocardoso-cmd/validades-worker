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
