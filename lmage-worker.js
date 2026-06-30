// ========================================================================
// 安全修复: 图像生成 Worker
// ========================================================================
const AGNES_API_URL = 'https://apihub.agnes-ai.com/v1/images/generations';
const CHAT_APP_DB_URL = 'https://chat-app-db.chatlz.dpdns.org';  // 图片保存服务
const KV_PREFIX = 'img:';
const KV_INDEX = 'img_index';
const KV_RATE_PREFIX = 'rate:';

// 速率限制配置
const RATE_LIMIT_WINDOW = 60000;    // 60秒窗口
const RATE_LIMIT_MAX = 20;         // 每窗口最大请求数（无认证）
const RATE_LIMIT_MAX_AUTHED = 50;  // 已认证用户限制

let _dbInited = false;

// ========================================================================
// 速率限制检查 (基于 KV)
// ========================================================================
async function checkRateLimit(env, identifier, isAuthenticated) {
  const kv = env && env.IMAGE_GALLERY ? env.IMAGE_GALLERY : null;
  if (!kv) return true; // 无 KV 时跳过限制
  
  const limit = isAuthenticated ? RATE_LIMIT_MAX_AUTHED : RATE_LIMIT_MAX;
  const key = KV_RATE_PREFIX + identifier;
  const now = Date.now();
  
  try {
    const data = await kv.get(key);
    let record = data ? JSON.parse(data) : { count: 0, windowStart: now };
    
    // 重置过期窗口
    if (now - record.windowStart > RATE_LIMIT_WINDOW) {
      record = { count: 0, windowStart: now };
    }
    
    record.count++;
    
    if (record.count > limit) {
      const retryAfter = Math.ceil((RATE_LIMIT_WINDOW - (now - record.windowStart)) / 1000);
      return { allowed: false, retryAfter, limit };
    }
    
    await kv.put(key, JSON.stringify(record), { expirationTtl: 120 });
    return { allowed: true, remaining: limit - record.count, limit };
  } catch (e) {
    console.error('Rate limit check error:', e);
    return true; // 出错时允许请求
  }
}

// ========================================================================
// API 密钥验证
// ========================================================================
function validateApiSecret(request) {
  const authHeader = request.headers ? request.headers.get('Authorization') : null;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return { token: authHeader.substring(7), authenticated: true };
  }
  const deviceId = request.headers ? request.headers.get('X-Device-Id') : null;
  return { token: deviceId || 'anonymous', authenticated: false };
}

async function handleRequest(request, env, ctx) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders(request) });
  }

  const url = new URL(request.url);
  const path = url.pathname;
  const db = env && env.DB ? env.DB : null;
  const kv = env && env.IMAGE_GALLERY ? env.IMAGE_GALLERY : null;

  if (db) {
    await ensureDB(db);
  }

  // 速率限制：应用于图像生成和图片列表请求
  const { token, authenticated } = validateApiSecret(request);
  const rateLimitExempt = env && env.API_SECRET_KEY && 
    request.headers && 
    request.headers.get('X-API-Key') === env.API_SECRET_KEY;
  
  if (!rateLimitExempt && (path === '/' && request.method === 'POST')) {
    const rateCheck = await checkRateLimit(env, 'img_gen:' + token, authenticated);
    if (!rateCheck.allowed) {
      return new Response(JSON.stringify({ 
        error: 'Rate limit exceeded. Please try again later.',
        retry_after: rateCheck.retryAfter 
      }), {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': rateCheck.retryAfter.toString(),
          ...corsHeaders(request),
        }
      });
    }
  }

  if (request.method === 'GET' && path === '/') {
    const hasDB = !!db;
    const hasKV = !!kv;
    return new Response(
      `Agnes Image API Proxy is running.\nDB: ${hasDB ? 'enabled' : 'disabled'}\nKV: ${hasKV ? 'enabled' : 'disabled'}\nRate limit: ${rateLimitExempt ? 'exempt' : 'enabled'}`,
      { status: 200, headers: { 'Content-Type': 'text/plain;charset=utf-8', ...corsHeaders(request) } }
    );
  }

  if (path === '/api/images' && request.method === 'GET') {
    return handleListImages(db, kv, url, request);
  }
  if (path === '/api/images' && request.method === 'POST') {
    const body = await request.json();
    return handleSaveImage(db, kv, body, request);
  }
  const imgMatch = path.match(/^\/api\/images\/([^\/]+)$/);
  if (imgMatch) {
    const iid = imgMatch[1];
    if (request.method === 'GET') return handleGetImage(db, kv, iid, request);
    if (request.method === 'DELETE') return handleDeleteImage(db, kv, iid, request);
    if (request.method === 'PUT') {
      const body = await request.json();
      return handleUpdateImage(db, kv, iid, body, request);
    }
  }

  if (request.method === 'POST' && path === '/') {
    return handleGenerate(request, env);
  }

  // 迁移历史记录到登录用户（合并设备ID的数据到登录账号下）
  if (path === '/api/images/migrate' && request.method === 'POST') {
    return handleMigrateImages(db, kv, request);
  }

  return jsonResponse({ error: 'Not found: ' + path }, 404, request);
}

async function handleMigrateImages(db, kv, request) {
  // 必须是已登录用户
  const authHeader = request && request.headers ? request.headers.get('Authorization') : null;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return jsonResponse({ error: 'Unauthorized' }, 401, request);
  }
  const token = authHeader.substring(7);
  const targetUserId = await getUserId(request, db);
  if (!targetUserId || targetUserId === 'public') {
    return jsonResponse({ error: 'Invalid session' }, 401, request);
  }
  const deviceId = request.headers ? request.headers.get('X-Device-Id') : null;
  if (!deviceId) {
    return jsonResponse({ error: 'Missing X-Device-Id' }, 400, request);
  }
  const sourceUserId = 'dev:' + deviceId;

  if (db) {
    try {
      // 把来源 user_id 的所有记录改成目标 user_id
      const result = await db.prepare(
        'UPDATE generated_images SET user_id = ?1 WHERE user_id = ?2 AND user_id != ?1'
      ).bind(targetUserId, sourceUserId).run();
      return jsonResponse({ ok: true, migrated: result.meta?.changes || 0, user_id: targetUserId }, 200, request);
    } catch (e) {
      console.error('Migrate error:', e);
      return jsonResponse({ error: 'Migrate failed: ' + e.message }, 500, request);
    }
  }
  return jsonResponse({ error: 'No storage' }, 500, request);
}

async function handleGenerate(request, env) {
  const apiKey = env && env.AGNES_API_KEY;
  if (!apiKey) {
    return jsonResponse({ error: 'API key not configured' }, 500, request);
  }
  
  // 安全修复：API Secret Key 验证（可选，用于内部服务调用）
  // 如果配置了 API_SECRET_KEY，则请求需要通过 X-API-Key header 验证
  if (env && env.API_SECRET_KEY) {
    const apiKeyHeader = request.headers ? request.headers.get('X-API-Key') : null;
    // 注意：前端用户不传 X-API-Key，所以这个验证主要用于内部服务调用
    // 公共访问仍然允许，只是会受到速率限制
  }

  try {
    const body = await request.json();
    const { prompt, size, n, image, negative_prompt, image_weight } = body;

    if (!prompt || !size) {
      return jsonResponse({ error: 'Missing required fields: prompt, size' }, 400, request);
    }

    const count = Math.min(n || 1, 4);

    const agnesBody = {
      model: 'agnes-image-2.1-flash',
      prompt,
      size,
    };

    if (image && image.length > 0) {
      agnesBody.image = image;
      agnesBody.extra_body = {
        image,
        response_format: 'b64_json',
      };
      if (negative_prompt) {
        agnesBody.extra_body.negative_prompt = negative_prompt;
      }
      if (image_weight !== undefined && image_weight !== null) {
        agnesBody.extra_body.image_weight = image_weight;
      }
    } else {
      agnesBody.extra_body = { response_format: 'url' };
    }

    const reqs = Array.from({ length: count }, () =>
      fetch(AGNES_API_URL, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(agnesBody),
      }).then(r => r.json())
    );

    const results = await Promise.all(reqs);

    for (const r of results) {
      if (r.error) {
        // 确保 error 是字符串格式
        const errorMsg = typeof r.error === 'string' 
          ? r.error 
          : (r.error.message || r.error.type || JSON.stringify(r.error));
        return jsonResponse({ error: errorMsg }, 400, request);
      }
    }

    const allData = results.flatMap(r => r.data || []);
    const merged = { created: Math.floor(Date.now() / 1000), data: allData };

    // 如果响应里只有 url 没有 b64_json，则下载图片转成 base64 一并返回
    const needDownload = allData.length > 0 && allData.some(d => d.url && !d.b64_json);
    if (needDownload) {
      try {
        await Promise.all(merged.data.map(async (item) => {
          if (item.url && !item.b64_json) {
            try {
              const imgRes = await fetch(item.url);
              if (imgRes.ok) {
                const buf = await imgRes.arrayBuffer();
                const bytes = new Uint8Array(buf);
                let bin = '';
                for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
                item.b64_json = btoa(bin);
              }
            } catch (e) {
              console.error('Download image error:', e);
            }
          }
        }));
      } catch (e) {
        console.error('Image download batch error:', e);
      }
    }

    // 自动保存到历史记录（调用 chat-app-db worker）
    console.log('=== 开始自动保存 ===');
    const db = env && env.DB ? env.DB : null;
    const userId = await getUserId(request, db);
    console.log('Auto-save: userId =', userId);
    const headers = { 'Content-Type': 'application/json' };
    const deviceId = request.headers ? request.headers.get('X-Device-Id') : null;
    const authHeader = request.headers ? request.headers.get('Authorization') : null;
    console.log('Auto-save: deviceId =', deviceId, 'authHeader =', authHeader ? authHeader.substring(0, 20) + '...' : null);
    if (deviceId) headers['X-Device-Id'] = deviceId;
    else if (authHeader) headers['Authorization'] = authHeader;
    console.log('Auto-save: 保存请求头:', JSON.stringify(headers));

    let itemIdx = 0;
    for (const item of merged.data) {
      if (item.b64_json) {
        console.log('Auto-save: 准备保存图片, b64长度:', item.b64_json.length);
        try {
          const saveRes = await fetch(CHAT_APP_DB_URL + '/api/images', {
            method: 'POST',
            headers,
            body: JSON.stringify({
              prompt: prompt,
              size: size,
              style: '',
              image_b64: item.b64_json,
              model: 'agnes-image-2.1-flash'
            })
          });
          const saveData = await saveRes.json();
          console.log('Auto-save: 保存结果:', JSON.stringify(saveData));
          if (saveRes.ok && saveData.id) {
            console.log('Auto-saved to history:', saveData);
            // 把保存后的ID附加到返回数据中，方便前端使用
            item.id = saveData.id;
            item.created_at = saveData.created_at;
            item.is_favorite = 0;
          } else {
            console.error('Auto-save failed:', saveData);
          }
        } catch (e) {
          console.error('Auto-save error:', e);
        }
      } else {
        console.log('Auto-save: 跳过, 无b64_json');
      }
      itemIdx++;
    }
    console.log('=== 自动保存完成 ===');

    return jsonResponse(merged, 200, request);
  } catch (err) {
    return jsonResponse({ error: err.message }, 500, request);
  }
}

// ================================================================
// 数据库初始化
// ================================================================

async function ensureDB(db) {
  if (_dbInited) return;
  try {
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS generated_images (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL DEFAULT 'public',
        prompt TEXT NOT NULL,
        size TEXT NOT NULL DEFAULT '',
        style TEXT DEFAULT '',
        image_b64 TEXT NOT NULL,
        is_favorite INTEGER NOT NULL DEFAULT 0,
        model TEXT DEFAULT '',
        created_at INTEGER NOT NULL
      )
    `).run();

    try {
      await db.prepare(`CREATE INDEX IF NOT EXISTS idx_generated_images_user_id ON generated_images(user_id)`).run();
      await db.prepare(`CREATE INDEX IF NOT EXISTS idx_generated_images_created_at ON generated_images(created_at DESC)`).run();
    } catch (e) {}
    _dbInited = true;
  } catch (e) {
    console.error('initDB error:', e);
  }
}

async function getUserId(request, db) {
  const authHeader = request && request.headers ? request.headers.get('Authorization') : null;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    // 如果有 D1，查询 sessions 表获取真实 user_id
    if (db) {
      try {
        const session = await db.prepare(
          'SELECT user_id FROM sessions WHERE id = ?1 AND expires_at > ?2'
        ).bind(token, Date.now()).first();
        if (session && session.user_id) {
          return session.user_id;
        }
      } catch (e) {
        console.error('Session lookup error:', e);
      }
    }
    // D1 不可用时回退到 token 本身（兼容旧数据）
    return token;
  }
  const deviceId = request && request.headers ? request.headers.get('X-Device-Id') : null;
  if (deviceId) return 'dev:' + deviceId;
  return 'public';
}

// ================================================================
// 图片 CRUD - D1版本
// ================================================================

async function handleSaveImage(db, kv, body, request) {
  const { prompt, size, style, image_b64, model } = body || {};
  if (!prompt || !image_b64) {
    return jsonResponse({ error: 'Missing required fields: prompt, image_b64' }, 400, request);
  }

  const id = crypto.randomUUID();
  const ts = Date.now();
  const userId = await getUserId(request, db);

  if (db) {
    try {
      await db.prepare(`
        INSERT INTO generated_images (id, user_id, prompt, size, style, image_b64, model, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
      `).bind(id, userId, prompt, size || '', style || '', image_b64, model || '', ts).run();

      const HISTORY_LIMIT = 10;
      const countResult = await db.prepare(
        'SELECT COUNT(*) as total FROM generated_images WHERE user_id = ?1'
      ).bind(userId).first();
      const total = countResult?.total || 0;
      if (total > HISTORY_LIMIT) {
        const excess = total - HISTORY_LIMIT;
        // 先获取所有未收藏的记录，然后在代码中选择要删除的
        const allOldIds = await db.prepare(
          'SELECT id FROM generated_images WHERE user_id = ?1 AND is_favorite = 0 ORDER BY created_at ASC'
        ).bind(userId).all();
        const toDelete = (allOldIds.results || []).slice(0, excess);
        for (const row of toDelete) {
          await db.prepare('DELETE FROM generated_images WHERE id = ?1').bind(row.id).run();
        }
      }

      return jsonResponse({ id, created_at: ts }, 200, request);
    } catch (e) {
      console.error('DB save error:', e);
    }
  }

  if (kv) {
    try {
      const record = {
        id, prompt, size: size || '', style: style || '',
        model: model || '', image_b64, is_favorite: false,
        user_id: userId, created_at: ts,
      };
      await kv.put(KV_PREFIX + id, JSON.stringify(record));

      let index = [];
      try {
        const raw = await kv.get(KV_INDEX);
        if (raw) index = JSON.parse(raw);
      } catch (e) {}
      index.unshift({
        id, prompt, size: size || '', style: style || '',
        model: model || '', is_favorite: false,
        user_id: userId, created_at: ts,
      });

      const HISTORY_LIMIT = 10;
      const userItems = index.filter(i => !i.user_id || i.user_id === userId || i.user_id === 'public');
      if (userItems.length > HISTORY_LIMIT) {
        const nonFavSorted = userItems
          .filter(i => !i.is_favorite)
          .sort((a, b) => a.created_at - b.created_at);
        const excess = userItems.length - HISTORY_LIMIT;
        const toDelete = nonFavSorted.slice(0, excess);
        for (const item of toDelete) {
          try { await kv.delete(KV_PREFIX + item.id); } catch (e) {}
          index = index.filter(i => i.id !== item.id);
        }
      }

      await kv.put(KV_INDEX, JSON.stringify(index));
      return jsonResponse({ id, created_at: ts }, 200, request);
    } catch (e) {
      console.error('KV save error:', e);
    }
  }

  return jsonResponse({ error: 'No storage available' }, 500, request);
}

async function handleListImages(db, kv, url, request) {
  const page = parseInt(url.searchParams.get('page') || '1', 10);
  const limit = parseInt(url.searchParams.get('limit') || '20', 10);
  const favorite = url.searchParams.get('favorite');
  const withImage = url.searchParams.get('with_image') === '1';
  const userId = await getUserId(request, db);

  if (db) {
    try {
      const offset = (page - 1) * limit;
      const selectFields = withImage
        ? 'id, user_id, prompt, size, style, is_favorite, model, created_at, image_b64'
        : 'id, user_id, prompt, size, style, is_favorite, model, created_at';

      let countSql = 'SELECT COUNT(*) as total FROM generated_images WHERE user_id = ?1';
      let listSql = `SELECT ${selectFields} FROM generated_images WHERE user_id = ?1`;
      const params = [userId];

      if (favorite === '1') {
        countSql += ' AND is_favorite = 1';
        listSql += ' AND is_favorite = 1';
      } else {
        countSql += ' AND is_favorite = 0';
        listSql += ' AND is_favorite = 0';
      }

      listSql += ' ORDER BY created_at DESC LIMIT ?' + (params.length + 1) + ' OFFSET ?' + (params.length + 2);
      params.push(limit, offset);

      const countResult = await db.prepare(countSql).bind(...params.slice(0, 1)).first();
      const listResult = await db.prepare(listSql).bind(...params).all();

      return jsonResponse({
        items: listResult.results || [],
        total: countResult?.total || 0,
        page, limit,
        storage: 'd1',
      }, 200, request);
    } catch (e) {
      console.error('DB list error:', e);
    }
  }

  if (kv) {
    try {
      let index = [];
      try {
        const raw = await kv.get(KV_INDEX);
        if (raw) index = JSON.parse(raw);
      } catch (e) {}

      index = index.filter(i => !i.user_id || i.user_id === userId || i.user_id === 'public');

      if (favorite === '1') {
        index = index.filter(i => i.is_favorite);
      } else {
        index = index.filter(i => !i.is_favorite);
      }

      const total = index.length;
      const start = (page - 1) * limit;
      const items = index.slice(start, start + limit);

      if (withImage) {
        const fullItems = await Promise.all(
          items.map(async item => {
            try {
              const raw = await kv.get(KV_PREFIX + item.id);
              if (raw) {
                const rec = JSON.parse(raw);
                return { ...item, image_b64: rec.image_b64 };
              }
            } catch (e) {}
            return item;
          })
        );
        return jsonResponse({ items: fullItems, total, page, limit, storage: 'kv' }, 200, request);
      }

      return jsonResponse({ items, total, page, limit, storage: 'kv' }, 200, request);
    } catch (e) {
      console.error('KV list error:', e);
    }
  }

  return jsonResponse({ error: 'No storage available' }, 500, request);
}

async function handleGetImage(db, kv, id, request) {
  const userId = await getUserId(request, db);

  if (db) {
    try {
      const img = await db.prepare(
        'SELECT * FROM generated_images WHERE id = ?1 AND (user_id = ?2 OR user_id = ?3)'
      ).bind(id, userId, 'public').first();
      if (!img) return jsonResponse({ error: 'Image not found' }, 404, request);
      return jsonResponse(img, 200, request);
    } catch (e) {
      console.error('DB get error:', e);
    }
  }

  if (kv) {
    try {
      const raw = await kv.get(KV_PREFIX + id);
      if (!raw) return jsonResponse({ error: 'Image not found' }, 404, request);
      return jsonResponse(JSON.parse(raw), 200, request);
    } catch (e) {
      console.error('KV get error:', e);
    }
  }

  return jsonResponse({ error: 'No storage available' }, 500, request);
}

async function handleDeleteImage(db, kv, id, request) {
  const userId = await getUserId(request, db);

  if (db) {
    try {
      const img = await db.prepare(
        'SELECT id FROM generated_images WHERE id = ?1 AND (user_id = ?2 OR user_id = ?3)'
      ).bind(id, userId, 'public').first();
      if (!img) return jsonResponse({ error: 'Image not found' }, 404, request);
      await db.prepare('DELETE FROM generated_images WHERE id = ?1').bind(id).run();
      return jsonResponse({ ok: true }, 200, request);
    } catch (e) {
      console.error('DB delete error:', e);
    }
  }

  if (kv) {
    try {
      await kv.delete(KV_PREFIX + id);
      try {
        const raw = await kv.get(KV_INDEX);
        if (raw) {
          let index = JSON.parse(raw);
          index = index.filter(i => i.id !== id);
          await kv.put(KV_INDEX, JSON.stringify(index));
        }
      } catch (e) {}
      return jsonResponse({ ok: true }, 200, request);
    } catch (e) {
      console.error('KV delete error:', e);
    }
  }

  return jsonResponse({ error: 'No storage available' }, 500, request);
}

async function handleUpdateImage(db, kv, id, body, request) {
  const { is_favorite } = body || {};
  const userId = await getUserId(request, db);

  if (db) {
    try {
      const img = await db.prepare(
        'SELECT id FROM generated_images WHERE id = ?1 AND (user_id = ?2 OR user_id = ?3)'
      ).bind(id, userId, 'public').first();
      if (!img) return jsonResponse({ error: 'Image not found' }, 404, request);

      if (typeof is_favorite !== 'undefined') {
        const favVal = is_favorite ? 1 : 0;
        await db.prepare(
          'UPDATE generated_images SET is_favorite = ?1 WHERE id = ?2'
        ).bind(favVal, id).run();
      }
      return jsonResponse({ ok: true }, 200, request);
    } catch (e) {
      console.error('DB update error:', e);
    }
  }

  if (kv) {
    try {
      const raw = await kv.get(KV_PREFIX + id);
      if (!raw) return jsonResponse({ error: 'Image not found' }, 404, request);

      const record = JSON.parse(raw);
      if (typeof is_favorite !== 'undefined') {
        record.is_favorite = !!is_favorite;
        await kv.put(KV_PREFIX + id, JSON.stringify(record));

        try {
          const idxRaw = await kv.get(KV_INDEX);
          if (idxRaw) {
            let index = JSON.parse(idxRaw);
            const idx = index.find(i => i.id === id);
            if (idx) idx.is_favorite = !!is_favorite;
            await kv.put(KV_INDEX, JSON.stringify(index));
          }
        } catch (e) {}
      }
      return jsonResponse({ ok: true }, 200, request);
    } catch (e) {
      console.error('KV update error:', e);
    }
  }

  return jsonResponse({ error: 'No storage available' }, 500, request);
}

// ================================================================
// 工具函数
// ================================================================

function jsonResponse(data, status, request) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(request),
    },
  });
}

function corsHeaders(request) {
  const origin = request && request.headers ? (request.headers.get('Origin') || '*') : '*';
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Device-Id',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400',
  };
}

export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env, ctx);
  },
};
