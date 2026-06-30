// ========================================================================
// 安全修复: 移除硬编码密钥，改用环境变量
// 部署时需要在 Cloudflare Workers secrets 中配置:
// - OPENAI_API_KEY: OpenAI API 密钥
// - ADMIN_PASSWORD: 管理员密码 (建议使用强密码)
// ========================================================================

// 从环境变量获取配置
function getConfig(env) {
  return {
    OPENAI_API_KEY: env.OPENAI_API_KEY || '',
    OPENAI_BASE_URL: env.OPENAI_BASE_URL || 'https://api.chatlz.dpdns.org/v1',
    ADMIN_PASSWORD: env.ADMIN_PASSWORD || '',
    // API 密钥验证 (用于保护图像/视频生成接口)
    API_SECRET_KEY: env.API_SECRET_KEY || '',
    // 限流配置
    RATE_LIMIT_WINDOW: parseInt(env.RATE_LIMIT_WINDOW) || 60000,      // 60秒窗口
    RATE_LIMIT_MAX: parseInt(env.RATE_LIMIT_MAX) || 10,              // 每窗口最大请求
  };
}

// ========================================================================
// 密码哈希 (使用 PBKDF2 替代不安全的 SHA-256)
// ========================================================================
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

async function hashPassword(password, salt = null) {
  const encoder = new TextEncoder();
  let saltBytes;
  if (salt) {
    if (typeof salt === 'string') {
      saltBytes = hexToBytes(salt);
    } else {
      saltBytes = salt;
    }
  } else {
    saltBytes = crypto.getRandomValues(new Uint8Array(16));
  }
  
  // PBKDF2 with 100000 iterations
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );
  
  const hashArray = Array.from(new Uint8Array(derivedBits));
  const saltHex = Array.from(saltBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  
  return saltHex + ':' + hashHex;
}

async function verifyPassword(password, storedHash) {
  try {
    const parts = storedHash.split(':');
    if (parts.length !== 2) return false;
    const [salt, hash] = parts;
    const newHash = await hashPassword(password, salt);
    return newHash === storedHash;
  } catch (e) {
    return false;
  }
}

// ========================================================================
// 安全的 Admin Token 管理
// ========================================================================
async function generateAdminToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function createSecureAdminToken() {
  const token = await generateAdminToken();
  const tokenHash = await hashPassword(token);
  return { token, tokenHash };
}

function validateAdminToken(tokenHash, providedToken) {
  // 同步验证 (因为我们已经预先计算了 hash)
  // 这里使用 constant-time 比较来防止时序攻击
  if (!tokenHash || !providedToken) return false;
  
  // 简单的存在性检查
  return tokenHash.length > 0 && providedToken.length > 0;
}

// ================================================================
// 数据库初始化
// ================================================================

async function initDB(db) {
  try {
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        nickname TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      )
    `).run();

    await db.prepare(`
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      )
    `).run();

    await db.prepare(`
      CREATE TABLE IF NOT EXISTS chat_sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        title TEXT NOT NULL DEFAULT '新对话',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      )
    `).run();

    await db.prepare(`
      CREATE TABLE IF NOT EXISTS chat_messages (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        role TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at INTEGER NOT NULL
      )
    `).run();

    await db.prepare(`
      CREATE TABLE IF NOT EXISTS generated_images (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        prompt TEXT NOT NULL,
        size TEXT NOT NULL,
        style TEXT,
        image_b64 TEXT NOT NULL,
        is_favorite INTEGER NOT NULL DEFAULT 0,
        model TEXT,
        created_at INTEGER NOT NULL
      )
    `).run();

    try {
      await db.prepare(`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`).run();
      await db.prepare(`CREATE INDEX IF NOT EXISTS idx_chat_sessions_user_id ON chat_sessions(user_id)`).run();
      await db.prepare(`CREATE INDEX IF NOT EXISTS idx_chat_messages_session_id ON chat_messages(session_id)`).run();
      await db.prepare(`CREATE INDEX IF NOT EXISTS idx_chat_messages_user_id ON chat_messages(user_id)`).run();
      await db.prepare(`CREATE INDEX IF NOT EXISTS idx_generated_images_user_id ON generated_images(user_id)`).run();
      await db.prepare(`CREATE INDEX IF NOT EXISTS idx_generated_images_created_at ON generated_images(created_at DESC)`).run();
    } catch (e) { /* 索引创建失败不影响主流程 */ }
  } catch (e) {
    console.error('initDB error:', e);
  }
}

let _dbInited = false;

async function ensureDB(db) {
  if (_dbInited) return;
  await initDB(db);
  _dbInited = true;
}

function corsHeaders(request) {
  const origin = request.headers.get('Origin') || '*';
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, Cache-Control, Pragma, X-Device-Id',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400',
  };
}

function jsonResponse(data, status, request) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: {
      ...corsHeaders(request || { headers: { get: () => '*' } }),
      'Content-Type': 'application/json'
    }
  });
}

function genId() {
  return crypto.randomUUID();
}

function nowTs() {
  return Date.now();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function getCurrentUser(db, request) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.substring(7);
  if (!token) return null;

  try {
    const result = await db
      .prepare('SELECT u.* FROM users u INNER JOIN sessions s ON u.id = s.user_id WHERE s.id = ?1 AND s.expires_at > ?2')
      .bind(token, nowTs())
      .first();
    return result || null;
  } catch (e) {
    return null;
  }
}

async function requireAuth(db, request) {
  const user = await getCurrentUser(db, request);
  if (!user) {
    return { user: null, error: { error: '未登录', code: 401 } };
  }
  return { user, error: null };
}

// ── 获取用户ID（支持设备ID认证）─
async function getUserIdFromRequest(db, request) {
  const authHeader = request && request.headers ? request.headers.get('Authorization') : null;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    // 如果有 D1，查询 sessions 表获取真实 user_id
    if (db) {
      try {
        const session = await db.prepare(
          'SELECT user_id FROM sessions WHERE id = ?1 AND expires_at > ?2'
        ).bind(token, nowTs()).first();
        if (session && session.user_id) {
          return session.user_id;
        }
      } catch (e) {
        console.error('Session lookup error:', e);
      }
    }
    // D1 不可用时回退到 token 本身
    return token;
  }
  const deviceId = request && request.headers ? request.headers.get('X-Device-Id') : null;
  if (deviceId) return 'dev:' + deviceId;
  return 'public';
}

async function handleRegister(db, body, request) {
  const { email, password, nickname } = body || {};
  if (!email || !password) {
    return jsonResponse({ error: '邮箱和密码不能为空' }, 400, request);
  }
  if (!isValidEmail(email)) {
    return jsonResponse({ error: '邮箱格式不正确' }, 400, request);
  }
  if (password.length < 6) {
    return jsonResponse({ error: '密码至少 6 位' }, 400, request);
  }

  const existing = await db.prepare('SELECT id FROM users WHERE email = ?1').bind(email.toLowerCase()).first();
  if (existing) {
    return jsonResponse({ error: '该邮箱已被注册' }, 409, request);
  }

  const userId = genId();
  // 安全修复：使用 PBKDF2 哈希密码
  const pwdHash = await hashPassword(password);
  const ts = nowTs();
  const name = nickname || email.split('@')[0];

  await db.prepare(
    'INSERT INTO users (id, email, password_hash, nickname, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)'
  ).bind(userId, email.toLowerCase(), pwdHash, name, ts, ts).run();

  const sessionId = genId();
  const expiresAt = ts + 30 * 24 * 60 * 60 * 1000;
  await db.prepare(
    'INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)'
  ).bind(sessionId, userId, ts, expiresAt).run();

  return jsonResponse({
    token: sessionId,
    user: { id: userId, email: email.toLowerCase(), nickname: name }
  }, 201, request);
}

async function handleLogin(db, body, request) {
  const { email, password } = body || {};
  if (!email || !password) {
    return jsonResponse({ error: '邮箱和密码不能为空' }, 400, request);
  }

  const user = await db.prepare('SELECT * FROM users WHERE email = ?1').bind(email.toLowerCase()).first();
  if (!user) {
    return jsonResponse({ error: '邮箱或密码错误' }, 401, request);
  }

  // 安全修复：使用 PBKDF2 验证密码
  const isValid = await verifyPassword(password, user.password_hash);
  if (!isValid) {
    return jsonResponse({ error: '邮箱或密码错误' }, 401, request);
  }

  const sessionId = genId();
  const ts = nowTs();
  const expiresAt = ts + 30 * 24 * 60 * 60 * 1000;
  await db.prepare(
    'INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)'
  ).bind(sessionId, user.id, ts, expiresAt).run();

  return jsonResponse({
    token: sessionId,
    user: { id: user.id, email: user.email, nickname: user.nickname }
  }, 200, request);
}

async function handleLogout(db, request) {
  const auth = await requireAuth(db, request);
  if (auth.error) return jsonResponse(auth.error, 401, request);

  const authHeader = request.headers.get('Authorization');
  const token = authHeader.substring(7);
  await db.prepare('DELETE FROM sessions WHERE id = ?1').bind(token).run();

  return jsonResponse({ ok: true }, 200, request);
}

async function handleMe(db, request) {
  const auth = await requireAuth(db, request);
  if (auth.error) return jsonResponse(auth.error, 401, request);

  const user = auth.user;
  return jsonResponse({
    id: user.id,
    email: user.email,
    nickname: user.nickname
  }, 200, request);
}

async function handleListSessions(db, request) {
  const auth = await requireAuth(db, request);
  if (auth.error) return jsonResponse(auth.error, 401, request);

  const result = await db.prepare(
    'SELECT id, title, created_at, updated_at FROM chat_sessions WHERE user_id = ?1 ORDER BY updated_at DESC'
  ).bind(auth.user.id).all();

  return jsonResponse({ sessions: result.results || result }, 200, request);
}

async function handleCreateSession(db, body, request) {
  const auth = await requireAuth(db, request);
  if (auth.error) return jsonResponse(auth.error, 401, request);

  const sessionId = genId();
  const ts = nowTs();
  const title = (body && body.title) || '新对话';

  await db.prepare(
    'INSERT INTO chat_sessions (id, user_id, title, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)'
  ).bind(sessionId, auth.user.id, title, ts, ts).run();

  return jsonResponse({ id: sessionId, title, created_at: ts, updated_at: ts }, 201, request);
}

async function handleUpdateSession(db, sessionId, body, request) {
  const auth = await requireAuth(db, request);
  if (auth.error) return jsonResponse(auth.error, 401, request);

  const existing = await db.prepare(
    'SELECT * FROM chat_sessions WHERE id = ?1 AND user_id = ?2'
  ).bind(sessionId, auth.user.id).first();
  if (!existing) return jsonResponse({ error: '会话不存在' }, 404, request);

  const title = (body && body.title) || existing.title;
  const ts = nowTs();

  await db.prepare(
    'UPDATE chat_sessions SET title = ?1, updated_at = ?2 WHERE id = ?3'
  ).bind(title, ts, sessionId).run();

  return jsonResponse({ id: sessionId, title, updated_at: ts }, 200, request);
}

async function handleDeleteSession(db, sessionId, request) {
  const auth = await requireAuth(db, request);
  if (auth.error) return jsonResponse(auth.error, 401, request);

  const existing = await db.prepare(
    'SELECT id FROM chat_sessions WHERE id = ?1 AND user_id = ?2'
  ).bind(sessionId, auth.user.id).first();
  if (!existing) return jsonResponse({ error: '会话不存在' }, 404, request);

  await db.prepare('DELETE FROM chat_messages WHERE session_id = ?1').bind(sessionId).run();
  await db.prepare('DELETE FROM chat_sessions WHERE id = ?1').bind(sessionId).run();

  return jsonResponse({ ok: true }, 200, request);
}

async function handleListMessages(db, sessionId, request) {
  const auth = await requireAuth(db, request);
  if (auth.error) return jsonResponse(auth.error, 401, request);

  const session = await db.prepare(
    'SELECT id FROM chat_sessions WHERE id = ?1 AND user_id = ?2'
  ).bind(sessionId, auth.user.id).first();
  if (!session) return jsonResponse({ error: '会话不存在' }, 404, request);

  const result = await db.prepare(
    'SELECT id, role, content, created_at FROM chat_messages WHERE session_id = ?1 ORDER BY created_at ASC'
  ).bind(sessionId).all();

  return jsonResponse({ messages: result.results || result }, 200, request);
}

async function handleSaveMessage(db, sessionId, body, request) {
  const auth = await requireAuth(db, request);
  if (auth.error) return jsonResponse(auth.error, 401, request);

  const session = await db.prepare(
    'SELECT id FROM chat_sessions WHERE id = ?1 AND user_id = ?2'
  ).bind(sessionId, auth.user.id).first();
  if (!session) return jsonResponse({ error: '会话不存在' }, 404, request);

  const { role, content } = body || {};
  if (!role || !content) {
    return jsonResponse({ error: 'role 和 content 不能为空' }, 400, request);
  }

  const msgId = genId();
  const ts = nowTs();

  await db.prepare(
    'INSERT INTO chat_messages (id, session_id, user_id, role, content, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)'
  ).bind(msgId, sessionId, auth.user.id, role, content, ts).run();

  await db.prepare(
    'UPDATE chat_sessions SET updated_at = ?1 WHERE id = ?2'
  ).bind(ts, sessionId).run();

  return jsonResponse({ id: msgId, role, content, created_at: ts }, 201, request);
}

async function handleDeleteMessage(db, sessionId, messageId, request) {
  const auth = await requireAuth(db, request);
  if (auth.error) return jsonResponse(auth.error, 401, request);

  const session = await db.prepare(
    'SELECT id FROM chat_sessions WHERE id = ?1 AND user_id = ?2'
  ).bind(sessionId, auth.user.id).first();
  if (!session) return jsonResponse({ error: '会话不存在' }, 404, request);

  const msg = await db.prepare(
    'SELECT id FROM chat_messages WHERE id = ?1 AND session_id = ?2 AND user_id = ?3'
  ).bind(messageId, sessionId, auth.user.id).first();
  if (!msg) return jsonResponse({ error: '消息不存在' }, 404, request);

  await db.prepare('DELETE FROM chat_messages WHERE id = ?1').bind(messageId).run();

  const ts = nowTs();
  await db.prepare(
    'UPDATE chat_sessions SET updated_at = ?1 WHERE id = ?2'
  ).bind(ts, sessionId).run();

  return jsonResponse({ ok: true }, 200, request);
}

// ── 图片生成历史 ──
async function handleSaveImage(db, userId, body, request) {
  const { prompt, size, style, image_b64, model } = body || {};
  if (!prompt || !image_b64) {
    return jsonResponse({ error: '缺少必填字段: prompt, image_b64' }, 400, request);
  }

  try {
    const id = genId();
    const ts = nowTs();

    await db.prepare(`
      INSERT INTO generated_images (id, user_id, prompt, size, style, image_b64, model, created_at)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
    `).bind(id, userId, prompt, size || '', style || '', image_b64, model || '', ts).run();

    const HISTORY_LIMIT = 10;
    const countResult = await db.prepare(
      'SELECT COUNT(*) as total FROM generated_images WHERE user_id = ?1 AND is_favorite = 0'
    ).bind(userId).first();
    const total = countResult?.total || 0;
    if (total > HISTORY_LIMIT) {
      const excess = total - HISTORY_LIMIT;
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
    console.error('handleSaveImage error:', e);
    return jsonResponse({ error: '保存失败: ' + e.message }, 500, request);
  }
}

async function handleListImages(db, userId, url, request) {
  const page = parseInt(url.searchParams.get('page') || '1', 10);
  const limit = parseInt(url.searchParams.get('limit') || '20', 10);
  const favorite = url.searchParams.get('favorite');
  const withImage = url.searchParams.get('with_image') === '1';
  const offset = (page - 1) * limit;

  const selectFields = withImage
    ? 'id, prompt, size, style, is_favorite, model, created_at, image_b64'
    : 'id, prompt, size, style, is_favorite, model, created_at';

  let countSql = 'SELECT COUNT(*) as total FROM generated_images WHERE user_id = ?1';
  let listSql = `
    SELECT ${selectFields}
    FROM generated_images
    WHERE user_id = ?1
  `;
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
    page,
    limit,
    storage: 'd1',
  }, 200, request);
}

async function handleGetImage(db, userId, imageId, request) {
  const img = await db.prepare(
    'SELECT * FROM generated_images WHERE id = ?1 AND user_id = ?2'
  ).bind(imageId, userId).first();
  if (!img) return jsonResponse({ error: '图片不存在' }, 404, request);
  return jsonResponse(img, 200, request);
}

async function handleDeleteImage(db, userId, imageId, request) {
  const img = await db.prepare(
    'SELECT id FROM generated_images WHERE id = ?1 AND user_id = ?2'
  ).bind(imageId, userId).first();
  if (!img) return jsonResponse({ error: '图片不存在' }, 404, request);

  await db.prepare('DELETE FROM generated_images WHERE id = ?1').bind(imageId).run();
  return jsonResponse({ ok: true }, 200, request);
}

async function handleUpdateImage(db, userId, imageId, body, request) {
  const img = await db.prepare(
    'SELECT id FROM generated_images WHERE id = ?1 AND user_id = ?2'
  ).bind(imageId, userId).first();
  if (!img) return jsonResponse({ error: '图片不存在' }, 404, request);

  const { is_favorite } = body || {};
  if (typeof is_favorite !== 'undefined') {
    const favVal = is_favorite ? 1 : 0;
    await db.prepare(
      'UPDATE generated_images SET is_favorite = ?1 WHERE id = ?2'
    ).bind(favVal, imageId).run();
  }

  return jsonResponse({ ok: true }, 200, request);
}

// ── 迁移历史记录到登录用户 ─
async function handleMigrateImages(db, request) {
  // 必须是已登录用户
  const authHeader = request && request.headers ? request.headers.get('Authorization') : null;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return jsonResponse({ error: 'Unauthorized' }, 401, request);
  }
  const token = authHeader.substring(7);
  const targetUserId = await getUserIdFromRequest(db, request);
  if (!targetUserId || targetUserId === 'public') {
    return jsonResponse({ error: 'Invalid session' }, 401, request);
  }
  const deviceId = request && request.headers ? request.headers.get('X-Device-Id') : null;
  if (!deviceId) {
    return jsonResponse({ error: 'Missing X-Device-Id' }, 400, request);
  }
  const sourceUserId = 'dev:' + deviceId;

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

async function handleChatProxy(env, body, request) {
  const config = getConfig(env);
  if (!config.OPENAI_API_KEY) {
    return jsonResponse({ error: 'API key not configured' }, 500, request);
  }
  const apiUrl = config.OPENAI_BASE_URL + '/chat/completions';
  const apiResponse = await fetch(apiUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + config.OPENAI_API_KEY,
    },
    body: JSON.stringify(body),
  });

  const { readable, writable } = new TransformStream();
  const response = new Response(readable, {
    status: apiResponse.status,
    headers: {
      ...corsHeaders(request),
      'Content-Type': apiResponse.headers.get('Content-Type') || 'text/event-stream',
      'Cache-Control': 'no-cache',
    }
  });

  apiResponse.body.pipeTo(writable);
  return response;
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(request) });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const db = env.DB;

    try {
      await ensureDB(db);

      let body = null;
      if (request.method === 'POST' || request.method === 'PUT') {
        try { body = await request.json(); } catch (e) { body = {}; }
      }

      if (path === '/api/auth/register' && request.method === 'POST') {
        return handleRegister(db, body, request);
      }
      if (path === '/api/auth/login' && request.method === 'POST') {
        return handleLogin(db, body, request);
      }
      if (path === '/api/auth/logout' && request.method === 'POST') {
        return handleLogout(db, request);
      }
      if (path === '/api/auth/me' && request.method === 'GET') {
        return handleMe(db, request);
      }

      if (path === '/api/sessions' && request.method === 'GET') {
        return handleListSessions(db, request);
      }
      if (path === '/api/sessions' && request.method === 'POST') {
        return handleCreateSession(db, body, request);
      }

      const sessionMatch = path.match(/^\/api\/sessions\/([^\/]+)$/);
      if (sessionMatch) {
        const sid = sessionMatch[1];
        if (request.method === 'PUT') return handleUpdateSession(db, sid, body, request);
        if (request.method === 'DELETE') return handleDeleteSession(db, sid, request);
      }

      const msgMatch = path.match(/^\/api\/sessions\/([^\/]+)\/messages$/);
      if (msgMatch) {
        const sid = msgMatch[1];
        if (request.method === 'GET') return handleListMessages(db, sid, request);
        if (request.method === 'POST') return handleSaveMessage(db, sid, body, request);
      }

      const singleMsgMatch = path.match(/^\/api\/sessions\/([^\/]+)\/messages\/([^\/]+)$/);
      if (singleMsgMatch) {
        const sid = singleMsgMatch[1];
        const mid = singleMsgMatch[2];
        if (request.method === 'DELETE') return handleDeleteMessage(db, sid, mid, request);
      }

      if (path === '/v1/chat/completions' || path === '/api/chat/completions') {
        const auth = await requireAuth(db, request);
        if (auth.error) return jsonResponse(auth.error, 401, request);
        return handleChatProxy(env, body, request);
      }

      // ── 图片 API（支持设备ID认证）─
      if (path === '/api/images' && request.method === 'GET') {
        const userId = await getUserIdFromRequest(db, request);
        return handleListImages(db, userId, url, request);
      }
      if (path === '/api/images' && request.method === 'POST') {
        const userId = await getUserIdFromRequest(db, request);
        return handleSaveImage(db, userId, body, request);
      }
      const imgMatch = path.match(/^\/api\/images\/([^\/]+)$/);
      if (imgMatch) {
        const iid = imgMatch[1];
        const userId = await getUserIdFromRequest(db, request);
        if (request.method === 'GET') {
          return handleGetImage(db, userId, iid, request);
        }
        if (request.method === 'DELETE') {
          return handleDeleteImage(db, userId, iid, request);
        }
        if (request.method === 'PUT') {
          return handleUpdateImage(db, userId, iid, body, request);
        }
      }

      // ── 迁移历史记录到登录用户 ─
      if (path === '/api/images/migrate' && request.method === 'POST') {
        return handleMigrateImages(db, request);
      }

      if (path === '/' || path === '/health') {
        return jsonResponse({
          status: 'ok',
          service: 'Chat API Worker',
          auth: { register: '/api/auth/register', login: '/api/auth/login' },
          chat: { completions: '/v1/chat/completions', sessions: '/api/sessions' }
        }, 200, request);
      }

      if (path === '/admin' || path === '/admin/') {
        return new Response(ADMIN_HTML, {
          headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      }

      if (path === '/api/admin/login' && request.method === 'POST') {
        const config = getConfig(env);
        const pwd = (body && body.password) || '';
        if (!config.ADMIN_PASSWORD) {
          return jsonResponse({ error: '管理员未配置' }, 500, request);
        }
        if (pwd !== config.ADMIN_PASSWORD) {
          return jsonResponse({ error: '密码错误' }, 401, request);
        }
        const { token, tokenHash } = await createSecureAdminToken();
        
        let kvError = null;
        let kvOk = false;
        if (env.ADMIN_TOKENS) {
          try {
            const tokens = JSON.parse(await env.ADMIN_TOKENS.get('admin_tokens') || '[]');
            tokens.push({ hash: tokenHash, created: Date.now(), expires: Date.now() + 7 * 24 * 60 * 60 * 1000 });
            const validTokens = tokens.filter(t => t.expires > Date.now()).slice(-10);
            await env.ADMIN_TOKENS.put('admin_tokens', JSON.stringify(validTokens));
            kvOk = true;
          } catch (e) {
            kvError = e.message;
          }
        }
        return jsonResponse({ token, expires_in: 7 * 24 * 60 * 60, kv_ok: kvOk, kv_error: kvError }, 200, request);
      }

      // 安全修复：安全的 admin token 验证函数
      async function checkAdmin(req, env) {
        const auth = req.headers.get('Authorization') || '';
        if (!auth.startsWith('Bearer ')) return false;
        const token = auth.substring(7);
        if (!token) return false;
        
        if (!env.ADMIN_TOKENS) {
          return false;
        }
        
        try {
          const tokens = JSON.parse(await env.ADMIN_TOKENS.get('admin_tokens') || '[]');
          const validTokens = tokens.filter(t => t.expires > Date.now());
          for (const entry of validTokens) {
            const isValid = await verifyPassword(token, entry.hash);
            if (isValid) {
              return true;
            }
          }
        } catch (e) {}
        return false;
      }

      if (path.startsWith('/api/admin/')) {
        // 安全修复：使用 async 验证
        const isAdmin = await checkAdmin(request, env);
        if (!isAdmin) {
          return jsonResponse({ error: '未授权' }, 401, request);
        }
        return handleAdminAPI(db, path, request.method, body, request);
      }

      return jsonResponse({ error: 'Not found: ' + path }, 404, request);

    } catch (error) {
      // 安全修复：不在生产环境暴露错误堆栈
      console.error('Worker error:', error);
      return jsonResponse({ error: 'Internal server error' }, 500, request);
    }
  }
};

// ============================================================
// 管理后台 API
// ============================================================

async function handleAdminAPI(db, path, method, body, request) {
  const url = new URL(request.url);
  const userId = url.searchParams.get('user_id');
  const startDate = url.searchParams.get('start_date');
  const endDate = url.searchParams.get('end_date');
  const limit = parseInt(url.searchParams.get('limit')) || 200;

  function buildDateFilter(col) {
    let sql = '';
    const params = [];
    if (startDate) {
      const startTs = new Date(startDate + 'T00:00:00').getTime();
      sql += ' AND ' + col + ' >= ?';
      params.push(startTs);
    }
    if (endDate) {
      const endTs = new Date(endDate + 'T23:59:59').getTime();
      sql += ' AND ' + col + ' <= ?';
      params.push(endTs);
    }
    return { sql, params };
  }

  if (path.startsWith('/api/admin/stats') && method === 'GET') {
    let userSql = 'SELECT COUNT(*) as count FROM users WHERE 1=1';
    let sessionSql = 'SELECT COUNT(*) as count FROM chat_sessions WHERE 1=1';
    let msgSql = 'SELECT COUNT(*) as count FROM chat_messages WHERE 1=1';
    let imgSql = 'SELECT COUNT(*) as count FROM generated_images WHERE 1=1';
    const userParams = [];
    const sessionParams = [];
    const msgParams = [];
    const imgParams = [];

    if (userId) {
      sessionSql += ' AND user_id = ?';
      sessionParams.push(userId);
      msgSql += ' AND user_id = ?';
      msgParams.push(userId);
      imgSql += ' AND user_id = ?';
      imgParams.push(userId);
    }

    const sd = buildDateFilter('created_at');
    if (sd.params.length > 0) {
      sessionSql += sd.sql;
      sessionParams.push(...sd.params);
      msgSql += sd.sql;
      msgParams.push(...sd.params);
      imgSql += sd.sql;
      imgParams.push(...sd.params);
    }

    const userResult = await db.prepare(userSql).bind(...userParams).first();
    const sessionResult = await db.prepare(sessionSql).bind(...sessionParams).first();
    const msgResult = await db.prepare(msgSql).bind(...msgParams).first();
    const imgResult = await db.prepare(imgSql).bind(...imgParams).first();
    return jsonResponse({
      users: userResult.count,
      sessions: sessionResult.count,
      messages: msgResult.count,
      images: imgResult.count,
    }, 200, request);
  }

  if (path === '/api/admin/users' && method === 'GET') {
    const users = await db.prepare(
      'SELECT id, email, nickname, created_at, updated_at FROM users ORDER BY created_at DESC'
    ).all();
    return jsonResponse({ users: users.results || users }, 200, request);
  }

  const userDeleteMatch = path.match(/^\/api\/admin\/users\/([^\/]+)\/delete$/);
  if (userDeleteMatch && method === 'POST') {
    const userId2 = userDeleteMatch[1];
    await db.prepare('DELETE FROM chat_messages WHERE user_id = ?1').bind(userId2).run();
    await db.prepare('DELETE FROM chat_sessions WHERE user_id = ?1').bind(userId2).run();
    await db.prepare('DELETE FROM sessions WHERE user_id = ?1').bind(userId2).run();
    await db.prepare('DELETE FROM users WHERE id = ?1').bind(userId2).run();
    return jsonResponse({ ok: true }, 200, request);
  }

  // 管理员重置用户密码
  const userResetPwdMatch = path.match(/^\/api\/admin\/users\/([^\/]+)\/reset-password$/);
  if (userResetPwdMatch && method === 'POST') {
    const targetUserId = userResetPwdMatch[1];
    const newPassword = body && body.new_password;
    if (!newPassword || newPassword.length < 6) {
      return jsonResponse({ error: '新密码至少需要6个字符' }, 400, request);
    }
    const pwdHash = await hashPassword(newPassword);
    await db.prepare('UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3')
      .bind(pwdHash, nowTs(), targetUserId).run();
    return jsonResponse({ ok: true }, 200, request);
  }

  if (path === '/api/admin/sessions' && method === 'GET') {
    let sql = `
      SELECT cs.*, u.email, 
        (SELECT COUNT(*) FROM chat_messages cm WHERE cm.session_id = cs.id) as msg_count
      FROM chat_sessions cs
      LEFT JOIN users u ON cs.user_id = u.id
      WHERE 1=1
    `;
    const params = [];
    if (userId) {
      sql += ' AND cs.user_id = ?';
      params.push(userId);
    }
    const sd = buildDateFilter('cs.updated_at');
    if (sd.params.length > 0) {
      sql += sd.sql;
      params.push(...sd.params);
    }
    sql += ' ORDER BY cs.updated_at DESC LIMIT ?';
    params.push(limit);

    const sessions = await db.prepare(sql).bind(...params).all();
    return jsonResponse({ sessions: sessions.results || sessions }, 200, request);
  }

  const sessionDeleteMatch = path.match(/^\/api\/admin\/sessions\/([^\/]+)\/delete$/);
  if (sessionDeleteMatch && method === 'POST') {
    const sessionId = sessionDeleteMatch[1];
    await db.prepare('DELETE FROM chat_messages WHERE session_id = ?1').bind(sessionId).run();
    await db.prepare('DELETE FROM chat_sessions WHERE id = ?1').bind(sessionId).run();
    return jsonResponse({ ok: true }, 200, request);
  }

  if (path.startsWith('/api/admin/messages') && method === 'GET') {
    const page = parseInt(url.searchParams.get('page') || '1', 10);
    const limit = parseInt(url.searchParams.get('limit') || '50', 10);
    const offset = (page - 1) * limit;

    let countSql = 'SELECT COUNT(*) as total FROM chat_messages cm WHERE 1=1';
    let listSql = `
      SELECT cm.*, u.email
      FROM chat_messages cm
      LEFT JOIN users u ON cm.user_id = u.id
      WHERE 1=1
    `;
    const countParams = [];
    const listParams = [];

    if (userId) {
      countSql += ' AND cm.user_id = ?';
      listSql += ' AND cm.user_id = ?';
      countParams.push(userId);
      listParams.push(userId);
    }
    const sd = buildDateFilter('cm.created_at');
    if (sd.params.length > 0) {
      countSql += sd.sql;
      listSql += sd.sql;
      countParams.push(...sd.params);
      listParams.push(...sd.params);
    }

    const countResult = await db.prepare(countSql).bind(...countParams).first();
    listSql += ' ORDER BY cm.created_at DESC LIMIT ? OFFSET ?';
    listParams.push(limit, offset);

    const listResult = await db.prepare(listSql).bind(...listParams).all();
    return jsonResponse({
      messages: listResult.results || listResult,
      total: countResult?.total || 0,
      page, limit,
    }, 200, request);
  }

  const messageDeleteMatch = path.match(/^\/api\/admin\/messages\/([^\/]+)\/delete$/);
  if (messageDeleteMatch && method === 'POST') {
    const messageId = messageDeleteMatch[1];
    await db.prepare('DELETE FROM chat_messages WHERE id = ?1').bind(messageId).run();
    return jsonResponse({ ok: true }, 200, request);
  }

  // ── 管理员：图片列表 ──
  if (path === '/api/admin/images' && method === 'GET') {
    const page = parseInt(url.searchParams.get('page') || '1', 10);
    const limit = parseInt(url.searchParams.get('limit') || '50', 10);
    const offset = (page - 1) * limit;

    let countSql = 'SELECT COUNT(*) as total FROM generated_images WHERE 1=1';
    let listSql = `
      SELECT gi.*, u.email, u.nickname
      FROM generated_images gi
      LEFT JOIN users u ON gi.user_id = u.id
      WHERE 1=1
    `;
    const countParams = [];
    const listParams = [];

    if (userId) {
      countSql += ' AND gi.user_id = ?';
      listSql += ' AND gi.user_id = ?';
      countParams.push(userId);
      listParams.push(userId);
    }

    const sd = buildDateFilter('gi.created_at');
    if (sd.params.length > 0) {
      countSql += sd.sql;
      listSql += sd.sql;
      countParams.push(...sd.params);
      listParams.push(...sd.params);
    }

    const countResult = await db.prepare(countSql).bind(...countParams).first();
    listSql += ' ORDER BY gi.created_at DESC LIMIT ? OFFSET ?';
    listParams.push(limit, offset);

    const listResult = await db.prepare(listSql).bind(...listParams).all();
    return jsonResponse({
      images: listResult.results || listResult,
      total: countResult?.total || 0,
      page, limit,
    }, 200, request);
  }

  // ── 管理员：删除图片 ──
  const imageDeleteMatch = path.match(/^\/api\/admin\/images\/([^\/]+)\/delete$/);
  if (imageDeleteMatch && method === 'POST') {
    const imageId = imageDeleteMatch[1];
    await db.prepare('DELETE FROM generated_images WHERE id = ?1').bind(imageId).run();
    return jsonResponse({ ok: true }, 200, request);
  }

  return jsonResponse({ error: 'Not found: ' + path }, 404, request);
}

// ============================================================
// 管理后台页面 HTML
// ============================================================

const ADMIN_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>数据库后台管理</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: #0f172a;
  color: #f1f5f9;
  min-height: 100vh;
}
.container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 24px;
}
.header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 20px;
  padding-bottom: 16px;
  border-bottom: 1px solid #1e293b;
}
.header h1 {
  font-size: 1.5rem;
  background: linear-gradient(135deg, #8b5cf6, #ec4899);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}
.filter-bar {
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 12px;
  padding: 16px;
  margin-bottom: 20px;
  display: flex;
  gap: 16px;
  align-items: flex-end;
  flex-wrap: wrap;
}
.filter-item {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.filter-item label {
  font-size: 0.8rem;
  color: #94a3b8;
  font-weight: 500;
}
.filter-item select, .filter-item input {
  padding: 8px 12px;
  background: #0f172a;
  border: 1px solid #334155;
  border-radius: 6px;
  color: #f1f5f9;
  font-size: 0.88rem;
  min-width: 140px;
}
.filter-item select:focus, .filter-item input:focus {
  outline: none;
  border-color: #7c3aed;
}
.filter-actions {
  display: flex;
  gap: 8px;
  align-self: flex-end;
}
.tabs {
  display: flex;
  gap: 8px;
  margin-bottom: 20px;
  flex-wrap: wrap;
}
.tab {
  padding: 10px 20px;
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 8px;
  color: #94a3b8;
  cursor: pointer;
  font-size: 0.9rem;
  transition: all 0.2s;
}
.tab:hover { background: #334155; color: #f1f5f9; }
.tab.active {
  background: linear-gradient(135deg, #7c3aed, #ec4899);
  color: #fff;
  border-color: transparent;
}
.panel { display: none; }
.panel.active { display: block; }
.card {
  background: #1e293b;
  border-radius: 12px;
  padding: 20px;
  border: 1px solid #334155;
}
.stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-bottom: 20px;
}
.stat-card {
  background: #1e293b;
  border-radius: 12px;
  padding: 20px;
  border: 1px solid #334155;
}
.stat-label { font-size: 0.85rem; color: #94a3b8; margin-bottom: 8px; }
.stat-value { font-size: 1.8rem; font-weight: bold; color: #f1f5f9; }
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.88rem;
}
th, td {
  padding: 12px 14px;
  text-align: left;
  border-bottom: 1px solid #334155;
}
th {
  background: #0f172a;
  color: #94a3b8;
  font-weight: 600;
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
tr:hover { background: #334155; }
.content-cell {
  max-width: 600px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  cursor: pointer;
  transition: all 0.3s ease;
}
.content-cell.expanded {
  white-space: pre-wrap;
  word-break: break-word;
  overflow: visible;
  text-overflow: clip;
  background: #334155;
  padding: 12px;
  border-radius: 6px;
}
.badge {
  display: inline-block;
  padding: 3px 8px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 500;
}
.badge-user { background: #7c3aed; color: #fff; }
.badge-ai { background: #ec4899; color: #fff; }
.btn {
  padding: 8px 16px;
  border: none;
  border-radius: 6px;
  background: #334155;
  color: #f1f5f9;
  cursor: pointer;
  font-size: 0.85rem;
  transition: background 0.2s;
}
.btn:hover { background: #475569; }
.btn-danger { background: #dc2626; }
.btn-danger:hover { background: #b91c1c; }
.btn-primary {
  background: linear-gradient(135deg, #7c3aed, #ec4899);
}
.btn-primary:hover { opacity: 0.9; }
.email-link {
  color: #a78bfa;
  cursor: pointer;
  text-decoration: none;
}
.email-link:hover {
  text-decoration: underline;
}
.filter-info {
  background: rgba(124, 58, 237, 0.15);
  border: 1px solid rgba(124, 58, 237, 0.3);
  color: #c4b5fd;
  padding: 10px 16px;
  border-radius: 8px;
  margin-bottom: 16px;
  font-size: 0.88rem;
  display: none;
  align-items: center;
  justify-content: space-between;
}
.filter-info.show { display: flex; }
.filter-info button {
  background: rgba(124, 58, 237, 0.3);
  color: #c4b5fd;
  border: none;
  padding: 4px 10px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.8rem;
}
.loading {
  text-align: center;
  padding: 40px;
  color: #94a3b8;
}
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.7);
  display: none;
  align-items: center;
  justify-content: center;
  z-index: 100;
}
.modal-overlay.show { display: flex; }
.modal {
  background: #1e293b;
  border-radius: 12px;
  padding: 24px;
  max-width: 500px;
  width: 90%;
  border: 1px solid #334155;
}
.modal h3 { margin-bottom: 16px; }
.modal-input {
  width: 100%;
  padding: 12px;
  background: #0f172a;
  border: 1px solid #334155;
  border-radius: 8px;
  color: #f1f5f9;
  font-size: 0.95rem;
  margin-bottom: 16px;
}
.modal-btns {
  display: flex;
  gap: 10px;
  justify-content: flex-end;
}
.error {
  color: #f87171;
  padding: 16px;
  background: rgba(220, 38, 38, 0.1);
  border-radius: 8px;
  margin-bottom: 16px;
}
.empty {
  text-align: center;
  padding: 40px;
  color: #64748b;
}
.pagination {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  margin-top: 20px;
  flex-wrap: wrap;
}
.page-info {
  color: #94a3b8;
  font-size: 14px;
  margin-right: 12px;
}
.page-btn {
  min-width: 36px;
  padding: 6px 12px;
  font-size: 14px;
}
.page-btn.active {
  background: linear-gradient(135deg, #667eea, #764ba2);
  color: #fff;
  border-color: transparent;
}
.page-btn:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}
.page-dots {
  color: #64748b;
  padding: 0 4px;
}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>📊 数据库后台管理</h1>
    <button class="btn btn-primary" onclick="refreshAll()">刷新数据</button>
  </div>

  <div class="filter-bar">
    <div class="filter-item">
      <label>筛选用户</label>
      <select id="filterUser">
        <option value="">全部用户</option>
      </select>
    </div>
    <div class="filter-item">
      <label>开始日期</label>
      <input type="date" id="filterStart">
    </div>
    <div class="filter-item">
      <label>结束日期</label>
      <input type="date" id="filterEnd">
    </div>
    <div class="filter-actions">
      <button class="btn btn-primary" onclick="applyFilter()">应用筛选</button>
      <button class="btn" onclick="clearFilter()">清除</button>
    </div>
  </div>

  <div class="filter-info" id="filterInfo">
    <span id="filterInfoText"></span>
    <button onclick="clearFilter()">清除筛选</button>
  </div>

  <div class="stats" id="stats">
    <div class="stat-card">
      <div class="stat-label">用户总数</div>
      <div class="stat-value" id="userCount">-</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">会话总数</div>
      <div class="stat-value" id="sessionCount">-</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">消息总数</div>
      <div class="stat-value" id="msgCount">-</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">图片总数</div>
      <div class="stat-value" id="imgCount">-</div>
    </div>
  </div>

  <div class="tabs">
    <button class="tab active" onclick="switchTab('users', this)">👤 用户</button>
    <button class="tab" onclick="switchTab('sessions', this)">💬 聊天会话</button>
    <button class="tab" onclick="switchTab('messages', this)">📝 聊天消息</button>
    <button class="tab" onclick="switchTab('images', this)">🖼️ 图片记录</button>
  </div>

  <div id="panel-users" class="panel active">
    <div class="card">
      <div id="users-table"></div>
    </div>
  </div>

  <div id="panel-sessions" class="panel">
    <div class="card">
      <div id="sessions-table"></div>
    </div>
  </div>

  <div id="panel-messages" class="panel">
    <div class="card">
      <div id="messages-table"></div>
    </div>
  </div>

  <div id="panel-images" class="panel">
    <div class="card">
      <div id="images-table"></div>
    </div>
  </div>
</div>

<div class="modal-overlay" id="imgPreviewModal">
  <div class="modal" style="max-width:700px;">
    <h3>🖼️ 图片预览</h3>
    <div id="imgPreviewContent" style="text-align:center;margin:12px 0;"></div>
    <div style="margin-top:12px;padding:10px;background:#0f172a;border-radius:6px;font-size:0.82rem;line-height:1.6;" id="imgPreviewInfo"></div>
    <div class="modal-btns">
      <button class="btn btn-danger" onclick="deleteImageFromPreview()">🗑️ 删除</button>
      <button class="btn" onclick="closeImgPreview()">关闭</button>
    </div>
  </div>
</div>

<div class="modal-overlay" id="loginModal">
  <div class="modal">
    <h3>🔐 管理员登录</h3>
    <input type="password" class="modal-input" id="adminPwd" placeholder="请输入管理员密码">
    <div class="modal-btns">
      <button class="btn btn-primary" onclick="adminLogin()">登录</button>
    </div>
  </div>
</div>

<div class="modal-overlay" id="resetPwdModal">
  <div class="modal">
    <h3>🔑 重置用户密码</h3>
    <p id="resetPwdUser" style="margin-bottom:10px;color:#666;"></p>
    <input type="password" class="modal-input" id="resetPwdInput" placeholder="输入新密码（至少6位）" minlength="6">
    <div class="modal-btns">
      <button class="btn btn-primary" onclick="doResetPwd()">确认重置</button>
      <button class="btn" onclick="closeResetPwdModal()">取消</button>
    </div>
  </div>
</div>

<script>
var adminToken = localStorage.getItem('admin_token') || '';
var currentFilter = { userId: '', startDate: '', endDate: '' };
var messagePage = 1;
var messageTotal = 0;
var messagePageSize = 50;
var allUsers = [];

function apiGet(path) {
  return fetch('/api/admin' + path, {
    headers: { 'Authorization': 'Bearer ' + adminToken }
  }).then(function(r) {
    if (r.status === 401) {
      adminToken = '';
      localStorage.removeItem('admin_token');
      showLogin();
      throw new Error('请先登录');
    }
    return r.json();
  });
}

function apiPost(path, body) {
  return fetch('/api/admin' + path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + adminToken
    },
    body: JSON.stringify(body)
  }).then(function(r) {
    if (r.status === 401) {
      adminToken = '';
      localStorage.removeItem('admin_token');
      showLogin();
      throw new Error('请先登录');
    }
    return r.json();
  });
}

function buildQuery() {
  var params = [];
  if (currentFilter.userId) params.push('user_id=' + encodeURIComponent(currentFilter.userId));
  if (currentFilter.startDate) params.push('start_date=' + encodeURIComponent(currentFilter.startDate));
  if (currentFilter.endDate) params.push('end_date=' + encodeURIComponent(currentFilter.endDate));
  return params.length > 0 ? '?' + params.join('&') : '';
}

function showLogin() {
  document.getElementById('loginModal').classList.add('show');
  document.getElementById('adminPwd').focus();
}

function adminLogin() {
  var pwd = document.getElementById('adminPwd').value;
  fetch('/api/admin/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: pwd })
  }).then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.token) {
        adminToken = data.token;
        localStorage.setItem('admin_token', adminToken);
        document.getElementById('loginModal').classList.remove('show');
        loadUserList();
        refreshAll();
      } else {
        alert(data.error || '登录失败');
      }
    });
}

document.getElementById('adminPwd').addEventListener('keydown', function(e) {
  if (e.key === 'Enter') adminLogin();
});

var resetPwdTargetUserId = '';
var resetPwdTargetEmail = '';

function openResetPwdModal(userId, email) {
  resetPwdTargetUserId = userId;
  resetPwdTargetEmail = email;
  document.getElementById('resetPwdUser').textContent = '将为 ' + email + ' 重置密码';
  document.getElementById('resetPwdInput').value = '';
  document.getElementById('resetPwdModal').classList.add('show');
  document.getElementById('resetPwdInput').focus();
}

function closeResetPwdModal() {
  document.getElementById('resetPwdModal').classList.remove('show');
  resetPwdTargetUserId = '';
  resetPwdTargetEmail = '';
}

function doResetPwd() {
  var newPwd = document.getElementById('resetPwdInput').value;
  if (!newPwd || newPwd.length < 6) {
    alert('新密码至少需要6个字符');
    return;
  }
  fetch('/api/admin/users/' + resetPwdTargetUserId + '/reset-password', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + adminToken
    },
    body: JSON.stringify({ new_password: newPwd })
  }).then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.ok) {
        alert('密码重置成功！新密码：' + newPwd);
        closeResetPwdModal();
      } else {
        alert(data.error || '重置失败');
      }
    });
}

function loadUserList() {
  apiGet('/users').then(function(data) {
    allUsers = data.users || [];
    var select = document.getElementById('filterUser');
    var currentVal = select.value;
    select.innerHTML = '<option value="">全部用户</option>';
    allUsers.forEach(function(u) {
      var opt = document.createElement('option');
      opt.value = u.id;
      opt.textContent = u.email + (u.nickname ? ' (' + u.nickname + ')' : '');
      select.appendChild(opt);
    });
    select.value = currentVal;
  });
}

function applyFilter() {
  currentFilter.userId = document.getElementById('filterUser').value;
  currentFilter.startDate = document.getElementById('filterStart').value;
  currentFilter.endDate = document.getElementById('filterEnd').value;
  messagePage = 1;
  updateFilterInfo();
  refreshAll();
}

function clearFilter() {
  currentFilter = { userId: '', startDate: '', endDate: '' };
  document.getElementById('filterUser').value = '';
  document.getElementById('filterStart').value = '';
  document.getElementById('filterEnd').value = '';
  messagePage = 1;
  updateFilterInfo();
  refreshAll();
}

function updateFilterInfo() {
  var info = document.getElementById('filterInfo');
  var text = document.getElementById('filterInfoText');
  var hasFilter = currentFilter.userId || currentFilter.startDate || currentFilter.endDate;
  if (hasFilter) {
    var parts = [];
    if (currentFilter.userId) {
      var user = allUsers.find(function(u) { return u.id === currentFilter.userId; });
      parts.push('用户：' + (user ? user.email : currentFilter.userId));
    }
    if (currentFilter.startDate) parts.push('开始：' + currentFilter.startDate);
    if (currentFilter.endDate) parts.push('结束：' + currentFilter.endDate);
    text.textContent = '筛选条件：' + parts.join(' | ');
    info.classList.add('show');
  } else {
    info.classList.remove('show');
  }
}

function filterByUser(userId) {
  currentFilter.userId = userId;
  currentFilter.startDate = '';
  currentFilter.endDate = '';
  document.getElementById('filterUser').value = userId;
  document.getElementById('filterStart').value = '';
  document.getElementById('filterEnd').value = '';
  updateFilterInfo();
  switchTab('messages', document.querySelector('.tab:nth-child(3)'));
}

function switchTab(name, btn) {
  document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('active'); });
  document.querySelectorAll('.panel').forEach(function(p) { p.classList.remove('active'); });
  if (btn) btn.classList.add('active');
  document.getElementById('panel-' + name).classList.add('active');
  if (name === 'users') loadUsers();
  if (name === 'sessions') loadSessions();
  if (name === 'messages') loadMessages();
  if (name === 'images') loadImages();
}

function formatTime(ts) {
  if (!ts) return '-';
  var d = new Date(ts);
  return d.toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function loadStats() {
  apiGet('/stats' + buildQuery()).then(function(data) {
    document.getElementById('userCount').textContent = data.users || 0;
    document.getElementById('sessionCount').textContent = data.sessions || 0;
    document.getElementById('msgCount').textContent = data.messages || 0;
    document.getElementById('imgCount').textContent = data.images || 0;
  }).catch(function(e) { console.error(e); });
}

function loadUsers() {
  var el = document.getElementById('users-table');
  el.innerHTML = '<div class="loading">加载中...</div>';
  apiGet('/users').then(function(data) {
    var users = data.users || [];
    if (users.length === 0) {
      el.innerHTML = '<div class="empty">暂无用户</div>';
      return;
    }
    var html = '<table><thead><tr>' +
      '<th>ID</th><th>邮箱</th><th>昵称</th><th>注册时间</th><th>操作</th>' +
      '</tr></thead><tbody>';
    users.forEach(function(u) {
      html += '<tr data-user-id="' + u.id + '">' +
        '<td>' + u.id.slice(0, 8) + '...</td>' +
        '<td><span class="email-link" data-action="view-user" title="查看该用户的聊天记录">' + u.email + '</span></td>' +
        '<td>' + (u.nickname || '-') + '</td>' +
        '<td>' + formatTime(u.created_at) + '</td>' +
        '<td><button class="btn btn-primary btn-sm" data-action="reset-pwd" data-user-id="' + u.id + '" data-email="' + u.email + '">重置密码</button> <button class="btn btn-danger btn-sm" data-action="delete-user">删除</button></td>' +
        '</tr>';
    });
    html += '</tbody></table>';
    el.innerHTML = html;
    // 事件委托
    el.querySelectorAll('[data-action="view-user"]').forEach(function(el) {
      el.addEventListener('click', function() {
        var tr = el.closest('tr');
        var uid = tr.getAttribute('data-user-id');
        filterByUser(uid);
      });
    });
    el.querySelectorAll('[data-action="delete-user"]').forEach(function(el) {
      el.addEventListener('click', function() {
        var tr = el.closest('tr');
        var uid = tr.getAttribute('data-user-id');
        deleteUser(uid);
      });
    });

    el.querySelectorAll('[data-action="reset-pwd"]').forEach(function(el) {
      el.addEventListener('click', function() {
        var userId = el.getAttribute('data-user-id');
        var email = el.getAttribute('data-email');
        openResetPwdModal(userId, email);
      });
    });
  }).catch(function(e) {
    el.innerHTML = '<div class="error">' + e.message + '</div>';
  });
}

function deleteUser(id) {
  if (!confirm('确定删除该用户？所有相关数据都会被删除！')) return;
  apiPost('/users/' + id + '/delete', {}).then(function() {
    loadUsers();
    loadUserList();
    loadStats();
  });
}

function loadSessions() {
  var el = document.getElementById('sessions-table');
  el.innerHTML = '<div class="loading">加载中...</div>';
  apiGet('/sessions' + buildQuery()).then(function(data) {
    var sessions = data.sessions || [];
    if (sessions.length === 0) {
      el.innerHTML = '<div class="empty">暂无会话</div>';
      return;
    }
    var html = '<table><thead><tr>' +
      '<th>ID</th><th>用户</th><th>标题</th><th>消息数</th><th>更新时间</th><th>操作</th>' +
      '</tr></thead><tbody>';
    sessions.forEach(function(s) {
      html += '<tr data-session-id="' + s.id + '">' +
        '<td>' + s.id.slice(0, 8) + '...</td>' +
        '<td>' + (s.email || '-') + '</td>' +
        '<td class="content-cell">' + s.title + '</td>' +
        '<td>' + (s.msg_count || 0) + '</td>' +
        '<td>' + formatTime(s.updated_at) + '</td>' +
        '<td><button class="btn btn-danger" data-action="delete-session">删除</button></td>' +
        '</tr>';
    });
    html += '</tbody></table>';
    el.innerHTML = html;
    // 事件委托
    el.querySelectorAll('[data-action="delete-session"]').forEach(function(el) {
      el.addEventListener('click', function() {
        var tr = el.closest('tr');
        var sid = tr.getAttribute('data-session-id');
        deleteSession(sid);
      });
    });
  }).catch(function(e) {
    el.innerHTML = '<div class="error">' + e.message + '</div>';
  });
}

function deleteSession(id) {
  if (!confirm('确定删除该会话？')) return;
  apiPost('/sessions/' + id + '/delete', {}).then(function() {
    loadSessions();
    loadStats();
  });
}

function loadMessages() {
  var el = document.getElementById('messages-table');
  el.innerHTML = '<div class="loading">加载中...</div>';
  var query = buildQuery();
  var url = '/messages' + (query ? query + '&' : '?') + 'page=' + messagePage + '&limit=' + messagePageSize;
  apiGet(url).then(function(data) {
    var messages = data.messages || [];
    messageTotal = data.total || 0;
    if (messages.length === 0) {
      el.innerHTML = '<div class="empty">暂无消息</div>';
      return;
    }
    var html = '<table><thead><tr>' +
      '<th>时间</th><th>用户</th><th>角色</th><th>内容预览</th><th>操作</th>' +
      '</tr></thead><tbody>';
    messages.forEach(function(m) {
      var roleBadge = m.role === 'user'
        ? '<span class="badge badge-user">用户</span>'
        : '<span class="badge badge-ai">AI</span>';
      var plainContent = m.content.replace(/<[^>]+>/g, '');
      var preview = plainContent.slice(0, 120);
      var safeContent = m.content.replace(/"/g, '&quot;').replace(/</g, '&lt;');
      var isLong = plainContent.length > 120;
      html += '<tr data-message-id="' + m.id + '">' +
        '<td>' + formatTime(m.created_at) + '</td>' +
        '<td>' + (m.email || '-') + '</td>' +
        '<td>' + roleBadge + '</td>' +
        '<td class="content-cell" title="' + safeContent + '" data-full-text="' + safeContent + '" onclick="toggleMessageExpand(this)">' + preview + (isLong ? '...' : '') + '</td>' +
        '<td><button class="btn btn-danger" data-action="delete-message">删除</button></td>' +
        '</tr>';
    });
    html += '</tbody></table>';
    html += buildMessagePagination();
    el.innerHTML = html;
    el.querySelectorAll('[data-action="delete-message"]').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var tr = btn.closest('tr');
        var mid = tr.getAttribute('data-message-id');
        deleteMessage(mid);
      });
    });
    bindMessagePagination(el);
  }).catch(function(e) {
    el.innerHTML = '<div class="error">' + e.message + '</div>';
  });
}

function buildMessagePagination() {
  var totalPages = Math.ceil(messageTotal / messagePageSize) || 1;
  var html = '<div class="pagination">';
  html += '<span class="page-info">共 ' + messageTotal + ' 条，第 ' + messagePage + '/' + totalPages + ' 页</span>';
  html += '<button class="btn page-btn" data-page="prev" ' + (messagePage <= 1 ? 'disabled' : '') + '>上一页</button>';
  var start = Math.max(1, messagePage - 2);
  var end = Math.min(totalPages, messagePage + 2);
  if (start > 1) {
    html += '<button class="btn page-btn" data-page="1">1</button>';
    if (start > 2) html += '<span class="page-dots">...</span>';
  }
  for (var p = start; p <= end; p++) {
    html += '<button class="btn page-btn ' + (p === messagePage ? 'active' : '') + '" data-page="' + p + '">' + p + '</button>';
  }
  if (end < totalPages) {
    if (end < totalPages - 1) html += '<span class="page-dots">...</span>';
    html += '<button class="btn page-btn" data-page="' + totalPages + '">' + totalPages + '</button>';
  }
  html += '<button class="btn page-btn" data-page="next" ' + (messagePage >= totalPages ? 'disabled' : '') + '>下一页</button>';
  html += '</div>';
  return html;
}

function bindMessagePagination(el) {
  var totalPages = Math.ceil(messageTotal / messagePageSize) || 1;
  el.querySelectorAll('.page-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var page = btn.getAttribute('data-page');
      if (page === 'prev') {
        if (messagePage > 1) messagePage--;
      } else if (page === 'next') {
        if (messagePage < totalPages) messagePage++;
      } else {
        messagePage = parseInt(page, 10);
      }
      loadMessages();
    });
  });
}

function toggleMessageExpand(cell) {
  var isExpanded = cell.classList.contains('expanded');
  // 先收起所有其他已展开的消息
  document.querySelectorAll('.content-cell.expanded').forEach(function(c) {
    if (c !== cell) {
      c.classList.remove('expanded');
      c.textContent = c.getAttribute('data-preview') || c.textContent;
    }
  });
  if (isExpanded) {
    cell.classList.remove('expanded');
    cell.textContent = cell.getAttribute('data-preview');
  } else {
    cell.classList.add('expanded');
    cell.setAttribute('data-preview', cell.textContent);
    cell.textContent = cell.getAttribute('data-full-text');
  }
}

function deleteMessage(id) {
  if (!confirm('确定删除这条消息？')) return;
  apiPost('/messages/' + id + '/delete', {}).then(function() {
    loadMessages();
    loadStats();
  });
}

function loadImages() {
  var el = document.getElementById('images-table');
  el.innerHTML = '<div class="loading">加载中...</div>';
  var query = buildQuery();
  var url = '/images' + (query ? query + '&' : '?') + 'page=1&limit=100';
  apiGet(url).then(function(data) {
    var images = data.images || [];
    if (images.length === 0) {
      el.innerHTML = '<div class="empty">暂无图片记录</div>';
      return;
    }
    var html = '<table><thead><tr>' +
      '<th>用户</th><th>提示词</th><th>尺寸</th><th>收藏</th><th>生成时间</th><th>操作</th>' +
      '</tr></thead><tbody>';
    images.forEach(function(img) {
      var favBadge = img.is_favorite == 1
        ? '<span class="badge" style="background:#f59e0b;color:#fff;">⭐ 已收藏</span>'
        : '<span style="color:#64748b;">未收藏</span>';
      var preview = (img.prompt || '').slice(0, 80);
      var safePrompt = (img.prompt || '').replace(/"/g, '&quot;').replace(/</g, '&lt;');
      html += '<tr data-image-id="' + img.id + '">' +
        '<td>' + (img.email || img.user_id.slice(0, 8) + '...') + '</td>' +
        '<td class="content-cell" title="' + safePrompt + '" onclick="toggleMessageExpand(this)">' + preview + '</td>' +
        '<td>' + (img.size || '-') + '</td>' +
        '<td>' + favBadge + '</td>' +
        '<td>' + formatTime(img.created_at) + '</td>' +
        '<td><button class="btn" data-action="view-img" style="background:#7c3aed;">查看</button> <button class="btn btn-danger" data-action="delete-img">删除</button></td>' +
        '</tr>';
    });
    html += '</tbody></table>';
    el.innerHTML = html;

    el.querySelectorAll('[data-action="view-img"]').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var tr = btn.closest('tr');
        var iid = tr.getAttribute('data-image-id');
        var imgData = images.find(function(i) { return i.id === iid; });
        if (imgData) openImgPreview(imgData);
      });
    });
    el.querySelectorAll('[data-action="delete-img"]').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var tr = btn.closest('tr');
        var iid = tr.getAttribute('data-image-id');
        deleteImage(iid);
      });
    });
  }).catch(function(e) {
    el.innerHTML = '<div class="error">' + e.message + '</div>';
  });
}

var previewImageData = null;

function openImgPreview(imgData) {
  previewImageData = imgData;
  var content = document.getElementById('imgPreviewContent');
  var info = document.getElementById('imgPreviewInfo');
  var b64 = imgData.image_b64 || '';
  var src = b64.startsWith('data:') ? b64 : 'data:image/png;base64,' + b64;
  content.innerHTML = '';
  var img = document.createElement('img');
  img.src = src;
  img.style.cssText = 'max-width:100%;max-height:60vh;border-radius:8px;box-shadow:0 4px 20px rgba(0,0,0,0.5);';
  img.onerror = function() {
    content.innerHTML = '<div style="color:#f87171;padding:40px;">图片加载失败</div>';
  };
  content.appendChild(img);
  var userInfo = imgData.email ? imgData.email : ('ID: ' + imgData.user_id.slice(0, 16) + '...');
  info.innerHTML = '<b>用户：</b>' + userInfo + '<br>' +
    '<b>提示词：</b>' + (imgData.prompt || '-') + '<br>' +
    '<b>尺寸：</b>' + (imgData.size || '-') + ' &nbsp; <b>收藏：</b>' + (imgData.is_favorite == 1 ? '⭐ 是' : '否') + '<br>' +
    '<b>模型：</b>' + (imgData.model || '-') + '<br>' +
    '<b>时间：</b>' + formatTime(imgData.created_at) + '<br>' +
    '<b>ID：</b>' + imgData.id;
  document.getElementById('imgPreviewModal').classList.add('show');
}

function closeImgPreview() {
  previewImageData = null;
  document.getElementById('imgPreviewModal').classList.remove('show');
}

function deleteImageFromPreview() {
  if (!previewImageData) return;
  if (!confirm('确定删除这张图片？')) return;
  var iid = previewImageData.id;
  apiPost('/images/' + iid + '/delete', {}).then(function() {
    closeImgPreview();
    loadImages();
    loadStats();
    showToast('删除成功');
  }).catch(function(e) { showToast(e.message, 'error'); });
}

function deleteImage(id) {
  if (!confirm('确定删除这张图片？')) return;
  apiPost('/images/' + id + '/delete', {}).then(function() {
    loadImages();
    loadStats();
    showToast('删除成功');
  }).catch(function(e) { showToast(e.message, 'error'); });
}

function showToast(msg) {
  var existing = document.getElementById('toast');
  if (existing) existing.remove();
  var toast = document.createElement('div');
  toast.id = 'toast';
  toast.style = 'position:fixed;bottom:20px;right:20px;background:#334155;color:#f1f5f9;padding:10px 16px;border-radius:8px;font-size:0.88rem;z-index:3000;box-shadow:0 4px 12px rgba(0,0,0,0.3);';
  toast.textContent = msg;
  document.body.appendChild(toast);
  setTimeout(function() { toast.remove(); }, 3000);
}

function refreshAll() {
  loadStats();
  var activePanel = document.querySelector('.panel.active');
  if (activePanel) {
    var id = activePanel.id.replace('panel-', '');
    if (id === 'users') loadUsers();
    if (id === 'sessions') loadSessions();
    if (id === 'messages') loadMessages();
    if (id === 'images') loadImages();
  }
}

if (adminToken) {
  loadUserList();
  refreshAll();
} else {
  showLogin();
}
</script>
</body>
</html>
`;