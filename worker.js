// ========================================================================
// 安全修复: 视频生成 Worker
// ========================================================================
const VIDEO_CREATE_URL = 'https://apihub.agnes-ai.com/v1/videos';
const VIDEO_POLL_URL = 'https://apihub.agnes-ai.com/agnesapi';
const VIDEO_POLL_URL_V1 = 'https://apihub.agnes-ai.com/v1/videos';

const CREATE_TIMEOUT_MS = 120000;
const POLL_TIMEOUT_MS = 30000;

// 速率限制配置
const KV_RATE_PREFIX = 'rate:';
const RATE_LIMIT_WINDOW = 60000;    // 60秒窗口
const RATE_LIMIT_MAX = 10;          // 每窗口最大创建请求
const RATE_LIMIT_MAX_AUTHED = 30;  // 已认证用户限制

// ========================================================================
// 速率限制检查
// ========================================================================
async function checkRateLimit(env, identifier, isAuthenticated) {
  const kv = env && env.VIDEO_KV ? env.VIDEO_KV : null;
  if (!kv) return true;
  
  const limit = isAuthenticated ? RATE_LIMIT_MAX_AUTHED : RATE_LIMIT_MAX;
  const key = KV_RATE_PREFIX + identifier;
  const now = Date.now();
  
  try {
    const data = await kv.get(key);
    let record = data ? JSON.parse(data) : { count: 0, windowStart: now };
    
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
    return true;
  }
}

// ========================================================================
// 请求验证
// ========================================================================
function validateRequest(request) {
  const authHeader = request.headers ? request.headers.get('Authorization') : null;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return { token: authHeader.substring(7), authenticated: true };
  }
  const deviceId = request.headers ? request.headers.get('X-Device-Id') : null;
  return { token: deviceId || 'anonymous', authenticated: false };
}

// ========================================================================
// CORS 配置（修复：统一配置并支持动态 Origin）
// ========================================================================
function corsHeaders(request) {
  const origin = request && request.headers ? (request.headers.get('Origin') || '*') : '*';
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Device-Id, X-API-Key',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400',
  };
}

export default {
  async fetch(request, env, ctx) {
    // 速率限制检查（仅对视频创建请求）
    const { token, authenticated } = validateRequest(request);
    const rateLimitExempt = env && env.API_SECRET_KEY && 
      request.headers && 
      request.headers.get('X-API-Key') === env.API_SECRET_KEY;
    
    if (!rateLimitExempt && request.method === 'POST') {
      let isCreateRequest = false;
      try {
        const clone = request.clone();
        const body = await clone.json();
        isCreateRequest = !body.action || body.action === 'echo';
      } catch (e) {
        isCreateRequest = true;
      }
      
      if (isCreateRequest) {
        const rateCheck = await checkRateLimit(env, 'video:' + token, authenticated);
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
    }

    if (request.method === 'GET') {
      return new Response('Agnes Video API Proxy is running.\nRate limit: ' + (rateLimitExempt ? 'exempt' : 'enabled'), {
        status: 200,
        headers: { 'Content-Type': 'text/plain;charset=utf-8', ...corsHeaders(request) },
      });
    }

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(request) });
    }

    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ error: 'Method not allowed' }), {
        status: 405,
        headers: corsHeaders(request),
      });
    }

    const apiKey = env && env.AGNES_API_KEY;
    if (!apiKey) {
      return new Response(JSON.stringify({ error: 'API key not configured' }), {
        status: 500,
        headers: corsHeaders(request),
      });
    }

    try {
      const body = await request.json();
      const { action, ...params } = body;

      if (action === 'echo') {
        return new Response(JSON.stringify({ received: params }), {
          headers: corsHeaders(request),
        });
      }

      if (action === 'poll') {
        const { video_id, task_id, model_name } = params;
        if (!video_id && !task_id) {
          return new Response(JSON.stringify({ error: 'Missing video_id or task_id' }), {
            status: 400,
            headers: corsHeaders(request),
          });
        }

        let pollUrl;
        let isV1Fallback = false;

        if (video_id) {
          pollUrl = `${VIDEO_POLL_URL}?video_id=${encodeURIComponent(video_id)}`;
          if (model_name) pollUrl += `&model_name=${encodeURIComponent(model_name)}`;
        } else if (task_id) {
          pollUrl = `${VIDEO_POLL_URL_V1}/${encodeURIComponent(task_id)}`;
          isV1Fallback = true;
        }

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), POLL_TIMEOUT_MS);
        let pollRes;
        try {
          pollRes = await fetch(pollUrl, {
            headers: { 'Authorization': `Bearer ${apiKey}` },
            signal: controller.signal,
          });
        } finally {
          clearTimeout(timeout);
        }
        const pollText = await pollRes.text();
        let pollData;
        try { pollData = JSON.parse(pollText); } catch (e) { pollData = { error: pollText }; }

        if (!pollRes.ok) {
          if (!isV1Fallback && (pollRes.status === 404 || pollText.includes('not found')) && task_id) {
            const v1Url = `${VIDEO_POLL_URL_V1}/${encodeURIComponent(task_id)}`;
            const v1Controller = new AbortController();
            const v1Timeout = setTimeout(() => v1Controller.abort(), POLL_TIMEOUT_MS);
            try {
              const v1Res = await fetch(v1Url, {
                headers: { 'Authorization': `Bearer ${apiKey}` },
                signal: v1Controller.signal,
              }).finally(() => clearTimeout(v1Timeout));
              if (v1Res.ok) {
                const v1Text = await v1Res.text();
                let v1Data;
                try { v1Data = JSON.parse(v1Text); } catch (e) { v1Data = { error: v1Text }; }
                return new Response(JSON.stringify(v1Data), {
                  headers: corsHeaders(request),
                });
              }
            } catch (e) {}
          }
          const errMsg = pollData.error?.message || pollData.error || pollData.message || pollText;
          const headers = corsHeaders(request);
          if (pollRes.status === 429) {
            headers['Retry-After'] = '30';
            return new Response(JSON.stringify({ error: errMsg, is_rate_limit: true }), {
              status: 429,
              headers,
            });
          }
          if (pollRes.status === 503) {
            headers['Retry-After'] = '15';
            return new Response(JSON.stringify({ error: errMsg, is_service_busy: true }), {
              status: 503,
              headers,
            });
          }
          return new Response(JSON.stringify({ error: errMsg }), {
            status: pollRes.status,
            headers: corsHeaders(request),
          });
        }
        return new Response(JSON.stringify(pollData), {
          headers: corsHeaders(request),
        });
      }

      const { prompt, image, mode, width, height, num_frames, frame_rate, negative_prompt, num_inference_steps, seed, extra_images } = params;

      if (!prompt) {
        return new Response(JSON.stringify({ error: 'Missing required field: prompt' }), {
          status: 400,
          headers: corsHeaders(request),
        });
      }

      const videoBody = {
        model: 'agnes-video-v2.0',
        prompt,
        width: width || 1152,
        height: height || 768,
        num_frames: num_frames || 121,
        frame_rate: frame_rate || 24,
      };

      if (mode && mode !== 'ti2vid') videoBody.mode = mode;
      if (negative_prompt) videoBody.negative_prompt = negative_prompt;
      if (num_inference_steps) videoBody.num_inference_steps = parseInt(num_inference_steps);
      if (seed) videoBody.seed = parseInt(seed);

      if (mode === 'keyframes' && extra_images && extra_images.length > 0) {
        videoBody.extra_body = { image: extra_images, mode: 'keyframes' };
      } else if (image) {
        if (mode === 'keyframes') {
          videoBody.extra_body = { image: Array.isArray(image) ? image : [image], mode: 'keyframes' };
        } else if (Array.isArray(image) && image.length > 1) {
          videoBody.extra_body = { image };
        } else {
          videoBody.image = Array.isArray(image) ? image[0] : image;
        }
      }

      const createController = new AbortController();
      const createTimeout = setTimeout(() => createController.abort(), CREATE_TIMEOUT_MS);
      let createRes;
      try {
        createRes = await fetch(VIDEO_CREATE_URL, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(videoBody),
          signal: createController.signal,
        }).finally(() => clearTimeout(createTimeout));
      } catch (fetchErr) {
        if (fetchErr.name === 'AbortError') {
          return new Response(JSON.stringify({ error: '创建任务超时，请稍后重试' }), {
            status: 504,
            headers: corsHeaders(request),
          });
        }
        return new Response(JSON.stringify({ error: fetchErr.message }), {
          status: 502,
          headers: corsHeaders(request),
        });
      }

      const createText = await createRes.text();
      let createData;
      try { createData = JSON.parse(createText); } catch (e) { createData = { error: createText }; }
      if (!createRes.ok) {
        const errMsg = createData.error?.message || createData.error || createData.message || createText;
        return new Response(JSON.stringify({ error: errMsg }), {
          status: createRes.status,
          headers: corsHeaders(request),
        });
      }
      if (!createData.video_id && !createData.id) {
        return new Response(JSON.stringify({ error: '创建任务成功但未返回 video_id', raw: createData }), {
          status: 500,
          headers: corsHeaders(request),
        });
      }
      return new Response(JSON.stringify(createData), {
        status: 200,
        headers: corsHeaders(request),
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 500,
        headers: corsHeaders(request),
      });
    }
  },
};
