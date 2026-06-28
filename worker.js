const VIDEO_CREATE_URL = 'https://apihub.agnes-ai.com/v1/videos';
const VIDEO_POLL_URL = 'https://apihub.agnes-ai.com/agnesapi';

const CREATE_TIMEOUT_MS = 90000;
const POLL_TIMEOUT_MS = 30000;

export default {
  async fetch(request, env) {
    if (request.method === 'GET') {
      return new Response('Agnes Video API Proxy is running.', {
        status: 200,
        headers: { 'Content-Type': 'text/plain;charset=utf-8' },
      });
    }

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders() });
    }

    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ error: 'Method not allowed' }), {
        status: 405,
        headers: corsHeaders(),
      });
    }

    const apiKey = env.AGNES_API_KEY;
    if (!apiKey) {
      return new Response(JSON.stringify({ error: 'API key not configured' }), {
        status: 500,
        headers: corsHeaders(),
      });
    }

    try {
      const body = await request.json();
      const { action, ...params } = body;

      if (action === 'echo') {
        return new Response(JSON.stringify({ received: params }), {
          headers: corsHeaders(),
        });
      }

      if (action === 'poll') {
        const { video_id, model_name } = params;
        if (!video_id) {
          return new Response(JSON.stringify({ error: 'Missing video_id' }), {
            status: 400,
            headers: corsHeaders(),
          });
        }
        let pollUrl = `${VIDEO_POLL_URL}?video_id=${encodeURIComponent(video_id)}`;
        if (model_name) pollUrl += `&model_name=${encodeURIComponent(model_name)}`;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), POLL_TIMEOUT_MS);
        const pollRes = await fetch(pollUrl, {
          headers: { 'Authorization': `Bearer ${apiKey}` },
          signal: controller.signal,
        }).finally(() => clearTimeout(timeout));
        const pollText = await pollRes.text();
        let pollData;
        try { pollData = JSON.parse(pollText); } catch (e) { pollData = { error: pollText }; }
        if (!pollRes.ok) {
          const errMsg = pollData.error?.message || pollData.error || pollData.message || pollText;
          return new Response(JSON.stringify({ error: errMsg }), {
            status: pollRes.status,
            headers: corsHeaders(),
          });
        }
        return new Response(JSON.stringify(pollData), {
          headers: corsHeaders(),
        });
      }

      const { prompt, image, mode, width, height, num_frames, frame_rate, negative_prompt, num_inference_steps, seed, extra_images } = params;

      if (!prompt) {
        return new Response(JSON.stringify({ error: 'Missing required field: prompt' }), {
          status: 400,
          headers: corsHeaders(),
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
            headers: corsHeaders(),
          });
        }
        return new Response(JSON.stringify({ error: fetchErr.message }), {
          status: 502,
          headers: corsHeaders(),
        });
      }

      const createText = await createRes.text();
      let createData;
      try { createData = JSON.parse(createText); } catch (e) { createData = { error: createText }; }
      if (!createRes.ok) {
        const errMsg = createData.error?.message || createData.error || createData.message || createText;
        return new Response(JSON.stringify({ error: errMsg }), {
          status: createRes.status,
          headers: corsHeaders(),
        });
      }
      if (!createData.video_id && !createData.id) {
        return new Response(JSON.stringify({ error: '创建任务成功但未返回 video_id', raw: createData }), {
          status: 500,
          headers: corsHeaders(),
        });
      }
      return new Response(JSON.stringify(createData), {
        status: 200,
        headers: corsHeaders(),
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 500,
        headers: corsHeaders(),
      });
    }
  },
};

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS, GET',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
  };
}