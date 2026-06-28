const AGNES_API_URL = 'https://apihub.agnes-ai.com/v1/images/generations';

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  if (request.method === 'GET') {
    return new Response('Agnes Image API Proxy is running. Use POST to generate images.', {
      status: 200,
      headers: { 'Content-Type': 'text/plain;charset=utf-8' },
    });
  }

  if (request.method === 'OPTIONS') {
    return new Response(null, {
      headers: corsHeaders(),
    });
  }

  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: corsHeaders(),
    });
  }

  const apiKey = globalThis.AGNES_API_KEY;
  if (!apiKey) {
    return new Response(JSON.stringify({ error: 'API key not configured' }), {
      status: 500,
      headers: corsHeaders(),
    });
  }

  try {
    const body = await request.json();
    const { prompt, size, n, image } = body;

    if (!prompt || !size) {
      return new Response(JSON.stringify({ error: 'Missing required fields: prompt, size' }), {
        status: 400,
        headers: corsHeaders(),
      });
    }

    const count = Math.min(n || 1, 4);

    const agnesBody = {
      model: 'agnes-image-2.1-flash',
      prompt,
      size,
      extra_body: { response_format: 'b64_json' },
    };

    if (image && image.length > 0) {
      agnesBody.image = image;
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
        return new Response(JSON.stringify(r), {
          status: 400,
          headers: corsHeaders(),
        });
      }
    }

    const allData = results.flatMap(r => r.data || []);
    const merged = { created: Math.floor(Date.now() / 1000), data: allData };

    return new Response(JSON.stringify(merged), {
      status: 200,
      headers: corsHeaders(),
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: corsHeaders(),
    });
  }
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS, GET',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
  };
}
