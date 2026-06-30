const API_URL = 'https://chat-app-db.shitou8848.workers.dev';

const deviceId = 'test-device-12345';
const prompt = '测试图片保存';
const size = '1024x1024';
const style = '写实';
const model = 'agnes-image-2.1-flash';
const imageB64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

async function test() {
  console.log('=== 测试保存图片 ===');
  try {
    const res = await fetch(API_URL + '/api/images', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Device-Id': deviceId,
      },
      body: JSON.stringify({ prompt, size, style, image_b64: imageB64, model }),
    });
    const data = await res.json();
    console.log('保存结果:', res.status, data);
    
    if (res.ok && data.id) {
      const imgId = data.id;
      
      console.log('\n=== 测试设置收藏 ===');
      const updateRes = await fetch(API_URL + '/api/images/' + imgId, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-Device-Id': deviceId,
        },
        body: JSON.stringify({ is_favorite: true }),
      });
      const updateData = await updateRes.json();
      console.log('收藏结果:', updateRes.status, updateData);
      
      console.log('\n=== 测试获取历史记录 ===');
      const listRes = await fetch(API_URL + '/api/images?page=1&limit=20&with_image=1', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'X-Device-Id': deviceId,
        },
      });
      const listData = await listRes.json();
      console.log('历史记录数量:', listData.items?.length || 0);
      console.log('历史记录:', JSON.stringify(listData, null, 2));
      
      console.log('\n=== 测试获取收藏列表 ===');
      const favRes = await fetch(API_URL + '/api/images?page=1&limit=20&favorite=1&with_image=1', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'X-Device-Id': deviceId,
        },
      });
      const favData = await favRes.json();
      console.log('收藏数量:', favData.items?.length || 0);
      console.log('收藏列表:', JSON.stringify(favData, null, 2));
    }
  } catch (e) {
    console.error('测试失败:', e);
  }
}

test();
