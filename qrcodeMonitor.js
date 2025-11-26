// qrcodeMonitor.js - 二维码监听脚本

(function() {
  console.log('[二维码监听] 开始监听二维码生成');
  
  // HTML实体解码函数
  function decodeHTMLEntities(text) {
    const textarea = document.createElement('textarea');
    textarea.innerHTML = text;
    return textarea.value;
  }
  
  // 解析二维码图片
  function decodeQRCode(imgSrc) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.crossOrigin = 'Anonymous';
      
      img.onload = function() {
        try {
          const canvas = document.createElement('canvas');
          const ctx = canvas.getContext('2d');
          canvas.width = img.width;
          canvas.height = img.height;
          ctx.drawImage(img, 0, 0);
          
          const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const code = jsQR(imageData.data, imageData.width, imageData.height);
          
          if (code && code.data) {
            console.log('[二维码监听] 解析成功:', code.data);
            resolve(code.data);
          } else {
            console.warn('[二维码监听] 未能解析二维码');
            reject(new Error('未能解析二维码'));
          }
        } catch (e) {
          console.error('[二维码监听] 解析错误:', e);
          reject(e);
        }
      };
      
      img.onerror = (e) => {
        console.error('[二维码监听] 图片加载失败:', e);
        reject(e);
      };
      
      img.src = imgSrc;
    });
  }
  
  // 从 URL 中提取登录参数 (loginId, action, loginType)
  function extractLoginParams(url) {
    try {
      const result = {
        loginId: null,
        action: null,
        loginType: null
      };
      
      // 方法1: 直接使用正则表达式提取（支持 hash 和 query）
      const loginIdMatch = url.match(/[?&]loginId=([^&]+)/);
      const actionMatch = url.match(/[?&]action=([^&]+)/);
      const loginTypeMatch = url.match(/[?&]loginType=([^&]+)/);
      
      if (loginIdMatch) result.loginId = loginIdMatch[1];
      if (actionMatch) result.action = actionMatch[1];
      if (loginTypeMatch) result.loginType = loginTypeMatch[1];
      
      // 如果已经找到所有参数，直接返回
      if (result.loginId && result.action && result.loginType) {
        return result;
      }
      
      // 方法2: 尝试从 URL 参数中提取（普通查询参数）
      const urlObj = new URL(url);
      if (!result.loginId) {
        result.loginId = urlObj.searchParams.get('loginId') || 
                        urlObj.searchParams.get('login_id') ||
                        urlObj.searchParams.get('id');
      }
      if (!result.action) {
        result.action = urlObj.searchParams.get('action');
      }
      if (!result.loginType) {
        result.loginType = urlObj.searchParams.get('loginType');
      }
      
      // 方法3: 从 hash 部分解析查询参数
      if (urlObj.hash && urlObj.hash.includes('?')) {
        const hashQuery = urlObj.hash.split('?')[1];
        const hashParams = new URLSearchParams(hashQuery);
        
        if (!result.loginId) {
          result.loginId = hashParams.get('loginId') || 
                          hashParams.get('login_id') ||
                          hashParams.get('id');
        }
        if (!result.action) {
          result.action = hashParams.get('action');
        }
        if (!result.loginType) {
          result.loginType = hashParams.get('loginType');
        }
      }
      
      // 方法4: 尝试从路径中提取 loginId
      if (!result.loginId) {
        const pathMatch = url.match(/\/([a-zA-Z0-9_-]+)\/?$/);
        if (pathMatch) {
          result.loginId = pathMatch[1];
        }
      }
      
      if (!result.loginId) {
        console.warn('[二维码监听] 未能从 URL 提取 loginId:', url);
        return null;
      }
      
      console.log('[二维码监听] 提取的参数:', result);
      return result;
    } catch (e) {
      console.error('[二维码监听] URL 解析失败:', e);
      return null;
    }
  }
  
  // 监听并自动点击"刷新二维码"按钮
  function watchRefreshButton() {
    let lastClickTime = 0; // 记录上次点击时间，防止频繁点击
    const clickInterval = 3000; // 3秒内不重复点击
    
    const refreshObserver = new MutationObserver(() => {
      const refreshBtn = document.querySelector('button.qrcode_refresh_btn');
      
      if (refreshBtn) {
        const now = Date.now();
        
        // 检查是否在冷却时间内
        if (now - lastClickTime < clickInterval) {
          return; // 跳过，避免频繁点击
        }
        
        console.log('[二维码监听] 🔄 检测到"刷新二维码"按钮，准备自动点击');
        
        // 短暂延迟后点击，确保按钮完全加载
        setTimeout(() => {
          try {
            refreshBtn.click();
            lastClickTime = Date.now();
            console.log('[二维码监听] ✅ 已自动点击"刷新二维码"按钮');
          } catch (e) {
            console.error('[二维码监听] ❌ 点击按钮失败:', e);
          }
        }, 100);
      }
    });
    
    // 开始监听整个文档
    if (document.body) {
      refreshObserver.observe(document.body, {
        childList: true,
        subtree: true
      });
      console.log('[二维码监听] 🔍 "刷新二维码"按钮监听已启动');
    }
  }
  
  // 启动监听
  function startObserver() {
    let lastLoginId = null;  // 记录上一次的 loginId，避免重复触发
    let isProcessing = false;  // 防止并发解析
    
    // 监听 DOM 变化
    const observer = new MutationObserver((mutations) => {
      // 查找二维码图片元素
      const qrcodeImg = document.querySelector('img.code_img[src^="data:image"]');
      
      if (qrcodeImg && qrcodeImg.src && !isProcessing) {
        isProcessing = true;
        console.log('[二维码监听] 检测到二维码图片元素，开始解析...');
        
        // 解析二维码
        decodeQRCode(qrcodeImg.src)
          .then(rawUrl => {
            // 解码HTML实体（&amp; -> &）
            const url = decodeHTMLEntities(rawUrl);
            console.log('[二维码监听] 二维码原始内容:', rawUrl);
            console.log('[二维码监听] 二维码解码后:', url);
            
            // 从 URL 中提取登录参数
            const params = extractLoginParams(url);
            
            if (params && params.loginId) {
              // 检查是否是新的二维码
              if (params.loginId !== lastLoginId) {
                console.log('[二维码监听] 🆕 检测到新二维码，参数:', params);
                lastLoginId = params.loginId;
                
                // 发送消息给 content script 保存
                window.postMessage({
                  type: 'SAVE_QRCODE',
                  payload: { 
                    qrcodeUrl: url, 
                    loginId: params.loginId,
                    action: params.action || 'face_login',
                    loginType: params.loginType || 'PlugFaceDoc'
                  }
                }, '*');
              } else {
                console.log('[二维码监听] 相同的 loginId，跳过:', params.loginId);
              }
            } else {
              console.warn('[二维码监听] 未能从 URL 提取登录参数:', url);
            }
            
            isProcessing = false;
          })
          .catch(err => {
            console.error('[二维码监听] 二维码解析失败:', err);
            isProcessing = false;
          });
      }
    });
    
    // 开始监听整个文档
    if (document.body) {
      observer.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['src']
      });
      console.log('[二维码监听] DOM 监听已启动');
    } else {
      console.error('[二维码监听] document.body 不存在，等待 DOM 加载');
    }
  }
  
  // 等待 DOM 加载完成
  if (document.body) {
    startObserver();
    watchRefreshButton();
  } else if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      startObserver();
      watchRefreshButton();
    });
  } else {
    // 使用短延迟等待 body
    setTimeout(() => {
      startObserver();
      watchRefreshButton();
    }, 100);
  }
})();

