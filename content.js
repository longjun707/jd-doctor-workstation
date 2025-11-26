// content.js

(function() {
  // 1. 注入主脚本（包含患者监听器）
  try {
    // 0. 先在脚本中内联音频 URL
    const audioUrl = chrome.runtime.getURL('preview.mp3');
    console.log('[扩展] 准备注入音频 URL:', audioUrl);
    
    const script = document.createElement('script');
    
    // 开发模式：使用ES6模块加载 page/main.js
    // 生产模式：使用打包后的 page/main.bundle.js
    const isDevelopment = false; // 改为 true 使用开发模式
    // const isDevelopment = false; // 改为 false 使用生产模式

    if (isDevelopment) {
      script.type = 'module'; // ES6模块
      script.src = chrome.runtime.getURL('page/main.js');
      console.log('[开发模式] 加载 ES6 模块版本');
    } else {
      // 在主脚本加载前先注入音频 URL
      const inlineScript = document.createElement('script');
      inlineScript.textContent = `window.__MARK_AUDIO_URL__ = "${audioUrl}"; console.log('[扩展] 音频 URL 已注入:', "${audioUrl}");`;
      (document.head || document.documentElement).appendChild(inlineScript);
      
      // script.type = 'module'; // This line must be removed.
      script.src = chrome.runtime.getURL('page/main.bundle.js');
      console.log('[生产模式] 加载打包版本（包含患者监听器）');
    }
    
    (document.head || document.documentElement).appendChild(script);
    
    script.onload = () => {
      console.log('[扩展] 页面脚本加载成功（包含患者监听器）');
      // The script can be removed from the DOM after it has been loaded.
      script.remove();
    };

    script.onerror = (e) => {
      console.error('[扩展] 页面脚本加载失败:', e);
      // Errors are not logged in production.
    }
  } catch (e) {
    console.error('[扩展] 注入脚本失败:', e);
    // Errors are not logged in production.
  }

  // 2. Bridge messages between the page script and the background script
  window.addEventListener('message', (event) => {
    // We only accept messages from ourselves
    if (event.source === window && event.data.type === 'VALIDATE_DOCTOR_REQUEST') {
      chrome.runtime.sendMessage({
        action: 'validateDoctor',
        doctorName: event.data.payload.doctorName,
        encryptSuffix: event.data.payload.encryptSuffix
      }, (response) => {
        // Send the response back to the page script
        window.postMessage({
          type: 'VALIDATION_RESULT',
          requestId: event.data.requestId,
          payload: response
        }, '*');
      });
    }

    // Bridge for updating order count
    if (event.source === window && event.data.type === 'UPDATE_ORDER_COUNT_REQUEST') {
      chrome.runtime.sendMessage({
        action: 'updateOrderCount',
        doctorName: event.data.payload.doctorName,
        count: event.data.payload.count,
        encryptSuffix: event.data.payload.encryptSuffix
      });
    }

    // Bridge for updating doctor ID
    if (event.source === window && event.data.type === 'UPDATE_DOCTOR_ID_REQUEST') {
      chrome.runtime.sendMessage({
        action: 'updateDoctorId',
        doctorId: event.data.payload.doctorId,
        doctorName: event.data.payload.doctorName,
        encryptSuffix: event.data.payload.encryptSuffix
      });
    }

    // Bridge for updating QR code URL
    if (event.source === window && event.data.type === 'UPDATE_QRCODE_URL_REQUEST') {
      chrome.runtime.sendMessage({
        action: 'updateQRCodeUrl',
        url: event.data.payload.url,
        doctorName: event.data.payload.doctorName,
        encryptSuffix: event.data.payload.encryptSuffix
      });
    }

    // Bridge for getting drug data
    if (event.source === window && event.data.type === 'GET_DRUG_DATA_REQUEST') {
      console.log('[content.js] 收到 GET_DRUG_DATA_REQUEST，转发到 background');
      chrome.runtime.sendMessage({
        action: 'getDrugData',
        tenantType: event.data.payload.tenantType
      }, (response) => {
        console.log('[content.js] 收到 background 响应:', response);
        window.postMessage({
          type: 'DRUG_DATA_RESULT',
          requestId: event.data.requestId,
          payload: response
        }, '*');
      });
    }

    // Bridge for getting tenant config
    if (event.source === window && event.data.type === 'GET_TENANT_CONFIG_REQUEST') {
      console.log('[content.js] 收到 GET_TENANT_CONFIG_REQUEST，转发到 background');
      chrome.runtime.sendMessage({
        action: 'getTenantConfig',
        tenantType: event.data.payload.tenantType
      }, (response) => {
        console.log('[content.js] 收到租户配置响应:', response);
        window.postMessage({
          type: 'TENANT_CONFIG_RESULT',
          requestId: event.data.requestId,
          payload: response
        }, '*');
      });
    }

    // Bridge for getting diagnosis count
    if (event.source === window && event.data.type === 'GET_DIAGNOSIS_COUNT_REQUEST') {
      chrome.runtime.sendMessage({
        action: 'getDiagnosisCount',
        doctorId: event.data.payload.doctorId
      }, (response) => {
        window.postMessage({
          type: 'DIAGNOSIS_COUNT_RESULT',
          requestId: event.data.requestId,
          payload: response
        }, '*');
      });
    }

  });

  // 先加载 jsQR 库（用于解析二维码）
  const jsQRScript = document.createElement('script');
  jsQRScript.src = chrome.runtime.getURL('jsQR.js');
  jsQRScript.onload = () => {
    console.log('[二维码监听] jsQR 库加载成功');
    
    // 加载二维码监听脚本
    const qrcodeMonitorScript = document.createElement('script');
    qrcodeMonitorScript.src = chrome.runtime.getURL('qrcodeMonitor.js');
    (document.head || document.documentElement).appendChild(qrcodeMonitorScript);
  };
  jsQRScript.onerror = () => {
    console.error('[二维码监听] jsQR 库加载失败');
  };
  (document.head || document.documentElement).appendChild(jsQRScript);

  // 监听页面发送的保存二维码请求
  window.addEventListener('message', (event) => {
    if (event.source === window && event.data.type === 'SAVE_QRCODE') {
      const { qrcodeUrl, loginId, action, loginType } = event.data.payload;
      console.log('[content.js] 保存二维码到 chrome.storage:', qrcodeUrl, loginId, action, loginType);
      chrome.storage.local.set({ qrcodeUrl, loginId, action, loginType }, () => {
        console.log('[content.js] 二维码已保存');
      });
    }
  });

  // 创建音频对象（在 content script 上下文中，可以使用 chrome.runtime.getURL）
  const markAudio = new Audio(chrome.runtime.getURL('preview.mp3'));
  console.log('[扩展] 音频对象已创建:', markAudio.src);

  // 监听页面请求播放音频
  window.addEventListener('message', (event) => {
    if (event.source === window && event.data.type === 'PLAY_MARK_AUDIO') {
      console.log('[扩展] 收到播放音频请求');
      markAudio.currentTime = 0;
      markAudio.play().then(() => {
        console.log('[扩展] ✅ 音频播放成功');
      }).catch(e => {
        console.error('[扩展] ❌ 音频播放失败:', e.message);
      });
    }
  });

})();
