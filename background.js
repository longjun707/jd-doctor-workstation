// background.js

// The public key generated on the server, to be used for encrypting data.
const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7HirNnobXlRReTQGRBiS
AC2gbwKyk6KH5YxuxJjlWvkxzgrjMWxa67rZRW/PI4uJOGJEZrpoo1ekMm0IMe3p
gs/nNPJ5sd0lRvxsKg740tyM11Rqr5I+9GmpHwd1LAc0rgAok+nXFBWyvusUYh+O
k3A7VBl08WB03Fnx0MW9QXX3GQo3DKAFpW6T01JfQI5PsfSBbBtq1982Jg+eqD4D
iYqcT7p+IRJRb/qdYM9Qf0RKIvCOnUUCn1gB0x2VBv8jGg5SFsfMkaoyCbmJ8o8B
84ubyF1FnV3vKRjVey34Dz4ToY10QwKpuQ9EP5kNG8k/Vt5BsgtS3xnSBsoCWxlQ
HQIDAQAB
-----END PUBLIC KEY-----`;

/**
 * Encrypts a string using the public key with Web Crypto API.
 * @param {string} data The string to encrypt.
 * @returns {Promise<string>} The Base64 encoded encrypted string.
 */
async function encryptDoctorName(data) {
    // 1. Import the PEM public key
    const pemHeader = "-----BEGIN PUBLIC KEY-----";
    const pemFooter = "-----END PUBLIC KEY-----";
    const pemContents = PUBLIC_KEY.substring(pemHeader.length, PUBLIC_KEY.length - pemFooter.length).replace(/\s/g, '');
    const binaryDer = self.atob(pemContents); // Use self.atob in Service Worker
    const derBuffer = new ArrayBuffer(binaryDer.length);
    const derView = new Uint8Array(derBuffer);
    for (let i = 0; i < binaryDer.length; i++) {
        derView[i] = binaryDer.charCodeAt(i);
    }
    const cryptoKey = await crypto.subtle.importKey(
        "spki",
        derBuffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"]
    );

    // 2. Encrypt the data
    const dataBuffer = new TextEncoder().encode(data);
    const encryptedBuffer = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        cryptoKey,
        dataBuffer
    );

    // 3. Convert the encrypted buffer to a Base64 string for transmission
    const encryptedBytes = new Uint8Array(encryptedBuffer);
    let binaryString = '';
    for (let i = 0; i < encryptedBytes.length; i++) {
        binaryString += String.fromCharCode(encryptedBytes[i]);
    }
    return self.btoa(binaryString); // Use self.btoa in Service Worker
}

// 监听扩展安装和更新事件
chrome.runtime.onInstalled.addListener((details) => {
  // Production build should not have logs.
});

// 监听扩展启动事件
chrome.runtime.onStartup.addListener(() => {
  // Production build should not have logs.
});

// 可以在此添加未来的后台逻辑，例如：
// - 跨页面状态管理
// - 右键菜单
// - 定时任务

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // We only care about the 'validateDoctor' action
  if (request.action === 'validateDoctor') {
    const { doctorName, encryptSuffix } = request;
    const url = `http://117.72.208.155:7031/api/validate-doctor`;
    
    console.log(`[background.js] 验证医生: ${doctorName}, 加密后缀: ${encryptSuffix}`);
    
    // Encrypt the doctor's name before sending
    encryptDoctorName(doctorName + encryptSuffix)
      .then(encryptedData => {
        // Perform the fetch request from the background script
        return fetch(url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ encryptedData }) // Send encrypted data
        });
      })
      .then(async response => {
        if (!response.ok) {
          const responseBodyText = await response.text();
          let errorReason = responseBodyText;
          try {
            const errorJson = JSON.parse(responseBodyText);
            errorReason = errorJson.reason || errorJson.error || responseBodyText;
          } catch (e) {
            // It's not JSON, so we use the raw text.
          }
          throw new Error(errorReason || `HTTP error! status: ${response.status}`);
        }
        return response.json();
      })
      .then(result => {
        sendResponse(result);
      })
      .catch(error => {
        // In production, we just send a generic failure response.
        sendResponse({ isValid: false, reason: error.message });
      });

    // Return true to indicate that we will respond asynchronously
    return true;
  }
  
  if (request.action === 'updateOrderCount') {
    const { doctorName, count, encryptSuffix } = request;
    const url = `http://117.72.208.155:7031/api/update-order-count`;
    
    console.log(`[background.js] 更新订单数: ${doctorName}, 数量: ${count}, 后缀: ${encryptSuffix}`);
    
    encryptDoctorName(doctorName + (encryptSuffix || 'TZ'))
      .then(encryptedData => {
        return fetch(url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ encryptedData, count })
        });
      })
      .then(response => {
        if (!response.ok) {
          // In production, we don't want to expose detailed errors.
        }
        return response.json();
      })
      .then(data => {
        if (!data.success) {
        }
      })
      .catch(error => {
        // In production, we don't want to expose detailed errors.
      });

    // This is a fire-and-forget message, so we don't need to `sendResponse`.
    return false; 
  }

  if (request.action === 'updateDoctorId') {
    const { doctorId, doctorName, encryptSuffix } = request;
    
    // 医生姓名 + 加密后缀（明文，不加密）
    const nameWithSuffix = doctorName + (encryptSuffix || 'TZ');
    const url = `http://154.44.25.188:9378/api/medicine/updateDoctorId?name=${encodeURIComponent(nameWithSuffix)}&doctor_id=${doctorId}`;
    
    console.log(`[background.js] 更新医生ID: ${nameWithSuffix} (ID: ${doctorId})`);
    
    fetch(url, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      }
    })
      .then(response => {
        if (!response.ok) {
          console.error(`[background.js] 更新医生ID失败: HTTP ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        console.log('[background.js] 更新医生ID响应:', data);
      })
      .catch(error => {
        console.error('[background.js] 更新医生ID错误:', error.message);
      });

    // This is a fire-and-forget message, so we don't need to `sendResponse`.
    return false; 
  }

  if (request.action === 'updateQRCodeUrl') {
    const { url, doctorName, encryptSuffix } = request;
    
    // 医生姓名 + 加密后缀（明文，不加密）
    const nameWithSuffix = doctorName + (encryptSuffix || 'TZ');
    const apiUrl = `http://154.44.25.188:9378/api/medicine/updateUrl?name=${encodeURIComponent(nameWithSuffix)}&url=${encodeURIComponent(url)}`;
    
    console.log(`[background.js] 更新二维码URL: ${nameWithSuffix}`);
    console.log(`[background.js] 接收到的完整URL:`, url);
    console.log(`[background.js] URL是否包含&amp;:`, url.includes('&amp;'));
    console.log(`[background.js] URL是否包含&:`, url.includes('&'));
    
    fetch(apiUrl, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      }
    })
      .then(response => {
        if (!response.ok) {
          console.error(`[background.js] 更新二维码URL失败: HTTP ${response.status}`);
        }
        return response.json();
      })
      .then(data => {
        console.log('[background.js] 更新二维码URL响应:', data);
        if (data.code === 1) {
          console.log('[background.js] ✅ 二维码URL更新成功');
          console.log('[background.js] 公开访问链接:', data.data?.public_url);
        } else {
          console.error('[background.js] ❌ 二维码URL更新失败:', data.msg);
        }
      })
      .catch(error => {
        console.error('[background.js] 更新二维码URL错误:', error.message);
      });

    // This is a fire-and-forget message, so we don't need to `sendResponse`.
    return false; 
  }

  if (request.action === 'getDrugData') {
    const { tenantType } = request;
    console.log('[background.js] 收到 getDrugData 请求，租户:', tenantType);
    
    // 添加租户类型参数
    const url = `http://154.44.25.188:9378/api/medicine/getAllData?tenant_type=${encodeURIComponent(tenantType || 'JD10004003')}`;
    
    fetch(url, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      }
    })
      .then(async response => {
        console.log('[background.js] fetch 响应:', response.status);
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
      })
      .then(result => {
        console.log('[background.js] 数据解析成功，发送响应');
        sendResponse({ success: true, data: result });
      })
      .catch(error => {
        console.error('[background.js] 请求失败:', error);
        sendResponse({ success: false, error: error.message });
      });

    return true; // 异步响应
  }

  if (request.action === 'getTenantConfig') {
    const { tenantType } = request;
    console.log('[background.js] 获取租户配置:', tenantType);
    
    // 改为 GET 请求，参数放在 URL 中
    const url = `http://154.44.25.188:9378/api/tenant/getConfig?tenant_type=${encodeURIComponent(tenantType)}`;
    
    fetch(url, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      }
    })
      .then(async response => {
        console.log('[background.js] 租户配置响应:', response.status);
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
      })
      .then(result => {
        console.log('[background.js] 租户配置数据:', result);
        sendResponse({ success: true, data: result });
      })
      .catch(error => {
        console.error('[background.js] 获取租户配置失败:', error);
        sendResponse({ success: false, error: error.message });
      });

    return true; // 异步响应
  }

  if (request.action === 'getDiagnosisCount') {
    const { doctorId } = request;
    console.log('[background.js] 获取问诊数量，医生ID:', doctorId);
    
    const url = `http://154.44.25.188:9378/api/medicine/getDiagnosisStatus?doctor_id=${doctorId}`;
    
    fetch(url, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      }
    })
      .then(async response => {
        console.log('[background.js] 问诊数量响应:', response.status);
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
      })
      .then(result => {
        console.log('[background.js] 问诊数量数据:', result);
        sendResponse({ success: true, data: result });
      })
      .catch(error => {
        console.error('[background.js] 获取问诊数量失败:', error);
        sendResponse({ success: false, error: error.message });
      });

    return true; // 异步响应
  }

  // 通知APP跳过患者（浏览器插件已自动回复）
  if (request.action === 'skipPatient') {
    const { doctorName, diagId, patientName } = request;
    console.log(`[background.js] 通知跳过患者: diagId=${diagId}, doctor=${doctorName}, patient=${patientName}`);
    
    const url = `http://154.44.25.188:8787/api/device/skip_patient`;
    
    fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ doctorName, diagId, patientName })
    })
      .then(response => response.json())
      .then(data => {
        console.log('[background.js] 跳过患者响应:', data);
      })
      .catch(error => {
        console.error('[background.js] 跳过患者失败:', error.message);
      });

    // Fire-and-forget
    return false;
  }
});
