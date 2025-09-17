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
    const { doctorName } = request;
    const url = `http://117.72.208.155:7031/api/validate-doctor`;
    
    // Encrypt the doctor's name before sending
    encryptDoctorName(doctorName+'TZ')
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
    const { doctorName, count } = request;
    const url = `http://117.72.208.155:7031/api/update-order-count`;
    
    encryptDoctorName(doctorName+'TZ')
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
});
