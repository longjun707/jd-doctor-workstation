/**
 * 🎯 患者消息监听器（稳定版）
 * 功能：监听患者消息、判断处方前后、自动回复、自动标记
 */

export function initializePatientListener() {
  
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('📱 患者消息监听器 v1.0');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  
  // 全局变量
  let patientMsgCount = 0;
  const processedMids = new Set();
  const repliedMids = new Set(); // 已回复的消息ID（废弃，改用患者名去重）
  const repliedPatients = new Set(); // 已回复的患者名称（按患者去重）
  const markedDuplicateDrugPatients = new Set(); // 已标记重复用药的患者（避免重复标记）

  // UUID生成器
  function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }
  
  // 根据患者消息内容决定回复什么
  function getReplyContent(patientContent) {
    if (patientContent.includes('线下已确诊')) {
      return '好的';
    }
    
    // 默认回复
    return '在的，请稍等';
  }
  
  // 发送自动回复（延迟700ms）
  async function sendAutoReply(socket, chat, patientPin, chatinfo, patientContent) {
    setTimeout(async () => {
      try {
        const replyContent = getReplyContent(patientContent);
        
        const message = {
          ver: "4.1",
          aid: chat.getAid(),
          id: generateUUID(),
          type: "duo_message",
          from: {
            clientType: "comet",
            app: "jd.doctor",
            pin: chat.getFromPin()
          },
          to: {
            app: "jd.dyf",
            pin: patientPin
          },
          body: {
            chatinfo: {
              sid: chatinfo?.sid,
              doctorPin: chat.getFromPin(),
              patientId: chatinfo?.patientId,
              patientName: chatinfo?.patientName,
              patientSex: chatinfo?.patientSex,
              patientAgeString: chatinfo?.patientAgeString || 
                              (chatinfo?.ageString ? parseInt(chatinfo.ageString) : undefined),
              diagId: chatinfo?.diagId,
              diagStu: chatinfo?.diagStu || 2,
              serviceType: chatinfo?.serviceType || 1,
              businessType: chatinfo?.businessType || 4,
              imLimitType: chatinfo?.imLimitType || 0,
              customJsonData: chatinfo?.customJsonData || "{}",
              tenantType: chatinfo?.tenantType || 'JD8888',
              orderId: chatinfo?.orderId,
              frontLogTime: 'ff' + Date.now()
            },
            type: "text",
            content: replyContent,
            riskCheck: true,
            useType: "im_danliao_hpc",
            channel: 1,
            atUsers: [],
            chatExtInfo: JSON.stringify({
              diagId: chatinfo?.diagId,
              orderId: chatinfo?.orderId
            })
          }
        };
        
        socket.send(JSON.stringify(message));
        console.log(`🤖 已自动回复: "${replyContent}"`);
        
        // 1秒后调用待回复API - 已注释掉
        // setTimeout(async () => {
        //   try {
        //     if (window.apiService && chatinfo?.diagId && chatinfo?.sid) {
        //       await window.apiService.setWaitAnswerSession(chatinfo.diagId, chatinfo.sid);
        //       console.log('✅ 已设置待回复状态');
        //     }
        //   } catch(apiErr) {
        //     console.error('设置待回复状态失败:', apiErr);
        //   }
        // }, 1000); // 1秒后
        
      } catch(err) {
        console.error('自动回复失败:', err);
      }
    }, 700);
  }
  
  // 检查聊天记录中是否包含药物信息
  function checkDrugInHistory(history) {
    const allContent = history.map(m => m.body?.content || '').join(' ');
    
    if (allContent.includes('需开药:') || allContent.includes('需开药：')) {
      return true;
    }
    
    return false;
  }
  
  // 从聊天记录中提取所有药品名称
  function extractDrugNamesFromHistory(history) {
    const drugNames = [];
    
    for (const msg of history) {
      const chatinfo = msg.body?.chatinfo;
      
      // 从处方卡片提取药品（最准确）
      if (chatinfo?.messageSign?.includes('idCardRxCheckSign') && 
          chatinfo?.customJsonData) {
        try {
          const customData = JSON.parse(chatinfo.customJsonData);
          const skuList = customData.skuList || [];
          
          skuList.forEach(sku => {
            if (sku.drugName) {
              drugNames.push(sku.drugName);
            }
          });
        } catch(e) {
          // JSON解析失败，跳过
        }
      }
    }
    
    return drugNames;
  }
  
  // 检测聊天记录中是否有重复药品
  function checkDuplicateDrugsInHistory(history) {
    const drugNames = extractDrugNamesFromHistory(history);
    
    if (drugNames.length === 0) {
      return null; // 没有药品信息
    }else{
      console.log(`💊 药品列表: ${drugNames.join(', ')}`);
    }
    
    // 检测重复
    const duplicates = drugNames.filter((name, index) => 
      drugNames.indexOf(name) !== index
    );
    
    if (duplicates.length > 0) {
      const uniqueDuplicates = [...new Set(duplicates)];
      return uniqueDuplicates; // 返回去重后的重复药品列表
    }
    
    return null; // 没有重复
  }
  
  // 触发自动标记事件
  function triggerAutoMark(patientName) {
    try {
      const event = new CustomEvent('autoMarkPatient', {
        detail: {
          patientName: patientName,
          displayText: patientName,
          reason: '自动回复',
          timestamp: Date.now(),
          source: 'patientListener'
        }
      });
      document.dispatchEvent(event);
      console.log(`📌 已标记患者: ${patientName}`);
    } catch(err) {
      console.error('标记患者失败:', err);
    }
  }
  
  // 分析处方状态
  async function analyzeMessageStatus(chat, sessionId, msgMid, tenantType) {
    try {
      const history = await chat.getSidPage(sessionId, 30, -1, 2);
      
      // JD8888租户：有药物 OR 处方前 → 回复
      if (tenantType === 'JD8888') {
        const hasDrug = checkDrugInHistory(history);
        
        const rxList = history.filter(m => {
          const ci = m.body?.chatinfo || m.body?.param;
          return ci?.msgId?.includes('rx_msg') || 
                 ci?.messageSign?.includes('Rx') ||
                 m.body?.content?.includes('处方已开具') ||
                 m.body?.content?.includes('处方已送达');
        });
        
        const hasRx = rxList.length > 0;
        const isBeforeRx = hasRx && msgMid < rxList[rxList.length - 1].mid;
        
        // OR逻辑
        const shouldReply = hasDrug || !hasRx || isBeforeRx;
        
        let status = '';
        if (hasDrug && !hasRx) status = '有药物+未开处方';
        else if (hasDrug && isBeforeRx) status = '有药物+处方前';
        else if (hasDrug && !isBeforeRx) status = '有药物+处方后';
        else if (!hasDrug && !hasRx) status = '无药物+未开处方';
        else if (!hasDrug && isBeforeRx) status = '无药物+处方前';
        else status = '无药物+处方后';
        
        return { status, shouldReply };
      }
      
      // 其他租户：只看处方前后
      const rxList = history.filter(m => {
        const ci = m.body?.chatinfo || m.body?.param;
        return ci?.msgId?.includes('rx_msg') || 
               ci?.messageSign?.includes('Rx') ||
               m.body?.content?.includes('处方已开具') ||
               m.body?.content?.includes('处方已送达');
      });
      
      if (rxList.length === 0) {
        return { status: '未开处方', shouldReply: true };
      }
      
      const latestRx = rxList[rxList.length - 1];
      
      if (msgMid < latestRx.mid) {
        return { status: '处方前', shouldReply: true };
      } else {
        return { status: '处方后', shouldReply: false };
      }
    } catch(err) {
      return { status: '分析失败', shouldReply: false };
    }
  }
  
  // 启动监听器
  function startListening() {
    const tryListen = () => {
      const chat = window._connection || window.__ddChat;
      
      if (!chat?.socket) {
        console.log('等待聊天连接建立...');
        setTimeout(tryListen, 500);
        return;
      }
      
      console.log('✅ 找到聊天连接');
      console.log('连接状态:', chat.socket.readyState === 1 ? '已连接' : '连接中');
      console.log('开始监听患者消息...\n');
      
      // 直接监听socket
      chat.socket.addEventListener('message', (event) => {
        setTimeout(() => {
          try {
            const data = JSON.parse(event.data);
            
            // 检查是否为患者消息
            if ((data.type === 'chat_message' || data.type === 'duo_message') &&
                data.from?.app === 'jd.dyf' &&
                data.mid > 0 &&
                data.from?.pin !== '@im.jd.com') {
              
              // 去重检查在条件通过后
              if (processedMids.has(data.mid)) {
                return;
              }
              processedMids.add(data.mid);
              
              const chatinfo = data.body?.chatinfo || data.body?.param;
              const content = data.body?.content || '';
              const patientName = chatinfo?.patientName || data.from?.pin;
              
              // 过滤系统消息 - 数组形式
              const systemKeywords = [
                '图文问诊',
                "无需补充，立即开方",
                "医生您好，以上病历我已确认无误，请医生帮我开方",
                "医生您好，以上病历资料我已确认无误，请医生帮我开方",
                "没有药物过敏史",
                "用过该药品，且没有相关禁忌症",
                "没有发生过药品不良反应",
                "服务已开始，请您详细描述问题，以便医生为您提供更优质的服务"
              ];
              
              const isSystemMsg = systemKeywords.some(keyword => content.includes(keyword)) ||
                                 data.body?.template?.nativeId;
              
              if (isSystemMsg) {
                return;
              }
              
              patientMsgCount++;
              
              console.log('━'.repeat(60));
              console.log(`患者: ${patientName}`);
              console.log(`内容: ${content}`);
              console.log(`MID: ${data.mid} | 时间: ${new Date(data.timestamp).toLocaleString('zh-CN', {hour12: false})}`);
              console.log(`租户: ${chatinfo?.tenantType || '未知'}`);
              
              const sessionId = chatinfo?.sid;
              const tenantType = chatinfo?.tenantType;
              
              if (sessionId) {
                (async () => {
                  try {
                    const history = await chat.getSidPage(sessionId, 30, -1, 2);
                    
                    // 🔍 JD8888 租户：检测重复药品（只标记一次）
                    if (tenantType === 'JD8888' && !markedDuplicateDrugPatients.has(patientName)) {
                      const duplicateDrugs = checkDuplicateDrugsInHistory(history);
                      if (duplicateDrugs && duplicateDrugs.length > 0) {
                        console.log(`⚠️ 检测到重复用药: ${patientName} (药品: ${duplicateDrugs.join(', ')})`);
                        
                        // 标记患者
                        const markEvent = new CustomEvent('autoMarkPatient', {
                          detail: {
                            patientName: patientName,
                            displayText: `${patientName}+重复用药`,
                            reason: `${patientName}+重复用药`,
                            timestamp: Date.now(),
                            source: 'duplicateDrugDetection'
                          }
                        });
                        document.dispatchEvent(markEvent);
                        
                        // 记录已标记，避免重复
                        markedDuplicateDrugPatients.add(patientName);
                        console.log(`✅ 已标记重复用药患者: ${patientName}`);
                        
                        // 检测到重复用药后，跳过后续处理
                        return;
                      }
                    }
                    
                    const result = await analyzeMessageStatus(chat, sessionId, data.mid, tenantType);
                    
                    console.log(`状态: ${result.status} ${result.shouldReply ? '→ 回复' : '→ 不回复'}`);
                    
                    // 自动回复（按患者去重：每个患者只回复一次）
                    if (result.shouldReply && !repliedPatients.has(patientName)) {
                      repliedPatients.add(patientName);
                      repliedMids.add(data.mid); // 保留消息ID记录，用于统计
                      
                      console.log(`🎯 首次回复患者: ${patientName}`);
                      sendAutoReply(chat.socket, chat, data.from.pin, chatinfo, content);
                      
                      // 自动标记
                      setTimeout(() => {
                        triggerAutoMark(patientName);
                      }, 600);
                    } else if (repliedPatients.has(patientName)) {
                      console.log(`⏭️  跳过：患者 ${patientName} 已回复过`);
                    }
                    
                  } catch(err) {
                    console.log('状态: 分析失败');
                  }
                })();
              } else {
                console.log('状态: 无会话ID');
              }
              
              console.log('━'.repeat(60));
              console.log(`总计: ${patientMsgCount} 条患者消息\n`);
            }
          } catch(parseErr) {
            // 静默忽略
          }
        }, 10);
      });
    };
    
    tryListen();
  }
  
  // 导出控制函数
  window.__patientListener = {
    getCount: () => patientMsgCount,
    getRepliedCount: () => repliedMids.size,
    getRepliedPatientsCount: () => repliedPatients.size,
    getRepliedPatients: () => Array.from(repliedPatients),
    getMarkedDuplicateDrugPatientsCount: () => markedDuplicateDrugPatients.size,
    getMarkedDuplicateDrugPatients: () => Array.from(markedDuplicateDrugPatients),
    clearRepliedPatients: () => {
      repliedPatients.clear();
      console.log('✅ 已清除已回复患者记录');
    },
    clearMarkedDuplicateDrugPatients: () => {
      markedDuplicateDrugPatients.clear();
      console.log('✅ 已清除重复用药标记记录');
    },
    getStats: () => {
      console.log('\n━━━━━━━━ 统计信息 ━━━━━━━━');
      console.log('患者消息:', patientMsgCount, '条');
      console.log('已回复消息:', repliedMids.size, '条');
      console.log('已回复患者:', repliedPatients.size, '人');
      console.log('患者列表:', Array.from(repliedPatients).join(', '));
      console.log('重复用药患者:', markedDuplicateDrugPatients.size, '人');
      if (markedDuplicateDrugPatients.size > 0) {
        console.log('重复用药列表:', Array.from(markedDuplicateDrugPatients).join(', '));
      }
      console.log('━━━━━━━━━━━━━━━━━━━━━━━\n');
    }
  };
  
  // 心跳检测
  setInterval(() => {
    const chat = window._connection || window.__ddChat;
    if (chat?.socket?.readyState !== 1) {
      console.log('⚠️ WebSocket连接异常');
    }
  }, 30000);
  
  // 启动监听
  startListening();
  
}
