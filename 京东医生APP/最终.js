const STATE = {
    ep: null,
    jec: null,
    phone: "UNKNOWN_PHONE", // 确保有默认值
    account_name: "UNKNOWN_ACCOUNT",
    aesKey: "eLZoZVqrg0wfNW0y",
    isConnected: false,
    diagId: null,
    delay: 2000,
    random_delay: 5000,
    lastRefreshTime: 0,
    refreshInProgress: false,
    concurrencyLimit: 10,

    currentProcessingCount: 0 // 当前正在处理的诊断单数量
};
const Utils = {
    log: (message, level = 'info') => {
        const levels = {
            info: 'ℹ️',
            warn: '⚠️',
            error: '❌',
            success: '✅'
        };
        console.log(`${levels[level] || ' '} ${message}`);
    },

    getRandomDelay: () => {
        return STATE.baseDelay + Math.random() * STATE.randomDelayRange;
    },

    validateTimestamp: (serverTime, clientTime) => {
        const MAX_DIFF = 5000;
        const diff = Math.abs(clientTime - serverTime);
        return diff <= MAX_DIFF;
    },

    sleep: (ms) => {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
};

const OrderRefresh = {
    // 状态标记
    isProcessingBatch: false,
    activeRequests: 0,
    lastRefreshTime: 0,
    isRunning: false,
    refreshTimer: null,

    // 主刷新入口
    refreshOrderList: async function () {
        if (!STATE.isConnected || STATE.refreshInProgress) {
            console.log(`[!] 跳过刷新 | 网络:${STATE.isConnected} 进行中:${STATE.refreshInProgress}`);
            return;
        }

        STATE.refreshInProgress = true;
        try {
            const response = await OkHttpManager.refreshOrderList();
            const data = JSON.parse(response.body);

            if (data.success && data.data?.length) {
                const diagIds = data.data.map(o => o.diagId?.toString()).filter(Boolean);
                console.log(`[→] 获取 ${diagIds.length} 个新订单`);

                // 立即并行处理所有订单
                this.processOrdersParallel(diagIds);
            }
        } catch (error) {
            console.error('[×] 刷新失败:', error);
        } finally {
            STATE.refreshInProgress = false;
            // this.lastRefreshTime = Date.now();
            // console.log(`[⏱] 刷新耗时: ${Date.now() - refreshStart}ms`);
        }
    },

    // 并行处理器
    processOrdersParallel: function (diagIds) {
        if (this.isProcessingBatch) {
            console.log('[!] 已有批次在处理中，跳过本次');
            return;
        }

        this.isProcessingBatch = true;
        const parallelStart = Date.now();
        const MAX_CONCURRENT = STATE.concurrencyLimit || 5;

        console.log(`[⚡] 并行处理开始 (并发数:${MAX_CONCURRENT})`);

        // 所有请求同时发出
        const requests = diagIds.map(diagId => {
            this.activeRequests++;
            return this.sendOrderRequest(diagId)
                .finally(() => this.activeRequests--);
        });

        Promise.allSettled(requests).then(results => {
            const successCount = results.filter(r => r.status === 'fulfilled').length;
            console.log(`[√] 并行完成: ${successCount}/${diagIds.length} 成功 | 耗时:${Date.now() - parallelStart}ms`);
        }).finally(() => {
            this.isProcessingBatch = false;
        });
    },

    // 严格延迟控制的刷新循环
    startAutoRefresh: function () {
        if (this.isRunning) {
            console.log('[!] 自动刷新已在运行中');
            return;
        }

        console.log(`[↻] 启动自动刷新 (间隔:${STATE.delay}-${STATE.delay + STATE.random_delay}ms)`);
        this.isRunning = true;

        const refreshCycle = async () => {
            if (!this.isRunning) return;

            await this.refreshOrderList();

            // 计算下次刷新延迟
            const nextDelay = STATE.delay + Math.random() * STATE.random_delay;
            // console.log(`[⏱] 下次刷新 ${nextDelay}ms 后 | 活跃请求:${this.activeRequests}`);

            STATE.refreshTimer = setTimeout(refreshCycle, nextDelay);
        };

        // 立即开始第一次刷新
        this.lastRefreshTime = Date.now() - STATE.delay;
        refreshCycle();
    },

    // 停止自动刷新
    stopAutoRefresh: function () {
        if (!this.isRunning) {
            console.log('[!] 自动刷新未运行');
            return;
        }

        console.log('[↻] 停止自动刷新');
        this.isRunning = false;
        if (STATE.refreshTimer) {
            clearTimeout(STATE.refreshTimer);
            STATE.refreshTimer = null;
        }
    },

    // 检查是否在运行
    isAutoRefreshRunning: function () {
        return this.isRunning;
    },

    // 订单请求
    sendOrderRequest: async function (diagId) {
        try {
            const startTime = Date.now();
            const response = await OkHttpManager.sendDiagnosisRequest(diagId);
            const result = JSON.parse(response.body);

            if (result.code === "0000") {
                console.log(`[√] 订单 ${diagId} 接单成功 (${Date.now() - startTime}ms)`);
                Network.sendMessage(`DEDUCT:${STATE.account_name}`);
                return true;
            }
            throw new Error(result.msg || '状态码非0000');
        } catch (error) {
            console.error(`[×] 订单 ${diagId} 失败:`, error.message);
            throw error;
        }
    }
};
const PrescriptionManager = {
    // 状态变量
    monitorInterval: null,
    lastActiveTime: 0,
    stopTimer: null,

    // 带日志的请求封装
    makeRequest: async function (name, url, data, headers) {
        // 请求日志
        console.log(`\n[→][${new Date().toLocaleTimeString()}] ${name}`);
        console.log(`├─ URL: ${url}`);
        console.log(`├─ Headers: ${JSON.stringify(headers, null, 2).replace(/\n/g, '\n│  ')}`);
        console.log(`└─ Body: ${JSON.stringify(data, null, 2).replace(/\n/g, '\n   ')}`);

        try {
            const startTime = Date.now();
            const response = await OkHttpManager.sendCustomRequest(url, JSON.stringify(data), headers);
            const duration = Date.now() - startTime;

            if (!response) {
                console.error(`[×][${new Date().toLocaleTimeString()}] ${name} 无响应`);
                return null;
            }

            // 响应日志
            console.log(`\n[←][${new Date().toLocaleTimeString()}] ${name} (${duration}ms)`);
            console.log(`├─ 状态码: ${response.code}`);

            try {
                const responseData = JSON.parse(response.body);
                console.log(`├─ 业务状态: ${responseData.success ? '成功' : '失败'}`);

                // 关键信息提取
                if (responseData.msg) {
                    console.log(`├─ 服务消息: ${responseData.msg}`);
                }

                // 诊断单信息提取
                if (responseData.data?.doctorDiagDtoList) {
                    console.log('├─ 诊断单列表:');
                    responseData.data.doctorDiagDtoList.slice(0, 3).forEach((diag, idx) => {
                        console.log(`│  ${idx + 1}. ${diag.patientName}(${diag.patientAgeString})`);
                        console.log(`│    诊断: ${diag.diseaseDesc.split(';')[0]}`);
                        console.log(`│    最后消息: ${diag.sessionContentDto?.lastContent || '无状态信息'}`);
                    });
                    if (responseData.data.doctorDiagDtoList.length > 3) {
                        console.log(`│  ...(共 ${responseData.data.doctorDiagDtoList.length} 条)`);
                    }
                }

                // 处方详情提取
                if (responseData.data?.rxItemDtoList) {
                    console.log('├─ 处方药品:');
                    responseData.data.rxItemDtoList.forEach(item => {
                        console.log(`│  - ${item.drugName} ${item.specification}`);
                        console.log(`│    数量: ${item.quantity} 天数: ${item.days || '未知'}`);
                    });
                }



                this.lastActiveTime = Date.now();
                return response;

            } catch (e) {
                console.log(`[⚠] 响应解析异常: ${e.message}`);
                console.log('└─ 原始响应:', response.body);
                return response; // 即使解析失败也返回原始响应
            }

        } catch (error) {
            console.error(`[×][${new Date().toLocaleTimeString()}] ${name} 请求失败:`);
            console.error(`└─ ${error.message}`);
            throw error;
        }
    },

    // 获取待开方诊断单列表
    getPendingPrescriptions: function () {
        return this.makeRequest(
            "获取待开方列表",
            "https://api.m.jd.com/api/JDD_APP_DiagList_getInDiagListEncrypt",
            { tenantType: "JD8888" },
            {
                "Content-Type": "application/json",

            }
        );
    },

    // 创建处方草稿
    createRxDraft: function (diagId, sid) {
        return this.makeRequest(
            "创建处方草稿",
            "https://api.m.jd.com/api/JDDAPP_rx_saveRx",
            {
                diagId: diagId,
                rxCategory: 1,
                patientId: 0,
                sid: sid,
                tenantType: "JD8888"
            },
            {
                "Content-Type": "application/json",

            }
        );
    },

    // 获取处方详情
    getRxDetail: function (rxId) {
        return this.makeRequest(
            "获取处方详情",
            "https://api.m.jd.com/api/jdd_queryRxDetailByRxId",
            { rxId: rxId },
            {
                "Content-Type": "application/json",

            }
        );
    },

    // 获取处方补充信息
    getRxSupplementInfo: function (rxId, diagnosisName) {
        return this.makeRequest(
            "获取处方补充信息",
            "https://api.m.jd.com/api/jdd_getRxSupplementInfo",
            {
                rxId: rxId,
                inputList: [diagnosisName],
                rxItemDtoList: []
            },
            {
                "Content-Type": "application/json",

            }
        );
    },

    // 临时保存处方
    tempSaveRx: function (rxId, diagnosisName) {
        return this.makeRequest(
            "临时保存处方",
            "https://api.m.jd.com/api/rx_tempSaveRxApp",
            {
                rxId: rxId,
                diagResult: diagnosisName,
                syndromeIdentifying: diagnosisName,
                noticeInfo: "",
                rxRemarks: "",
                rxCategory: 1,
                tempSaveStamp: Date.now()
            },
            {
                "Content-Type": "application/json",

            }
        );
    },

    // 确认处方
    confirmRx: function (rxId, diagnosisName) {
        return this.makeRequest(
            "确认处方",
            "https://api.m.jd.com/api/rx_confirmRxApp",
            {
                rxId: rxId,
                diagResult: diagnosisName,
                noticeInfo: "",
                rxRemarks: "",
                tempSaveStamp: Date.now()
            },
            {
                "Content-Type": "application/json",

            }
        );
    },

    // 提交处方（带超7天药量处理）
    submitRx: function (rxId, diagnosisName, isOver7Days = false) {
        const payload = {
            rxId: rxId,
            diagnosisName: diagnosisName,
            diagResult: diagnosisName,
            noticeInfo: "",
            comprehensiveRxId: "0",
            rxRemarks: isOver7Days ? "患者因病情需要开具超7天药量；无过敏史；" : ""
        };

        return this.makeRequest(
            "提交处方",
            "https://api.m.jd.com/api/rx_submitRxApp",
            payload,
            {
                "Content-Type": "application/json",

            }
        );
    },

    // 检查是否需要超7天药量的备注
    checkOver7Days: function (supplementResponse) {
        try {
            const data = JSON.parse(supplementResponse.body);
            if (data.data && data.data.rxItemDtoList) {
                return data.data.rxItemDtoList.some(item =>
                    item.days && parseInt(item.days) > 7
                );
            }
        } catch (e) {
            console.log("[-] 解析药品天数失败: " + e.message);
        }
        return false;
    },

    // 自动开方流程
    autoPrescribe: async function (diagId, sid, diagnosisName) {
        try {
            console.log(`\n[⚡] 开始处理诊断单: ${diagId}`);
            this.lastActiveTime = Date.now();

            // 1. 创建处方草稿
            const draftResponse = await this.createRxDraft(diagId, sid);
            if (!draftResponse || draftResponse.code !== 200) {
                throw new Error("创建处方草稿失败");
            }

            const draftData = JSON.parse(draftResponse.body);
            if (!draftData.success || !draftData.data) {
                throw new Error(draftData.msg || "处方草稿数据无效");
            }

            const rxId = draftData.data;
            console.log(`[✔] 处方草稿创建成功，rxId: ${rxId}`);

            // 2. 获取处方详情
            const detailResponse = await this.getRxDetail(rxId);
            if (!detailResponse || detailResponse.code !== 200) {
                throw new Error("获取处方详情失败");
            }

            // 3. 获取处方补充信息并检查药品天数
            const supplementResponse = await this.getRxSupplementInfo(rxId, diagnosisName);
            const isOver7Days = this.checkOver7Days(supplementResponse);
            if (isOver7Days) {
                console.log("[⚠️] 检测到超7天药量，将添加特殊备注");
            }

            // 4. 临时保存处方
            await this.tempSaveRx(rxId, diagnosisName);

            // 5. 确认处方
            const confirmResponse = await this.confirmRx(rxId, diagnosisName);
            if (!confirmResponse || confirmResponse.code !== 200) {
                throw new Error("确认处方失败");
            }

            // 6. 提交处方（首次尝试）
            const submitResponse = await this.submitRx(rxId, diagnosisName, isOver7Days);
            if (!submitResponse || submitResponse.code !== 200) {
                throw new Error("提交处方失败");
            }

            const submitData = JSON.parse(submitResponse.body);
            if (!submitData.success) {
                // 特殊处理超7天药量的情况
                if (submitData.msg && submitData.msg.includes("超7天药量")) {
                    console.log("[🔄] 检测到超7天药量提示，尝试重新提交...");
                    const retryResponse = await this.submitRx(rxId, diagnosisName, true);
                    const retryData = JSON.parse(retryResponse.body);
                    if (!retryData.success) {
                        throw new Error(retryData.msg || "处方提交失败");
                    }
                    console.log(`[✔] 处方重新提交成功（已添加备注）`);
                } else {
                    throw new Error(submitData.msg || "处方提交失败");
                }
            }

            console.log(`[🎉] 处方提交成功，诊断单ID: ${diagId}, rxId: ${rxId}`);
            return true;
        } catch (error) {
            console.error(`[💥] 开方失败: ${error.message}`);
            return false;
        }
    },

    // 检查是否需要处理的诊断单
    shouldProcessDiag: function (item) {
        const sessionContent = item.sessionContentDto;
        if (!sessionContent) return false;


        const validKeywords = [
            "无须补充",
            "立即开方",
            "已确认没有补充信息",
            "请及时为患者复诊续方",
            "已完成患者信息确认环节",
            "您已确诊过此疾病并使用过",
            "线下已确诊",
            "没有发生过药品不良反应",
            "且没有相关禁忌",
            "没有药物过敏史",
            "线下已确诊",
            "好的",
        ];

        return validKeywords.some(kw => sessionContent.lastContent.includes(kw));
    },

    // 检查是否应该停止
    shouldStop: function () {
        // 超过1分钟没有活动且网络断开
        return !STATE.isConnected && (Date.now() - this.lastActiveTime > 60000);
    },

    // 主监控循环
    startPrescriptionMonitor: async function () {
        if (this.isMonitoring) {
            console.log("[⏸] 监控已在运行中");
            return;
        }

        console.log("[👀] 启动处方监控 (5-15秒间隔)");
        this.isMonitoring = true;

        try {
            while (this.isMonitoring) { // 改为状态标志控制
                if (!STATE.isConnected) {
                    console.log("[📴] 网络未连接，暂停处理");
                    await new Promise(r => setTimeout(r, 5000));
                    continue;
                }

                if (this.shouldStop()) {
                    console.log("[⏹] 检测到停止条件");
                    this.stopMonitoring();
                    break;
                }

                try {
                    console.log("\n[🔍] 检查待开方列表...");
                    const response = await this.getPendingPrescriptions();

                    if (response && response.code === 200) {
                        const data = JSON.parse(response.body);

                        if (data.success && data.data?.doctorDiagDtoList) {
                            // 处理诊断单
                            await this.processDiags(data.data.doctorDiagDtoList);
                        }
                    }
                } catch (error) {
                    console.error(`[⚠️] 监控周期出错: ${error.message}`);
                }


                // 使用可中断的延迟
                await this.interruptibleDelay(this.getFixedDelay());
            }
        } finally {
            this.isMonitoring = false;
        }
    },


    interruptibleDelay: function (ms) {
        return new Promise(resolve => {
            this.stopTimer = setTimeout(resolve, ms);
        });
    },
    // 处理诊断单（带延迟）
    processDiags: async function (diags) {
        for (const item of diags) {
            if (this.shouldProcessDiag(item)) {

                console.log(`\n[✨] 发现待开方诊断单: 
ID: ${item.diagId}
患者: ${item.patientName}
诊断: ${item.diseaseDesc.split(";")[0] || "未指定诊断"}`);
                this.autoPrescribe(item.diagId, item.sid, item.diseaseDesc.split(";")[0])
                    .then(success => {
                        if (success) Network.sendMessage(`PRESCRIBE_SUCCESS:${item.diagId}`);
                    });
            }
        }
    },

    // 获取固定延迟（5-15秒）
    getFixedDelay: function () {
        return Math.floor(Math.random() * 10000) + 5000; // 5-15秒
    },

    // 停止监控
    stopMonitoring: function () {
        if (!this.isMonitoring) {
            console.log("[⏹] 监控未运行");
            return;
        }

        console.log("[🛑] 正在停止处方监控...");

        // 1. 清除定时器
        if (this.stopTimer) {
            clearTimeout(this.stopTimer);
            this.stopTimer = null;
        }

        // 2. 停止循环
        this.isMonitoring = false;

        // 3. 重置状态
        this.lastActiveTime = 0;

        console.log("[✅] 处方监控已完全停止");
    },

};



const Network = {
    host: '117.72.208.155',
    port: 5555,
    reconnectInterval: 3000,
    isRunning: true,
    currentChannel: null,

    startHeartbeat: function () {
        Java.perform(() => {
            const Thread = Java.use('java.lang.Thread');
            const Runnable = Java.use('java.lang.Runnable');

            const HeartbeatRunnable = Java.registerClass({
                name: 'com.example.HeartbeatRunnable',
                implements: [Runnable],
                methods: {
                    run: function () {
                        while (Network.isRunning) {
                            try {
                                if (Network.currentChannel && Network.currentChannel.isConnected()) {
                                    Network.sendMessage("HEARTBEAT");
                                }
                                Thread.sleep(5000);
                            } catch (e) {
                                console.log("[-] 心跳失败: " + e);
                            }
                        }
                    }
                }
            });

            Thread.$new(HeartbeatRunnable.$new()).start();
        });
    },

    sendMessage: function (message) {
        // 确保消息安全
        if (!message) {
            console.log("[-] 尝试发送空消息，已阻止");
            return false;
        }

        const safeMessage = message.toString().trim();

        if (!this.currentChannel || !this.currentChannel.isConnected()) {
            console.log("[-] 无活动的连接");
            return false;
        }

        try {
            const ByteBuffer = Java.use('java.nio.ByteBuffer');
            const messageToSend = safeMessage + "\n";

            const javaString = Java.retain(Java.use('java.lang.String').$new(messageToSend));
            const sendBuffer = Java.retain(ByteBuffer.wrap(javaString.getBytes()));

            while (sendBuffer.hasRemaining()) {
                this.currentChannel.write(sendBuffer);
            }

            console.log("[+] 消息已发送: " + safeMessage);
            return true;
        } catch (e) {
            console.log("[-] 发送失败: " + e);
            return false;
        } finally {
            // 安全释放资源
            try {
                if (javaString) javaString.$dispose();
                if (sendBuffer) sendBuffer.$dispose();
            } catch (e) { }
        }
    },

    startNetwork: function () {
        Java.perform(() => {
            const SocketChannel = Java.use('java.nio.channels.SocketChannel');
            const InetSocketAddress = Java.use('java.net.InetSocketAddress');
            const ByteBuffer = Java.use('java.nio.ByteBuffer');
            const Thread = Java.use('java.lang.Thread');
            const Charset = Java.use('java.nio.charset.Charset');
            const Runnable = Java.use('java.lang.Runnable');

            const NetworkRunnable = Java.registerClass({
                name: 'com.example.NetworkRunnable',
                implements: [Runnable],
                methods: {
                    run: function () {
                        while (Network.isRunning) {
                            let channel = null;
                            try {
                                console.log("[*] 连接中 " + Network.host + ":" + Network.port + "...");

                                // 使用正确的SocketChannel.open()方法
                                channel = SocketChannel.open();

                                // 创建socket地址
                                const socketAddress = InetSocketAddress.$new(Network.host, Network.port);

                                // 连接服务器
                                if (channel.connect(socketAddress)) {
                                    console.log("[+] 连接成功");
                                    Network.currentChannel = channel;

                                    // 发送安全的电话信息
                                    Network.sendMessage(STATE.phone);

                                    const buffer = ByteBuffer.allocate(1024);
                                    const utf8 = Charset.forName("UTF-8");

                                    while (Network.isRunning && channel.isConnected()) {
                                        const bytesRead = channel.read(buffer);
                                        if (bytesRead > 0) {
                                            buffer.flip();
                                            const received = utf8.decode(buffer).toString();

                                            console.log("[*] 收到: " + received.trim());

                                            // 处理服务器消息
                                            if (received.includes("USER_DATA")) {
                                                try {
                                                    const jsonStart = received.indexOf('{');
                                                    const jsonEnd = received.lastIndexOf('}') + 1;
                                                    const jsonStr = received.substring(jsonStart, jsonEnd);
                                                    const dataObj = JSON.parse(jsonStr);

                                                    STATE.account_name = dataObj.account_name
                                                    if (dataObj.status == "1") {
                                                        STATE.isConnected = true;
                                                    } else {
                                                        STATE.isConnected = false;
                                                    }

                                                    if (STATE.isConnected) {

                                                        OrderRefresh.startAutoRefresh()
                                                        PrescriptionManager.startPrescriptionMonitor();
                                                    } else {
                                                        OrderRefresh.stopAutoRefresh();
                                                        const MyRunnable = Java.registerClass({
                                                            name: 'com.example.NetworkRunnable',
                                                            implements: [Java.use('java.lang.Runnable')],
                                                            methods: {
                                                                run: function () {
                                                                    Java.use('java.lang.Thread').sleep(60000);
                                                                    if (!STATE.isConnected) {
                                                                        console.log("[⚠️] 网络仍未恢复，正在停止处方监控...");
                                                                        try {
                                                                            PrescriptionManager.stopMonitoring();
                                                                            console.log("[✅] 处方监控已安全停止");
                                                                        } catch (e) {
                                                                            console.error("[❌] 停止处方监控失败:", e.message);
                                                                        }
                                                                    } else {
                                                                        console.log("[♻️] 网络已恢复，保持处方监控运行");
                                                                    }
                                                                }
                                                            }
                                                        });


                                                        Java.use('java.lang.Thread').$new(MyRunnable.$new()).start();

                                                    }



                                                    STATE.delay = dataObj.delay
                                                    STATE.random_delay = dataObj.random_delay

                                                    console.log("[+] 服务器配置更新");
                                                } catch (e) {
                                                    console.error("[-] 解析失败:", e);
                                                }
                                            }

                                            if (received.trim() === "PING") {
                                                Network.sendMessage("PONG");
                                            }

                                            buffer.clear();
                                        } else if (bytesRead === -1) {
                                            console.log("[-] 服务器断开连接");
                                            STATE.isConnected = false;
                                            break;
                                        }
                                        Thread.sleep(100);
                                    }
                                }
                            } catch (e) {
                                console.log("[-] 连接失败: " + e);
                            } finally {
                                if (channel) {
                                    try {
                                        channel.close();
                                    } catch (e) {
                                        console.log("[-] 关闭连接错误: " + e);
                                    }
                                }
                                Network.currentChannel = null;
                            }

                            console.log("[*] " + (Network.reconnectInterval / 1000) + "秒后重试...");
                            Thread.sleep(Network.reconnectInterval);
                        }
                    }
                }
            });

            // 创建并启动线程
            const thread = Thread.$new(NetworkRunnable.$new());
            thread.start();

            // 启动心跳
            this.startHeartbeat();
        });
    }
};
const OkHttpManager = {
    targetClient: null,
    autoCaptureSet: false,
    TARGET_CLIENT_CONFIG: {
        connectTimeout: 5000,
        readTimeout: 10000,
        writeTimeout: 10000,
        callTimeout: 0,
        interceptorsCount: 7,
        networkInterceptorsCount: 1,
        dnsClass: "com.jd.dh.common.utils.httpdns.JdDns",
        dispatcherMaxRequests: 64,
        dispatcherMaxPerHost: 5
    },

    init: function () {
        Java.perform(() => {
            this.findTargetClient();
            this.setupAutoCapture();
        });
    },

    findTargetClient: function () {
        if (this.targetClient) return true;

        let found = false;
        Java.choose('okhttp3.OkHttpClient', {
            onMatch: (instance) => {
                try {
                    if (this.isTargetInstance(instance)) {
                        this.targetClient = instance;
                        Utils.log("找到目标实例并缓存", 'success');
                        found = true;
                        return "stop";
                    }
                } catch (e) {
                    Utils.log(`实例检查出错: ${e.message}`, 'error');
                }
                return "continue";
            },
            onComplete: () => {
                if (!found) {
                    Utils.log("未找到目标实例", 'warn');
                }
            }
        });
        return found;
    },

    isTargetInstance: function (instance) {
        try {
            if (!instance) return false;

            // Check timeouts
            if (instance.connectTimeoutMillis() !== this.TARGET_CLIENT_CONFIG.connectTimeout) return false;
            if (instance.readTimeoutMillis() !== this.TARGET_CLIENT_CONFIG.readTimeout) return false;
            if (instance.writeTimeoutMillis() !== this.TARGET_CLIENT_CONFIG.writeTimeout) return false;
            if (instance.callTimeoutMillis() !== this.TARGET_CLIENT_CONFIG.callTimeout) return false;

            // Check interceptors
            const interceptors = instance.interceptors();
            const networkInterceptors = instance.networkInterceptors();
            if (!interceptors || !networkInterceptors) return false;
            if (interceptors.size() !== this.TARGET_CLIENT_CONFIG.interceptorsCount) return false;
            if (networkInterceptors.size() !== this.TARGET_CLIENT_CONFIG.networkInterceptorsCount) return false;

            // Check DNS
            const dns = instance.dns();
            if (!dns || dns.$className !== this.TARGET_CLIENT_CONFIG.dnsClass) return false;

            // Check dispatcher
            const dispatcher = instance.dispatcher();
            if (!dispatcher) return false;
            if (dispatcher.getMaxRequests() !== this.TARGET_CLIENT_CONFIG.dispatcherMaxRequests) return false;
            if (dispatcher.getMaxRequestsPerHost() !== this.TARGET_CLIENT_CONFIG.dispatcherMaxPerHost) return false;

            return true;
        } catch (e) {
            Utils.log(`配置检查出错: ${e.message}`, 'error');
            return false;
        }
    },

    setupAutoCapture: function () {
        if (this.autoCaptureSet) return;

        try {
            const Builder = Java.use('okhttp3.OkHttpClient$Builder');
            const originalBuild = Builder.build;

            Builder.build.implementation = function () {
                const instance = originalBuild.call(this);
                try {
                    if (OkHttpManager.isTargetInstance(instance)) {
                        Utils.log("捕获到目标实例", 'success');
                        OkHttpManager.targetClient = instance;
                    }
                } catch (e) {
                    Utils.log(`捕获钩子出错: ${e.message}`, 'error');
                }
                return instance;
            };

            this.autoCaptureSet = true;
            Utils.log("自动捕获钩子已设置", 'success');
        } catch (e) {
            Utils.log(`设置自动捕获失败: ${e.message}`, 'error');
        }
    },

    // ==================== 请求相关方法 ====================
    sendCustomRequest: function (requestUrl, requestBody, headers, forceRefresh) {
        return new Promise((resolve, reject) => {
            Java.perform(() => {
                let callbackImpl = null;
                try {
                    if (forceRefresh || !this.targetClient) {
                        Utils.log("尝试重新查找目标实例...", 'info');
                        const found = this.findTargetClient();
                        if (!found) {
                            Utils.log("未找到目标实例", 'warn');
                            reject(new Error("未找到目标实例"));
                            return;
                        }
                    }

                    const client = this.targetClient;
                    // Utils.log(`准备发送请求到: ${requestUrl}`, 'info');

                    const RequestBuilder = Java.use('okhttp3.Request$Builder');
                    const RequestBody = Java.use('okhttp3.RequestBody');
                    const MediaType = Java.use('okhttp3.MediaType');

                    // 保留Java对象引用
                    const builder = Java.retain(RequestBuilder.$new());
                    builder.url(requestUrl);

                    let bodyObj = null;
                    if (requestBody) {
                        const mediaType = Java.retain(MediaType.parse("application/json"));

                        // 处理特殊格式的请求体
                        if (typeof requestBody === 'string' && requestBody.match(/^\d+/)) {
                            // 直接使用原始字符串（如包含用户ID前缀的情况）
                            bodyObj = Java.retain(RequestBody.create(mediaType, requestBody));
                        } else {
                            // 普通JSON格式
                            bodyObj = Java.retain(RequestBody.create(
                                mediaType,
                                typeof requestBody === 'string' ? requestBody : JSON.stringify(requestBody)
                            ));
                        }
                        builder.post(bodyObj);
                    }

                    // 添加请求头
                    if (headers) {
                        for (const key in headers) {
                            if (headers.hasOwnProperty(key)) {
                                builder.addHeader(key, headers[key]);
                            }
                        }
                    } else if (bodyObj) {
                        builder.addHeader("Content-Type", "application/json");
                    }

                    const request = builder.build();
                    const call = client.newCall(request);
                    const callback = Java.use("okhttp3.Callback");

                    callbackImpl = Java.registerClass({
                        name: "com.example.OkHttpCallback" + Math.random().toString(36).substring(2),
                        implements: [callback],
                        methods: {
                            onFailure: function (call, e) {
                                try {
                                    Utils.log(`请求失败: ${e.getMessage()}`, 'error');
                                    reject(new Error(e.getMessage()));
                                } finally {
                                    if (callbackImpl) {
                                        callbackImpl.$dispose();
                                    }
                                }
                            },
                            onResponse: function (call, response) {
                                try {
                                    const retainedResponse = Java.retain(response);
                                    const responseCode = retainedResponse.code();
                                    // Utils.log(`响应码: ${responseCode}`, 'info');

                                    const responseBody = retainedResponse.body();
                                    let responseString = null;
                                    if (responseBody) {
                                        const retainedBody = Java.retain(responseBody);
                                        responseString = retainedBody.string();
                                        // Utils.log(`响应体长度: ${responseString.length}`, 'info');
                                        retainedBody.close();
                                    } else {
                                        Utils.log("响应体为空", 'warn');
                                    }

                                    retainedResponse.close();
                                    // Utils.log("请求完成!", 'success');

                                    resolve({
                                        code: responseCode,
                                        body: responseString,
                                        headers: retainedResponse.headers() ? retainedResponse.headers().toMultimap() : {}
                                    });
                                } catch (e) {
                                    Utils.log(`响应处理失败: ${e.message}`, 'error');
                                    reject(e);
                                } finally {
                                    if (callbackImpl) {
                                        callbackImpl.$dispose();
                                    }
                                }
                            }
                        }
                    });

                    call.enqueue(callbackImpl.$new());

                } catch (e) {
                    Utils.log(`请求失败: ${e.message}`, 'error');
                    reject(e);
                    if (callbackImpl) {
                        callbackImpl.$dispose();
                    }
                }
            });
        });
    },

    // ==================== 特定API请求方法 ====================
    sendDiagnosisRequest: function (diagId, forceRefresh) {
        return this.sendCustomRequest(
            "https://api.m.jd.com/api/JDDAPP_C_doctorReceive",
            { "diagId": diagId, "receiveEntranceSource": 2 },
            { "Content-Type": "application/json" },
            forceRefresh
        );
    },

    refreshOrderList: function (forceRefresh) {
        return this.sendCustomRequest(
            "https://api.m.jd.com/api/JDDAPP_grab_getEnableDiagOrderList",
            '{"venderId":"8888","tenantType":"JD8888","pageSize":20,"grabTab":"all"}',
            {
                "Content-Type": "application/json",

            },
            forceRefresh
        );
    },

    // ==================== 工具方法 ====================
    printClientInfo: function () {
        Java.perform(() => {
            if (!this.targetClient) {
                Utils.log("当前没有目标实例", 'warn');
                return;
            }

            try {
                const client = this.targetClient;
                Utils.log("当前目标实例信息:", 'info');
                Utils.log(`  - 连接超时: ${client.connectTimeoutMillis()}ms`, 'info');
                Utils.log(`  - 读取超时: ${client.readTimeoutMillis()}ms`, 'info');
                Utils.log(`  - 写入超时: ${client.writeTimeoutMillis()}ms`, 'info');
                Utils.log(`  - 调用超时: ${client.callTimeoutMillis()}ms`, 'info');

                const interceptors = client.interceptors();
                const networkInterceptors = client.networkInterceptors();
                Utils.log(`  - 应用拦截器数量: ${interceptors ? interceptors.size() : 'N/A'}`, 'info');
                Utils.log(`  - 网络拦截器数量: ${networkInterceptors ? networkInterceptors.size() : 'N/A'}`, 'info');

                const dns = client.dns();
                Utils.log(`  - DNS服务: ${dns ? dns.$className : 'N/A'}`, 'info');

                const dispatcher = client.dispatcher();
                if (dispatcher) {
                    Utils.log(`  - 最大请求数: ${dispatcher.getMaxRequests()}`, 'info');
                    Utils.log(`  - 每主机最大请求数: ${dispatcher.getMaxRequestsPerHost()}`, 'info');
                }
            } catch (e) {
                Utils.log(`打印客户端信息出错: ${e.message}`, 'error');
            }
        });
    }
};
// 更健壮的文件读取实现
function extractDoctorInfo() {
    try {
        const ActivityThread = Java.use('android.app.ActivityThread');
        const context = ActivityThread.currentApplication().getApplicationContext();
        const filesDir = context.getFilesDir();
        const sharedPrefsDir = filesDir.getParent() + "/shared_prefs/";
        const fileName = "cacheDoctorInfo.xml";
        const fullPath = sharedPrefsDir + fileName;

        console.log("[*] 尝试读取医生信息: " + fullPath);

        const File = Java.use('java.io.File');
        const file = File.$new(fullPath);

        if (!file.exists()) {
            console.log("[-] 医生信息文件不存在");
            return null;
        }

        // 使用更可靠的文件读取方式
        const FileInputStream = Java.use('java.io.FileInputStream');
        const fis = FileInputStream.$new(file);
        const ByteArrayOutputStream = Java.use('java.io.ByteArrayOutputStream');
        const bos = ByteArrayOutputStream.$new();

        const buffer = Java.array('byte', [1024]);
        let length = 0;

        while ((length = fis.read(buffer)) !== -1) {
            bos.write(buffer, 0, length);
        }

        fis.close();
        const bytes = bos.toByteArray();
        bos.close();

        // 使用UTF-8解码
        const content = Java.use('java.lang.String').$new(bytes, "UTF-8");
        console.log("[+] 成功读取医生信息文件");

        // 提取JSON部分
        const jsonStart = content.indexOf('{');
        const jsonEnd = content.lastIndexOf('}') + 1;
        if (jsonStart < 0 || jsonEnd <= jsonStart) {
            console.log("[-] 未找到有效的JSON数据");
            return null;
        }

        let jsonStr = content.substring(jsonStart, jsonEnd);
        console.log("[*] 提取的原始JSON: " + jsonStr);

        // 修复JSON字符串 - 替换HTML实体和非法转义
        jsonStr = jsonStr
            .replace(/&quot;/g, '"')
            .replace(/&amp;/g, '&')
            .replace(/&lt;/g, '<')
            .replace(/&gt;/g, '>')
            .replace(/\\u([\dA-Fa-f]{4})/g, (match, grp) =>
                String.fromCharCode(parseInt(grp, 16)))
            .replace(/\\\//g, '/')
            .replace(/\\"/g, '"');

        console.log("[*] 修复后的JSON: " + jsonStr);

        return JSON.parse(jsonStr);
    } catch (e) {
        console.log("[-] 医生信息提取错误: " + e);
        return null;
    }
}

// 初始化函数
function initialize() {
    Java.perform(() => {
        try {
            console.log("[*] 开始初始化...");

            // 1. 获取医生信息
            const doctorInfo = extractDoctorInfo();
            if (doctorInfo) {
                if (doctorInfo.phone) {
                    STATE.phone = doctorInfo.phone;
                    console.log("[+] 医生手机号: " + STATE.phone);
                }
                if (doctorInfo.name) {
                    STATE.account_name = doctorInfo.name;
                    console.log("[+] 医生姓名: " + STATE.account_name);
                }
            }

            // 2. 启动网络连接
            console.log("[*] 启动网络连接");
            Network.startNetwork();


            console.log("[+] 初始化完成");
        } catch (e) {
            console.log("[-] 初始化失败: " + e);
        }
    });
}

// 启动脚本
setTimeout(initialize, 2000);