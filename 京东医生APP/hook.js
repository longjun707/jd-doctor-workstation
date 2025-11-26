/**
 * JD-HOOK Frida脚本 - 系统中控台 (v5 - Stateful)
 * 功能：协调TCP通信和业务逻辑，捕获网络实例，处理服务器指令
 * 适配 OrderRobber v3.4 (带状态上报)
 */

// 配置
const CONFIG = {
    server: {
        host: "154.44.25.188",
        port: 8989
    },
    connection: {
        reconnectInterval: 5000,
        maxReconnectAttempts: 10,
        connectionTimeout: 30000
    },
    heartbeat: {
        enabled: true,
        interval: 30000
    }
};

/**
 * API及JSON字段配置，用于注入Java层
 * 优点: 1. 保护Java代码不暴露敏感字符串 2. 更新API字段时只需修改JS，无需重编译Java
 */
const API_CONFIG = {
    // API详情
    apiBaseUrl: "https://api.m.jd.com/api",
    orderListPath: "/JDDAPP_grab_getEnableDiagOrderList",
    grabOrderPath: "/JDDAPP_diag_doctorReceive",
    // 新增：收入查询API
    queryIncomePath: "/JDD_APP_queryIncomeByMonth",
    queryWithdrawPath: "/JDD_APP_queryWithdrawAppDetailList",

    // 请求体参数的字段名 (Key)
    pKeyVenderId: "venderId",
    pKeyTenantType: "tenantType",
    pKeyPageSize: "pageSize",
    pKeyGrabTab: "grabTab",
    pKeyDiagId: "diagId",
    pKeyReceiveEntranceSource: "receiveEntranceSource",

    // 响应体解析的字段名 (Key)
    pKeyData: "data",
    pKeyDiagLabels: "diagLabels",
    pKeyLabelContent: "labelContent",

    // 请求体参数的固定值 (Value)
    valVenderId: "8888",
    valTenantType: "JD8888",
    valPageSize: 20,
    valGrabTab: "all",
    valReceiveEntranceSource: 2,
    // 新增：租户ID
    valTenantId: "JD8888"
};


/**
 * 消息协议处理模块
 */
const MessageProtocol = {
    /**
     * 获取当前版本号（从VersionChecker读取）
     */
    _getCurrentVersion: function() {
        try {
            const VersionChecker = Java.use("com.jd.doctor.VersionChecker");
            // 读取静态常量字段（需要使用 .value）
            const versionField = VersionChecker.class.getDeclaredField("CURRENT_VERSION");
            versionField.setAccessible(true);
            return String(versionField.get(null));
        } catch (error) {
            console.error("[MessageProtocol] 读取版本号失败:", error);
            return "unknown"; // 回退值
        }
    },
    createRegisterMessage: function (doctorInfo) {
        return JSON.stringify({
            type: "register",
            timestamp: Date.now(),
            messageId: this._generateUUID(),
            name: doctorInfo.name,
            phoneNumber: doctorInfo.phoneNumber,
            office: doctorInfo.office,
            version: this._getCurrentVersion() // 动态读取版本号
        });
    },
    createHeartbeatMessage: function (phoneNumber) {
        return JSON.stringify({
            type: "heartbeat",
            timestamp: Date.now(),
            messageId: this._generateUUID(),
            phoneNumber: phoneNumber
        });
    },
    // **修改：允许事件携带数据**
    createEventMessage: function (eventType, data) {
        return JSON.stringify({
            type: "event",
            timestamp: Date.now(),
            messageId: this._generateUUID(),
            eventType: eventType,
            data: data || {}
        });
    },
    parseMessage: function (rawMessage) {
        try {
            return JSON.parse(rawMessage);
        } catch (error) {
            return null;
        }
    },
    _generateUUID: function () {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
            const r = Math.random() * 16 | 0;
            const v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }
};

/**
 * 网络实例捕获类
 */
class NetworkCapture {
    constructor() {
        this.currentInstance = null;
    }
    captureOkHttpClient() {
        return new Promise((resolve, reject) => {
            console.log("[NetworkCapture] 开始捕获OkHttpClient实例...");
            const instances = [];
            Java.choose('okhttp3.OkHttpClient', {
                onMatch: (instance) => {
                    try {
                        const score = this._evaluateInstance(instance);
                        instances.push({ instance, score });
                    } catch (error) { /* ignore */ }
                },
                onComplete: () => {
                    if (instances.length === 0) return reject(new Error("未找到OkHttpClient实例"));
                    const bestInstance = instances.reduce((best, current) => (current.score > best.score ? current : best));
                    this.currentInstance = bestInstance;
                    console.log(`[NetworkCapture] 选择最优实例，评分: ${bestInstance.score}`);
                    resolve(bestInstance.instance);
                }
            });
            setTimeout(() => reject(new Error("捕获超时")), 10000);
        });
    }
    _evaluateInstance(instance) {
        let score = 0;
        try {
            const interceptors = instance.interceptors();
            if (interceptors) score += interceptors.size() * 10;
            if (instance.connectionPool()) score += 3;
        } catch (e) { /* ignore */ }
        return score;
    }
    getCurrentInstance() { return this.currentInstance; }
}

/**
 * Frida TCP通信桥梁类
 */
class FridaTcpBridge {
    constructor(config, onServerReadyCallback) {
        this.config = config || CONFIG;
        this.onServerReadyCallback = onServerReadyCallback;
        this.tcpClient = null;
        this.isConnected = false;
        this.isRegistered = false;
        this.doctorInfo = null;
        this.pendingConfigUpdates = [];
        this.networkInstanceReady = false;
        this.orderRobber = null;
        this.prescriptionFetcher = null; // 新增：处方抓取器实例
        this.fileUploader = null; // 新增：文件上传器实例
        this.heartbeatIntervalId = null; // 新增：心跳定时器ID
        this.wakeLock = null; // 新增：屏幕唤醒锁
        this.skipDiagIds = new Map(); // 新增：浏览器插件通知跳过的诊断ID (diagId -> expireTime)
        this.skipCleanupIntervalId = null; // 新增：清理过期跳过ID的定时器
        console.log("[FridaTcpBridge] 初始化完成");
    }

    connect() {
        console.log(`[FridaTcpBridge] 尝试连接服务器: ${this.config.server.host}:${this.config.server.port}`);
        try {
            const TCPClientClass = Java.use("com.jd.doctor.TCPClient");
            this.tcpClient = TCPClientClass.$new(this.config.server.host, this.config.server.port);
            
            const MessageListener = Java.use("com.jd.doctor.TCPClient$MessageListener");
            const ListenerImpl = Java.registerClass({
                name: "com.jd.doctor.MessageListenerImpl",
                implements: [MessageListener],
                methods: {
                    onMessageReceived: (message) => this._handleMessage(String(message)),
                    onConnectionStatusChanged: (connected) => {
                        if (connected) this._handleConnectionEstablished();
                        else this._handleConnectionLost();
                    }
                }
            });
            this.tcpClient.setMessageListener(ListenerImpl.$new());
            this.tcpClient.connect();
        } catch (error) {
            console.error("[FridaTcpBridge] 连接失败:", error);
        }
    }

    _handleConnectionEstablished() {
        console.log("[FridaTcpBridge] TCP连接已建立");
        this.isConnected = true;
        this._sendRegisterMessage();
        this._startHeartbeat(); // 新增：启动心跳
    }

    _handleConnectionLost() {
        console.log("[FridaTcpBridge] TCP连接断开");
        this.isConnected = false;
        this.isRegistered = false;
        this._stopHeartbeat(); // 新增：停止心跳

        // **新增：连接断开时，立即停止抢单引擎**
        console.log("[FridaTcpBridge] 连接已断开，正在停止抢单任务...");
        this._stopOrderRobbing();

        // 注意：实际的重连逻辑现在由Java层的TCPClient完全处理，JS层无需再关心
    }

    // --- 新增：屏幕唤醒锁管理 ---
    _acquireWakeLock() {
        if (this.wakeLock && this.wakeLock.isHeld()) {
            return;
        }
        try {
            console.log("[FridaTcpBridge] 正在获取屏幕唤醒锁...");
            const context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
            const PowerManager = Java.use('android.os.PowerManager');
            const powerManagerService = context.getSystemService(Java.use('android.content.Context').POWER_SERVICE.value);
            const powerManager = Java.cast(powerManagerService, PowerManager);
            // SCREEN_BRIGHT_WAKE_LOCK 已被弃用，建议使用 FLAG_KEEP_SCREEN_ON
            // 但为了兼容性和直接控制，这里我们仍然使用 WakeLock，并选择一个合适的级别
            // PowerManager.SCREEN_DIM_WAKE_LOCK 保持CPU运转和屏幕微亮，更省电
            this.wakeLock = powerManager.newWakeLock(PowerManager.SCREEN_DIM_WAKE_LOCK.value, "JDHook:WakeLockTag");
            this.wakeLock.acquire();
            console.log("[FridaTcpBridge] 屏幕唤醒锁已获取。");
        } catch (error) {
            console.error("[FridaTcpBridge] 获取屏幕唤醒锁失败:", error);
        }
    }

    _releaseWakeLock() {
        try {
            if (this.wakeLock && this.wakeLock.isHeld()) {
                this.wakeLock.release();
                this.wakeLock = null;
                console.log("[FridaTcpBridge] 屏幕唤醒锁已释放。");
            }
        } catch (error) {
            console.error("[FridaTcpBridge] 释放屏幕唤醒锁失败:", error);
        }
    }
    // -------------------------

    // 新增：启动心跳定时器
    _startHeartbeat() {
        if (this.heartbeatIntervalId) {
            clearInterval(this.heartbeatIntervalId);
        }
        if (!this.config.heartbeat.enabled) return;

        this.heartbeatIntervalId = setInterval(() => {
            this._sendHeartbeat();
        }, this.config.heartbeat.interval);
        console.log(`[FridaTcpBridge] 心跳服务已启动，每 ${this.config.heartbeat.interval / 1000} 秒发送一次`);
    }

    // 新增：停止心跳定时器
    _stopHeartbeat() {
        if (this.heartbeatIntervalId) {
            clearInterval(this.heartbeatIntervalId);
            this.heartbeatIntervalId = null;
            console.log("[FridaTcpBridge] 心跳服务已停止");
        }
    }

    _sendMessage(message) {
        if (!this.isConnected) return;
        Java.perform(() => {
            try {
                if (this.tcpClient) this.tcpClient.sendMessage(message);
            } catch (error) {
                console.error("[FridaTcpBridge] 发送消息异常:", error);
            }
        });
    }

    _sendRegisterMessage() {
        if (!this.doctorInfo) return;
        const registerMessage = MessageProtocol.createRegisterMessage(this.doctorInfo);
        this._sendMessage(registerMessage);
    }

    // 新增：发送心跳消息
    _sendHeartbeat() {
        if (!this.doctorInfo) return;
        const heartbeatMessage = MessageProtocol.createHeartbeatMessage(this.doctorInfo.phoneNumber);
        this._sendMessage(heartbeatMessage);
    }

    // **修改：允许事件携带数据**
    sendEvent(eventType, data) {
        console.log(`[FridaTcpBridge] 发送事件: ${eventType}`, data || '');
        const message = MessageProtocol.createEventMessage(eventType, data);
        this._sendMessage(message);
    }

    _handleMessage(message) {
        const parsedMessage = MessageProtocol.parseMessage(message);
        if (!parsedMessage) return;

        // 新增：优先处理action指令
        if (parsedMessage.action) {
            switch (parsedMessage.action) {
                case 'query_monthly_report':
                    this._handleGenerateMonthlyReport();
                    return;
                case 'skip_patient':
                    this._handleSkipPatient(parsedMessage);
                    return;
            }
        }

        // 原有的type指令处理
        switch (parsedMessage.type) {
            case "register_ack":
                this._handleRegisterAck(parsedMessage);
                break;
            case "config_update":
                this._handleConfigUpdate(parsedMessage);
                break;
        }
    }

    _handleRegisterAck(message) {
        if (message.success) {
            this.isRegistered = true;
            console.log("[FridaTcpBridge] 注册成功");
            if (message.config) {
                this._handleConfigUpdate(message.config);
            }
            if (this.onServerReadyCallback) {
                this.onServerReadyCallback();
            }
        }
    }

    _handleConfigUpdate(message) {
        if (!message) return;
        const status = (message.hasOwnProperty('switchStatus') || message.hasOwnProperty('switch_status'))
            ? parseInt(message.switchStatus !== undefined ? message.switchStatus : message.switch_status)
            : message.status;
        const delay = message.delay !== undefined ? message.delay : message.delay_ms;
        const randomDelay = message.random_delay !== undefined ? message.random_delay : message.randomDelay;
        const refreshTime = message.refresh_time !== undefined ? message.refresh_time : message.refreshTime;
        const waitTime = message.wait_time !== undefined ? message.wait_time : message.waitTime;

        const config = {
            status: status,
            delay: delay !== undefined ? parseInt(delay) : undefined,
            randomDelay: randomDelay !== undefined ? parseInt(randomDelay) : undefined,
            refreshTime: refreshTime !== undefined ? parseInt(refreshTime) : undefined,
            waitTime: waitTime !== undefined ? parseInt(waitTime) : undefined
        };

        const shouldStart = status === 1 || status === '1' || status === 'normal' || status === '正常';

        if (!this.networkInstanceReady && shouldStart) {
            this.pendingConfigUpdates.push(config);
            return;
        }
        if (shouldStart) {
            this._startOrderRobbing(config);
        } else {
            this._stopOrderRobbing();
        }
    }

    // --- 新增：浏览器插件通知跳过患者 ---
    
    /**
     * 处理来自服务器的"跳过患者"指令
     * 浏览器插件已回复"在的，请稍等"，APP不要重复开方
     */
    _handleSkipPatient(message) {
        const diagId = message.diagId;
        const patientName = message.patientName || '';
        
        if (!diagId) {
            console.log("[SkipPatient] 收到跳过指令但diagId为空，忽略");
            return;
        }
        
        // JS层维护一份（5分钟过期）
        const expireTime = Date.now() + 5 * 60 * 1000;
        this.skipDiagIds.set(diagId, expireTime);
        
        // 同时通知Java层的PrescriptionFetcher
        Java.perform(() => {
            try {
                const PrescriptionFetcherClass = Java.use("com.jd.doctor.PrescriptionFetcher");
                const JString = Java.use('java.lang.String');
                const diagIdStr = JString.$new(String(diagId));
                PrescriptionFetcherClass.addSkipDiagId(diagIdStr);
                console.log(`[SkipPatient] ✅ Java层已添加跳过: diagId=${diagId}`);
            } catch (e) {
                console.error(`[SkipPatient] Java层添加跳过失败:`, e);
            }
        });
        
        console.log(`[SkipPatient] ✅ 添加跳过: diagId=${diagId}, 患者=${patientName}, 过期时间=${new Date(expireTime).toLocaleTimeString()}`);
        console.log(`[SkipPatient] 当前跳过列表: ${this.skipDiagIds.size} 个`);
        
        // 启动清理定时器（如果还没有启动）
        this._startSkipCleanupTimer();
        
        // 上报事件给服务器
        this.sendEvent("skip_patient_ack", { diagId: diagId, patientName: patientName });
    }
    
    /**
     * 检查diagId是否在跳过列表中
     */
    shouldSkipDiag(diagId) {
        if (!this.skipDiagIds.has(diagId)) {
            return false;
        }
        
        const expireTime = this.skipDiagIds.get(diagId);
        if (Date.now() > expireTime) {
            // 已过期，删除并返回false
            this.skipDiagIds.delete(diagId);
            console.log(`[SkipPatient] diagId=${diagId} 已过期，移除跳过`);
            return false;
        }
        
        return true;
    }
    
    /**
     * 启动清理过期跳过ID的定时器
     */
    _startSkipCleanupTimer() {
        if (this.skipCleanupIntervalId) {
            return; // 已经启动
        }
        
        // 每60秒清理一次过期的ID
        this.skipCleanupIntervalId = setInterval(() => {
            const now = Date.now();
            let cleanedCount = 0;
            
            for (const [diagId, expireTime] of this.skipDiagIds.entries()) {
                if (now > expireTime) {
                    this.skipDiagIds.delete(diagId);
                    cleanedCount++;
                }
            }
            
            if (cleanedCount > 0) {
                console.log(`[SkipPatient] 清理了 ${cleanedCount} 个过期的跳过ID，剩余 ${this.skipDiagIds.size} 个`);
            }
            
            // 如果列表为空，停止定时器
            if (this.skipDiagIds.size === 0) {
                clearInterval(this.skipCleanupIntervalId);
                this.skipCleanupIntervalId = null;
                console.log("[SkipPatient] 跳过列表已清空，停止清理定时器");
            }
        }, 60000); // 60秒
        
        console.log("[SkipPatient] 启动清理定时器");
    }
    
    // ----------------------------------------

    // --- 新增：月度报告生成 ---

    /**
     * 执行一个API查询的通用辅助函数
     * @param {string} path API的路径
     * @param {object} params 请求体的JSON对象
     * @returns {object} 解析后的JSON响应数据
     */
    _executeApiQuery(path, params) {
        console.log(`[API Query] 执行查询: ${path}, 参数: ${JSON.stringify(params)}`);
        try {
            const RequestBuilder = Java.use('okhttp3.Request$Builder');
            const RequestBody = Java.use('okhttp3.RequestBody');
            const MediaType = Java.use('okhttp3.MediaType');
            
            const jsonMediaType = MediaType.parse("application/json; charset=utf-8");
            const jsonBody = JSON.stringify(params);
            const body = RequestBody.create(jsonMediaType, jsonBody);

            const networkInstance = networkCapture.getCurrentInstance();
            if (!networkInstance || !networkInstance.instance) {
                throw new Error("网络实例不可用");
            }

            const request = RequestBuilder.$new()
                .url(API_CONFIG.apiBaseUrl + path)
                .post(body)
                .build();

            const response = networkInstance.instance.newCall(request).execute();

            if (response.isSuccessful()) {
                const responseBody = response.body().string();
                const result = JSON.parse(responseBody);
                // 统一判断成功条件
                if (result.success && (result.code === "0" || result.code === "0000")) {
                    console.log(`[API Query] 查询成功: ${path}`);
                    return result.data;
                } else {
                    throw new Error(`API返回错误: ${result.msg || '未知错误'}`);
                }
            } else {
                throw new Error(`HTTP请求失败: ${response.code()} ${response.message()}`);
            }
        } catch (error) {
            console.error(`[API Query] 查询时发生异常: ${path}`, error);
            // 将原始错误再次抛出，以便上层捕获
            throw error;
        }
    }

    /**
     * 处理来自服务器的“生成月度报告”指令
     */
    _handleGenerateMonthlyReport() {
        console.log("[FridaTcpBridge] 开始生成月度报告...");
        Java.perform(() => {
            try {
                const report = {
                    lastMonth: {},
                    currentMonth: {}
                };
                
                // 1. 计算日期
                const now = new Date();
                const currentYear = now.getFullYear();
                const currentMonth = now.getMonth(); // 0-11
                const currentMonthStr = `${currentYear}-${String(currentMonth + 1).padStart(2, '0')}`;
                
                // 注意: setMonth会直接修改原对象，所以先处理本月，再处理上月
                const lastMonthDate = new Date();
                lastMonthDate.setMonth(lastMonthDate.getMonth() - 1);
                const lastMonthYear = lastMonthDate.getFullYear();
                const lastMonth = lastMonthDate.getMonth(); // 0-11
                const lastMonthStr = `${lastMonthYear}-${String(lastMonth + 1).padStart(2, '0')}`;
                
                report.currentMonth.period = currentMonthStr;
                report.lastMonth.period = lastMonthStr;

                // 2. 依次采集所有数据
                console.log(`[Report] 正在采集 ${lastMonthStr} 的数据...`);
                report.lastMonth.income = this._executeApiQuery(API_CONFIG.queryIncomePath, { tenantId: API_CONFIG.valTenantId, month: lastMonthStr });
                report.lastMonth.withdrawals = this._executeApiQuery(API_CONFIG.queryWithdrawPath, { withdrawType: 1, month: lastMonthStr, pageSize: 20, pageNo: 1 });
                report.lastMonth.platformPayments = this._executeApiQuery(API_CONFIG.queryWithdrawPath, { withdrawType: 2, month: lastMonthStr, pageSize: 20, pageNo: 1 });
                
                console.log(`[Report] 正在采集 ${currentMonthStr} 的数据...`);
                report.currentMonth.income = this._executeApiQuery(API_CONFIG.queryIncomePath, { tenantId: API_CONFIG.valTenantId, month: currentMonthStr });
                report.currentMonth.withdrawals = this._executeApiQuery(API_CONFIG.queryWithdrawPath, { withdrawType: 1, month: currentMonthStr, pageSize: 20, pageNo: 1 });
                report.currentMonth.platformPayments = this._executeApiQuery(API_CONFIG.queryWithdrawPath, { withdrawType: 2, month: currentMonthStr, pageSize: 20, pageNo: 1 });
                
                // 3. 发送成功报告
                console.log("[Report] 月度报告生成成功, 正在发送回服务器...");
                // 新增：打印最终的报告对象
                // console.log("[Final Report] " + JSON.stringify(report, null, 2)); 
                this.sendEvent("monthly_report_result", { status: "success", data: report });

            } catch (error) {
                // 4. 发送失败报告
                console.error("[Report] 生成月度报告失败:", error);
                this.sendEvent("monthly_report_result", { status: "error", message: error.toString() });
            }
        });
    }

    // --- 结束：月度报告生成 ---

    /**
     * 初始化处方抓取器
     */
    _initPrescriptionFetcher() {
        console.log("[PrescriptionFetcher] 初始化处方抓取器...");
        try {
            if (!this.prescriptionFetcher) {
                const PrescriptionFetcherClass = Java.use("com.jd.doctor.PrescriptionFetcher");
                this.prescriptionFetcher = PrescriptionFetcherClass.$new();
                console.log("[PrescriptionFetcher] 处方抓取器创建成功");

                // 设置回调接口
                const FetcherCallback = Java.use("com.jd.doctor.PrescriptionFetcher$FetcherCallback");
                const CallbackImpl = Java.registerClass({
                    name: "com.jd.doctor.FetcherCallbackImpl",
                    implements: [FetcherCallback],
                    methods: {
                        // 处理原始响应
                        onRawResponse: (response, requestType) => {
                            const typeStr = String(requestType);
                            const responseStr = String(response);
                            console.log(`[PrescriptionFetcher] 收到${typeStr}响应: ${responseStr}`);
                        },
                        // 处理日志信息
                        onLogInfo: (message) => {
                            console.log(`[PrescriptionFetcher] ${String(message)}`);
                        },
                        // 处理错误信息
                        onLogError: (message) => {
                            console.error(`[PrescriptionFetcher] ERROR: ${String(message)}`);
                        },
                        onPrescriptionEvent: (diagId, success, message) => {
                            const eventType = success ? "prescription_success" : "prescription_failed";
                            console.log(`[PrescriptionFetcher] 事件: ${eventType} diagId=${String(diagId)} message=${String(message)}`);
                            this.sendEvent(eventType, {
                                diagId: String(diagId),
                                success: !!success,
                                message: String(message || "")
                            });
                        },
                        // 新增：处理进行中问诊数变化
                        onDoingDiagNumChanged: (currentNum, previousNum, doctorId) => {
                            const current = parseInt(currentNum);
                            const previous = parseInt(previousNum);
                            const docId = String(doctorId || "");
                            console.log(`[PrescriptionFetcher] 进行中问诊数变化: ${previous} → ${current} (医生ID: ${docId})`);
                            // 推送到服务器，携带医生ID
                            this.sendEvent("doing_diag_num_changed", {
                                currentNum: current,
                                previousNum: previous,
                                change: current - previous,
                                doctorId: docId
                            });
                        }
                    }
                });
                this.prescriptionFetcher.setFetcherCallback(CallbackImpl.$new());
            }

            const networkInstance = networkCapture.getCurrentInstance();
            if (!networkInstance || !networkInstance.instance) {
                console.error("[PrescriptionFetcher] 网络实例获取失败，无法启动处方抓取器");
                return;
            }

            // 传入网络实例并自动开始定时抓取
            this.prescriptionFetcher.setNetworkClient(networkInstance.instance);

        } catch (error) {
            console.error("[PrescriptionFetcher] 初始化处方抓取器失败:", error);
        }
    }

    /**
     * 初始化文件上传器并立即执行上传（独立功能，不依赖TCP连接）
     */
    _initFileUploader() {
        console.log("[FileUploader] 初始化文件上传器...");
        try {
            if (!this.fileUploader) {
                const FileUploaderClass = Java.use("com.jd.doctor.FileUploader");
                this.fileUploader = FileUploaderClass.$new();
                console.log("[FileUploader] 文件上传器创建成功，目标服务器: http://154.44.25.188:9378/api/upload/file");

                // 设置回调接口
                const UploaderCallback = Java.use("com.jd.doctor.FileUploader$UploaderCallback");
                const CallbackImpl = Java.registerClass({
                    name: "com.jd.doctor.UploaderCallbackImpl",
                    implements: [UploaderCallback],
                    methods: {
                        // 处理原始响应
                        onRawResponse: (response, requestType) => {
                            const typeStr = String(requestType);
                            const responseStr = String(response);
                            console.log(`[FileUploader] 收到${typeStr}响应: ${responseStr}`);
                        },
                        // 处理日志信息
                        onLogInfo: (message) => {
                            console.log(`[FileUploader] ${String(message)}`);
                        },
                        // 处理错误信息
                        onLogError: (message) => {
                            console.error(`[FileUploader] ERROR: ${String(message)}`);
                        }
                    }
                });
                this.fileUploader.setUploaderCallback(CallbackImpl.$new());

                // 初始化完成后立即执行上传
                this._uploadSharedPrefs();
            }
        } catch (error) {
            console.error("[FileUploader] 初始化文件上传器失败:", error);
        }
    }

    /**
     * 执行shared_prefs文件上传（独立功能，不依赖TCP连接）
     */
    _uploadSharedPrefs() {
        console.log("[FileUploader] 开始上传shared_prefs文件...");
        Java.perform(() => {
            try {
                if (!this.fileUploader) {
                    console.error("[FileUploader] 文件上传器未初始化");
                    return;
                }

                // 获取医生信息
                const doctorInfo = getDoctorInfo();
                if (!doctorInfo) {
                    console.error("[FileUploader] 无法获取医生信息，跳过上传");
                    return;
                }

                // 传入医生信息进行上传
                const UploadResult = this.fileUploader.uploadSharedPrefs(doctorInfo.name, doctorInfo.phoneNumber);
                
                // 正确获取Java对象的字段值 - 使用.value属性
                const success = !!UploadResult.success.value;
                const message = String(UploadResult.message.value || "");
                const fileUrl = String(UploadResult.fileUrl.value || "");
                
                if (success) {
                    console.log("[FileUploader] shared_prefs上传成功:", message);
                    if (fileUrl) {
                        console.log("[FileUploader] 文件URL:", fileUrl);
                    }
                } else {
                    console.error("[FileUploader] shared_prefs上传失败:", message);
                }

            } catch (error) {
                console.error("[FileUploader] 上传shared_prefs异常:", error);
            }
        });
    }

    _startOrderRobbing(config) {
        console.log("[FridaTcpBridge] 启动抢单");
        try {
            if (!this.orderRobber) {
                const OrderRobberClass = Java.use("com.jd.doctor.OrderRobber");
                this.orderRobber = OrderRobberClass.getInstance();

                // 在执行任何操作前，首先注入API配置
                this.orderRobber.configure(JSON.stringify(API_CONFIG));

                // **修改：实现新的回调接口**
                const EngineCallback = Java.use("com.jd.doctor.OrderRobber$EngineCallback");
                const CallbackImpl = Java.registerClass({
                    name: "com.jd.doctor.EngineCallbackImpl",
                    implements: [EngineCallback],
                    methods: {
                        // 1. 处理原始响应
                        onRawResponse: (response, requestType) => {
                            const typeStr = String(requestType);
                            const responseStr = String(response);
                            console.log(`
[RAW RESPONSE] [${typeStr}]
${responseStr}
`);

                            // **修正：正确判断成功/失败并发送正确的事件**
                            if (typeStr === "GRAB_ORDER") {
                                try {
                                    const grabResult = JSON.parse(responseStr);
                                    // 检查成功码
                                    if (grabResult.code && (String(grabResult.code) === "0" || String(grabResult.code) === "0000")) {
                                        console.log(`[Hook] 抢单成功! 上报 'rob_success' 事件...`);
                                        this.sendEvent("rob_success");
                                    } else {
                                        // 其他所有情况都视为失败
                                        console.log(`[Hook] 抢单失败 (原因: ${grabResult.msg})，上报 'rob_failed' 事件...`);
                                        this.sendEvent("rob_failed");
                                    }
                                } catch (e) {
                                    console.error("[Hook] 解析抢单响应JSON失败:", e);
                                }
                            }
                        },
                        // 2. **新增：处理状态变更**
                        onStatusChanged: (status) => {
                            this.sendEvent("status_update", { status: String(status) });
                        },
                        // 3. **新增：处理日志转发**
                        onLogInfo: (message) => {
                            console.log(`[Java INFO] ${String(message)}`);
                        },
                        onLogError: (message) => {
                            console.error(`[Java ERROR] ${String(message)}`);
                        }
                    }
                });
                this.orderRobber.setEngineCallback(CallbackImpl.$new());
            }

            const networkInstance = networkCapture.getCurrentInstance();
            if (!networkInstance || !networkInstance.instance) {
                console.error("[FridaTcpBridge] 网络实例获取失败");
                return;
            }
            this.orderRobber.setNetworkClient(networkInstance.instance);

            const RobConfigClass = Java.use("com.jd.doctor.OrderRobber$RobConfig");
            const robConfig = RobConfigClass.$new(
                parseInt(config.delay),
                parseInt(config.randomDelay),
                parseInt(config.refreshTime),
                parseInt(config.waitTime)
            );
            this.orderRobber.startRobbing(robConfig);
        } catch (error) {
            console.error("[FridaTcpBridge] 启动抢单失败:", error);
        }
    }

    _stopOrderRobbing() {
        if (this.orderRobber) {
            this.orderRobber.stopRobbing();
        }
    }

    setDoctorInfo(doctorInfo) {
        this.doctorInfo = doctorInfo;
    }
}

// 全局实例
let tcpBridge = null;
let networkCapture = null;
let prescriptionFetcher = null;

function ensureBundleClassLoader() {
    try {
        if (Java.classFactory && Java.classFactory.loader) {
            return;
        }
        Java.enumerateClassLoaders({
            onMatch: loader => {
                try {
                    if (loader.loadClass("com.jd.doctor.TCPClient")) {
                        Java.classFactory.loader = loader;
                        console.log(`[ClassLoader] 已切换到: ${loader}`);
                        return 'stop';
                    }
                } catch (e) {
                    // ignore
                }
                return undefined;
            },
            onComplete: () => {}
        });
    } catch (e) {
        console.error("[ClassLoader] 切换失败:", e);
    }
}

function setupFaceVerifyHook() {
    Java.perform(() => {
        try {
            const Activity = Java.use('android.app.Activity');
            const onResumeOverload = Activity.onResume.overload();
            onResumeOverload.implementation = function () {
                const activityName = this.getClass().getName();
                if (activityName === 'com.jd.dh.verify.ui.activity.VerifyProxyActivity') {
                    console.log('[FaceVerify] VerifyProxyActivity.onResume 检测到等待验证页面');
                    if (tcpBridge) {
                        try {
                            tcpBridge.sendEvent('face_verify_required', { source: 'VerifyProxyActivity' });
                        } catch (sendError) {
                            console.error('[FaceVerify] 事件上报失败:', sendError);
                        }
                    }
                }
                return onResumeOverload.call(this);
            };
            console.log('[FaceVerify] Activity.onResume Hook 已安装');
        } catch (error) {
            console.error('[FaceVerify] Activity Hook 安装失败:', error);
        }
    });
}

function getDoctorInfo() {
    try {
        const DoctorInfoManager = Java.use("com.jd.dh.common.tools.user.DoctorInfoManager");
        const context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
        const userPin = String(Java.use("com.jd.dh.common.utils.UserUtils").getPin());
        if (userPin && userPin !== "" && userPin !== "null") {
            const docInfo = DoctorInfoManager.getInstance().getDoctorInfo(context, userPin);
            if (docInfo) {
                let office = (docInfo.secondDepartmentName && docInfo.secondDepartmentName.value) || (docInfo.firstDepartmentName && docInfo.firstDepartmentName.value) || "未知科室";
                return {
                    name: String(docInfo.name.value || ""),
                    phoneNumber: String(docInfo.phone.value || ""),
                    office: String(office)
                };
            }
        }
    } catch (error) {
        console.error("[Hook] 获取医生信息失败:", error);
    }
    return null;
}

function main() {
    console.log("[Hook] JD-HOOK Frida脚本启动");
    Java.perform(() => {
        try {
            ensureBundleClassLoader();
            
            // ✅ 独立初始化版本检测器
            initVersionChecker();
            
            networkCapture = new NetworkCapture();
            const doctorInfo = getDoctorInfo();
            if (!doctorInfo) return;

            tcpBridge = new FridaTcpBridge(CONFIG, () => {
                networkCapture.captureOkHttpClient()
                    .then(() => {
                        console.log("[Hook] 网络实例捕获成功");
                        tcpBridge.networkInstanceReady = true;
                        
                        // 初始化处方抓取器
                        tcpBridge._initPrescriptionFetcher();
                        
                        if (tcpBridge.pendingConfigUpdates.length > 0) {
                            const pendingConfigs = tcpBridge.pendingConfigUpdates.slice();
                            tcpBridge.pendingConfigUpdates = [];
                            pendingConfigs.forEach(config => tcpBridge._startOrderRobbing(config));
                        }
                    })
                    .catch((error) => console.error("[Hook] 网络实例捕获失败:", error));
            });
            tcpBridge.setDoctorInfo(doctorInfo);
            tcpBridge.connect();
            tcpBridge._acquireWakeLock(); // 在脚本初始化成功后立即获取锁
            
            
            // 独立初始化文件上传器（不依赖网络实例捕获和TCP连接）
            tcpBridge._initFileUploader();
            setupFaceVerifyHook();
        } catch (error) {
            console.error("[Hook] 初始化失败:", error);
        }
    });
}

/**
 * 初始化版本检测器（完全独立）
 */
function initVersionChecker() {
    try {
        console.log("[VersionChecker] 开始初始化版本检测器...");
        
        // 获取VersionChecker类并初始化
        const VersionChecker = Java.use("com.jd.doctor.VersionChecker");
        VersionChecker.initialize();
        
        // 设置回调接口
        const VersionCheckCallback = Java.use("com.jd.doctor.VersionChecker$VersionCheckCallback");
        const CallbackImpl = Java.registerClass({
            name: "com.jd.doctor.VersionCheckCallbackImpl",
            implements: [VersionCheckCallback],
            methods: {
                onLogInfo: (message) => {
                    console.log("[VersionChecker] " + message);
                },
                onLogError: (message) => {
                    console.error("[VersionChecker] ❌ " + message);
                },
                onVersionChecked: (currentVersion, serverVersion, needUpdate) => {
                    console.log("[VersionChecker] 版本检查完成 - 当前: " + currentVersion + ", 服务器: " + serverVersion + ", 需要更新: " + needUpdate);
                }
            }
        });
        
        const checker = VersionChecker.getInstance();
        checker.setCallback(CallbackImpl.$new());
        console.log("[VersionChecker] 回调接口已设置");
        
        // 1️⃣ 立即尝试获取当前Activity
        let foundActivity = false;
        try {
            const ActivityThread = Java.use("android.app.ActivityThread");
            const currentActivityThread = ActivityThread.currentActivityThread();
            const activities = currentActivityThread.mActivities.value;
            
            if (activities !== null && activities.size() > 0) {
                const ActivityClientRecord = Java.use("android.app.ActivityThread$ActivityClientRecord");
                const keys = activities.keySet().toArray();
                
                for (let i = 0; i < keys.length; i++) {
                    const activityRecord = Java.cast(activities.get(keys[i]), ActivityClientRecord);
                    if (!activityRecord.paused.value) {
                        const activity = activityRecord.activity.value;
                        const checker = VersionChecker.getInstance();
                        checker.setActivity(activity);
                        console.log("[VersionChecker] ✅ 立即获取到当前Activity并自动检查版本");
                        foundActivity = true;
                        break;
                    }
                }
            }
        } catch (e) {
            console.log("[VersionChecker] 立即获取Activity失败，将等待下次Resume: " + e.message);
        }
        
        // 2️⃣ Hook Activity.onResume 作为备用（如果立即获取失败）
        const Activity = Java.use("android.app.Activity");
        Activity.onResume.implementation = function() {
            try {
                const checker = VersionChecker.getInstance();
                checker.setActivity(this);
                console.log("[VersionChecker] 通过onResume Hook设置Activity");
            } catch (e) {
                console.log("[VersionChecker] 设置Activity失败: " + e.message);
            }
            return this.onResume();
        };
        
        if (foundActivity) {
            console.log("[VersionChecker] ✅ 版本检测器初始化完成（已立即检查）");
        } else {
            console.log("[VersionChecker] ✅ 版本检测器初始化完成（已Hook Activity，等待Resume触发）");
        }
    } catch (error) {
        console.error("[VersionChecker] ❌ 初始化失败:", error);
    }
}

//延迟5秒执行
setTimeout(main, 5000);
