const STATE = {
    ep: null,
    jec: null,
    phone: null,
    account_name: null,
    aesKey: "eLZoZVqrg0wfNW0y",
    isConnected: false,
    diagId: null,
    delay: 2000,
    random_delay: 5000,
    processedDiagIds: new Set(),
    lastRefreshTime: 0,
    refreshInProgress: false
};

const Network = {
    host: '192.168.1.11',
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
                                Thread.sleep(5000); // 每5秒发送一次心跳
                            } catch (e) {
                                console.log("[-] 心跳发送失败: " + e);
                            }
                        }
                    }
                }
            });

            Java.use('java.lang.Thread').$new(HeartbeatRunnable.$new()).start();
        });
    },

    sendMessage: function (message) {
        if (this.currentChannel == null || !this.currentChannel.isConnected()) {
            console.log("[-] 当前没有活动的连接");
            return false;
        }

        try {
            const ByteBuffer = Java.use('java.nio.ByteBuffer');
            if (!message.endsWith("\n")) {
                message += "\n";
            }

            const javaString = Java.retain(Java.use('java.lang.String').$new(message));
            const sendBuffer = Java.retain(ByteBuffer.wrap(javaString.getBytes()));
            try {
                while (sendBuffer.hasRemaining()) {
                    this.currentChannel.write(sendBuffer);
                }
            } finally {
                javaString.$dispose();
                sendBuffer.$dispose();
            }

            console.log("[+] 消息已发送: " + message.trim());
            return true;
        } catch (e) {
            console.log("[-] 发送消息失败: " + e);
            return false;
        }
    },

    startNetwork: function () {
        Java.perform(() => {
            const SocketChannel = Java.use('java.nio.channels.SocketChannel');
            const InetSocketAddress = Java.use('java.net.InetSocketAddress');
            const ByteBuffer = Java.use('java.nio.ByteBuffer');
            const Charset = Java.use('java.nio.charset.Charset');
            const Thread = Java.use('java.lang.Thread');

            const NetworkRunnable = Java.registerClass({
                name: 'com.example.NetworkRunnable',
                implements: [Java.use('java.lang.Runnable')],
                methods: {
                    run: function () {
                        while (Network.isRunning) {
                            var channel = null;
                            try {
                                console.log("[*] 尝试连接到 " + Network.host + ":" + Network.port + "...");
                                channel = Java.retain(SocketChannel.open());
                                const socketAddress = Java.retain(InetSocketAddress.$new(Network.host, Network.port));
                                channel.connect(socketAddress);

                                if (channel.isConnected()) {
                                    console.log("[+] SocketChannel已成功连接");
                                    Network.currentChannel = channel;
                                    Network.sendMessage(STATE.phone);

                                    const buffer = Java.retain(ByteBuffer.allocate(1024));
                                    while (Network.isRunning && channel.isConnected()) {
                                        try {
                                            const bytesRead = channel.read(buffer);
                                            socketAddress.$dispose();
                                            if (bytesRead > 0) {
                                                buffer.flip();
                                                const received = Charset.forName("UTF-8").decode(buffer).toString();

                                                console.log("[*] 收到服务器消息: " + received.trim());
                                                if (received.trim().includes("USER_DATA")) {
                                                    try {
                                                        // 提取JSON部分 - 从第一个{开始到最后一个}结束
                                                        const jsonStart = received.indexOf('{');
                                                        const jsonEnd = received.lastIndexOf('}') + 1;
                                                        const jsonStr = received.slice(jsonStart, jsonEnd);

                                                        const dataObj = JSON.parse(jsonStr);

                                                        STATE.account_name = dataObj.account_name;

                                                        if (dataObj.status == "1") {
                                                            STATE.isConnected = true;
                                                            Network.sendMessage("update_state:正常");
                                                        } else {
                                                            STATE.isConnected = false;
                                                        }
                                                        STATE.delay = dataObj.delay;
                                                        STATE.random_delay = dataObj.random_delay;
                                                        console.log("[+] 已获取到用户信息: " + JSON.stringify(STATE));
                                                    } catch (e) {
                                                        console.error("[-] 解析用户数据时出错:", e.message);
                                                        console.error("原始数据:", received);
                                                    }
                                                }







                                                if (received.trim() === "PING") {
                                                    console.log("[*] 收到PING消息，自动回复PONG");
                                                    Network.sendMessage("PONG");
                                                }



                                                buffer.clear();
                                            } else if (bytesRead === -1) {
                                                console.log("[-] 服务器断开连接");
                                                STATE.isConnected = false;
                                                break;
                                            }
                                            Thread.sleep(100);
                                        } catch (e) {
                                            console.log("[-] 接收数据时出错: " + e);
                                            break;
                                        }
                                    }
                                }
                            } catch (e) {
                                console.log("[-] 连接失败: " + e);
                            } finally {
                                if (channel != null) {
                                    try {
                                        channel.close();
                                        if (Network.currentChannel === channel) {
                                            Network.currentChannel = null;
                                        }
                                    } catch (e) {
                                        console.log("[-] 关闭连接时出错: " + e);
                                    }
                                }
                            }

                            if (Network.isRunning) {
                                console.log("[*] " + (Network.reconnectInterval / 1000) + "秒后尝试重连...");
                                Thread.sleep(Network.reconnectInterval);
                            }
                        }
                    }
                }
            });

            Java.use('java.lang.Thread').$new(NetworkRunnable.$new()).start();

            // 导出RPC方法
            rpc.exports = {
                sendsms: function (message) {
                    return Network.sendMessage(message);
                }
            };

            console.log("[+] 网络模块已加载");
        });
    }
};

const HOOK_CONFIG = {
    RETRY_INTERVAL: 2000,
    MAX_RETRIES: 3,
    TARGET_CLASSES: {
        DEVICE_CTRL: "com.jd.dh.report.utils.encrypt.JdColorParamEncryptController",
        DECRYPT_SERVICE: "com.jd.dh.common.utils.NetworkEncryptUtils",
        PHONE_DECRYPT: "com.jd.dh.common.utils.encrypt.AesUtils",
        JEC_CTRL: "com.jd.dh.common.tools.network.encrypt.EncryptHeaderController"
    }
};


// ==================== 工具函数 ====================
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

// ==================== HOOK 加载器 ====================
function createHookLoader({ name, targetClass, hookMethod, processor }) {
    let retryCount = 0;

    const loadHook = () => {
        try {
            const clazz = Java.use(targetClass);
            if (!clazz[hookMethod]) throw new Error(`${hookMethod} 方法不存在`);

            clazz[hookMethod].implementation = function (...args) {
                const originalResult = this[hookMethod](...args);
                try {
                    processor.call(this, originalResult, ...args);
                } catch (e) {
                    Utils.log(`[${name}] 数据处理异常: ${e.message}`, 'error');
                }
                return originalResult;
            };

            Utils.log(`${name} HOOK加载成功`, 'success');
        } catch (e) {
            if (retryCount < HOOK_CONFIG.MAX_RETRIES) {
                retryCount++;
                Utils.log(`${name} 加载失败，第${retryCount}次重试...`, 'warn');
                setTimeout(loadHook, HOOK_CONFIG.RETRY_INTERVAL);
            } else {
                Utils.log(`${name} 永久加载失败: ${e.message}`, 'error');
            }
        }
    };

    loadHook();
}


// ==================== 订单刷新逻辑（使用OkHttpManager） ====================
const OrderRefresh = {
    refreshOrderList: function () {
        if (!STATE.isConnected) return Promise.reject("网络未连接");
        if (STATE.refreshInProgress) return Promise.reject("刷新操作正在进行中");

        STATE.refreshInProgress = true;

        // 添加整体超时控制（30秒）
        const timeoutPromise = new Promise((_, reject) =>
            setTimeout(() => reject(new Error("订单刷新超时")), 2000)
        );

        const refreshPromise = new Promise((resolve, reject) => {
            const currentTime = Date.now();
            const requiredDelay = STATE.delay;
            if (currentTime - STATE.lastRefreshTime < requiredDelay) {
                const waitTime = STATE.lastRefreshTime + requiredDelay - currentTime;
                setTimeout(() => this.executeHttpRefresh(resolve, reject), waitTime);
                return;
            }
            this.executeHttpRefresh(resolve, reject);
        }).finally(() => {
            STATE.refreshInProgress = false;
        });

        return Promise.race([refreshPromise, timeoutPromise]);
    },

    executeHttpRefresh: function (resolve, reject) {
        OkHttpManager.refreshOrderList()
            .then(response => {
                STATE.lastRefreshTime = Date.now();
                console.log("刷新成功:", response.body);

                try {
                    const responseData = JSON.parse(response.body);
                    if (responseData.success && responseData.data?.length > 0) {
                        // 提取所有诊断单ID（diagId）
                        const diagIds = responseData.data.map(order => order.diagId.toString());
                        console.log("待处理诊断单ID:", diagIds);

                        // 并发接单（限制并发数）
                        this.processOrdersConcurrently(diagIds)
                            .then(() => console.log("所有订单处理完成"))
                            .catch(() => console.log("部分订单接单失败（详见日志）"));
                    } else {
                        console.warn("未找到有效订单数据");
                    }
                } catch (e) {
                    console.error("解析响应数据失败:", e);
                }

                resolve(response);
            })
            .catch(error => {
                console.error("刷新失败:", error);
                reject(error);
            });
    },

    // 并发处理订单（带限制）
    processOrdersConcurrently: async function (diagIds) {
        if (!Array.isArray(diagIds)) {
            console.error("错误：diagIds 必须是数组");
            return;
        }

        const batches = [];
        for (let i = 0; i < diagIds.length; i += STATE.concurrencyLimit || 3) {
            batches.push(diagIds.slice(i, i + (STATE.concurrencyLimit || 3)));
        }

        for (const batch of batches) {
            const results = await Promise.allSettled(
                batch.map(diagId =>
                    OkHttpManager.sendDiagnosisRequest(diagId)
                        .then(res => {
                            // 检查响应格式
                            const response = typeof res.body === 'string' ?
                                JSON.parse(res.body) : res.body;

                            console.log(`✅ 诊断单 ${diagId} 接单响应:`, JSON.stringify(response));

                            if (response?.msg === "OK" && response?.code === "0000") {
                                console.log(`📢 发送消息: DEDUCT:${STATE.account_name}`);
                                // 实际发送消息的代码
                                Network.sendMessage("DEDUCT:" + STATE.account_name);
                            }
                            return response;
                        })
                        .catch(err => {
                            console.error(`❌ 诊断单 ${diagId} 接单失败:`, err.message);
                            throw err;
                        })
                )
            );

            // 批次间延迟（使用STATE.delay作为基础延迟）
            await new Promise(resolve => setTimeout(resolve, STATE.delay));
        }
    },

    startAutoRefresh: function () {
        const initialDelay = Utils.getRandomDelay(
            STATE.delay,
            STATE.delay + STATE.random_delay
        );
        setTimeout(() => {
            this.refreshOrderList()
                .finally(() => {
                    const nextDelay = Utils.getRandomDelay(
                        STATE.delay,
                        STATE.delay + STATE.random_delay
                    );
                    setTimeout(() => this.startAutoRefresh(), nextDelay);
                });
        }, initialDelay);
    },
};

// ==================== OkHttp 客户端管理 ====================
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
                                    Utils.log(`响应码: ${responseCode}`, 'info');

                                    const responseBody = retainedResponse.body();
                                    let responseString = null;
                                    if (responseBody) {
                                        const retainedBody = Java.retain(responseBody);
                                        responseString = retainedBody.string();
                                        Utils.log(`响应体长度: ${responseString.length}`, 'info');
                                        retainedBody.close();
                                    } else {
                                        Utils.log("响应体为空", 'warn');
                                    }

                                    retainedResponse.close();
                                    Utils.log("请求完成!", 'success');

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
                "User-Agent": "JD4iPhone/10.2.0"
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



// ==================== 医生信息提取 ====================
function extractDoctorInfo(filePath) {
    try {
        const bytes = readFileBytes(filePath);
        if (!bytes || bytes.length === 0) return null;

        const StringClass = Java.use("java.lang.String");
        const xmlContent = StringClass.$new(bytes, "UTF-8");

        const jsonStart = xmlContent.indexOf('{');
        const jsonEnd = xmlContent.lastIndexOf('}') + 1;
        if (jsonStart < 0 || jsonEnd <= jsonStart) return null;

        const rawJsonStr = xmlContent.substring(jsonStart, jsonEnd);
        const jsonStr = rawJsonStr
            .replace(/&quot;/g, '"')
            .replace(/&amp;/g, '&')
            .replace(/&lt;/g, '<')
            .replace(/&gt;/g, '>')
            .replace(/\\"/g, '"')
            .replace(/\\\//g, '/')
            .replace(/\\u([\dA-Fa-f]{4})/g, (match, grp) =>
                String.fromCharCode(parseInt(grp, 16)));

        return JSON.parse(jsonStr);
    } catch (e) {
        Utils.log(`提取医生信息失败: ${e.message}`, 'error');
        return null;
    }
}

function readFileBytes(fileName) {
    try {
        const Files = Java.use("java.nio.file.Files");
        const Paths = Java.use("java.nio.file.Paths");
        const URI = Java.use("java.net.URI");
        const path = Paths.get(URI.create("file://" + fileName));
        return Files.readAllBytes(path);
    } catch (e) {
        Utils.log(`文件读取失败: ${fileName}`, 'error');
        return null;
    }
}

// ==================== HOOK初始化 ====================
function initializeHooks() {
    // 设备信息HOOK
    createHookLoader({
        name: "设备信息",
        targetClass: HOOK_CONFIG.TARGET_CLASSES.DEVICE_CTRL,
        hookMethod: "getColorQueryParamsFromUri$com_jd_dh_report",
        processor: function (result) {
            try {
                const encryptParam = result.get("encrypt")?.toString();
                if (!encryptParam || encryptParam === STATE.ep) return;

                if (STATE.phone && STATE.jec) {
                    STATE.ep = encryptParam.split("ep=")[1];
                    Utils.log(`设备参数更新: ${STATE.ep.slice(0, 6)}***`, 'info');
                    // Network.httpPost({ phone: STATE.phone, ep: STATE.ep, jec: STATE.jec });
                }
            } catch (e) {
                Utils.log(`设备参数处理异常: ${e.message}`, 'error');
            }
        }
    });

    // JEC凭证HOOK
    createHookLoader({
        name: "JEC参数",
        targetClass: HOOK_CONFIG.TARGET_CLASSES.JEC_CTRL,
        hookMethod: "getJECValue",
        processor: function (result) {
            if (!result || result === STATE.jec) return;
            STATE.jec = result;
            Utils.log(`JEC凭证更新: ${result.slice(0, 6)}***`, 'info');
        }
    });

    // 响应数据解析HOOK
    createHookLoader({
        name: "响应数据解析",
        targetClass: HOOK_CONFIG.TARGET_CLASSES.DECRYPT_SERVICE,
        hookMethod: "rebuildResponseData",
        processor: function (result) {
            if (!result) return;

            try {
                const resultStr = result.toString();
                const newDiagIds = [];
                let pos = 0;

                while ((pos = resultStr.indexOf('"diagId":', pos)) !== -1) {
                    const idStart = pos + 9;
                    const idEnd = resultStr.indexOf(',', idStart);
                    const diagId = resultStr.slice(idStart, idEnd).trim();

                    if (!STATE.processedDiagIds.has(diagId)) {
                        const labelPos = resultStr.indexOf('"specialLabels"', pos);
                        if (labelPos !== -1 && resultStr.slice(labelPos, labelPos + 150).includes('复')) {
                            newDiagIds.push(diagId);
                            STATE.processedDiagIds.add(diagId);
                        }
                    }
                    pos = idEnd;
                }

                if (newDiagIds.length) {
                    Java.scheduleOnMainThread(() => {
                        // 使用 Promise.all 处理所有请求
                        const requests = newDiagIds.map(id => {
                            Utils.log(`发现新标签：${id}`, 'info');

                            // 异步发送诊断请求
                            return OkHttpManager.sendDiagnosisRequest(id)
                                .then(response => {
                                    if (response && response.code === 200) {
                                        Utils.log(`诊断请求成功: ${id}`, 'success');
                                    } else {
                                        Utils.log(`诊断请求失败: ${id}`, 'error');
                                    }
                                })
                                .catch(e => {
                                    Utils.log(`诊断请求异常: ${e.message}`, 'error');
                                });
                        });

                        // 等待所有请求完成
                        Promise.all(requests)
                            .then(() => Utils.log("所有诊断请求处理完成", 'info'))
                            .catch(e => Utils.log(`诊断请求处理异常: ${e.message}`, 'error'));
                    });
                }
            } catch (e) {
                Utils.log(`响应数据处理异常: ${e.message}`, 'error');
            }
        }
    });
}

// ==================== 初始化函数 ====================
function initialize() {
    Java.perform(function () {
        try {
            const context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
            const sharedPrefsDir = context.getFilesDir().getParent() + "/shared_prefs/";
            const doctorInfo = extractDoctorInfo(sharedPrefsDir + "cacheDoctorInfo.xml");

            if (!doctorInfo || !doctorInfo.name || !doctorInfo.phone) {
                Utils.log("无法读取有效的医生信息", 'error');
                return;
            }

            STATE.phone = doctorInfo.phone;
            Utils.log(`医生信息加载成功 - 姓名: ${doctorInfo.name}, 手机号: ${doctorInfo.phone}`, 'success');

            // 初始化OkHttp管理器
            OkHttpManager.init();

            // 初始化HOOK
            initializeHooks();

            // 启动自动刷新
            OrderRefresh.startAutoRefresh();


            Network.startNetwork();
       




            var Activity = Java.use("android.app.Activity");
            Activity.onResume.implementation = function () {
                var currentActivity = this.getClass().getName();
                console.log("[*] Current Activity: " + currentActivity);
                if (currentActivity == "com.jd.dh.verify.ui.activity.VerifyProxyActivity") {
                    const MyRunnable = Java.registerClass({
                        name: 'com.example.NetworkRunnable',
                        implements: [Java.use('java.lang.Runnable')],
                        methods: {
                            run: function () {
                                Network.sendMessage("update_state:等待验证");
                            }
                        }
                    });

                    // 启动网络线程
                    Java.use('java.lang.Thread').$new(MyRunnable.$new()).start();


                }
                this.onResume()

            }
        } catch (e) {
            Utils.log(`初始化失败: ${e.message}`, 'error');
        }
    });

}




// ==================== 启动脚本 ====================
setTimeout(initialize, 3000);



