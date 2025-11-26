// page/main.js
import { ui } from './ui.js';
import { monitoringService } from './monitoring.js';
import { eventService } from './events.js';
import { Logger, waitForElement } from './utils.js';
import { NOTIFICATION_SOUND_URL, SELECTORS } from './config.js';
import { apiService } from './api.js';
import { state, saveTenantConfig } from './state.js'; // 导入保存函数
import { cacheService } from './cache.js'; // 导入缓存服务以初始化
import { drugDataService } from './drugData.js'; // 导入药物数据服务
import { initializePatientListener } from './patientListener.js'; // 导入患者监听器

const logger = new Logger('MAIN');
const notificationAudio = new Audio(NOTIFICATION_SOUND_URL);

/**
 * 主应用程序类
 */
class Application {
    constructor() {
        this.processedUrgentPatients = new Set();
    }

    /**
     * 初始化整个应用程序
     */
    async initialize() {
        
        // 0. 导出 apiService 到全局供 patientListener 使用
        window.apiService = apiService;
        
        // 1. 初始化租户类型（从 sessionStorage 读取并获取加密后缀）
        const tenantTypeValid = await this.#initializeTenantType();
        if (!tenantTypeValid) {
            logger.error('租户类型读取失败，插件不加载');
            return; // 停止加载插件
        }

        // 2. 在继续之前验证医生身份
        const doctorNameEl = await waitForElement(SELECTORS.DOCTOR_NAME, 15000);

        if (!doctorNameEl) {
            return;
        }

        const doctorName = doctorNameEl.innerText.trim();
        state.doctorName = doctorName; // 将名称保存到共享状态
        const isValid = await apiService.validateDoctor(doctorName, state.encryptSuffix);

        if (!isValid) {
            return;
        }

        // 检查是否为禁用租户
        const isDisabledTenant = state.tenantType === 'JD8888';
        state.isDisabledTenant = isDisabledTenant; // 保存到全局状态
        
        if (isDisabledTenant) {
            logger.warn(`⚠️ 检测到 ${state.tenantType} 租户，禁用开方和单量功能`);
        }

        // 3. 初始化药物数据服务（必须先获取配置）
        // 所有租户都需要药物数据（用于检测敏感药物和病症）
        await drugDataService.initialize(state.tenantType);
        
        // 4. 检查自动回复开关，如果启用则初始化患者消息监听器
        if (drugDataService.isAutoReplyEnabled()) {
            logger.info('✅ 自动回复已启用，启动患者消息监听器');
            initializePatientListener();
        } else {
            logger.warn('⚠️ 自动回复未启用，跳过患者消息监听器初始化');
        }
        // --- 初始化结束 ---

        // 5. 开始订单计数轮询（JD8888租户不启动）
        if (!isDisabledTenant) {
            this.#startOrderCountPolling();
        }

        // 6. 开始问诊数量轮询（所有租户）
        this.#startDiagnosisCountPolling();

        // 7. 创建用户界面（JD8888租户不显示开方按钮）
        ui.createInitialUI(isDisabledTenant);

        // 8. 配置监控服务回调函数
        this.#configureMonitoring();

        // 9. 开始监控页面变化
        console.log(`[插件启动] 开始启动监控服务...`);
        monitoringService.start();
        console.log(`[插件启动] 监控服务启动完成`);

        // 10. 初始化用户交互的所有事件监听器
        eventService.initialize();

        // 11. 默认启动自动开药循环（JD8888租户不启动）
        if (!isDisabledTenant) {
            eventService.startAutoRxLoop();
        }

        // 12. 监听二维码保存消息，自动上传URL到服务器
        this.#setupQRCodeListener();
    }

    /**
     * 初始化租户类型（优先使用 localStorage 缓存，否则从 sessionStorage 读取）
     * @returns {Promise<boolean>} 是否成功读取
     */
    async #initializeTenantType() {
        try {
            // 1. 检查是否已从 localStorage 加载了有效配置
            if (state.tenantType && state.encryptSuffix) {
                logger.info(`✅ 已从 localStorage 加载租户配置: ${state.tenantType}, 加密后缀: ${state.encryptSuffix}`);
                return true;
            }

            // 2. 从 sessionStorage 读取租户类型
            const tenantType = sessionStorage.getItem("TENANT_TYPE");
            if (!tenantType) {
                logger.error('❌ 未找到 TENANT_TYPE，插件不加载');
                return false;
            }

            // 去除可能的引号
            const cleanTenantType = tenantType.replace(/^["']|["']$/g, '');
            state.tenantType = cleanTenantType;
            state.docTenantType = cleanTenantType;
            logger.info(`✅ 已从 sessionStorage 读取租户类型: ${cleanTenantType}`);

            // 3. 从服务器获取加密后缀
            const configResult = await this.#getTenantConfig(cleanTenantType);
            if (!configResult.success) {
                logger.error('❌ 获取租户配置失败，插件不加载');
                return false;
            }

            state.encryptSuffix = configResult.encryptSuffix;
            logger.info(`✅ 已获取加密后缀: ${state.encryptSuffix}`);

            // 4. 检查是否为禁用租户
            const isDisabledTenant = cleanTenantType === 'JD8888';
            state.isDisabledTenant = isDisabledTenant;

            // 5. 保存到 localStorage（持久化）
            saveTenantConfig(cleanTenantType, cleanTenantType, state.encryptSuffix, isDisabledTenant);
            logger.info('✅ 租户配置已持久化到 localStorage');

            return true;

        } catch (error) {
            logger.error('❌ 初始化租户类型失败，插件不加载:', error.message);
            return false;
        }
    }

    /**
     * 从服务器获取租户配置
     * @param {string} tenantType - 租户类型
     * @returns {Promise<Object>} { success: boolean, encryptSuffix?: string }
     */
    async #getTenantConfig(tenantType) {
        return new Promise((resolve) => {
            const requestId = `get-tenant-config-${Date.now()}-${Math.random()}`;

            const listener = (event) => {
                if (event.source === window && 
                    event.data.type === 'TENANT_CONFIG_RESULT' && 
                    event.data.requestId === requestId) {
                    window.removeEventListener('message', listener);
                    
                    const payload = event.data.payload;
                    if (payload.success && payload.data && payload.data.code === 1) {
                        resolve({
                            success: true,
                            encryptSuffix: payload.data.data.encrypt_suffix
                        });
                    } else {
                        resolve({ success: false });
                    }
                }
            };

            window.addEventListener('message', listener);

            // 5秒超时
            setTimeout(() => {
                window.removeEventListener('message', listener);
                resolve({ success: false });
            }, 5000);

            window.postMessage({
                type: 'GET_TENANT_CONFIG_REQUEST',
                requestId: requestId,
                payload: { tenantType }
            }, '*');
        });
    }

    #configureMonitoring() {
        monitoringService.callbacks.onDoctorNameChange = (name) => {
            ui.updateDoctorName(name);
        };

        monitoringService.callbacks.onPatientCountdown = (patientName, totalSeconds) => {
            if (totalSeconds <= 55 && !this.processedUrgentPatients.has(patientName)) {
                const added = ui.addPatientToButton(patientName);
                if (added) {
                    notificationAudio.play().catch(e => { /* 忽略音频播放错误 */ });
                    this.processedUrgentPatients.add(patientName);
                }
            }
        };
    }

    /**
     * 初始化定期获取和更新订单计数的进程
     */
    async #startOrderCountPolling() {
        try {
            // 1. 在初始化时获取医生的ID
            const doctorInfo = await apiService.getDoctorInfo();
            if (!doctorInfo || !doctorInfo.doctorId) {
                logger.error('Could not retrieve doctorId. Order count polling will not start.');
                return;
            }
            state.doctorId = doctorInfo.doctorId; // 将ID保存到共享状态
            logger.info(`Successfully retrieved doctorId: ${state.doctorId}`);

            // 1.5. 上报医生ID到服务器
            apiService.updateDoctorId(state.doctorId, state.doctorName);

            // 2. 定义轮询函数
            const poll = async () => {
                try {
                    const now = new Date();
                    const year = now.getFullYear();
                    const month = String(now.getMonth() + 1).padStart(2, '0');
                    const day = String(now.getDate()).padStart(2, '0');
                    const today = `${year}-${month}-${day}`; // 正确获取本地的'YYYY-MM-DD'格式

                    const count = await apiService.getOrderCount(state.doctorId, today);
                    logger.info(`Fetched order count: ${count}`);
                    apiService.updateOrderCount(count); // 发送不等待更新到我们的后端
                } catch (error) {
                    // 这个catch块确保一次失败的轮询不会停止间隔器
                    logger.error('An error occurred during a polling cycle:', error.message);
                }
            };

            // 3. 立即轮询一次，然后开始间隔器
            await poll();
            setInterval(poll, 60000); // 每60秒轮询一次

        } catch (error) {
            // 这里捕获初始`getDoctorInfo`调用期间的错误
            logger.error('Failed to initialize order count polling:', error.message);
        }
    }

    /**
     * 初始化定期获取和更新问诊数量的进程（每5秒一次）
     */
    async #startDiagnosisCountPolling() {
        try {
            // 确保已经获取了 doctorId
            if (!state.doctorId) {
                // 如果还没有获取，先获取医生信息
                const doctorInfo = await apiService.getDoctorInfo();
                if (!doctorInfo || !doctorInfo.doctorId) {
                    logger.error('Could not retrieve doctorId. Diagnosis count polling will not start.');
                    return;
                }
                state.doctorId = doctorInfo.doctorId;
                logger.info(`Successfully retrieved doctorId for diagnosis polling: ${state.doctorId}`);
                
                // 上报医生ID到服务器
                apiService.updateDoctorId(state.doctorId, state.doctorName);
            }

            // 定义轮询函数
            const poll = async () => {
                try {
                    const count = await apiService.getDiagnosisCount(state.doctorId);
                    logger.info(`问诊中数量: ${count}`);
                    ui.updateDiagnosisCount(count); // 更新UI显示
                } catch (error) {
                    // 确保一次失败不会停止轮询
                    logger.error('获取问诊数量时出错:', error.message);
                }
            };

            // 立即轮询一次，然后开始间隔器
            await poll();
            setInterval(poll, 5000); // 每5秒轮询一次

        } catch (error) {
            logger.error('初始化问诊数量轮询失败:', error.message);
        }
    }

    /**
     * 设置二维码监听器，当检测到新的二维码时自动上传URL到服务器
     */
    #setupQRCodeListener() {
        window.addEventListener('message', (event) => {
            // 只接受来自同源的消息
            if (event.source === window && event.data.type === 'SAVE_QRCODE') {
                let { qrcodeUrl } = event.data.payload;
                
                if (qrcodeUrl && state.doctorName) {
                    // 双重保护：再次解码HTML实体（防止某些情况下qrcodeMonitor.js的解码没生效）
                    const textarea = document.createElement('textarea');
                    textarea.innerHTML = qrcodeUrl;
                    qrcodeUrl = textarea.value;
                    
                    logger.info('📱 检测到新二维码，准备上传到服务器');
                    logger.info('   原始URL:', event.data.payload.qrcodeUrl);
                    logger.info('   解码后URL:', qrcodeUrl);
                    
                    // 调用 API 服务更新二维码 URL
                    apiService.updateQRCodeUrl(qrcodeUrl, state.doctorName);
                } else {
                    logger.warn('⚠️ 二维码或医生姓名缺失，跳过上传');
                }
            }
        });
        
        logger.info('✅ 二维码监听器已设置');
    }

}

// --- 入口点 ---
// 确保脚本只在正确的页面上运行，并且在DOM准备好之后
if (window.location.href.includes('jddoctor.jd.com')) {
    const app = new Application();
    app.initialize();
} else {
    // 生产构建不应该有日志
}
