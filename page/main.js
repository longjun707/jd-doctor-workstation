// page/main.js
import { ui } from './ui.js';
import { monitoringService } from './monitoring.js';
import { eventService } from './events.js';
import { Logger, waitForElement } from './utils.js';
import { NOTIFICATION_SOUND_URL, SELECTORS } from './config.js';
import { apiService } from './api.js';
import { state } from './state.js';
import { cacheService } from './cache.js'; // 导入缓存服务以初始化

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
        // 1. 在继续之前验证医生身份
        const doctorNameEl = await waitForElement(SELECTORS.DOCTOR_NAME, 15000);

        if (!doctorNameEl) {
            return;
        }

        const doctorName = doctorNameEl.innerText.trim();
        state.doctorName = doctorName; // 将名称保存到共享状态
        const isValid = await apiService.validateDoctor(doctorName);

        if (!isValid) {
            return;
        }

        // --- 新增: 开始订单计数轮询 ---
        this.#startOrderCountPolling();
        // --- 新增结束 ---

        // 2. 创建用户界面
        ui.createInitialUI();

        // 3. 配置监控服务回调函数
        this.#configureMonitoring();

        // 4. 开始监控页面变化
        console.log(`[插件启动] 开始启动监控服务...`);
        monitoringService.start();
        console.log(`[插件启动] 监控服务启动完成`);

        // 5. 初始化用户交互的所有事件监听器
        eventService.initialize();

        // 6. 默认启动自动开药循环
        eventService.startAutoRxLoop();
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
}

// --- 入口点 ---
// 确保脚本只在正确的页面上运行，并且在DOM准备好之后
if (window.location.href.includes('jddoctor.jd.com')) {
    const app = new Application();
    app.initialize();
} else {
    // 生产构建不应该有日志
}
