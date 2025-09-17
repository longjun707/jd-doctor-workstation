// page/monitoring.js
import { SELECTORS } from './config.js';
import { Logger } from './utils.js';

const logger = new Logger('MONITOR');

/**
 * 监控页面变化，包括DOM变化
 */
class MonitoringService {
    constructor({ onDoctorNameChange, onPatientCountdown }) {
        this.callbacks = { onDoctorNameChange, onPatientCountdown };
        this.patientListObserver = null;
        this.doctorNameObserver = null;
        this.globalObserver = null;
    }

    /**
     * 启动所有监控活动
     */
    start() {
        this.#startDOMObservers();
        // 备用监控方法：直接监控整个文档
        this.#startGlobalObserver();
    }

    /**
     * 停止所有监控活动
     */
    stop() {
        if (this.patientListObserver) this.patientListObserver.disconnect();
        if (this.doctorNameObserver) this.doctorNameObserver.disconnect();
        if (this.globalObserver) this.globalObserver.disconnect();
    }

    #startDOMObservers() {
        // 在开始监控之前等待元素准备好
        this.#waitForElement(SELECTORS.PATIENT_LIST_CONTAINER, () => this.#observePatientList());
        this.#waitForElement(SELECTORS.DOCTOR_NAME, () => this.#observeDoctorName());
    }

    #observePatientList() {
        const targetNode = document.querySelector(SELECTORS.PATIENT_LIST_CONTAINER);
        if (!targetNode) {
            return;
        }

        this.patientListObserver = new MutationObserver((mutations) => {
            for (const mutation of mutations) {
                if (mutation.type === 'childList' || mutation.type === 'characterData') {
                    this.#parsePatientList(targetNode);
                    break;
                }
            }
        });

        this.patientListObserver.observe(targetNode, { 
            childList: true, 
            subtree: true, 
            characterData: true,
            attributes: true,
            attributeOldValue: true,
            characterDataOldValue: true
        });
        this.#parsePatientList(targetNode);
    }

    #parsePatientList(container) {
        const patientItems = container.querySelectorAll(SELECTORS.PATIENT_LIST_ITEM);
        if (patientItems.length === 0) {
            return;
        }

        patientItems.forEach((item) => {
            const nameElement = item.querySelector(SELECTORS.PATIENT_NAME_IN_LIST);
            const countdownElement = item.querySelector(SELECTORS.PATIENT_COUNTDOWN_IN_LIST);

            const allElements = item.querySelectorAll('*');
            let foundCountdownElements = [];

            allElements.forEach((el) => {
                const text = el.textContent.trim();
                const hasTimeFormat = text.match(/请于\d{1,2}:\d{2}内回复/);

                if (hasTimeFormat) {
                    foundCountdownElements.push({element: el, text: text});
                }
            });

            if (countdownElement) {
                foundCountdownElements.push({element: countdownElement, text: countdownElement.textContent.trim()});
            }

            if (nameElement) {
                const patientName = nameElement.textContent.trim();

                let processed = false;
                for (let i = 0; i < foundCountdownElements.length; i++) {
                    const {element, text} = foundCountdownElements[i];

                    const patterns = [
                        /请于(\d{1,2}):(\d{2})内回复/,  // 只识别这种格式
                    ];

                    let matched = false;
                    for (const pattern of patterns) {
                        const countdownMatch = text.match(pattern);
                        if (countdownMatch) {
                            let minutes = 0, seconds = 0;

                            // 对于"请于XX:XX内回复"格式，总是有分钟和秒数两个捕获组
                            minutes = parseInt(countdownMatch[1], 10) || 0;
                            seconds = parseInt(countdownMatch[2], 10) || 0;

                            const totalSeconds = minutes * 60 + seconds;

                            if (this.callbacks.onPatientCountdown) {
                                this.callbacks.onPatientCountdown(patientName, totalSeconds);
                            }
                            matched = true;
                            processed = true;
                            break;
                        }
                    }
                    if (matched) break;
                }
            }
        });
    }

    #observeDoctorName() {
        const targetNode = document.querySelector(SELECTORS.DOCTOR_NAME);
        if (!targetNode) {
            return;
        }

        this.doctorNameObserver = new MutationObserver(() => {
            const name = targetNode.textContent.trim();
            if (name && this.callbacks.onDoctorNameChange) {
                this.callbacks.onDoctorNameChange(name);
            }
        });

        this.doctorNameObserver.observe(targetNode, { childList: true, characterData: true });
        // 初始检查
        if (targetNode.textContent && this.callbacks.onDoctorNameChange) {
            this.callbacks.onDoctorNameChange(targetNode.textContent.trim());
        }
    }

    #startGlobalObserver() {
        let lastCheckTime = 0;
        
        this.globalObserver = new MutationObserver((mutations) => {
            const now = Date.now();
            if (now - lastCheckTime < 500) {
                return;
            }
            lastCheckTime = now;
            this.#scanAllCountdownElements();
        });

        this.globalObserver.observe(document.body, {
            childList: true,
            subtree: true,
            characterData: true,
            attributes: true
        });
        
        setInterval(() => {
            this.#scanAllCountdownElements();
        }, 5000);
    }

    #scanAllCountdownElements() {
        const countdownSelectors = [
            '.ant-statistic-content-value',
            '[class*="countdown"]',
            '[class*="time"]',
            '[class*="timer"]',
            '[class*="statistic"]'
        ];
        
        const allCountdownElements = [];
        countdownSelectors.forEach(selector => {
            const elements = document.querySelectorAll(selector);
            elements.forEach(el => allCountdownElements.push(el));
        });
        
        allCountdownElements.forEach((el) => {
            const text = el.textContent.trim();
            
            const patterns = [
                /请于(\d{1,2}):(\d{2})内回复/,  // 只识别这种格式
            ];
            
            for (const pattern of patterns) {
                const match = text.match(pattern);
                if (match) {
                    let minutes = 0, seconds = 0;
                    
                    // 对于"请于XX:XX内回复"格式，总是有分钟和秒数两个捕获组
                    minutes = parseInt(match[1], 10) || 0;
                    seconds = parseInt(match[2], 10) || 0;
                    
                    const totalSeconds = minutes * 60 + seconds;
                    
                    let patientElement = el.closest('.contact-item');
                    if (!patientElement) {
                        patientElement = el.closest('.variable-size-list-item');
                    }
                    
                    if (patientElement) {
                        const nameElement = patientElement.querySelector('.name');
                        if (nameElement) {
                            const patientName = nameElement.textContent.trim();
                            
                            if (this.callbacks.onPatientCountdown) {
                                this.callbacks.onPatientCountdown(patientName, totalSeconds);
                            }
                        }
                    }
                    break;
                }
            }
        });
    }

    #waitForElement(selector, callback, timeout = 30000) {
        let intervalId = null;
        const check = () => {
            const el = document.querySelector(selector);
            if (el) {
                if (intervalId) clearInterval(intervalId);
                callback();
                return true;
            }
            return false;
        };

        if (!check()) {
            intervalId = setInterval(() => {
                if (check()) {
                    clearInterval(intervalId);
                }
            }, 2000); // 每2秒检查一次，无限期
        }
    }
}

export const monitoringService = new MonitoringService({});
