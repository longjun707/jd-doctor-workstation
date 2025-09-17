// page/events.js
import { ui } from './ui.js';
import { autoRxService } from './autoRx.js';
import { apiService } from './api.js';
import { Logger, getRandomDelay } from './utils.js'; // Import getRandomDelay
import { UI_CONFIG, SELECTORS } from './config.js'; // Import SELECTORS

/**
 * Handles all user interaction events.
 */
class EventService {
    constructor() {
        this.isAutoRxRunning = false;
        this.autoRxIntervalId = null;
        this.isWorkStatusOpen = true; // 默认开诊状态
        this.isRightPanelVisible = false; // 默认隐藏面板 // 默认右侧面板可见
    }

    /**
     * Attaches all event listeners to the UI elements.
     */
    initialize() {
        const { buttonsContainer, doctorStatusLabel, workStatusLabel, autoRxStatusLabel, panelToggleButton } = ui.elements;

        if (buttonsContainer) {
            buttonsContainer.addEventListener('click', this.#handleButtonsContainerClick.bind(this));
        }
        if (doctorStatusLabel) {
            doctorStatusLabel.addEventListener('click', this.#handleDoctorStatusClick.bind(this));
        }
        if (workStatusLabel) {
            workStatusLabel.addEventListener('click', this.#handleWorkStatusClick.bind(this));
        }
        if (autoRxStatusLabel) {
            autoRxStatusLabel.addEventListener('click', this.#handleAutoRxClick.bind(this));
        }
        if (panelToggleButton) {
            panelToggleButton.addEventListener('click', this.#handlePanelToggleClick.bind(this));
        }
        
        // 初始化面板状态
        this.#initializePanelState();
        
        // 启动面板自动检测和隐藏
        this.#startPanelAutoHide();
    }

    #handleButtonsContainerClick(event) {
        const button = event.target.closest('.dr-helper-button');
        if (!button) return;

        switch (button.id) {
            case 'clear-button':
                ui.clearPatientButtons();
                break;
            case 'patient-button-1':
            case 'patient-button-2':
            case 'patient-button-3':
                this.#handlePatientButtonClick(button);
                break;
        }
    }

    #handlePatientButtonClick(button) {
        const buttonText = button.textContent;

        if (buttonText && buttonText !== UI_CONFIG.BUTTON_STATE.IDLE) {
            // Case 1: Button has a patient name - search for the patient
            ui.searchForPatient(buttonText);

            // Reset only the clicked button
            button.textContent = UI_CONFIG.BUTTON_STATE.IDLE;
            button.style.setProperty('background-color', UI_CONFIG.BUTTON_COLORS.IDLE, 'important');
            // Remove from map if it exists
            for (const [name, btn] of ui.patientButtonMap.entries()) {
                if (btn === button) {
                    ui.patientButtonMap.delete(name);
                    break;
                }
            }

        } else {
            // Case 2: Button is idle - mark the current patient
            const currentPatientName = document.querySelector(SELECTORS.CURRENT_PATIENT_NAME)?.textContent.trim();
            if (currentPatientName) {
                button.textContent = currentPatientName;
                button.style.setProperty('background-color', UI_CONFIG.BUTTON_COLORS.MARKED, 'important');
            } else {
                // Production build should not have logs.
            }
        }
    }

    #handleDoctorStatusClick() {
        autoRxService.isTimerEnabled = !autoRxService.isTimerEnabled;
        const isActive = autoRxService.isTimerEnabled;
        ui.updateTimerStatus(isActive);
    }

    async #handleWorkStatusClick() {
        try {
            // 根据当前按钮状态决定要发送的请求
            // 如果当前显示"开诊"，点击后发送开诊请求，然后变为"关诊"
            // 如果当前显示"关诊"，点击后发送关诊请求，然后变为"开诊"
            const workStatus = this.isWorkStatusOpen ? 1 : 2; // 当前状态对应的API请求
            
            // 调用API
            await apiService.changeWorkStatus(workStatus);
            
            // 切换UI状态
            this.isWorkStatusOpen = !this.isWorkStatusOpen;
            ui.updateWorkStatus(this.isWorkStatusOpen);
            
            console.log(`发送${workStatus === 1 ? '开诊' : '关诊'}请求，按钮状态切换为: ${this.isWorkStatusOpen ? '开诊' : '关诊'}`);
        } catch (error) {
            console.error('切换工作状态失败:', error);
        }
    }

    #handlePanelToggleClick() {
        // 切换面板显示状态
        this.isRightPanelVisible = !this.isRightPanelVisible;
        
        // 更新UI
        ui.toggleRightPanel(this.isRightPanelVisible);
        
        // 保存状态到本地存储
        this.#savePanelState();
        
        console.log(`右侧面板状态切换为: ${this.isRightPanelVisible ? '显示' : '隐藏'}`);
    }

    /**
     * 初始化面板状态
     */
    async #initializePanelState() {
        try {
            // 从本地存储读取面板状态
            const savedState = await this.#loadPanelState();
            if (savedState !== null) {
                this.isRightPanelVisible = savedState;
            }
            
            // 应用状态
            ui.toggleRightPanel(this.isRightPanelVisible);
        } catch (error) {
            console.error('初始化面板状态失败:', error);
        }
    }

    /**
     * 保存面板状态到本地存储
     */
    #savePanelState() {
        try {
            localStorage.setItem('dr-helper-panel-visible', JSON.stringify(this.isRightPanelVisible));
        } catch (error) {
            console.error('保存面板状态失败:', error);
        }
    }

    /**
     * 从本地存储加载面板状态
     */
    async #loadPanelState() {
        try {
            const saved = localStorage.getItem('dr-helper-panel-visible');
            return saved ? JSON.parse(saved) : null;
        } catch (error) {
            console.error('加载面板状态失败:', error);
            return null;
        }
    }

    /**
     * 启动面板自动检测和隐藏
     */
    #startPanelAutoHide() {
        // 每500ms检查一次面板是否存在，如果存在且应该隐藏，则自动隐藏
        setInterval(() => {
            if (!this.isRightPanelVisible) {
                // 检查面板是否存在
                const rightPanel = document.querySelector('div[style*="border-left: 1px solid rgb(204, 204, 204)"][style*="position: absolute"][style*="right: 0px"][style*="top: 0px"]') ||
                                 document.querySelector('.plugin-container');
                
                if (rightPanel && rightPanel.style.display !== 'none') {
                    console.log('检测到面板显示，自动隐藏');
                    ui.toggleRightPanel(false);
                }
            }
        }, 500);
    }

    #handleAutoRxClick() {
        if (this.isAutoRxRunning) {
            this.stopAutoRxLoop();
        } else {
            this.startAutoRxLoop();
        }
    }

    startAutoRxLoop() {
        this.isAutoRxRunning = true;
        ui.updateAutoRxStatus(true);

        const run = async () => {
            if (!this.isAutoRxRunning) return;
            await autoRxService.runFullProcedure();
            // Schedule next run
            if (this.isAutoRxRunning) {
                const delay = getRandomDelay(5000, 10000); // Use random delay
                this.autoRxIntervalId = setTimeout(run, delay);
            }
        };

        run(); // Start immediately
    }

    stopAutoRxLoop() {
        this.isAutoRxRunning = false;
        ui.updateAutoRxStatus(false);
        if (this.autoRxIntervalId) {
            clearTimeout(this.autoRxIntervalId);
            this.autoRxIntervalId = null;
        }
    }
}

export const eventService = new EventService();
