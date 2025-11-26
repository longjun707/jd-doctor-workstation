// page/ui.js
import { UI_CONFIG, SELECTORS, MARK_SOUND_URL } from './config.js';
import { Logger } from './utils.js';

/**
 * 管理扩展的所有DOM元素和UI更新
 */
class UI {
    constructor() {
        this.elements = {};
        this.patientButtonMap = new Map(); // 患者姓名到按钮元素的映射
        this.originalLayoutStyles = null; // 保存原始布局样式
        this.lastDiagnosisCount = 0; // 上次问诊数量
        this.lastCountChangeTime = Date.now(); // 上次数量变化时间
        this.diagnosisCheckTimer = null; // 问诊数量检查定时器
        this.isAlertMode = false; // 是否处于红色警告模式
        this.STORAGE_KEY = 'dr-helper-marked-patients'; // localStorage key
    }

    /**
     * 创建初始UI元素并将其注入到页面中
     * @param {boolean} isDisabledTenant - 是否为禁用租户（JD8888等）
     */
    createInitialUI(isDisabledTenant = false) {
        this.#createStyles();
        this.#createButtonsContainer();
        this.#createStatusLabels(isDisabledTenant); // 传递参数
        // this.#createPanelToggleButton(); // 已移除面板切换按钮，使用自动窗口大小调整
        this.#setupAutoMarkListener();
        
        // 延迟启动保护，确保元素已经创建完成
        setTimeout(() => {
            this.#startGlobalPositionProtection();
            this.#debugUIElements();
            this.#startPageScrollControl();
        }, 1000);
    }

    /**
     * 设置自动标记事件监听器
     */
    #setupAutoMarkListener() {
        document.addEventListener('autoMarkPatient', (event) => {
            const { displayText, patientName, orderId, reason } = event.detail;
            this.#autoMarkPatient(displayText || patientName, reason);
        });
    }

    /**
     * 自动标记患者（由定时器触发）
     * @param {string} displayText 显示文本（患者名+分类）
     * @param {string} reason 标记原因
     */
    #autoMarkPatient(displayText, reason) {
        try {
            // 查找可用的按钮（空闲状态的按钮）
            const availableButton = this.#findAvailablePatientButton();
            
            if (availableButton) {
                // 设置按钮文本和颜色（显示完整的 "患者名+分类"）
                availableButton.textContent = displayText;
                availableButton.style.setProperty('background-color', UI_CONFIG.BUTTON_COLORS.NOTIFIED, 'important');
                
                // 添加到映射中（使用 displayText 作为 key，避免重复显示）
                this.patientButtonMap.set(displayText, availableButton);
                
                // 保存到 localStorage
                this.#saveMarkedPatients();
                
                console.log(`自动标记: ${displayText} (原因: ${reason})`);
                
                // 播放标记提醒声音
                this.#playMarkSound();
            } else {
                console.warn(`无可用按钮标记: ${displayText}`);
            }
        } catch (error) {
            console.error('自动标记患者失败:', error);
        }
    }

    /**
     * 查找可用的患者按钮（空闲状态）
     * @returns {HTMLElement|null} 可用的按钮元素
     */
    #findAvailablePatientButton() {
        for (let i = 1; i <= 3; i++) {
            const button = this.elements[`patientButton${i}`];
            if (button && button.textContent === UI_CONFIG.BUTTON_STATE.IDLE) {
                return button;
            }
        }
        return null;
    }

    /**
     * 播放标记提醒声音（通过 content script）
     */
    #playMarkSound() {
        try {
            console.log('🔊 请求播放音频');
            // 发送消息给 content script 播放音频
            window.postMessage({ type: 'PLAY_MARK_AUDIO' }, '*');
        } catch (error) {
            console.error('❌ 发送播放音频请求失败:', error);
        }
    }

    /**
     * 为UI元素注入必要的CSS样式
     */
    #createStyles() {
        const styles = `
            /* 防止页面水平滚动 */
            html, body {
                overflow-x: hidden !important;
                max-width: 100vw !important;
            }
            
            /* 确保所有容器不会溢出 */
            * {
                max-width: 100% !important;
            }
            
            .dr-helper-button {
                background-color: #4CAF50 !important;
                color: white !important;
                padding: 6px 12px !important;
                font-size: 18px !important;
                margin: 1px !important;
                cursor: pointer !important;
                border-radius: 5px !important;
                border: none !important;
                transition: background-color 0.3s !important;
            }
            .dr-helper-status-label {
                position: fixed !important;
                color: white !important;
                padding: 10px !important;
                font-size: 24px !important;
                border-radius: 5px !important;
                border: none !important;
                cursor: pointer !important;
                z-index: 999999 !important;
                transition: background-color 0.3s !important;
            }
            .dr-helper-container {
                position: fixed !important;
                left: 10px !important;
                z-index: 999999 !important;
                pointer-events: auto !important;
                transform: none !important;
            }
        `;
        const styleSheet = document.createElement("style");
        styleSheet.type = "text/css";
        styleSheet.innerText = styles;
        document.head.appendChild(styleSheet);
    }

    /**
     * 为患者标记按钮创建左上角容器
     */
    #createButtonsContainer() {
        const container = document.createElement('div');
        container.id = "dr-helper-buttons-container";
        container.className = "dr-helper-container";
        container.style.cssText = "top: 10px !important; padding: 5px !important; background-color: transparent !important; border: none !important;";
        
        // 创建3个患者按钮和1个清除按钮
        for (let i = 1; i <= 3; i++) {
            const button = this.#createButton(`patient-button-${i}`, UI_CONFIG.BUTTON_STATE.IDLE, UI_CONFIG.BUTTON_COLORS.IDLE);
            this.elements[`patientButton${i}`] = button;
            container.appendChild(button);
        }
        const clearButton = this.#createButton('clear-button', '清除', UI_CONFIG.BUTTON_COLORS.CLEAR);
        this.elements.clearButton = clearButton;
        container.appendChild(clearButton);

        document.body.appendChild(container);
        this.elements.buttonsContainer = container;
        
        // 延迟恢复标记的患者，确保 DOM 完全准备好
        setTimeout(() => {
            this.#restoreMarkedPatients();
        }, 100);
        
        // 简化的位置保护 - 仅针对顶部容器
        this.#protectTopContainer(container);
    }

    /**
     * 为医生姓名、工作状态和自动开药状态创建左下角状态标签
     * @param {boolean} isDisabledTenant - 是否为禁用租户（JD8888等）
     */
    #createStatusLabels(isDisabledTenant = false) {
        // 创建一个包装容器用于相对定位
        const doctorLabelWrapper = document.createElement('div');
        doctorLabelWrapper.id = 'doctor-label-wrapper';
        doctorLabelWrapper.style.cssText = `
            position: fixed !important;
            bottom: 10px !important;
            left: 10px !important;
            z-index: 999999 !important;
            display: inline-block !important;
        `;
        
        // 注意：不使用 #createButton，因为它会设置 textContent，会清空子元素
        const doctorLabel = document.createElement('button');
        doctorLabel.id = 'doctor-status-label';
        doctorLabel.className = 'dr-helper-status-label';
        // 创建文本节点而不是使用 textContent
        doctorLabel.appendChild(document.createTextNode('加载中...'));
        doctorLabel.style.cssText = `
            position: relative !important;
            color: white !important;
            padding: 10px !important;
            font-size: 24px !important;
            border-radius: 5px !important;
            border: none !important;
            cursor: pointer !important;
            background-color: ${UI_CONFIG.TIMER_STATUS_COLORS.ACTIVE} !important;
            display: block !important;
            visibility: visible !important;
            opacity: 1 !important;
        `;
        this.elements.doctorStatusLabel = doctorLabel;

        // 创建问诊数量角标（显示在右上角）
        const diagnosisBadge = document.createElement('span');
        diagnosisBadge.id = 'diagnosis-count-badge';
        diagnosisBadge.textContent = '0'; // 默认显示0
        diagnosisBadge.style.cssText = `
            position: absolute !important;
            top: -14px !important;
            right: -10px !important;
            background-color: rgb(255, 87, 34) !important;
            color: white !important;
            padding: 4px 10px !important;
            font-size: 16px !important;
            font-weight: bold !important;
            border-radius: 12px !important;
            border: 2px solid white !important;
            display: block !important;
            visibility: visible !important;
            min-width: 28px !important;
            text-align: center !important;
            box-shadow: 0 2px 5px rgba(0,0,0,0.3) !important;
            line-height: 1.2 !important;
        `;
        this.elements.diagnosisBadge = diagnosisBadge;
        console.log('✅ 问诊徽章已创建:', diagnosisBadge);
        
        // 组装：wrapper -> label -> badge
        doctorLabel.appendChild(diagnosisBadge);
        console.log('✅ 徽章已添加到医生标签，父元素:', diagnosisBadge.parentElement?.id);
        doctorLabelWrapper.appendChild(doctorLabel);
        console.log('✅ 医生标签已添加到 wrapper');
        this.elements.doctorLabelWrapper = doctorLabelWrapper;

        const workStatusLabel = this.#createButton('work-status-label', UI_CONFIG.WORK_STATUS_BUTTON_STATE.OPEN, UI_CONFIG.WORK_STATUS_BUTTON_COLORS.OPEN, 'dr-helper-status-label');
        workStatusLabel.style.cssText = `
            position: fixed !important;
            bottom: 80px !important;
            left: 10px !important;
            z-index: 999999 !important;
            color: white !important;
            padding: 10px !important;
            font-size: 24px !important;
            border-radius: 5px !important;
            border: none !important;
            cursor: pointer !important;
            background-color: ${UI_CONFIG.WORK_STATUS_BUTTON_COLORS.OPEN} !important;
            display: block !important;
            visibility: visible !important;
            opacity: 1 !important;
        `;
        this.elements.workStatusLabel = workStatusLabel;

        document.body.appendChild(doctorLabelWrapper);
        console.log('✅ wrapper 已添加到 body');
        
        // 添加点击事件：点击医生标签恢复颜色
        doctorLabel.addEventListener('click', () => {
            if (this.isAlertMode) {
                this.#resetDoctorLabelColor();
                this.lastCountChangeTime = Date.now(); // 重置计时
                console.log('✅ 用户点击医生标签，警告模式已解除');
            }
        });
        
        // 启动问诊数量监控定时器
        this.#startDiagnosisMonitor();
        
        // 验证徽章是否在DOM中
        setTimeout(() => {
            const badge = document.getElementById('diagnosis-count-badge');
            console.log('🔍 1秒后检查徽章是否在DOM中:', badge ? '找到了' : '未找到');
            if (badge) {
                console.log('徽章详情:', {
                    id: badge.id,
                    textContent: badge.textContent,
                    parent: badge.parentElement?.id,
                    grandParent: badge.parentElement?.parentElement?.id
                });
            }
        }, 1000);
        
        // 只有非禁用租户才创建工作状态和开方按钮
        if (!isDisabledTenant) {
            document.body.appendChild(workStatusLabel);
            
            const rxLabel = this.#createButton('autorx-status-label', UI_CONFIG.PRESCRIPTION_BUTTON_STATE.IDLE, UI_CONFIG.PRESCRIPTION_BUTTON_COLORS.IDLE, 'dr-helper-status-label');
            rxLabel.style.cssText = `
                position: fixed !important;
                bottom: 150px !important;
                left: 10px !important;
                z-index: 999999 !important;
                color: white !important;
                padding: 10px !important;
                font-size: 24px !important;
                border-radius: 5px !important;
                border: none !important;
                cursor: pointer !important;
                background-color: ${UI_CONFIG.PRESCRIPTION_BUTTON_COLORS.IDLE} !important;
                display: block !important;
                visibility: visible !important;
                opacity: 1 !important;
            `;
            this.elements.autoRxStatusLabel = rxLabel;
            document.body.appendChild(rxLabel);
            
            // 包含开方按钮和工作状态按钮的位置保护
            this.#protectBottomElements(doctorLabelWrapper, workStatusLabel, rxLabel);
        } else {
            // JD8888租户：只显示医生名字，隐藏开诊和开方按钮
            console.log('⚠️ JD8888租户：已禁用开诊和开方按钮');
            this.#protectBottomElements(doctorLabelWrapper);
        }
    }

    /**
     * 创建面板切换按钮
     */
    #createPanelToggleButton() {
        const toggleButton = document.createElement('button');
        toggleButton.id = 'panel-toggle-button';
        toggleButton.textContent = UI_CONFIG.PANEL_TOGGLE_BUTTON_STATE.HIDE;
        toggleButton.className = 'dr-helper-panel-toggle';
        toggleButton.style.cssText = `
            position: fixed !important;
            right: 0px !important;
            top: 50% !important;
            transform: translateY(-50%) !important;
            z-index: 999999 !important;
            width: 30px !important;
            height: 60px !important;
            background-color: ${UI_CONFIG.PANEL_TOGGLE_BUTTON_COLORS.NORMAL} !important;
            color: white !important;
            border: none !important;
            border-radius: 5px 0 0 5px !important;
            cursor: pointer !important;
            font-size: 16px !important;
            font-weight: bold !important;
            transition: all 0.3s ease !important;
            box-shadow: -2px 0 5px rgba(0,0,0,0.2) !important;
        `;
        
        // 添加悬停效果
        toggleButton.addEventListener('mouseenter', () => {
            toggleButton.style.backgroundColor = UI_CONFIG.PANEL_TOGGLE_BUTTON_COLORS.HOVER;
        });
        
        toggleButton.addEventListener('mouseleave', () => {
            toggleButton.style.backgroundColor = UI_CONFIG.PANEL_TOGGLE_BUTTON_COLORS.NORMAL;
        });
        
        // 添加调试功能 - 双击按钮显示面板信息
        toggleButton.addEventListener('dblclick', () => {
            this.#debugPanelElements();
        });
        
        this.elements.panelToggleButton = toggleButton;
        document.body.appendChild(toggleButton);
    }

    /**
     * 调试面板元素 - 帮助找到正确的面板
     */
    #debugPanelElements() {
        console.log('=== 面板元素调试 ===');
        
        // 查找所有可能的右侧面板元素
        const candidates = [];
        
        // 查找所有绝对定位且right为0的元素
        const allElements = document.querySelectorAll('*');
        allElements.forEach(element => {
            const style = window.getComputedStyle(element);
            if (style.position === 'absolute' && style.right === '0px') {
                candidates.push({
                    element: element,
                    tagName: element.tagName,
                    className: element.className,
                    id: element.id,
                    textContent: element.textContent ? element.textContent.substring(0, 100) : '',
                    innerHTML: element.innerHTML ? element.innerHTML.substring(0, 200) : ''
                });
            }
        });
        
        console.log('找到的右侧绝对定位元素:', candidates);
        
        // 查找包含特定文本的元素
        const textCandidates = [];
        allElements.forEach(element => {
            if (element.textContent && (
                element.textContent.includes('风险检测') ||
                element.textContent.includes('用药助手') ||
                element.textContent.includes('话术') ||
                element.textContent.includes('智能接诊')
            )) {
                textCandidates.push({
                    element: element,
                    tagName: element.tagName,
                    className: element.className,
                    id: element.id,
                    textContent: element.textContent.substring(0, 100)
                });
            }
        });
        
        console.log('包含特定文本的元素:', textCandidates);
    }

    /**
     * 创建通用按钮的辅助函数
     */
    #createButton(id, text, color, className = 'dr-helper-button') {
        const button = document.createElement('button');
        button.id = id;
        button.textContent = text;
        button.className = className;
        button.style.backgroundColor = color;
        return button;
    }

    /**
     * 保护顶部容器位置
     */
    #protectTopContainer(container) {
        if (!container) return;
        
        const resetPosition = () => {
            container.style.position = 'fixed !important';
            container.style.top = '10px !important';
            container.style.left = '10px !important';
            container.style.zIndex = '999999';
        };
        
        resetPosition();
        
        // 简单的定期检查
        setInterval(resetPosition, 5000);
    }

    /**
     * 保护底部元素位置
     */
    #protectBottomElements(doctorLabelWrapper, workStatusLabel, rxLabel) {
        const resetDoctorLabel = () => {
            if (doctorLabelWrapper) {
                doctorLabelWrapper.style.position = 'fixed !important';
                doctorLabelWrapper.style.bottom = '10px !important';
                doctorLabelWrapper.style.left = '10px !important';
                doctorLabelWrapper.style.zIndex = '999999';
                doctorLabelWrapper.style.display = 'inline-block !important';
                doctorLabelWrapper.style.visibility = 'visible !important';
            }
        };
        
        const resetWorkStatusLabel = () => {
            if (workStatusLabel) {
                workStatusLabel.style.position = 'fixed !important';
                workStatusLabel.style.bottom = '80px !important';
                workStatusLabel.style.left = '10px !important';
                workStatusLabel.style.zIndex = '999999';
                workStatusLabel.style.display = 'block !important';
                workStatusLabel.style.visibility = 'visible !important';
            }
        };
        
        const resetRxLabel = () => {
            if (rxLabel) {
                rxLabel.style.position = 'fixed !important';
                rxLabel.style.bottom = '150px !important';
                rxLabel.style.left = '10px !important';
                rxLabel.style.zIndex = '999999';
                rxLabel.style.display = 'block !important';
                rxLabel.style.visibility = 'visible !important';
            }
        };
        
        // 立即执行
        resetDoctorLabel();
        resetWorkStatusLabel();
        resetRxLabel();
        
        // 定期保护
        setInterval(() => {
            resetDoctorLabel();
            resetWorkStatusLabel();
            resetRxLabel();
        }, 3000);
    }

    /**
     * 调试UI元素 - 检查元素是否正确创建和显示
     */
    #debugUIElements() {
        console.log('=== UI Elements Debug ===');
        
        // 检查底部状态标签
        const doctorLabel = document.getElementById('doctor-status-label');
        const diagnosisBadge = document.getElementById('diagnosis-count-badge');
        const workStatusLabel = document.getElementById('work-status-label');
        const rxLabel = document.getElementById('autorx-status-label');
        
        console.log('Doctor Label:', doctorLabel ? 'Found' : 'NOT FOUND');
        if (doctorLabel) {
            console.log('Doctor Label Styles:', {
                position: doctorLabel.style.position,
                bottom: doctorLabel.style.bottom,
                left: doctorLabel.style.left,
                display: doctorLabel.style.display,
                visibility: doctorLabel.style.visibility,
                zIndex: doctorLabel.style.zIndex
            });
        }
        
        console.log('Diagnosis Badge:', diagnosisBadge ? 'Found' : 'NOT FOUND');
        if (diagnosisBadge) {
            console.log('Diagnosis Badge Styles:', {
                position: diagnosisBadge.style.position,
                top: diagnosisBadge.style.top,
                right: diagnosisBadge.style.right,
                display: diagnosisBadge.style.display,
                visibility: diagnosisBadge.style.visibility,
                textContent: diagnosisBadge.textContent,
                parent: diagnosisBadge.parentElement?.id
            });
        }
        
        const doctorWrapper = document.getElementById('doctor-label-wrapper');
        console.log('Doctor Wrapper:', doctorWrapper ? 'Found' : 'NOT FOUND');
        if (doctorWrapper) {
            console.log('Doctor Wrapper Styles:', {
                position: doctorWrapper.style.position,
                bottom: doctorWrapper.style.bottom,
                left: doctorWrapper.style.left,
                display: doctorWrapper.style.display,
                visibility: doctorWrapper.style.visibility
            });
        }
        
        console.log('Work Status Label:', workStatusLabel ? 'Found' : 'NOT FOUND');
        if (workStatusLabel) {
            console.log('Work Status Label Styles:', {
                position: workStatusLabel.style.position,
                bottom: workStatusLabel.style.bottom,
                left: workStatusLabel.style.left,
                display: workStatusLabel.style.display,
                visibility: workStatusLabel.style.visibility,
                zIndex: workStatusLabel.style.zIndex
            });
        }
        
        console.log('RX Label:', rxLabel ? 'Found' : 'NOT FOUND');
        if (rxLabel) {
            console.log('RX Label Styles:', {
                position: rxLabel.style.position,
                bottom: rxLabel.style.bottom,
                left: rxLabel.style.left,
                display: rxLabel.style.display,
                visibility: rxLabel.style.visibility,
                zIndex: rxLabel.style.zIndex
            });
        }
        
        // 强制重置一次
        if (doctorLabel) {
            doctorLabel.style.cssText = `
                position: fixed !important;
                bottom: 10px !important;
                left: 10px !important;
                z-index: 999999 !important;
                color: white !important;
                padding: 10px !important;
                font-size: 24px !important;
                border-radius: 5px !important;
                border: none !important;
                cursor: pointer !important;
                background-color: rgb(30, 144, 255) !important;
                display: block !important;
                visibility: visible !important;
                opacity: 1 !important;
            `;
        }
        
        if (workStatusLabel) {
            workStatusLabel.style.cssText = `
                position: fixed !important;
                bottom: 80px !important;
                left: 10px !important;
                z-index: 999999 !important;
                color: white !important;
                padding: 10px !important;
                font-size: 24px !important;
                border-radius: 5px !important;
                border: none !important;
                cursor: pointer !important;
                background-color: rgb(76, 175, 80) !important;
                display: block !important;
                visibility: visible !important;
                opacity: 1 !important;
            `;
        }
        
        if (rxLabel) {
            rxLabel.style.cssText = `
                position: fixed !important;
                bottom: 150px !important;
                left: 10px !important;
                z-index: 999999 !important;
                color: white !important;
                padding: 10px !important;
                font-size: 24px !important;
                border-radius: 5px !important;
                border: none !important;
                cursor: pointer !important;
                background-color: rgb(30, 144, 255) !important;
                display: block !important;
                visibility: visible !important;
                opacity: 1 !important;
            `;
        }
    }

    /**
     * 启动页面滚动控制 - 确保页面始终保持在左侧
     */
    #startPageScrollControl() {
        
        // 立即将页面滚动到左侧
        const scrollToLeft = () => {
            if (window.scrollX > 0) {
                window.scrollTo(0, window.scrollY);
            }
            
            // 同时检查所有可能的滚动容器
            const scrollableElements = document.querySelectorAll('*');
            scrollableElements.forEach(element => {
                if (element.scrollLeft > 0) {
                    element.scrollLeft = 0;
                }
            });
        };
        
        // 立即执行一次
        scrollToLeft();
        
        // 监听窗口滚动事件
        const handleScroll = () => {
            // 使用requestAnimationFrame确保平滑性能
            requestAnimationFrame(scrollToLeft);
        };
        
        // 添加滚动监听
        window.addEventListener('scroll', handleScroll, { passive: false });
        
        // 监听触摸滚动（移动设备）
        let startX = 0;
        const handleTouchStart = (e) => {
            startX = e.touches[0].clientX;
        };
        
        const handleTouchMove = (e) => {
            const currentX = e.touches[0].clientX;
            const deltaX = startX - currentX;
            
            // 如果是向右滑动，阻止默认行为
            if (deltaX < 0) {
                e.preventDefault();
                scrollToLeft();
            }
        };
        
        document.addEventListener('touchstart', handleTouchStart, { passive: true });
        document.addEventListener('touchmove', handleTouchMove, { passive: false });
        
        // 监听键盘事件（左右箭头键）
        const handleKeydown = (e) => {
            // 阻止左右箭头键的水平滚动
            if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
                if (e.target.tagName !== 'INPUT' && e.target.tagName !== 'TEXTAREA') {
                    e.preventDefault();
                    scrollToLeft();
                }
            }
        };
        
        document.addEventListener('keydown', handleKeydown);
        
        // 监听鼠标滚轮事件
        const handleWheel = (e) => {
            // 如果是水平滚轮，阻止并恢复位置
            if (Math.abs(e.deltaX) > Math.abs(e.deltaY)) {
                e.preventDefault();
                scrollToLeft();
            }
        };
        
        document.addEventListener('wheel', handleWheel, { passive: false });
        
        // 定期检查并纠正位置（每500ms）
        setInterval(() => {
            scrollToLeft();
        }, 500);
        
        // 监听页面大小变化
        const resizeObserver = new ResizeObserver(() => {
            setTimeout(scrollToLeft, 100);
        });
        
        resizeObserver.observe(document.body);
        
        // 监听DOM变化，可能影响滚动的元素
        const mutationObserver = new MutationObserver(() => {
            setTimeout(scrollToLeft, 100);
        });
        
        mutationObserver.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ['style', 'class']
        });
        

    }

    /**
     * 启动全局位置保护机制
     */
    #startGlobalPositionProtection() {
        // 全局检查所有插件元素的位置
        const globalCheck = () => {
            // 检查所有插件创建的元素
            const pluginElements = document.querySelectorAll('[id^="dr-helper-"], #doctor-label-wrapper, .dr-helper-button, .dr-helper-status-label, .dr-helper-container, .dr-helper-panel-toggle');
            
            pluginElements.forEach(element => {
                if (element.id === 'doctor-label-wrapper') {
                    // wrapper 使用 fixed 定位
                    element.style.position = 'fixed !important';
                    element.style.bottom = '10px !important';
                    element.style.left = '10px !important';
                    element.style.top = '';
                    element.style.right = '';
                    element.style.display = 'inline-block !important';
                    element.style.visibility = 'visible !important';
                } else if (element.style.position === 'fixed' || element.classList.contains('dr-helper-status-label') || element.classList.contains('dr-helper-container') || element.classList.contains('dr-helper-panel-toggle')) {
                    // 确保position固定
                    element.style.position = 'fixed !important';
                    
                    // 特别处理不同位置的元素
                    if (element.id === 'work-status-label') {
                        element.style.bottom = '80px !important';
                        element.style.left = '10px !important';
                        element.style.top = '';
                        element.style.right = '';
                    } else if (element.id === 'autorx-status-label') {
                        element.style.bottom = '150px !important';
                        element.style.left = '10px !important';
                        element.style.top = '';
                        element.style.right = '';
                    } else if (element.id === 'dr-helper-buttons-container') {
                        element.style.top = '10px !important';
                        element.style.left = '10px !important';
                        element.style.bottom = '';
                        element.style.right = '';
                    }
                    // 面板切换按钮已移除
                    // else if (element.id === 'panel-toggle-button') {
                    //     element.style.right = '0px !important';
                    //     element.style.top = '50% !important';
                    //     element.style.transform = 'translateY(-50%) !important';
                    //     element.style.left = '';
                    //     element.style.bottom = '';
                    // }
                }
            });
            
            // 单独保护问诊徽章（角标样式）
            const badge = document.getElementById('diagnosis-count-badge');
            if (badge) {
                badge.style.position = 'absolute !important';
                badge.style.top = '-8px !important';
                badge.style.right = '-8px !important';
                badge.style.display = 'block !important';
                badge.style.visibility = 'visible !important';
            }
        };
        
        // 立即执行一次
        globalCheck();
        
        // 定期执行全局检查（每3秒一次）
        setInterval(globalCheck, 3000);
        
        // 监听页面变化，可能影响元素位置的事件
        const events = ['resize', 'scroll', 'orientationchange'];
        events.forEach(eventName => {
            window.addEventListener(eventName, globalCheck, { passive: true });
        });
        
        // 监听DOM变化，防止页面的JavaScript意外修改我们的元素
        const bodyObserver = new MutationObserver(() => {
            // 延迟执行，让页面变化完成
            setTimeout(globalCheck, 100);
        });
        
        bodyObserver.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ['style', 'class']
        });
    }

    // --- Public Methods for UI Updates ---

    updateDoctorName(name) {
        if (this.elements.doctorStatusLabel) {
            // 找到第一个文本节点并更新，保留子元素（徽章）
            const textNode = Array.from(this.elements.doctorStatusLabel.childNodes).find(node => node.nodeType === Node.TEXT_NODE);
            if (textNode) {
                textNode.textContent = name;
            } else {
                // 如果没有文本节点，创建一个并插入到徽章之前
                const newTextNode = document.createTextNode(name);
                this.elements.doctorStatusLabel.insertBefore(newTextNode, this.elements.doctorStatusLabel.firstChild);
            }
            console.log('✅ 医生姓名已更新为:', name, '，徽章是否还在:', document.getElementById('diagnosis-count-badge') ? '在' : '丢失');
        }
    }

    updateAutoRxStatus(isActive) {
        if (this.elements.autoRxStatusLabel) {
            this.elements.autoRxStatusLabel.textContent = isActive ? UI_CONFIG.PRESCRIPTION_BUTTON_STATE.ACTIVE : UI_CONFIG.PRESCRIPTION_BUTTON_STATE.IDLE;
            this.elements.autoRxStatusLabel.style.backgroundColor = isActive ? UI_CONFIG.PRESCRIPTION_BUTTON_COLORS.ACTIVE : UI_CONFIG.PRESCRIPTION_BUTTON_COLORS.IDLE;
        }
    }

    updateWorkStatus(isOpen) {
        if (this.elements.workStatusLabel) {
            this.elements.workStatusLabel.textContent = isOpen ? UI_CONFIG.WORK_STATUS_BUTTON_STATE.OPEN : UI_CONFIG.WORK_STATUS_BUTTON_STATE.CLOSED;
            this.elements.workStatusLabel.style.backgroundColor = isOpen ? UI_CONFIG.WORK_STATUS_BUTTON_COLORS.OPEN : UI_CONFIG.WORK_STATUS_BUTTON_COLORS.CLOSED;
        }
    }

    /**
     * 切换右侧面板的显示状态
     * @param {boolean} isVisible - 面板是否可见
     */
    toggleRightPanel(isVisible) {
        if (isVisible) {
            // 显示面板 - 还原页面布局
            this.#restorePageLayout();
            
            // 恢复保存的面板
            if (this.savedRightPanel) {
                document.body.appendChild(this.savedRightPanel);
                this.savedRightPanel.style.display = 'block';
                this.savedRightPanel.style.visibility = 'visible';
                this.savedRightPanel.style.opacity = '1';
            }
        } else {
            // 隐藏面板 - 执行页面布局优化
            this.#saveCurrentLayout();
            this.#optimizePageLayout();
            
            // 隐藏面板
            this.#findAndHideRightPanel();
        }
        
        // 面板切换按钮已移除
        // if (this.elements.panelToggleButton) {
        //     this.elements.panelToggleButton.textContent = isVisible ? 
        //         UI_CONFIG.PANEL_TOGGLE_BUTTON_STATE.HIDE : 
        //         UI_CONFIG.PANEL_TOGGLE_BUTTON_STATE.SHOW;
        // }
    }

    /**
     * 保存当前布局状态
     */
    #saveCurrentLayout() {
        if (this.originalLayoutStyles) return; // 已经保存过了
        
        const mainElement = document.querySelector("#root > div.view.main-view > div.view-inner > div.view-main");
        const viewSide = document.querySelector(".view-side");
        const viewInner = document.querySelector(".view-inner");
        
        this.originalLayoutStyles = {};
        
        if (mainElement) {
            this.originalLayoutStyles.main = {
                position: mainElement.style.position,
                zIndex: mainElement.style.zIndex,
                top: mainElement.style.top,
                left: mainElement.style.left,
                width: mainElement.style.width,
                height: mainElement.style.height,
                background: mainElement.style.background
            };
        }
        
        if (viewSide) {
            this.originalLayoutStyles.viewSide = {
                position: viewSide.style.position,
                zIndex: viewSide.style.zIndex,
                left: viewSide.style.left,
                top: viewSide.style.top,
                height: viewSide.style.height
            };
        }
        
        if (viewInner) {
            this.originalLayoutStyles.viewInner = {
                marginLeft: viewInner.style.marginLeft,
                position: viewInner.style.position,
                zIndex: viewInner.style.zIndex
            };
        }
    }

    /**
     * 优化页面布局
     */
    #optimizePageLayout() {
        // 第一步：执行 optimizePageLayering 函数
        this.#optimizePageLayering();
        
        // 第二步：执行全屏优化
        const element = document.querySelector("#root > div.view.main-view > div.view-inner > div.view-main");
        if (element) {
            element.style.position = "fixed";
            element.style.zIndex = "9999";
            element.style.top = "0";
            element.style.left = "0";
            element.style.width = "100vw";
            element.style.height = "100vh";
            element.style.background = "white";
        }
    }

    /**
     * 第一步优化函数
     */
    #optimizePageLayering() {
        const element = document.querySelector("#root > div.view.main-view > div.view-inner > div.view-main");
        const viewSide = document.querySelector(".view-side");
        const viewInner = document.querySelector(".view-inner");
        
        if (element) {
            // 设置主内容区域
            element.style.position = "relative";
            element.style.zIndex = "9999";
            element.style.background = "white";
            
            // 确保侧边栏也在上层
            if (viewSide) {
                viewSide.style.position = "fixed";
                viewSide.style.zIndex = "10000"; // 比主内容更高
                viewSide.style.left = "0";
                viewSide.style.top = "0";
                viewSide.style.height = "100vh";
            }
            
            // 调整主内容区域位置，避免与侧边栏重叠
            if (viewInner) {
                viewInner.style.marginLeft = "335px"; // 侧边栏宽度
                viewInner.style.position = "relative";
                viewInner.style.zIndex = "9999";
            }
        }
    }

    /**
     * 还原页面布局
     */
    #restorePageLayout() {
        if (!this.originalLayoutStyles) return;
        
        const mainElement = document.querySelector("#root > div.view.main-view > div.view-inner > div.view-main");
        const viewSide = document.querySelector(".view-side");
        const viewInner = document.querySelector(".view-inner");
        
        if (mainElement && this.originalLayoutStyles.main) {
            Object.assign(mainElement.style, this.originalLayoutStyles.main);
        }
        
        if (viewSide && this.originalLayoutStyles.viewSide) {
            Object.assign(viewSide.style, this.originalLayoutStyles.viewSide);
        }
        
        if (viewInner && this.originalLayoutStyles.viewInner) {
            Object.assign(viewInner.style, this.originalLayoutStyles.viewInner);
        }
        
        // 清除保存的样式
        this.originalLayoutStyles = null;
    }

    /**
     * 查找并隐藏右侧面板
     */
    #findAndHideRightPanel() {
        // 如果已经有保存的面板引用，直接隐藏
        if (this.savedRightPanel) {
            this.savedRightPanel.style.display = 'none';
            this.savedRightPanel.remove();
            return;
        }
        
        // 尝试多种选择器来找到右侧面板
        let rightPanel = null;
        
        // 方法1: 查找最外层的右侧面板容器
        const allDivs = document.querySelectorAll('div');
        for (let div of allDivs) {
            const style = div.style;
            if (style.position === 'absolute' && 
                style.right === '0px' && 
                style.top === '0px' &&
                style.borderLeft && 
                style.borderLeft.includes('rgb(204, 204, 204)') &&
                div.innerHTML.includes('plugin-container')) {
                rightPanel = div;
                break;
            }
        }
        
        // 方法2: 通过class查找
        if (!rightPanel) {
            rightPanel = document.querySelector('.plugin-container');
        }
        
        // 方法3: 查找包含特定版本号的容器
        if (!rightPanel) {
            const versionElements = document.querySelectorAll('*');
            for (let element of versionElements) {
                if (element.textContent && element.textContent.includes('v25-09-05-01')) {
                    let parent = element;
                    while (parent && parent !== document.body) {
                        if (parent.style.position === 'absolute' && 
                            parent.style.right === '0px' && 
                            parent.style.top === '0px') {
                            rightPanel = parent;
                            break;
                        }
                        parent = parent.parentElement;
                    }
                    if (rightPanel) break;
                }
            }
        }
        
        if (rightPanel) {
            this.savedRightPanel = rightPanel;
            rightPanel.style.display = 'none';
            rightPanel.remove();
        } else {
            console.warn('未找到右侧面板元素');
        }
    }

    updateTimerStatus(isActive) {
        if (this.elements.doctorStatusLabel) {
            // 只保持蓝色，移除绿色状态
            this.elements.doctorStatusLabel.style.backgroundColor = UI_CONFIG.TIMER_STATUS_COLORS.ACTIVE;
        }
    }

    /**
     * 更新问诊数量徽章
     * @param {number} count - 问诊中的数量
     */
    updateDiagnosisCount(count) {
        if (this.elements.diagnosisBadge) {
            this.elements.diagnosisBadge.textContent = count;
            
            // 检查数量是否变化
            if (count !== this.lastDiagnosisCount) {
                this.lastDiagnosisCount = count;
                this.lastCountChangeTime = Date.now();
                
                // 如果数量变化，恢复颜色
                if (this.isAlertMode) {
                    this.#resetDoctorLabelColor();
                }
                
                console.log(`📊 问诊数量已更新: ${count}`);
            }
        }
    }
    
    /**
     * 启动问诊数量监控定时器
     */
    #startDiagnosisMonitor() {
        // 每10秒检查一次
        this.diagnosisCheckTimer = setInterval(() => {
            const currentCount = parseInt(this.elements.diagnosisBadge?.textContent || '0');
            const timeSinceLastChange = Date.now() - this.lastCountChangeTime;
            const oneMinute = 60 * 1000;
            
            // 如果数量>0 且 超过1分钟没变化 且 还未进入警告模式
            if (currentCount > 0 && timeSinceLastChange >= oneMinute && !this.isAlertMode) {
                this.#setDoctorLabelAlert();
                console.log('⚠️ 问诊数量超过1分钟未变化，标签变红');
            }
            
            // 如果数量变为0，恢复颜色
            if (currentCount === 0 && this.isAlertMode) {
                this.#resetDoctorLabelColor();
            }
        }, 10000); // 每10秒检查一次
    }
    
    /**
     * 设置医生标签为红色警告模式
     */
    #setDoctorLabelAlert() {
        if (this.elements.doctorStatusLabel) {
            this.isAlertMode = true;
            this.elements.doctorStatusLabel.style.backgroundColor = 'rgb(220, 38, 38)'; // 红色
            this.elements.doctorStatusLabel.style.cursor = 'pointer';
        }
    }
    
    /**
     * 恢复医生标签颜色
     */
    #resetDoctorLabelColor() {
        if (this.elements.doctorStatusLabel) {
            this.isAlertMode = false;
            this.elements.doctorStatusLabel.style.backgroundColor = 'rgb(30, 144, 255)'; // 蓝色
        }
    }

    addPatientToButton(patientName) {
        if (this.patientButtonMap.has(patientName)) {
            return false; // 已存在
        }

        for (let i = 1; i <= 3; i++) {
            const button = this.elements[`patientButton${i}`];

            if (button && button.textContent === UI_CONFIG.BUTTON_STATE.IDLE) {
                button.textContent = patientName;
                button.style.setProperty('background-color', UI_CONFIG.BUTTON_COLORS.NOTIFIED, 'important');
                this.patientButtonMap.set(patientName, button);
                // 保存到 localStorage
                this.#saveMarkedPatients();
                // 播放标记提醒声音
                this.#playMarkSound();
                return true;
            }
        }
        return false; // 没有空闲按钮
    }
    
    /**
     * 保存标记的患者到 localStorage
     */
    #saveMarkedPatients() {
        try {
            const patients = Array.from(this.patientButtonMap.keys());
            localStorage.setItem(this.STORAGE_KEY, JSON.stringify(patients));
            console.log('💾 保存标记患者到 localStorage:', patients);
        } catch (error) {
            console.error('保存标记患者失败:', error);
        }
    }
    
    /**
     * 公开的保存方法，供外部调用
     */
    saveMarkedPatientsPublic() {
        this.#saveMarkedPatients();
    }
    
    /**
     * 从 localStorage 恢复标记的患者
     */
    #restoreMarkedPatients() {
        try {
            const saved = localStorage.getItem(this.STORAGE_KEY);
            if (saved) {
                const patients = JSON.parse(saved);
                console.log('📋 尝试恢复标记的患者:', patients);
                
                if (patients && patients.length > 0) {
                    patients.forEach((patientName, index) => {
                        if (index < 3) { // 最多3个按钮
                            const button = this.elements[`patientButton${index + 1}`];
                            if (button) {
                                button.textContent = patientName;
                                button.style.setProperty('background-color', UI_CONFIG.BUTTON_COLORS.NOTIFIED, 'important');
                                this.patientButtonMap.set(patientName, button);
                                console.log(`✅ 恢复患者 ${index + 1}: ${patientName}`);
                            } else {
                                console.warn(`❌ 按钮 ${index + 1} 不存在`);
                            }
                        }
                    });
                    console.log('✅ 标记患者恢复完成');
                } else {
                    console.log('ℹ️ 没有需要恢复的患者');
                }
            } else {
                console.log('ℹ️ localStorage 中没有保存的患者数据');
            }
        } catch (error) {
            console.error('❌ 恢复标记患者失败:', error);
        }
    }
    
    clearPatientButtons() {
        for (let i = 1; i <= 3; i++) {
            const button = this.elements[`patientButton${i}`];
            button.textContent = UI_CONFIG.BUTTON_STATE.IDLE;
            button.style.setProperty('background-color', UI_CONFIG.BUTTON_COLORS.IDLE, 'important');
        }
        this.patientButtonMap.clear();
        // 清除 localStorage 中的数据
        this.#saveMarkedPatients();
        console.log('✅ 已清除所有标记患者（包括持久化数据）');
    }

    /**
     * Simulates typing text into the patient search input.
     * @param {string} text The patient name to search for.
     */
    searchForPatient(text) {
        try {
            document.querySelector(SELECTORS.SEARCH_PATIENT_TAB)?.click();

            // Wait for the input element to appear, as the tab switch might cause a re-render
            const interval = setInterval(() => {
                const inputElement = document.querySelector(SELECTORS.SEARCH_PATIENT_INPUT);
                if (inputElement) {
                    clearInterval(interval);
                    const lastValue = inputElement.value;
                    inputElement.value = text;
                    const event = new Event('input', { bubbles: true });
                    // React 15/16 compatibility
                    const tracker = inputElement._valueTracker;
                    if (tracker) {
                        tracker.setValue(lastValue);
                    }
                    inputElement.dispatchEvent(event);
                }
            }, 100); // Check every 100ms

        } catch (error) {
            // Errors are not logged in production.
        }
    }
}

// Export a singleton instance
export const ui = new UI();
