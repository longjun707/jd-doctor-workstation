
// page/config.js

// Audio notification for new patients
export const NOTIFICATION_SOUND_URL = 'https://img.tukuppt.com//newpreview_music//01//66//41//63c0e76601774734.mp3';

// --- UI Configuration ---
export const UI_CONFIG = {
    BUTTON_STATE: {
        IDLE: '待标记',
    },
    BUTTON_COLORS: {
        IDLE: 'rgb(76, 175, 80)',      // Green - 空闲状态
        NOTIFIED: 'rgb(255, 0, 0)',    // Red - 自动标记（倒计时触发）
        MARKED: 'rgb(255, 165, 0)',    // Orange-Yellow - 手动标记（用户点击）
        CLEAR: 'rgb(46, 139, 87)',     // Dark Green - 清除按钮
    },
    PRESCRIPTION_BUTTON_STATE: {
        IDLE: '开方',
        ACTIVE: '开方中',
    },
    PRESCRIPTION_BUTTON_COLORS: {
        IDLE: 'rgb(30, 144, 255)',     // Blue
        ACTIVE: 'rgb(30, 144, 255)',      // Blue (Same as IDLE)
    },
    WORK_STATUS_BUTTON_STATE: {
        OPEN: '开诊',
        CLOSED: '关诊',
    },
    WORK_STATUS_BUTTON_COLORS: {
        OPEN: 'rgb(76, 175, 80)',      // Green - 开诊状态
        CLOSED: 'rgb(255, 87, 34)',    // Orange-Red - 关诊状态
    },
    PANEL_TOGGLE_BUTTON_STATE: {
        SHOW: '◀',     // 显示面板（向左箭头）
        HIDE: '▶',     // 隐藏面板（向右箭头）
    },
    PANEL_TOGGLE_BUTTON_COLORS: {
        NORMAL: 'rgb(52, 152, 219)',   // Blue - 正常状态
        HOVER: 'rgb(41, 128, 185)',    // Dark Blue - 悬停状态
    },
    TIMER_STATUS_COLORS: {
        ACTIVE: 'rgb(30, 144, 255)',  // Blue
        INACTIVE: 'rgb(46, 139, 87)', // Dark Green
    }
};

// --- API & Security Configuration ---
export const API_CONFIG = {
    BASE_URL: "https://api.m.jd.com/api",
    TENANT_ID: "JD10004003",
    APP_ID: "JDDoctorPC",
    SECURITY_LIBS: {
        CRYPTO_JS: 'https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js',
        PARAMS_SIGN: 'https://storage.360buyimg.com/webcontainer/js_security_v3_0.1.5.js'
    },
    // functionId -> appId mapping for h5st signature
    SIGN_MAP: {
        'rx_ppdoctor_saveRx': 'f1f4b',
        'ppdoctor_queryRxDetailByRxIdPost': '2baa1',
        'rx_ppdoctor_confirmRxForPc': '3796d',
        'rx_ppdoctor_submitRx': 'b17ef',
        'JDDPC_RX_assessCompletelyRxSku': '8b518'
    }
};

// --- 批量开药配置 ---
export const BATCH_RX_CONFIG = {
    // 并行处理阈值（≤10个订单并行处理，>10个订单串行处理）
    PARALLEL_THRESHOLD: 10,
    
    // 批量处理的最大订单数
    MAX_BATCH_SIZE: 100
};

// --- Custom Backend API ---
export const MY_BACKEND_CONFIG = {
    BASE_URL: 'http://117.72.208.155:7031/api', // Your actual backend server address
    VALIDATE_DOCTOR: '/validate-doctor'
};

// --- DOM Selectors ---
export const SELECTORS = {
    // Patient/Doctor Info
    CURRENT_PATIENT_NAME: '#im-Box > div.page.im-page > div.page-inner > div._1bw4iCipVXN5AWILItsaJ_ > div > div._1VYBOIoeTkGqX9UAuBnVsc > div._2IylWrUfASNqCIYanc0PA > div.NU3ykBsGY13lNX0uqJZGI',
    DOCTOR_NAME: '#root > div.view.main-view > div > div.view-main > div.view-header > div > div.rr-content > div > div.doctor-state-info > div.name',
    PATIENT_LIST_CONTAINER: '#root > div.view.main-view > div > div.view-main > div.view-body > div > div > div.page-block.diag-im-col > div.page-left > div.panel.diag-order-panel > div > div.panel-body > div > div > div > div > div > div',
    PATIENT_LIST_ITEM: '.contact-item',
    PATIENT_NAME_IN_LIST: '.name',
    PATIENT_COUNTDOWN_IN_LIST: '.ant-statistic-content-value, [class*="countdown"], [class*="time"], [class*="timer"]',

    // Patient search
    SEARCH_PATIENT_TAB: '#root > div.view.main-view > div > div.view-main > div.view-body > div > div > div.page-block.diag-im-col > div.page-left > div.panel.diag-order-panel > div > div.panel-header > ul > li:nth-child(4) > button > span',
    SEARCH_PATIENT_INPUT: '#root > div.view.main-view > div > div.view-main > div.view-body > div > div > div.page-block.diag-im-col > div.page-left > div.panel.diag-order-panel > div > div.panel-body > div > div > div._1WBxIUtuFVz7wbu6xLeY0U > div._2FtdmfZ8q8TMrcK8uJG8qV > input',
};
