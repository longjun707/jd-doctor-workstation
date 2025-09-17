// page/utils.js

/**
 * A simple and consistent logger.
 */
export class Logger {
    constructor(category = 'SYSTEM') {
        this.category = category;
        this.levels = { 
            INFO: '[INFO]', 
            SUCCESS: '[SUCCESS]', 
            WARN: '[WARN]', 
            ERROR: '[ERROR]', 
            API: '[API]', 
            SECURITY: '[SECURITY]' 
        };
    }

    _formatLog(level, ...args) {
        const time = new Date().toLocaleTimeString('zh-CN', { hour12: false });
        return [`%c${this.levels[level]}%c [${this.category}] [${time}]`, 'font-weight:bold;', 'font-weight:normal;', ...args];
    }

    info(...args) { console.info(...this._formatLog('INFO', ...args)); }
    success(...args) { console.log(...this._formatLog('SUCCESS', ...args)); }
    warn(...args) { console.warn(...this._formatLog('WARN', ...args)); }
    error(...args) { console.error(...this._formatLog('ERROR', ...args)); }
    api(...args) { console.info(...this._formatLog('API', ...args)); }
    security(...args) { console.warn(...this._formatLog('SECURITY', ...args)); }
}

/**
 * A promise-based delay function.
 * @param {number} ms - The number of milliseconds to wait.
 */
export function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Generates a random delay within a given range.
 * @param {number} min - The minimum delay in milliseconds.
 * @param {number} max - The maximum delay in milliseconds.
 * @returns {number} A random delay value.
 */
export function getRandomDelay(min = 5000, max = 10000) {
    return Math.floor(Math.random() * (max - min)) + min;
}

/**
 * Dynamically loads a script and returns a promise.
 * @param {string} url - The URL of the script to load.
 * @param {function} checker - A function that returns true when the script has loaded.
 * @param {string} name - The name of the library for logging.
 * @returns {Promise<void>}
 */
export function loadScript(url, checker, name) {
    return new Promise((resolve, reject) => {
        if (checker()) {
            return resolve();
        }
        const script = document.createElement('script');
        script.src = url;
        script.onload = () => resolve();
        script.onerror = () => reject(new Error(`${name} 加载失败`));
        document.head.appendChild(script);
    });
}

/**
 * Waits for a DOM element to appear on the page.
 * @param {string} selector - The CSS selector for the element.
 * @param {number} timeout - The maximum time to wait in milliseconds.
 * @returns {Promise<Element|null>} The element if found, otherwise null.
 */
export function waitForElement(selector, timeout = 10000) {
    return new Promise(resolve => {
        const interval = 100;
        let time = 0;

        const check = () => {
            const el = document.querySelector(selector);
            if (el) {
                resolve(el);
            } else if (time < timeout) {
                time += interval;
                setTimeout(check, interval);
            } else {
                resolve(null);
            }
        };
        check();
    });
}
