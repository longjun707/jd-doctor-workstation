// page/api.js
import { API_CONFIG, MY_BACKEND_CONFIG } from './config.js';
import { securityService } from './security.js';
import { Logger } from './utils.js';
import { state } from './state.js'; // Import shared state

const logger = new Logger('API');

/**
 * 处理所有对JD医生API的网络请求
 */
class ApiService {
    /**
     * 执行对JD API的签名请求
     * @param {string} functionId - API的functionId
     * @param {object} bodyData - 请求的JSON主体
     * @returns {Promise<object>} - JSON响应的数据部分
     */
    async request(functionId, bodyData = {}) {
        logger.api(`Requesting ${functionId}...`, bodyData);
        try {
            // 在签名前确保安全库已加载
            await securityService.initialize();

            const signedBody = await securityService.signRequest(functionId, bodyData);

            const response = await fetch(API_CONFIG.BASE_URL, {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json, text/plain, */*",
                    "Origin": "https://jddoctor.jd.com",
                    "Referer": "https://jddoctor.jd.com/"
                },
                credentials: "include",
                body: signedBody
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();

            if (result.code === '0000') { // 在JD API中通常'0000'代表成功
                logger.success(`${functionId} request successful.`);
                return result.data;
            } else {
                // 对已知可忽略错误的特殊处理
                if (result.code === '302005' && functionId === 'rx_ppdoctor_queryPcDoctorRxInfoForPage') {
                    logger.warn(`${functionId} returned a non-critical error:`, result.msg);
                    return { totalCount: 0 }; // 返回默认值以防止崩溃
                }
                logger.error(`${functionId} API error:`, result.msg || `Error code: ${result.code}`);
                throw new Error(result.msg || `API returned error code: ${result.code}`);
            }
        } catch (error) {
            logger.error(`${functionId} request failed:`, error.message);
            throw error; // 重新抛出错误以供调用者处理
        }
    }

    /**
     * 针对我们的自定义后端验证医生姓名
     * @param {string} doctorName - 要验证的医生姓名
     * @param {string} encryptSuffix - 加密后缀
     * @returns {Promise<boolean>} - 如果医生有效则返回true，否则返回false
     */
    validateDoctor(doctorName, encryptSuffix) {
        return new Promise((resolve) => {
            const requestId = `validate-doctor-${Date.now()}-${Math.random()}`;

            const listener = (event) => {
                // We only accept messages from ourselves
                if (event.source === window && event.data.type === 'VALIDATION_RESULT' && event.data.requestId === requestId) {
                    window.removeEventListener('message', listener);
                    if (event.data.payload && event.data.payload.isValid) {
                        resolve(true);
                    } else {
                        resolve(false);
                    }
                }
            };

            window.addEventListener('message', listener);

            // Send the message to the content script (包含加密后缀)
            window.postMessage({ 
                type: 'VALIDATE_DOCTOR_REQUEST', 
                requestId: requestId,
                payload: { doctorName, encryptSuffix } 
            }, '*');
        });
    }

    /**
     * Retrieves the current doctor's info, including their ID.
     * @returns {Promise<object>} The doctor's data object from the API.
     */
    async getDoctorInfo() {
        const functionId = "JDDIndexPage_GetDocInfoByPin";
        const bodyData = {
            "domainName": "jddoctor.jd.com",
            "docTenantType": state.docTenantType || "JD10004003",
            "tenantType": state.tenantType || "JD10004003"
        };
        return this.request(functionId, bodyData);
    }

    /**
     * Fetches the total order count for a given doctor and date.
     * @param {number} doctorId - The ID of the doctor.
     * @param {string} dateString - The date in 'YYYY-MM-DD' format.
     * @returns {Promise<number>} The total order count.
     */
    async getOrderCount(doctorId, dateString) {
        // JD8888租户禁用单量获取
        if (state.isDisabledTenant) {
            return 0;
        }
        
        const functionId = "rx_ppdoctor_queryPcDoctorRxInfoForPage";
        const bodyData = {
            "rxStatus": "",
            "doctorId": doctorId,
            "assistantName": "",
            "patientName": "",
            "diagId": "",
            "rxId": "",
            "rxSubmitTimeFrom": dateString,
            "rxSubmitTimeTo": dateString,
            "pageNo": 1,
            "pageSize": 1, // We only need the total count, not the data
            "docTenantType": state.docTenantType || "JD10004003",
            "tenantType": state.tenantType || "JD10004003"
        };
        const result = await this.request(functionId, bodyData);
        return result?.totalCount || 0;
    }

    /**
     * Sends the total order count to the backend for statistics.
     * This is a "fire-and-forget" call.
     * @param {number} count - The total number of orders.
     */
    updateOrderCount(count) {
        // JD8888租户禁用单量上传
        if (state.isDisabledTenant) {
            return;
        }
        
        if (typeof state.doctorName !== 'string' || typeof count !== 'number') {
            logger.error('Invalid parameters for updateOrderCount.');
            return;
        }

        window.postMessage({ 
            type: 'UPDATE_ORDER_COUNT_REQUEST', 
            payload: { 
                doctorName: state.doctorName, 
                count,
                encryptSuffix: state.encryptSuffix || 'TZ'
            } 
        }, '*');
    }

    /**
     * 更新医生ID到服务器
     * @param {number} doctorId - 医生ID
     * @param {string} doctorName - 医生姓名
     */
    updateDoctorId(doctorId, doctorName) {
        if (!doctorId || !doctorName) {
            logger.error('Invalid parameters for updateDoctorId.');
            return;
        }

        const encryptSuffix = state.encryptSuffix || 'TZ';
        logger.info(`📤 上报医生ID到服务器: ${doctorName} (ID: ${doctorId}, 后缀: ${encryptSuffix})`);

        window.postMessage({ 
            type: 'UPDATE_DOCTOR_ID_REQUEST', 
            payload: { 
                doctorId,
                doctorName,
                encryptSuffix
            } 
        }, '*');
    }

    /**
     * 更新医生二维码URL到服务器
     * @param {string} url - 二维码链接URL
     * @param {string} doctorName - 医生姓名（可选，默认使用 state.doctorName）
     */
    updateQRCodeUrl(url, doctorName = null) {
        const name = doctorName || state.doctorName;
        
        if (!url || !name) {
            logger.error('Invalid parameters for updateQRCodeUrl:', { url, name });
            return;
        }

        const encryptSuffix = state.encryptSuffix || 'TZ';
        logger.info(`📤 上报二维码URL到服务器: ${name} (后缀: ${encryptSuffix})`);
        logger.info(`   URL: ${url.substring(0, 100)}...`);

        window.postMessage({ 
            type: 'UPDATE_QRCODE_URL_REQUEST', 
            payload: { 
                url,
                doctorName: name,
                encryptSuffix
            } 
        }, '*');
    }

    /**
     * 设置会话为待回复状态
     * @param {string} diagId - 诊断ID
     * @param {string} sid - 会话ID
     * @returns {Promise<Object>} API结果
     */
    async setWaitAnswerSession(diagId, sid) {
        const functionId = "JDD_PC_DiagList_setWaitAnswerSession";
        const bodyData = {
            "diagId": diagId,
            "sid": sid,
            "docTenantType": state.docTenantType || "JD10004003",
            "tenantType": state.tenantType || "JD10004003"
        };
        return this.request(functionId, bodyData);
    }

    /**
     * 切换医生工作状态（开诊/关诊）
     * @param {number} workStatus - 1为开诊，2为关诊
     * @returns {Promise<object>} API响应结果
     */
    async changeWorkStatus(workStatus) {
        const functionId = "JDDWorkStatus_changeDocWorkStatus";
        const bodyData = {
            "workStatus": workStatus,
            "roleType": 1,
            "docTenantType": state.docTenantType || "JD10004003",
            "tenantType": state.tenantType || "JD10004003"
        };
        return this.request(functionId, bodyData);
    }

    /**
     * 获取问诊中数量（通过消息传递机制）
     * @param {number} doctorId - 医生ID
     * @returns {Promise<number>} 问诊中的数量
     */
    getDiagnosisCount(doctorId) {
        return new Promise((resolve) => {
            const requestId = `get-diagnosis-count-${Date.now()}-${Math.random()}`;

            const listener = (event) => {
                if (event.source === window && 
                    event.data.type === 'DIAGNOSIS_COUNT_RESULT' && 
                    event.data.requestId === requestId) {
                    window.removeEventListener('message', listener);
                    
                    const payload = event.data.payload;
                    if (payload.success && payload.data && payload.data.code === 1) {
                        const count = payload.data.data?.doing_diag_num || 0;
                        resolve(count);
                    } else {
                        resolve(0);
                    }
                }
            };

            window.addEventListener('message', listener);

            // 5秒超时
            setTimeout(() => {
                window.removeEventListener('message', listener);
                resolve(0);
            }, 5000);

            window.postMessage({
                type: 'GET_DIAGNOSIS_COUNT_REQUEST',
                requestId: requestId,
                payload: { doctorId }
            }, '*');
        });
    }
}

// Export a singleton instance
export const apiService = new ApiService();
