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
     * @returns {Promise<boolean>} - 如果医生有效则返回true，否则返回false
     */
    validateDoctor(doctorName) {
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

            // Send the message to the content script
            window.postMessage({ 
                type: 'VALIDATE_DOCTOR_REQUEST', 
                requestId: requestId,
                payload: { doctorName } 
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
            "docTenantType": "JD10004003",
            "tenantType": "JD10004003"
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
            "docTenantType": "JD10004003",
            "tenantType": "JD10004003"
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
        if (typeof state.doctorName !== 'string' || typeof count !== 'number') {
            logger.error('Invalid parameters for updateOrderCount.');
            return;
        }

        window.postMessage({ 
            type: 'UPDATE_ORDER_COUNT_REQUEST', 
            payload: { doctorName: state.doctorName, count } 
        }, '*');
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
            "docTenantType": "JD10004003",
            "tenantType": "JD10004003"
        };
        return this.request(functionId, bodyData);
    }
}

// Export a singleton instance
export const apiService = new ApiService();
