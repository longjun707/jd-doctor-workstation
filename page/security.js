// page/security.js
import { API_CONFIG } from './config.js';
import { Logger, loadScript } from './utils.js';

const logger = new Logger('SECURITY');

/**
 * Manages the loading of external security libraries and request signing.
 */
class SecurityService {
    constructor() {
        this.isReady = false;
    }

    /**
     * Loads required external libraries like CryptoJS and ParamsSign.
     */
    async initialize() {
        if (this.isReady) return;
        try {
            await Promise.all([
                loadScript(API_CONFIG.SECURITY_LIBS.CRYPTO_JS, () => window.CryptoJS, 'CryptoJS'),
                loadScript(API_CONFIG.SECURITY_LIBS.PARAMS_SIGN, () => window.ParamsSign, 'ParamsSign')
            ]);
            this.isReady = true;
        } catch (error) {
            throw error;
        }
    }

    /**
     * Generates the eid-token required for some API calls.
     * @returns {Promise<string|null>}
     */
    async #generateEidToken() {
        try {
            return await new Promise(resolve => window.getJsToken(res => resolve(res?.jsToken), 0));
        } catch (error) {
            return null;
        }
    }

    /**
     * Generates the h5st signature for a given request body.
     * @param {string} functionId - The API functionId.
     * @param {object} bodyData - The JSON body of the request.
     * @returns {Promise<string|null>}
     */
    async #generateH5st(functionId, bodyData) {
        const appId = API_CONFIG.SIGN_MAP[functionId];
        if (!appId) {
            return null;
        }

        if (!this.isReady || typeof window.ParamsSign === 'undefined' || typeof window.CryptoJS === 'undefined') {
            throw new Error('Security libraries are not initialized.');
        }

        try {
            const ps = new window.ParamsSign({ appId, debug: false, preRequest: false });
            const bodyHash = window.CryptoJS.SHA256(JSON.stringify(bodyData)).toString();
            const { h5st } = await ps.sign({ appid: API_CONFIG.APP_ID, functionId, body: bodyHash });
            return h5st;
        } catch (error) {
            throw error;
        }
    }

    /**
     * Signs a request by adding eid-token and h5st if necessary.
     * @param {string} functionId - The API functionId.
     * @param {object} bodyData - The JSON body of the request.
     * @returns {Promise<object>} - The signed URLSearchParams object.
     */
    async signRequest(functionId, bodyData) {
        const baseParams = { functionId, body: JSON.stringify(bodyData), loginType: "3", appid: API_CONFIG.APP_ID };

        // Only sign if the functionId is in the SIGN_MAP
        if (!API_CONFIG.SIGN_MAP[functionId]) {
            return new URLSearchParams(baseParams);
        }

        const [eidToken, h5st] = await Promise.all([
            this.#generateEidToken(),
            this.#generateH5st(functionId, bodyData)
        ]);

        const signedParams = { ...baseParams, h5st };
        if (eidToken) {
            signedParams['x-api-eid-token'] = eidToken;
        }

        return new URLSearchParams(signedParams);
    }
}

// Export a singleton instance
export const securityService = new SecurityService();
