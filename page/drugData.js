// page/drugData.js
import { Logger } from './utils.js';

const logger = new Logger('DRUG-DATA');

/**
 * 药物数据管理服务
 * 负责从服务器获取敏感药物和病症数据，并提供检测功能
 */
class DrugDataService {
    constructor() {
        this.data = {
            multi_drugs: { names: [] },
            single_drugs: { names: [], by_category: {} },
            symptoms: { names: [], by_category: {} },
            meta: { 
                minor_enabled: false, 
                auto_reply_enabled: false,  // 自动回复开关
                version: '' 
            }
        };
        this.isInitialized = false;
        this.updateIntervalId = null;
        this.tenantType = null; // 租户类型
        this.API_URL = 'http://154.44.25.188:9378/api/medicine/getAllData';
        this.UPDATE_INTERVAL = 5 * 60 * 1000; // 5分钟
        this.LOCAL_VERSION = '4.2.1'; // 本地扩展版本号
    }

    /**
     * 初始化服务：立即获取数据并启动定时更新
     * @param {string} tenantType - 租户类型
     */
    async initialize(tenantType) {
        this.tenantType = tenantType;
        logger.info(`初始化药物数据服务，租户: ${tenantType}`);
        await this.updateData();
        this.startAutoUpdate();
    }

    /**
     * 从服务器获取最新数据（通过 background.js）
     */
    async updateData() {
        try {
            logger.info('正在从服务器获取药物数据...');
            
            const result = await this.#fetchDrugData();
            
            if (result.success && result.data.code === 1 && result.data.data) {
                this.data = result.data.data;
                this.isInitialized = true;
                
                // 版本号检查
                const serverVersion = this.data.meta?.version || '';
                if (serverVersion && serverVersion !== this.LOCAL_VERSION) {
                    this.#showVersionMismatchAlert(serverVersion);
                }
                
                const minorStatus = this.data.meta?.minor_enabled ? '已启用' : '未启用';
                const autoReplyStatus = this.data.meta?.auto_reply_enabled ? '已启用' : '未启用';
                logger.success(`药物数据更新成功！多药物: ${this.data.multi_drugs.count}, 单药物: ${this.data.single_drugs.count}, 症状: ${this.data.symptoms.count}, 未成年检测: ${minorStatus}, 自动回复: ${autoReplyStatus}, 版本: ${serverVersion || '未知'}`);
            } else {
                throw new Error(`数据格式错误: ${result.error || 'Unknown error'}`);
            }
        } catch (error) {
            logger.error('获取药物数据失败，继续使用旧数据:', error.message);
            // 失败时不清空现有数据，继续使用旧数据
        }
    }
    
    /**
     * 显示版本不匹配提醒对话框
     * @param {string} serverVersion - 服务器版本号
     */
    #showVersionMismatchAlert(serverVersion) {
        const message = `版本提醒\n\n服务器版本: ${serverVersion}\n本地版本: ${this.LOCAL_VERSION}\n\n版本不一致，建议更新扩展到最新版本以获得最佳体验。\n\n点击"确定"继续使用。`;
        
        // 使用原生alert对话框
        setTimeout(() => {
            alert(message);
            logger.warn(`版本不匹配：服务器版本 ${serverVersion}，本地版本 ${this.LOCAL_VERSION}`);
        }, 500);
    }
    
    /**
     * 设置租户类型（用于请求药物数据）
     * @param {string} tenantType - 租户类型
     */
    setTenantType(tenantType) {
        this.tenantType = tenantType;
    }

    /**
     * 通过消息传递机制获取药物数据
     */
    #fetchDrugData() {
        return new Promise((resolve) => {
            const requestId = `get-drug-data-${Date.now()}-${Math.random()}`;
            console.log('[drugData.js] 发送药物数据请求，ID:', requestId);
            
            let isResolved = false;

            const listener = (event) => {
                // 只处理 DRUG_DATA_RESULT 类型的消息
                if (isResolved) return;
                if (event.source !== window) return;
                if (event.data.type !== 'DRUG_DATA_RESULT') return;
                if (event.data.requestId !== requestId) return;
                
                console.log('[drugData.js] 收到匹配的药物数据响应:', event.data.payload);
                isResolved = true;
                window.removeEventListener('message', listener);
                resolve(event.data.payload);
            };

            window.addEventListener('message', listener);

            // 15秒超时（增加超时时间）
            const timeoutId = setTimeout(() => {
                if (isResolved) return;
                console.warn('[drugData.js] 药物数据请求超时，requestId:', requestId);
                isResolved = true;
                window.removeEventListener('message', listener);
                resolve({ success: false, error: 'Timeout' });
            }, 15000);

            console.log('[drugData.js] 发送 postMessage，租户:', this.tenantType);
            window.postMessage({ 
                type: 'GET_DRUG_DATA_REQUEST', 
                requestId: requestId,
                payload: { tenantType: this.tenantType }
            }, '*');
        });
    }

    /**
     * 启动自动更新（每5分钟）
     */
    startAutoUpdate() {
        if (this.updateIntervalId) {
            clearInterval(this.updateIntervalId);
        }
        
        this.updateIntervalId = setInterval(() => {
            this.updateData();
        }, this.UPDATE_INTERVAL);
        
        logger.info(`已启动自动更新，间隔: ${this.UPDATE_INTERVAL / 1000}秒`);
    }

    /**
     * 停止自动更新
     */
    stopAutoUpdate() {
        if (this.updateIntervalId) {
            clearInterval(this.updateIntervalId);
            this.updateIntervalId = null;
            logger.info('已停止自动更新');
        }
    }

    /**
     * 获取自动回复开关状态
     * @returns {boolean} 自动回复是否已启用
     */
    isAutoReplyEnabled() {
        return this.data.meta?.auto_reply_enabled === true;
    }

    /**
     * 检测处方中的敏感药物和病症
     * @param {Object} rxDetail - 处方详情对象
     * @returns {Object|null} - 检测结果 { type: 'multi_drugs'|'single_drugs'|'symptoms'|'spec_mismatch'|'minor', category: string } 或 null
     */
    checkPrescription(rxDetail) {
        if (!this.isInitialized) {
            logger.warn('药物数据尚未初始化，跳过检测');
            return null;
        }

        if (!rxDetail) {
            logger.warn('处方详情为空，跳过检测');
            return null;
        }

        // 🔍 0. 检测未成年人（最高优先级）
        const minorResult = this.#checkMinor(rxDetail);
        if (minorResult) {
            return minorResult;
        }

        // 1. 检测多药物（需要匹配到≥2种）
        const multiDrugResult = this.#checkMultiDrugs(rxDetail);
        if (multiDrugResult) {
            return multiDrugResult;
        }

        // 2. 检测单药物
        const singleDrugResult = this.#checkSingleDrugs(rxDetail);
        if (singleDrugResult) {
            return singleDrugResult;
        }

        // 3. 检测病症
        const symptomResult = this.#checkSymptoms(rxDetail);
        if (symptomResult) {
            return symptomResult;
        }

        // 4. 检测规格不匹配
        const specResult = this.#checkSpecificationMismatch(rxDetail);
        if (specResult) {
            return specResult;
        }

        return null; // 未检测到问题
    }

    /**
     * 检测未成年人（年龄<18岁）
     */
    #checkMinor(rxDetail) {
        // 检查是否启用未成年检测
        if (!this.data.meta?.minor_enabled) {
            return null;
        }

        // 提取患者年龄
        const patientAge = this.#extractPatientAge(rxDetail);
        
        if (patientAge === null) {
            logger.warn('无法获取患者年龄，跳过未成年检测');
            return null;
        }

        // 判断是否未成年（<18岁）
        if (patientAge < 18) {
            logger.warn(`检测到未成年患者：年龄 ${patientAge} 岁`);
            return {
                type: 'minor',
                category: '未成年',
                matchedItems: [`年龄${patientAge}岁`]
            };
        }

        return null;
    }

    /**
     * 从处方详情中提取患者年龄
     */
    #extractPatientAge(rxDetail) {
        // 尝试多种可能的年龄字段
        const ageFields = [
            rxDetail.patientAge,
            rxDetail.patientAgeString,
            rxDetail.ageString,
            rxDetail.age
        ];

        for (const ageValue of ageFields) {
            if (ageValue !== undefined && ageValue !== null) {
                // 如果是字符串，尝试提取数字
                if (typeof ageValue === 'string') {
                    const match = ageValue.match(/(\d+)/);
                    if (match) {
                        return parseInt(match[1], 10);
                    }
                }
                // 如果是数字，直接返回
                if (typeof ageValue === 'number') {
                    return ageValue;
                }
            }
        }

        return null; // 无法获取年龄
    }

    /**
     * 检测多药物（匹配到≥2种）
     */
    #checkMultiDrugs(rxDetail) {
        const drugNames = this.#extractDrugNames(rxDetail);
        const multiDrugNames = this.data.multi_drugs.names || [];
        
        let matchCount = 0;
        const matchedDrugs = [];

        for (const drugName of drugNames) {
            for (const sensitiveDrug of multiDrugNames) {
                if (drugName.includes(sensitiveDrug)) {
                    matchCount++;
                    matchedDrugs.push(sensitiveDrug);
                    break; // 一个药品只计数一次
                }
            }
        }

        if (matchCount >= 2) {
            logger.warn(`检测到多药物：${matchedDrugs.join(', ')}`);
            return {
                type: 'multi_drugs',
                category: '多药物',
                matchedItems: matchedDrugs
            };
        }

        return null;
    }

    /**
     * 检测单药物
     */
    #checkSingleDrugs(rxDetail) {
        const drugNames = this.#extractDrugNames(rxDetail);
        const singleDrugs = this.data.single_drugs.list || [];

        for (const drugName of drugNames) {
            for (const sensitiveItem of singleDrugs) {
                if (drugName.includes(sensitiveItem.name)) {
                    const category = sensitiveItem.category || '未分类';
                    logger.warn(`检测到单药物：${sensitiveItem.name}（分类：${category}）`);
                    return {
                        type: 'single_drugs',
                        category: category,
                        matchedItems: [sensitiveItem.name]
                    };
                }
            }
        }

        return null;
    }

    /**
     * 检测病症
     */
    #checkSymptoms(rxDetail) {
        const diagnosisName = rxDetail.diagnosisName || '';
        const symptoms = this.data.symptoms.list || [];

        for (const symptom of symptoms) {
            if (diagnosisName.includes(symptom.name)) {
                const category = symptom.category || '未分类';
                logger.warn(`检测到敏感症状：${symptom.name}（分类：${category}）`);
                return {
                    type: 'symptoms',
                    category: category,
                    matchedItems: [symptom.name]
                };
            }
        }

        return null;
    }

    /**
     * 检测规格不匹配
     */
    #checkSpecificationMismatch(rxDetail) {
        const rxItemDTOS = rxDetail.rxItemDTOS || [];
        
        for (const item of rxItemDTOS) {
            const specificationUnit = item.specificationUnit || '';
            const specificationShow = item.specificationShow || '';
            const drugName = item.drugName || '未知药品';
            
            // 如果 specificationUnit 不为空，且在 specificationShow 中找不到
            if (specificationUnit && !specificationShow.includes(specificationUnit)) {
                logger.warn(`检测到规格不匹配：${drugName}（单位：${specificationUnit}，规格：${specificationShow}）`);
                return {
                    type: 'spec_mismatch',
                    category: '核对用法用量',
                    matchedItems: [`${drugName}(${specificationUnit}≠${specificationShow})`]
                };
            }
        }
        
        return null;
    }

    /**
     * 从处方详情中提取所有药物名称
     */
    #extractDrugNames(rxDetail) {
        const drugNames = [];
        const rxItemDTOS = rxDetail.rxItemDTOS || [];

        for (const item of rxItemDTOS) {
            if (item.drugName) {
                drugNames.push(item.drugName);
            }
        }

        return drugNames;
    }
}

// 导出单例实例
export const drugDataService = new DrugDataService();

