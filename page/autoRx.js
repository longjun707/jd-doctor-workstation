// page/autoRx.js
import { apiService } from './api.js';
import { Logger } from './utils.js';
import { API_CONFIG, BATCH_RX_CONFIG } from './config.js'; // 导入配置
import { state } from './state.js'; // 导入共享状态
import { cacheService } from './cache.js'; // 导入新的缓存服务
import { drugDataService } from './drugData.js'; // 导入药物数据服务

const logger = new Logger('AUTO-RX');

/**
 * 管理整个自动开药流程。
 */
class AutoRxSystem {
    constructor() {
        this.state = {}; // 保存当前开药流程的数据
        this.currentStep = '';
        this.isTimerEnabled = true; // 默认开启
    }

    /**
     * 运行自动开药流程的主入口点 - 支持批量处理
     * @returns {Promise<{success: boolean, message: string, results?: Array}>}
     */
    async runFullProcedure() {
        // 检查租户类型 - JD8888租户禁用开方功能
        if (state.isDisabledTenant) {
            logger.warn('⚠️ JD8888租户：开方功能已禁用');
            return { success: false, message: '该租户不支持自动开方功能' };
        }
        
        try {
            // 获取所有符合条件的订单
            const orderGroups = await this.#getAllValidOrders();
            const { prescribeOrders, markOrders } = orderGroups;
            
            if ((!prescribeOrders || prescribeOrders.length === 0) && (!markOrders || markOrders.length === 0)) {
                return { success: true, message: '没有订单需要处理。' };
            }

            logger.info(`找到 ${prescribeOrders.length} 个开药订单，${markOrders.length} 个标记订单`);

            const results = [];
            let processedCount = 0;

            // 处理开药订单
            if (prescribeOrders.length > 0) {
                const limitedPrescribeOrders = prescribeOrders.slice(0, BATCH_RX_CONFIG.MAX_BATCH_SIZE);
                if (prescribeOrders.length > BATCH_RX_CONFIG.MAX_BATCH_SIZE) {
                    logger.warn(`开药订单数量超限，只处理前 ${BATCH_RX_CONFIG.MAX_BATCH_SIZE} 个`);
                }

                const prescribeResults = limitedPrescribeOrders.length <= BATCH_RX_CONFIG.PARALLEL_THRESHOLD
                    ? await this.#processOrdersParallel(limitedPrescribeOrders)  // 并行处理
                    : await this.#processOrdersSerial(limitedPrescribeOrders);   // 串行处理
                
                results.push(...prescribeResults);
                processedCount += limitedPrescribeOrders.length;
            }

            // 处理标记订单
            if (markOrders.length > 0) {
                const limitedMarkOrders = markOrders.slice(0, BATCH_RX_CONFIG.MAX_BATCH_SIZE);
                if (markOrders.length > BATCH_RX_CONFIG.MAX_BATCH_SIZE) {
                    logger.warn(`标记订单数量超限，只处理前 ${BATCH_RX_CONFIG.MAX_BATCH_SIZE} 个`);
                }

                const markResults = limitedMarkOrders.length <= BATCH_RX_CONFIG.PARALLEL_THRESHOLD
                    ? await this.#processMarkOrdersParallel(limitedMarkOrders)  // 并行标记
                    : await this.#processMarkOrdersSerial(limitedMarkOrders);   // 串行标记
                
                results.push(...markResults);
                processedCount += limitedMarkOrders.length;
            }
            
            const successCount = results.filter(r => r.success).length;
            const prescribeSuccessCount = results.filter(r => r.success && r.action !== 'mark').length;
            const markSuccessCount = results.filter(r => r.success && r.action === 'mark').length;
            
            return {
                success: true,
                message: `批量处理完成：开药成功 ${prescribeSuccessCount} 个，标记成功 ${markSuccessCount} 个，失败 ${results.length - successCount} 个`,
                results: results,
                totalOrders: processedCount,
                prescribeCount: prescribeOrders.length,
                markCount: markOrders.length
            };

        } catch (error) {
            return { success: false, message: error.message, step: this.currentStep };
        }
    }

    /**
     * 并行处理订单（≤10个订单时使用）
     */
    async #processOrdersParallel(orders) {
        logger.info(`并行处理 ${orders.length} 个订单`);
        const promises = orders.map(order => this.#processSingleOrder(order));
        const results = await Promise.allSettled(promises);
        
        return results.map((result, index) => {
            if (result.status === 'fulfilled') {
                return result.value;
            } else {
                return {
                    success: false,
                    orderId: orders[index].orderId,
                    message: result.reason?.message || '处理失败'
                };
            }
        });
    }

    /**
     * 串行处理订单（>10个订单时使用）
     */
    async #processOrdersSerial(orders) {
        logger.info(`串行处理 ${orders.length} 个订单`);
        const results = [];
        
        for (let i = 0; i < orders.length; i++) {
            const order = orders[i];
            try {
                const result = await this.#processSingleOrder(order);
                results.push(result);
                
                // 每个订单间隔1秒（除了最后一个）
                if (i < orders.length - 1) {
                    await new Promise(resolve => setTimeout(resolve, 1000));
                }
            } catch (error) {
                results.push({
                    success: false,
                    orderId: order.orderId,
                    message: error.message || '处理失败'
                });
            }
        }
        
        return results;
    }

    /**
     * 并行处理标记订单（≤10个订单时使用）
     */
    async #processMarkOrdersParallel(orders) {
        logger.info(`并行标记 ${orders.length} 个订单`);
        const promises = orders.map(order => this.#markSingleOrder(order));
        const results = await Promise.allSettled(promises);
        
        return results.map((result, index) => {
            if (result.status === 'fulfilled') {
                return result.value;
            } else {
                return {
                    success: false,
                    orderId: orders[index].orderId,
                    action: 'mark',
                    message: result.reason?.message || '标记失败'
                };
            }
        });
    }

    /**
     * 串行处理标记订单（>10个订单时使用）
     */
    async #processMarkOrdersSerial(orders) {
        logger.info(`串行标记 ${orders.length} 个订单`);
        const results = [];
        
        for (let i = 0; i < orders.length; i++) {
            const order = orders[i];
            try {
                const result = await this.#markSingleOrder(order);
                results.push(result);
                
                // 每个订单间隔500毫秒（标记操作相对轻量）
                if (i < orders.length - 1) {
                    await new Promise(resolve => setTimeout(resolve, 500));
                }
            } catch (error) {
                results.push({
                    success: false,
                    orderId: order.orderId,
                    action: 'mark',
                    message: error.message || '标记失败'
                });
            }
        }
        
        return results;
    }

    /**
     * 处理单个订单的完整流程
     * @param {Object} order 订单对象
     * @returns {Promise<Object>} 处理结果
     */
    async #processSingleOrder(order) {
        try {
            logger.info(`开始处理订单 ${order.orderId}`);

            // 1. 创建处方
            const rxId = await this.#createRx(order);
            
            // 2. 获取处方详情
            const rxDetail = await this.#getRxDetail(rxId);
            
            // 🔍 3. 检测敏感药物和病症
            const checkResult = drugDataService.checkPrescription(rxDetail);
            if (checkResult) {
                const patientName = rxDetail.patientName || '未知患者';
                const alertMessage = `${patientName}+${checkResult.category}`;
                
                logger.warn(`⚠️ 检测到敏感内容：${alertMessage}`);
                
                // 标记患者到UI（左上角按钮）
                await this.#notifyUIToMarkPatient({
                    ...order,
                    patientName: patientName,
                    reason: alertMessage
                });
                
                // 永久跳过此订单（加入缓存）
                cacheService.addProcessedOrder(order.orderId);
                
                return {
                    success: false,
                    orderId: order.orderId,
                    rxId: rxId,
                    action: 'skipped',
                    message: `跳过开方：${alertMessage}`,
                    checkResult: checkResult
                };
            }
            
            // 4. 确认处方（检测重复药品）
            const rxAdvice = await this.#confirmRx(rxId, rxDetail);
            
            // 5. 提交处方
            const result = await this.#submitRx(rxId, rxDetail, rxAdvice);

            // 6. 成功后添加到缓存
            cacheService.addProcessedOrder(order.orderId);

            logger.success(`订单 ${order.orderId} 开药成功`);
            
            return {
                success: true,
                orderId: order.orderId,
                rxId: rxId,
                result: result,
                message: '开药成功'
            };

        } catch (error) {
            // 特殊处理：检测到重复药品
            if (error.isDuplicateDrug) {
                const alertMessage = error.message; // 已格式化为 "患者名+重复药品:药名"
                
                logger.warn(`⚠️ 检测到重复药品，跳过开方：${alertMessage}`);
                
                // 标记患者到UI（左上角按钮）
                await this.#notifyUIToMarkPatient({
                    ...order,
                    patientName: error.patientName,
                    reason: alertMessage
                });
                
                // 永久跳过此订单（加入缓存）
                cacheService.addProcessedOrder(order.orderId);
                
                return {
                    success: false,
                    orderId: order.orderId,
                    rxId: rxId || null,
                    action: 'skipped',
                    message: `跳过开方：${alertMessage}`,
                    duplicateDrugs: error.duplicateDrugs
                };
            }
            
            // 其他错误正常处理
            logger.error(`订单 ${order.orderId} 处理失败:`, error.message);
            return {
                success: false,
                orderId: order.orderId,
                message: error.message
            };
        }
    }

    /**
     * 标记单个订单（不开药）
     * @param {Object} order 订单对象
     * @returns {Promise<Object>} 标记结果
     */
    async #markSingleOrder(order) {
        try {
            logger.info(`开始标记订单 ${order.orderId}`);

            // 模拟标记操作：这里可以添加实际的标记逻辑
            // 例如：通知UI组件标记该患者
            await this.#notifyUIToMarkPatient(order);
            
            // 添加到缓存，避免重复标记
            cacheService.addProcessedOrder(order.orderId);

            logger.success(`订单 ${order.orderId} 标记成功`);
            
            return {
                success: true,
                orderId: order.orderId,
                action: 'mark',
                message: '标记成功'
            };

        } catch (error) {
            logger.error(`订单 ${order.orderId} 标记失败:`, error.message);
            return {
                success: false,
                orderId: order.orderId,
                action: 'mark',
                message: error.message
            };
        }
    }

    /**
     * 通知UI组件标记患者
     * @param {Object} order 订单对象
     */
    async #notifyUIToMarkPatient(order) {
        try {
            // 获取患者姓名和原因
            const patientName = order.patientName || order.sessionContentDto?.patientName || '未知患者';
            const reason = order.reason || '定时器触发标记';
            
            // 向UI组件发送标记事件
            const markEvent = new CustomEvent('autoMarkPatient', {
                detail: {
                    displayText: reason, // 直接使用完整的显示文本（患者名+分类）
                    patientName: patientName,
                    orderId: order.orderId,
                    reason: reason
                }
            });
            
            document.dispatchEvent(markEvent);
            logger.info(`已发送标记事件：${reason}`);
            
        } catch (error) {
            logger.error('通知UI标记失败:', error.message);
            throw error;
        }
    }



    // --- 开药决策的业务逻辑 ---

    #isAlreadyPrescribed(order) {
        // 1. 检查最后消息是否表明已开方
        const lastContent = order.sessionContentDto?.lastContent || '';
        if (lastContent.includes('处方已送达药师审核')) {
            return true; // 已开方
        }
        
        // 2. 检查标签
        const specialLabels = order.pcSpecialLabelList || [];
        
        // 有"复诊续方"标签说明还没开方
        const hasRenewalTag = specialLabels.some(label => 
            label.content === "复诊续方"
        );
        if (hasRenewalTag) {
            return false; // 未开方
        }
        
        // 有"待开方"标签说明还没开方
        const hasPendingPrescription = specialLabels.some(label => 
            label.content === "待开方"
        );
        
        // 有"待开方"标签说明还没开方，返回false；没有则说明已开方，返回true
        return !hasPendingPrescription;
    }

    #hasKeywordsInLastMessage(order) {
        const lastContent = order.sessionContentDto?.lastContent || '';
        const keywords = ['好的', '患者已确认没有补充信息', '已完成患者信息确认环节'];
        return keywords.some(k => lastContent.includes(k));
    }

    #isOrderTimeExceeded(order, minSeconds = 80, maxSeconds = 95) {
        const timeDiff = (Date.now() - order.orderTime) / 1000;
        return timeDiff >= minSeconds && timeDiff <= maxSeconds;
    }

    #shouldPrescribe(order) {
        // --- 新功能：最高优先级的缓存检查 ---
        if (cacheService.isOrderProcessed(order.orderId)) {
            return { should: false, reason: '已处理（在缓存中）' };
        }

        if (this.#isAlreadyPrescribed(order)) {
            return { should: false, reason: '已开药' };
        }
        
        if (this.#hasKeywordsInLastMessage(order)) {
            return { should: true, reason: '关键词匹配' };
        }
        
        return { should: false, reason: '条件不满足' };
    }

    #shouldMark(order) {
        // --- 标记逻辑：基于时间条件进行标记 ---
        if (cacheService.isOrderProcessed(order.orderId)) {
            return { should: false, reason: '已处理（在缓存中）' };
        }

        if (this.#isAlreadyPrescribed(order)) return { should: false, reason: '已开药' };
        if (this.#hasKeywordsInLastMessage(order)) return { should: false, reason: '有关键词，应开药而非标记' };
        // if (this.#isOrderTimeExceeded(order)) return { should: true, reason: '定时器已过，需要标记' };
        return { should: false, reason: '标记条件不满足' };
    }

    // --- 逐步开药流程 ---

    async #getAllValidOrders() {
        const result = await apiService.request("JDD_PC_DiagList_getInDiagList", { 
            tenantType: state.tenantType || "JD10004003", 
            diagScopeType: 3, 
            docTenantType: state.docTenantType || "JD10004003" 
        });
        const orders = result.doctorDiagDtoList || [];
        const prescribeOrders = [];
        const markOrders = [];

        for (const order of orders) {
            if (!order) continue; // 跳过无效订单

            const prescribeDecision = this.#shouldPrescribe(order);
            const markDecision = this.#shouldMark(order);
            
            if (prescribeDecision.should) {
                prescribeOrders.push({ ...order, action: 'prescribe', reason: prescribeDecision.reason });
            } else if (markDecision.should) {
                markOrders.push({ ...order, action: 'mark', reason: markDecision.reason });
            }
        }

        logger.info(`找到 ${prescribeOrders.length} 个开药订单，${markOrders.length} 个标记订单，共 ${orders.length} 个订单`);
        return { prescribeOrders, markOrders };
    }

    // --- 单个订单的开药流程方法 ---

    async #createRx(order) {
        const { diagId, patientId } = order;
        return await apiService.request("rx_ppdoctor_saveRx", { 
            diagId, 
            patientId, 
            rxCreateChannel: 2, 
            tenantType: state.tenantType || "JD10004003", 
            docTenantType: state.docTenantType || "JD10004003" 
        });
    }

    async #getRxDetail(rxId) {
        return await apiService.request("ppdoctor_queryRxDetailByRxIdPost", { 
            rxId, 
            tenantType: state.tenantType || "JD10004003", 
            docTenantType: state.docTenantType || "JD10004003" 
        });
    }

    async #confirmRx(rxId, rxDetail) {
        const drugList = (rxDetail.rxItemDTOS || [])
            .map(drug => ({ 
                ...drug, 
                operateType: 1, 
                class: "com.jd.nethp.rx.doctor.export.jd.dto.RxItemDTO" 
            }))
            .filter(Boolean);

        if (drugList.length === 0) {
            throw new Error('药品列表为空');
        }

        // 🔍 检测重复药品名称
        const drugNames = (rxDetail.rxItemDTOS || []).map(drug => drug.drugName).filter(Boolean);
        const duplicates = drugNames.filter((name, index) => drugNames.indexOf(name) !== index);
        
        if (duplicates.length > 0) {
            const uniqueDuplicates = [...new Set(duplicates)];
            const patientName = rxDetail.patientName || '未知患者';
            const errorMessage = `${patientName}+重复药品`;
            
            logger.warn(`⚠️ 检测到重复药品：${errorMessage} (药品: ${uniqueDuplicates.join(',')})`);
            
            // 抛出特殊错误，标记为重复药品
            const error = new Error(errorMessage);
            error.isDuplicateDrug = true; // 标记为重复药品错误
            error.patientName = patientName;
            error.duplicateDrugs = uniqueDuplicates;
            throw error;
        }

        const result = await apiService.request("rx_ppdoctor_confirmRxForPc", {
            diagnosisName: rxDetail.diagnosisName || " ",
            rxId,
            disease: rxDetail.disease || "[]",
            drugList,
            rxRemarks: rxDetail.rxRemarks || "无过敏药史，因疾病需要，特此确定用药 ；患者因病情需要开具超七天药量！"
        });

        return result?.rxAdvice ? String(result.rxAdvice).replace(/^null/, '').trim() : null;
    }

    async #submitRx(rxId, rxDetail, rxAdvice) {
        const submitParams = {
            diagnosisName: rxDetail.diagnosisName || " ",
            rxId,
            disease: rxDetail.disease || "[]",
            rxRemarks: rxDetail.rxRemarks || "无过敏药史，因疾病需要，特此确定用药 ；患者因病情需要开具超七天药量！"
        };

        try {
            if (rxAdvice) submitParams.rxAdvice = rxAdvice;
            return await apiService.request("rx_ppdoctor_submitRx", submitParams);
        } catch (error) {
            // 重试机制：如果需要添加说明
            if (error.message?.includes('请加处方说明')) {
                submitParams.rxAdvice = '无过敏药史，因疾病需要，特此确定用药 ；患者因病情需要开具超七天药量！';
                return await apiService.request("rx_ppdoctor_submitRx", submitParams);
            }
            throw error;
        }
    }
}

// 导出单例实例
export const autoRxService = new AutoRxSystem();