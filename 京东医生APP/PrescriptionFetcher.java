package com.jd.doctor;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

import org.json.JSONObject;
import org.json.JSONArray;
import org.json.JSONException;

/**
 * 处方抓取器 - 定时获取患者列表
 * 当外部传入网络实例后自动开始定时请求
 */
public class PrescriptionFetcher {
    private static final String TAG = "PrescriptionFetcher";
    private static final MediaType JSON_MEDIA_TYPE = MediaType.parse("application/json; charset=utf-8");
    private static final String DEFAULT_BASE_URL = "https://api.m.jd.com/api";
    private static final String PATIENT_LIST_PATH = "/JDD_APP_DiagList_getInDiagListEncrypt";
    private static final String CREATE_RX_PATH = "/JDDAPP_rx_saveRx";
    private static final String RX_DETAIL_PATH = "/jdd_queryRxDetailByRxId";
    private static final String RX_SUPPLEMENT_PATH = "/jdd_getRxSupplementInfo";
    private static final String RX_TEMP_SAVE_PATH = "/rx_tempSaveRxApp";
    private static final String RX_CONFIRM_PATH = "/rx_confirmRxApp";
    private static final String RX_SUBMIT_PATH = "/rx_submitRxApp";

    private static final long DEFAULT_FETCH_INTERVAL_MS = 5000L; // 默认5秒间隔
    private static final int DEFAULT_CONCURRENCY = 5;
    private static final String DEFAULT_TENANT = "JD8888";
    // 默认备注（已废弃，现在根据系统提示动态决定备注）
    // private static final String DEFAULT_OVER_SEVEN_DAYS_REMARK = "无过敏史；疾病需要，特此确认用药；";
    private static final List<String> PRESCRIPTION_KEYWORDS = Collections.unmodifiableList(Arrays.asList(
            "无须补充",
            "立即开方",
            "已确认没有补充信息",
            "请及时为患者复诊续方",
            "已完成患者信息确认环节",
            "线下已确诊",
            "没有发生过药品不良反应",
            "且没有相关禁忌",
            "没有药物过敏史",
            "好的"
    ));

    private final String baseUrl;
    private volatile long fetchIntervalMs;
    private volatile int concurrencyLimit;

    private volatile OkHttpClient networkClient;
    private ScheduledExecutorService scheduler;
    private ExecutorService prescriptionExecutor;
    private volatile FetcherCallback fetcherCallback;
    private final Set<String> processingDiagIds = Collections.synchronizedSet(new HashSet<>());
    private final AtomicBoolean connected = new AtomicBoolean(true);
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicLong lastActivity = new AtomicLong(0);
    private final AtomicLong lastDoingDiagNum = new AtomicLong(-1); // 追踪上次的进行中问诊数，初始为-1表示未初始化
    
    // 新增：浏览器插件通知跳过的诊断ID列表 (diagId -> expireTimestamp)
    private static final java.util.concurrent.ConcurrentHashMap<String, Long> skipDiagIds = new java.util.concurrent.ConcurrentHashMap<>();
    private static final long SKIP_EXPIRE_MS = 5 * 60 * 1000; // 5分钟过期

    /**
     * 默认构造函数，使用默认配置
     */
    public PrescriptionFetcher() {
        this(DEFAULT_BASE_URL, DEFAULT_FETCH_INTERVAL_MS, DEFAULT_CONCURRENCY);
    }

    /**
     * 自定义构造函数
     * @param baseUrl API基础地址
     * @param fetchIntervalMs 抓取间隔时间(毫秒)
     */
    public PrescriptionFetcher(String baseUrl, long fetchIntervalMs) {
        this(baseUrl, fetchIntervalMs, DEFAULT_CONCURRENCY);
    }

    public PrescriptionFetcher(String baseUrl, long fetchIntervalMs, int concurrencyLimit) {
        this.baseUrl = baseUrl;
        this.fetchIntervalMs = fetchIntervalMs;
        this.concurrencyLimit = Math.max(1, concurrencyLimit);
    }

    /**
     * 设置回调接口
     * @param callback 回调接口实例
     */
    public void setFetcherCallback(FetcherCallback callback) {
        this.fetcherCallback = callback;
    }

    /**
     * 设置网络客户端并自动开始定时请求
     * @param client 外部传入的OkHttpClient实例
     */
    public synchronized void setNetworkClient(OkHttpClient client) {
        this.networkClient = client;
        if (client != null) {
            notifyLogInfo("网络实例已设置，自动开始定时请求患者列表...");
            start(); // 自动开始定时任务
        }
    }

    /**
     * 启动定时任务
     */
    public synchronized void start() {
        if (scheduler != null && !scheduler.isShutdown()) {
            return;
        }
        scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleWithFixedDelay(this::safeFetch, 0, fetchIntervalMs, TimeUnit.MILLISECONDS);

        if (prescriptionExecutor == null || prescriptionExecutor.isShutdown()) {
            prescriptionExecutor = Executors.newFixedThreadPool(concurrencyLimit);
        }

        running.set(true);
        notifyLogInfo("定时任务已启动，每" + (fetchIntervalMs / 1000) + "秒获取一次患者列表");
    }

    /**
     * 停止定时任务
     */
    public synchronized void stop() {
        running.set(false);
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
            notifyLogInfo("定时任务已停止");
        }
        if (prescriptionExecutor != null) {
            prescriptionExecutor.shutdownNow();
            prescriptionExecutor = null;
        }
        processingDiagIds.clear();
    }

    /**
     * 安全的抓取方法，包含异常处理
     */
    private void safeFetch() {
        if (!connected.get()) {
            notifyLogInfo("当前未连接，跳过抓取");
            return;
        }

        try {
            fetchAndProcessPatientList();
        } catch (Exception e) {
            notifyLogError("抓取失败: " + e.getMessage());
        }
    }

    /**
     * 执行患者列表请求
     */
    private void fetchAndProcessPatientList() throws IOException {
        OkHttpClient client = networkClient;
        if (client == null) {
            notifyLogInfo("网络客户端未设置，跳过本次请求");
            return;
        }

        JSONObject payload = new JSONObject();
        try {
            payload.put("tenantType", DEFAULT_TENANT);
            payload.put("clientVersion", "3.8.0");
        } catch (JSONException e) {
            notifyLogError("构建患者列表请求参数失败: " + e.getMessage());
            return;
        }

        ResponsePayload response = executeRequest(PATIENT_LIST_PATH, payload);
        if (response == null) {
            return;
        }

        // 患者列表响应数据太大，不打印原始日志（只在出错时打印）
        // notifyRawResponse(response.body, "PATIENT_LIST");

        if (!response.isHttpSuccess() || !response.isBusinessSuccess()) {
            notifyLogError("患者列表请求失败: " + response.getBusinessMessage());
            // 出错时才打印响应
            notifyRawResponse(response.body, "PATIENT_LIST_ERROR");
            return;
        }

        // 先提取 data 对象
        JSONObject data = response.json.optJSONObject("data");
        if (data == null) {
            notifyLogInfo("返回数据为空，跳过本次处理");
            return;
        }

        // 提取 doingDiagNum 字段（从data对象中获取）
        int currentDoingDiagNum = data.optInt("doingDiagNum", 0);
        long previousDoingDiagNum = lastDoingDiagNum.get();
        
        // 提取医生ID（从第一个问诊记录中获取）
        String doctorId = extractDoctorId(response.json);
        
        // 每次都通知问诊数（不管是否变化）
        if (previousDoingDiagNum != -1 && previousDoingDiagNum != currentDoingDiagNum) {
            // 数量变化时，记录日志
            notifyLogInfo("检测到进行中问诊数变化: " + previousDoingDiagNum + " → " + currentDoingDiagNum + " (医生ID: " + doctorId + ")");
        }
        
        // 无论是否变化，都通知服务器更新
        notifyDoingDiagNumChanged(currentDoingDiagNum, (int)previousDoingDiagNum, doctorId);
        lastDoingDiagNum.set(currentDoingDiagNum);

        JSONArray diagList = data.optJSONArray("doctorDiagDtoList");
        if (diagList == null || diagList.length() == 0) {
            notifyLogInfo("未检测到待处理诊断单");
            return;
        }

        notifyLogInfo("获取到" + diagList.length() + "条诊断记录，开始筛选...");

        for (int i = 0; i < diagList.length(); i++) {
            JSONObject item = diagList.optJSONObject(i);
            if (item == null) {
                continue;
            }

            String diagId = item.optString("diagId", null);
            String sid = item.optString("sid", null);
            String diseaseDesc = item.optString("diseaseDesc", "");

            JSONObject sessionContent = item.optJSONObject("sessionContentDto");
            String lastContent = sessionContent != null ? sessionContent.optString("lastContent", "") : "";

            if (shouldProcessDiag(lastContent)) {
                schedulePrescription(diagId, sid, diseaseDesc);
            }
        }
    }

    /**
     * 通知原始响应数据
     */
    private void notifyRawResponse(String rawResponse, String requestType) {
        if (fetcherCallback != null && rawResponse != null) {
            try {
                fetcherCallback.onRawResponse(rawResponse, requestType);
            } catch (Exception e) {
                // 忽略回调异常
            }
        }
    }

    /**
     * 通知日志信息
     */
    private void notifyLogInfo(String message) {
        if (fetcherCallback != null) {
            try {
                fetcherCallback.onLogInfo(message);
            } catch (Exception e) {
                // 忽略回调异常
            }
        }
    }

    /**
     * 通知错误信息
     */
    private void notifyLogError(String message) {
        if (fetcherCallback != null) {
            try {
                fetcherCallback.onLogError(message);
            } catch (Exception e) {
                // 忽略回调异常
            }
        }
    }

    /**
     * 通知进行中问诊数变化
     */
    private void notifyDoingDiagNumChanged(int currentNum, int previousNum, String doctorId) {
        if (fetcherCallback != null) {
            try {
                fetcherCallback.onDoingDiagNumChanged(currentNum, previousNum, doctorId);
            } catch (Exception e) {
                // 忽略回调异常
            }
        }
    }

    /**
     * 从响应数据中提取医生ID
     */
    private String extractDoctorId(JSONObject responseJson) {
        if (responseJson == null) {
            return "";
        }
        try {
            JSONObject data = responseJson.optJSONObject("data");
            if (data != null) {
                JSONArray diagList = data.optJSONArray("doctorDiagDtoList");
                if (diagList != null && diagList.length() > 0) {
                    JSONObject firstDiag = diagList.optJSONObject(0);
                    if (firstDiag != null) {
                        // 优先返回 receptionDoctorId（长整型）
                        long doctorIdLong = firstDiag.optLong("receptionDoctorId", 0);
                        if (doctorIdLong > 0) {
                            return String.valueOf(doctorIdLong);
                        }
                    }
                }
            }
        } catch (Exception e) {
            notifyLogError("提取医生ID失败: " + e.getMessage());
        }
        return "";
    }

    /**
     * 更新连接状态
     */
    public void setConnected(boolean connected) {
        this.connected.set(connected);
        notifyLogInfo("连接状态更新: " + connected);
    }

    /**
     * 更新抓取间隔
     */
    public synchronized void updateFetchInterval(long intervalMs) {
        if (intervalMs <= 0) {
            return;
        }
        this.fetchIntervalMs = intervalMs;
        notifyLogInfo("抓取间隔已更新为 " + intervalMs + " ms");
        if (running.get()) {
            stop();
            start();
        }
    }

    /**
     * 更新并发度
     */
    public synchronized void updateConcurrency(int concurrency) {
        if (concurrency <= 0) {
            return;
        }
        this.concurrencyLimit = concurrency;
        notifyLogInfo("并发度已更新为 " + concurrency);
        if (prescriptionExecutor != null && !prescriptionExecutor.isShutdown()) {
            prescriptionExecutor.shutdownNow();
            prescriptionExecutor = Executors.newFixedThreadPool(concurrencyLimit);
        }
    }

    private boolean shouldProcessDiag(String lastContent) {
        if (lastContent == null || lastContent.isEmpty()) {
            return false;
        }
        return PRESCRIPTION_KEYWORDS.stream().anyMatch(lastContent::contains);
    }
    
    // --- 新增：浏览器插件通知跳过患者功能 ---
    
    /**
     * 添加要跳过的诊断ID（由JS层调用）
     * @param diagId 诊断ID
     */
    public static void addSkipDiagId(String diagId) {
        if (diagId != null && !diagId.isEmpty()) {
            long expireTime = System.currentTimeMillis() + SKIP_EXPIRE_MS;
            skipDiagIds.put(diagId, expireTime);
        }
    }
    
    /**
     * 检查诊断ID是否应该跳过
     * @param diagId 诊断ID
     * @return true表示应该跳过
     */
    public static boolean shouldSkipDiag(String diagId) {
        if (diagId == null || diagId.isEmpty()) {
            return false;
        }
        
        Long expireTime = skipDiagIds.get(diagId);
        if (expireTime == null) {
            return false;
        }
        
        if (System.currentTimeMillis() > expireTime) {
            // 已过期，移除并返回false
            skipDiagIds.remove(diagId);
            return false;
        }
        
        return true;
    }
    
    /**获取当前跳过列表大小*/
    public static int getSkipListSize() {
        return skipDiagIds.size();
    }
    
    // ----------------------------------------

    private void schedulePrescription(String diagId, String sid, String diseaseDesc) {
        if (diagId == null || diagId.isEmpty() || sid == null || sid.isEmpty()) {
            return;
        }
        
        // 新增：检查是否在浏览器插件通知的跳过列表中
        if (shouldSkipDiag(diagId)) {
            notifyLogInfo("⚠️ 诊断单 " + diagId + " 在浏览器插件跳过列表中，跳过开方");
            return;
        }

        if (processingDiagIds.contains(diagId)) {
            notifyLogInfo("诊断单 " + diagId + " 已在处理队列，跳过");
            return;
        }

        if (prescriptionExecutor == null) {
            notifyLogError("处方执行线程池未初始化，无法处理诊断单");
            return;
        }

        processingDiagIds.add(diagId);
        prescriptionExecutor.submit(() -> {
            try {
                lastActivity.set(Instant.now().toEpochMilli());
                boolean success = processPrescriptionWorkflow(diagId, sid, diseaseDesc);
                notifyPrescriptionEvent(diagId, success, success ? "处方提交成功" : "处方处理失败");
            } finally {
                processingDiagIds.remove(diagId);
            }
        });
    }

    private boolean processPrescriptionWorkflow(String diagId, String sid, String diseaseDesc) {
        try {
            String diagnosisName = extractDiagnosisName(diseaseDesc);

            // 1. 创建处方草稿
            JSONObject draftPayload = new JSONObject();
            try {
                draftPayload.put("diagId", diagId);
                draftPayload.put("rxCategory", 1);
                draftPayload.put("patientId", 0);
                draftPayload.put("sid", sid);
                draftPayload.put("tenantType", DEFAULT_TENANT);
            } catch (JSONException e) {
                notifyLogError("构建处方草稿参数失败: " + e.getMessage());
                return false;
            }

            ResponsePayload draftResponse = executeRequest(CREATE_RX_PATH, draftPayload);
            if (!isValidResponse(draftResponse, "创建处方草稿失败")) {
                return false;
            }

            String rxId = draftResponse.json.optString("data", null);
            if (rxId == null) {
                notifyLogError("创建处方草稿返回数据无效");
                return false;
            }
            notifyLogInfo("处方草稿创建成功，rxId=" + rxId);

            // 2. 获取处方详情
            JSONObject detailPayload = new JSONObject();
            try {
                detailPayload.put("rxId", rxId);
            } catch (JSONException e) {
                notifyLogError("构建处方详情参数失败: " + e.getMessage());
                return false;
            }
            ResponsePayload detailResponse = executeRequest(RX_DETAIL_PATH, detailPayload);
            if (!isValidResponse(detailResponse, "获取处方详情失败")) {
                return false;
            }

            // 3. 获取处方补充信息
            JSONObject supplementPayload = new JSONObject();
            try {
                supplementPayload.put("rxId", rxId);
                supplementPayload.put("inputList", new JSONArray().put(diagnosisName));
                supplementPayload.put("rxItemDtoList", new JSONArray());
            } catch (JSONException e) {
                notifyLogError("构建处方补充信息参数失败: " + e.getMessage());
                return false;
            }

            ResponsePayload supplementResponse = executeRequest(RX_SUPPLEMENT_PATH, supplementPayload);
            
            // 检测重复药品（已禁用）
            // if (hasDuplicateDrugs(supplementResponse)) {
            //     notifyLogError("❌ 诊断单 " + diagId + " 存在重复药品，跳过开方");
            //     return false;
            // }
            
            boolean overSevenDays = containsOverSevenDays(supplementResponse);

            if (overSevenDays) {
                notifyLogInfo("✓ 检测到诊断单 " + diagId + " 存在超7天药量，将添加备注");
            } else {
                notifyLogInfo("✗ 诊断单 " + diagId + " 未超7天药量");
            }

            // 4. 临时保存处方
            JSONObject tempSavePayload = new JSONObject();
            try {
                tempSavePayload.put("rxId", rxId);
                tempSavePayload.put("diagResult", diagnosisName);
                tempSavePayload.put("syndromeIdentifying", diagnosisName);
                tempSavePayload.put("noticeInfo", "");
                // 不填备注，让系统在第5步检测并返回建议
                tempSavePayload.put("rxRemarks", "");
                tempSavePayload.put("rxCategory", 1);
                tempSavePayload.put("tempSaveStamp", System.currentTimeMillis());
            } catch (JSONException e) {
                notifyLogError("构建临时保存参数失败: " + e.getMessage());
                return false;
            }
            ResponsePayload tempSaveResponse = executeRequest(RX_TEMP_SAVE_PATH, tempSavePayload);
            if (!isValidResponse(tempSaveResponse, "临时保存处方失败")) {
                return false;
            }

            // 5. 确认处方
            JSONObject confirmPayload = new JSONObject();
            try {
                confirmPayload.put("rxId", rxId);
                confirmPayload.put("diagResult", diagnosisName);
                confirmPayload.put("noticeInfo", "");
                // 不填备注，让系统检测并返回建议（触发errorMsgBoxInfoDTO）
                confirmPayload.put("rxRemarks", "");
                confirmPayload.put("tempSaveStamp", System.currentTimeMillis());
            } catch (JSONException e) {
                notifyLogError("构建确认处方参数失败: " + e.getMessage());
                return false;
            }

            ResponsePayload confirmResponse = executeRequest(RX_CONFIRM_PATH, confirmPayload);
            if (!isValidResponse(confirmResponse, "确认处方失败")) {
                return false;
            }

            // 从确认响应中提取系统建议的备注
            String suggestedRemarks = extractSuggestedRemarks(confirmResponse);
            String finalRemarks = "";
            boolean shouldSkip = false;
            
            if (!suggestedRemarks.isEmpty()) {
                notifyLogInfo("✓ 检测到系统建议备注（原始内容）");
                
                // 多层判断逻辑（对原始内容进行判断）
                String lowerRemarks = suggestedRemarks.toLowerCase();
                
                // 第一次判断：关键词"禁"或"不" -> 不要开方
                if (lowerRemarks.contains("禁") || lowerRemarks.contains("不")) {
                    notifyLogInfo("⚠️ [第一次判断] 检测到'禁'或'不'关键字，跳过开方");
                    shouldSkip = true;
                }
                // 第二次判断：关键词"重复"和"无" -> 特定备注
                else if (lowerRemarks.contains("重复") && lowerRemarks.contains("无")) {
                    finalRemarks = "无过敏史；患者需长期使用此药物，开具超7天药量；一种使用完再使用另一种";
                    notifyLogInfo("✓ [第二次判断] 检测到'重复'和'无'关键字，使用特定备注");
                }
                // 第三次判断：关键词"重复" -> 特定备注
                else if (lowerRemarks.contains("重复")) {
                    finalRemarks = "患者需长期使用此药物，开具超7天药量；一种使用完再使用另一种";
                    notifyLogInfo("✓ [第三次判断] 检测到'重复'关键字，使用特定备注");
                }
                // 第四次判断：关键词"无"和"7" -> 特定备注
                else if (lowerRemarks.contains("无") && lowerRemarks.contains("7")) {
                    finalRemarks = "无过敏史；患者需长期使用此药物，开具超7天药量；";
                    notifyLogInfo("✓ [第四次判断] 检测到'无'和'7'关键字，使用特定备注");
                }
                // 第五次判断：关键词"7" -> 特定备注
                else if (lowerRemarks.contains("7")) {
                    finalRemarks = "患者需长期使用此药物，开具超7天药量；";
                    notifyLogInfo("✓ [第五次判断] 检测到'7'关键字，使用特定备注");
                }
                // 第六次判断：关键词"无" -> 特定备注
                else if (lowerRemarks.contains("无")) {
                    finalRemarks = "无过敏史；";
                    notifyLogInfo("✓ [第六次判断] 检测到'无'关键字，使用特定备注");
                }
                // 如果出现谨慎就使用空备注完成
                else if (lowerRemarks.contains("谨慎")) {
                    finalRemarks = "";
                    notifyLogInfo("✓ [第七次判断] 检测到'谨慎'关键字，使用空备注");
                }
                // 第八次判断：关键词"缺少补充说明" -> 特定备注
                else if (lowerRemarks.contains("缺少补充说明")) {
                    finalRemarks = "因疾病需要，特此确定用药;";
                    notifyLogInfo("✓ [第八次判断] 检测到'缺少补充说明'关键字，使用特定备注");
                }
                // 没有匹配任何关键词：不开方
                else {
                    notifyLogInfo("⚠️ [默认情况] 有系统建议但无匹配关键词，跳过开方");
                    shouldSkip = true;
                }


            } else {
                notifyLogInfo("✗ 未检测到系统建议备注（使用空备注）");
                finalRemarks = "";
            }

            // 如果需要跳过开方
            if (shouldSkip) {
                notifyLogInfo("⚠️ 根据判断逻辑跳过开方，diagId=" + diagId);
                return false;
            }

            // 6. 提交处方（使用最终确定的备注）
            if (submitPrescription(rxId, diagnosisName, finalRemarks)) {
                notifyLogInfo("处方提交成功，diagId=" + diagId + " rxId=" + rxId);
                notifyLogInfo("使用备注: " + (finalRemarks.isEmpty() ? "[空备注]" : finalRemarks));
                return true;
            }

            notifyLogError("处方提交失败，diagId=" + diagId);
            return false;
        } catch (Exception e) {
            notifyLogError("诊断单 " + diagId + " 处理异常: " + e.getMessage());
            return false;
        }
    }

    private boolean submitPrescription(String rxId, String diagnosisName, String finalRemarks) throws IOException {
        ResponsePayload submitResponse = executeRequest(RX_SUBMIT_PATH, buildSubmitPayload(rxId, diagnosisName, finalRemarks));
        return isValidResponse(submitResponse, "处方提交失败");
    }

    private JSONObject buildSubmitPayload(String rxId, String diagnosisName, String finalRemarks) {
        JSONObject submitPayload = new JSONObject();
        try {
            submitPayload.put("rxId", rxId);
            submitPayload.put("diagnosisName", diagnosisName);
            submitPayload.put("diagResult", diagnosisName);
            submitPayload.put("noticeInfo", "");
            submitPayload.put("comprehensiveRxId", "0");
            
            // 直接使用传入的备注（已经在上层处理完逻辑）
            String remarks = finalRemarks;
            submitPayload.put("rxRemarks", remarks);
        } catch (JSONException e) {
            notifyLogError("构建提交处方参数失败: " + e.getMessage());
            return new JSONObject();
        }
        return submitPayload;
    }

    /**
     * 检测处方中是否存在重复药品（已禁用）
     * 如需启用，请取消注释方法调用和实现代码
     */
    private boolean hasDuplicateDrugs(ResponsePayload payload) {
        // 功能已禁用，始终返回 false（不检测重复）
        return false;
        
        // 以下代码已注释（原重复检测逻辑）
        /*
        if (payload == null || payload.json == null) {
            return false;
        }
        JSONObject data = payload.json.optJSONObject("data");
        if (data == null) {
            return false;
        }
        JSONArray rxItems = data.optJSONArray("rxItemDtoList");
        if (rxItems == null || rxItems.length() == 0) {
            return false;
        }
        
        // 使用 HashSet 检测重复
        java.util.HashSet<String> drugNames = new java.util.HashSet<>();
        java.util.ArrayList<String> duplicates = new java.util.ArrayList<>();
        
        for (int i = 0; i < rxItems.length(); i++) {
            JSONObject item = rxItems.optJSONObject(i);
            if (item == null) {
                continue;
            }
            String drugName = item.optString("drugName", "").trim();
            if (!drugName.isEmpty()) {
                if (!drugNames.add(drugName)) {
                    // 添加失败说明已存在（重复）
                    duplicates.add(drugName);
                }
            }
        }
        
        if (!duplicates.isEmpty()) {
            notifyLogError("发现重复药品: " + String.join(", ", duplicates));
            return true;
        }
        
        return false;
        */
    }

    private boolean containsOverSevenDays(ResponsePayload payload) {
        if (payload == null || payload.json == null) {
            return false;
        }
        JSONObject data = payload.json.optJSONObject("data");
        if (data == null) {
            return false;
        }
        JSONArray rxItems = data.optJSONArray("rxItemDtoList");
        if (rxItems == null) {
            return false;
        }
        for (int i = 0; i < rxItems.length(); i++) {
            JSONObject item = rxItems.optJSONObject(i);
            if (item == null) {
                continue;
            }
            String daysText = item.optString("days", "");
            try {
                if (!daysText.isEmpty() && Integer.parseInt(daysText) > 7) {
                    return true;
                }
            } catch (NumberFormatException ignored) {
                // ignore invalid number
            }
        }
        return false;
    }

    private boolean isValidResponse(ResponsePayload payload, String errorMessage) {
        if (payload == null) {
            notifyLogError(errorMessage + ": 网络或解析失败");
            return false;
        }
        if (!payload.isHttpSuccess()) {
            notifyLogError(errorMessage + ": HTTP " + payload.code);
            return false;
        }
        if (!payload.isBusinessSuccess()) {
            notifyLogError(errorMessage + ": " + payload.getBusinessMessage());
            return false;
        }
        return true;
    }

    private String extractDiagnosisName(String diseaseDesc) {
        if (diseaseDesc == null || diseaseDesc.isEmpty()) {
            return "默认诊断";
        }
        int idx = diseaseDesc.indexOf(';');
        return idx > 0 ? diseaseDesc.substring(0, idx) : diseaseDesc;
    }

    /**
     * 从确认处方响应中提取系统建议的备注
     * @param confirmResponse 确认处方接口的响应
     * @return 提取的备注信息，如果没有则返回空字符串
     */
    private String extractSuggestedRemarks(ResponsePayload confirmResponse) {
        if (confirmResponse == null || confirmResponse.json == null) {
            return "";
        }
        
        try {
            JSONObject data = confirmResponse.json.optJSONObject("data");
            if (data == null) {
                return "";
            }
            
            JSONObject errorMsgBox = data.optJSONObject("errorMsgBoxInfoDTO");
            if (errorMsgBox == null) {
                return "";
            }
            
            String subTitle = errorMsgBox.optString("subTitle", "");
            if (subTitle.isEmpty()) {
                return "";
            }
            
            // 直接返回原始的subTitle内容，不做任何处理
            // 格式示例: "• 备注提醒\n金荞麦片开药量超7天，请补充说明：患者需长期使用此药物，开具超7天药量"
            notifyLogInfo("原始弹窗内容: " + subTitle);
            return subTitle;
            
        } catch (Exception e) {
            notifyLogError("提取系统建议备注失败: " + e.getMessage());
            return "";
        }
    }

    /**
     * 从系统提示的 subTitle 中解析出备注内容
     * @param subTitle 系统提示的副标题
     * @return 解析出的备注，如果解析失败则返回空字符串
     */
    private String parseRemarksFromSubTitle(String subTitle) {
        if (subTitle == null || subTitle.isEmpty()) {
            return "";
        }
        
        // 移除 HTML 标签
        String cleaned = subTitle.replaceAll("<[^>]+>", "");
        
        // 移除换行符和多余的空格，统一为单个空格
        cleaned = cleaned.replaceAll("[\\r\\n]+", " ").replaceAll("\\s+", " ").trim();
        
        // 查找最后一个冒号的位置（提取最后一条建议，避免重复）
        int lastColonIndex = cleaned.lastIndexOf("：");
        if (lastColonIndex != -1) {
            // 取冒号后面的所有内容
            String remark = cleaned.substring(lastColonIndex + 1).trim();
            
            // 直接返回系统建议的备注，不做任何修改
            if (!remark.isEmpty()) {
                return remark;
            }
        }
        
        // 如果无法提取，返回空字符串
        return "";
    }

    private void notifyPrescriptionEvent(String diagId, boolean success, String message) {
        if (fetcherCallback != null) {
            try {
                fetcherCallback.onPrescriptionEvent(diagId, success, message);
            } catch (Exception ignored) {
            }
        }
    }

    private ResponsePayload executeRequest(String path, JSONObject payload) throws IOException {
        OkHttpClient client = networkClient;
        if (client == null) {
            notifyLogError("网络客户端未设置，无法执行请求: " + path);
            return null;
        }

        RequestBody body = RequestBody.create(JSON_MEDIA_TYPE, payload != null ? payload.toString() : "{}");
        Request request = new Request.Builder()
                .url(baseUrl + path)
                .post(body)
                .build();

        try (Response response = client.newCall(request).execute()) {
            ResponseBody responseBody = response.body();
            String bodyText = responseBody != null ? responseBody.string() : null;

            return new ResponsePayload(response.code(), bodyText);
        }
    }

    private static class ResponsePayload {
        private final int code;
        private final String body;
        private final JSONObject json;

        ResponsePayload(int code, String body) {
            this.code = code;
            this.body = body;
            JSONObject parsed = null;
            if (body != null && !body.isEmpty()) {
                try {
                    parsed = new JSONObject(body);
                } catch (JSONException ignored) {
                }
            }
            this.json = parsed;
        }

        boolean isHttpSuccess() {
            return code >= 200 && code < 300;
        }

        boolean isBusinessSuccess() {
            return json != null && json.optBoolean("success", false);
        }

        String getBusinessMessage() {
            return json != null ? json.optString("msg", "") : "";
        }
    }

    /**
     * 回调接口
     */
    public interface FetcherCallback {
        void onRawResponse(String response, String requestType);
        void onLogInfo(String message);
        void onLogError(String message);

        default void onPrescriptionEvent(String diagId, boolean success, String message) {
            // optional callback
        }

        /**
         * 当进行中问诊数发生变化时调用
         * @param currentNum 当前进行中问诊数
         * @param previousNum 上一次的进行中问诊数
         * @param doctorId 医生ID
         */
        default void onDoingDiagNumChanged(int currentNum, int previousNum, String doctorId) {
            // optional callback
        }
    }
}

