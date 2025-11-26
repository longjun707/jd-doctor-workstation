package com.jd.doctor;

import android.os.Looper;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import okhttp3.Call;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import android.util.JsonReader;

public class OrderRobber {
    private static final String TAG = "OrderRobber";

    private static final MediaType JSON_MEDIA_TYPE = MediaType.parse("application/json; charset=utf-8");

    // --- Config fields to be injected from Frida ---
    private String apiBaseUrl;
    private String orderListPath;
    private String grabOrderPath;
    private String pKeyVenderId;
    private String pKeyTenantType;
    private String pKeyPageSize;
    private String pKeyGrabTab;
    private String pKeyDiagId;
    private String pKeyReceiveEntranceSource;
    private String pKeyData;
    private String pKeyDiagLabels;
    private String pKeyLabelContent;
    private String valVenderId;
    private String valTenantType;
    private int valPageSize;
    private String valGrabTab;
    private int valReceiveEntranceSource;
    private boolean isConfigured = false;
    // --- End of config fields ---

    private static final int DEFAULT_REQUEST_TIMEOUT_SECONDS = 30;

    private static volatile OrderRobber instance;
    private static final Object INSTANCE_LOCK = new Object();

    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private volatile RobConfig currentConfig;
    private final AtomicLong lastOrderSeenTime = new AtomicLong(0);

    private volatile OkHttpClient networkClient;

    private ExecutorService executor;
    private ExecutorService logExecutor; // For async logging
    private final Object taskLock = new Object();

    private volatile EngineCallback engineCallback;

    private final Random random = new Random();

    private OrderRobber() {
        logExecutor = Executors.newSingleThreadExecutor();
    }

    public void configure(String jsonConfig) {
        try {
            JSONObject config = new JSONObject(jsonConfig);
            this.apiBaseUrl = config.getString("apiBaseUrl");
            this.orderListPath = config.getString("orderListPath");
            this.grabOrderPath = config.getString("grabOrderPath");
            this.pKeyVenderId = config.getString("pKeyVenderId");
            this.pKeyTenantType = config.getString("pKeyTenantType");
            this.pKeyPageSize = config.getString("pKeyPageSize");
            this.pKeyGrabTab = config.getString("pKeyGrabTab");
            this.pKeyDiagId = config.getString("pKeyDiagId");
            this.pKeyReceiveEntranceSource = config.getString("pKeyReceiveEntranceSource");
            this.pKeyData = config.getString("pKeyData");
            this.pKeyDiagLabels = config.getString("pKeyDiagLabels");
            this.pKeyLabelContent = config.getString("pKeyLabelContent");
            this.valVenderId = config.getString("valVenderId");
            this.valTenantType = config.getString("valTenantType");
            this.valPageSize = config.getInt("valPageSize");
            this.valGrabTab = config.getString("valGrabTab");
            this.valReceiveEntranceSource = config.getInt("valReceiveEntranceSource");
            this.isConfigured = true;
        } catch (Exception e) {
            this.isConfigured = false;
        }
    }

    public static OrderRobber getInstance() {
        if (instance == null) {
            synchronized (INSTANCE_LOCK) {
                if (instance == null) {
                    instance = new OrderRobber();
                }
            }
        }
        return instance;
    }

    public boolean startRobbing(RobConfig config) {
        if (!isConfigured) {
            return false;
        }

        if (config == null) {
            return false;
        }

        synchronized (taskLock) {
            stopRobbing();

            if (networkClient == null) {
                return false;
            }

            this.currentConfig = config;
            
            ThreadFactory highPriorityThreadFactory = r -> {
                Thread t = new Thread(r, "OrderRobber-HighPriority");
                t.setPriority(Thread.MAX_PRIORITY);
                return t;
            };
            this.executor = Executors.newSingleThreadExecutor(highPriorityThreadFactory);

            lastOrderSeenTime.set(System.currentTimeMillis());
            isRunning.set(true);

            executor.submit(this::executeRobLoop);

            notifyStatusChanged("正常");
            return true;
        }
    }

    public void stopRobbing() {
        synchronized (taskLock) {
            if (!isRunning.getAndSet(false)) {
                return;
            }
            if (executor != null && !executor.isShutdown()) {
                executor.shutdownNow();
                notifyStatusChanged("已结束");
            }
            // 错误：不应该在这里关闭日志执行器，它需要持续存在
            // if (logExecutor != null && !logExecutor.isShutdown()) {
            //     logExecutor.shutdown();
            // }
        }
    }

    public void setNetworkClient(OkHttpClient client) {
        this.networkClient = client;
    }

    public void setEngineCallback(EngineCallback callback) {
        this.engineCallback = callback;
    }

    public boolean isRobbing() {
        return isRunning.get();
    }

    private void executeRobLoop() {
        // 防御性代码：清除任何可能由线程复用遗留下来的中断状态
        if (Thread.interrupted()) {
        }
        while (isRunning.get() && !Thread.currentThread().isInterrupted()) {
            try {
                RobConfig config = currentConfig;
                if (config == null) {
                    break;
                }

                if (shouldEnterWaitingState(config)) {
                    enterWaitingState(config);
                    continue;
                }

                String orderListResponse = getOrderList();

                String orderId = parseAvailableOrder(orderListResponse);
                if (orderId != null) {
                    boolean wasSuccessful = grabOrder(orderId);
                    if (wasSuccessful) {
                        // 抢单成功，进入专属的随机冷却时间
                        int specialDelay = 5000 + random.nextInt(15000 - 5000 + 1);
                        Thread.sleep(specialDelay);
                        // 冷却结束后，立即开始下一轮循环，而不是等待常规延迟
                        continue;
                    }
                    // 如果抢单不成功（例如已被抢），则继续走下面的常规延迟
                }

                int delay = calculateDelay(config);
                if (delay > 0) {
                    Thread.sleep(delay);
                }

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
    }

    private boolean shouldEnterWaitingState(RobConfig config) {
        if (config.refreshTime <= 0) return false;
        long timeSinceLastOrder = System.currentTimeMillis() - lastOrderSeenTime.get();
        return timeSinceLastOrder > (long) config.refreshTime * 60 * 1000L;
    }

    private void enterWaitingState(RobConfig config) throws InterruptedException {
        notifyStatusChanged("等待中");
        Thread.sleep((long) config.waitTime * 60 * 1000L);
        lastOrderSeenTime.set(System.currentTimeMillis());
        notifyStatusChanged("正常");
    }

    private String getOrderList() throws Exception {
        JSONObject requestBody = new JSONObject();
        requestBody.put(this.pKeyVenderId, this.valVenderId);
        requestBody.put(this.pKeyTenantType, this.valTenantType);
        requestBody.put(this.pKeyPageSize, this.valPageSize);
        requestBody.put(this.pKeyGrabTab, this.valGrabTab);
        return sendRequest(this.apiBaseUrl + this.orderListPath, requestBody.toString());
    }

    private boolean grabOrder(String orderId) throws Exception {
        JSONObject requestBody = new JSONObject();
        requestBody.put(this.pKeyDiagId, Long.parseLong(orderId));
        requestBody.put(this.pKeyReceiveEntranceSource, this.valReceiveEntranceSource);
        String responseBody = sendRequest(this.apiBaseUrl + this.grabOrderPath, requestBody.toString());

        // 无论成功与否，都立刻将原始响应发给Frida进行记录和上报
        lastOrderSeenTime.set(System.currentTimeMillis());
        notifyRawResponse(responseBody, "GRAB_ORDER");

        // 在Java层直接解析，判断是否成功
        try {
            JSONObject responseJson = new JSONObject(responseBody);
            String code = responseJson.optString("code");
            return "0".equals(code) || "0000".equals(code);
        } catch (Exception e) {
            return false;
        }
    }

    private String sendRequest(String url, String jsonBody) throws IOException {
        if (networkClient == null) {
            throw new IOException("网络客户端不可用");
        }

        RequestBody body = RequestBody.create(JSON_MEDIA_TYPE, jsonBody);
        Request request = new Request.Builder()
                .url(url)
                .post(body)
                .build();

        // Use try-with-resources to ensure the Response is closed
        try (Response response = networkClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("HTTP请求失败，错误码: " + response.code());
            }

            ResponseBody responseBody = response.body();
            if (responseBody == null) {
                throw new IOException("HTTP响应体为空");
            }

            return responseBody.string();
        }
    }

    private String parseAvailableOrder(String response) {
        try (JsonReader reader = new JsonReader(new StringReader(response))) {
            reader.beginObject(); // Start of root {

            while (reader.hasNext()) {
                String name = reader.nextName();
                if (name.equals(this.pKeyData)) {
                    reader.beginArray(); // Start of data [
                    while (reader.hasNext()) {
                        String diagId = null;
                        boolean isMatch = false;

                        reader.beginObject(); // Start of order {
                        while (reader.hasNext()) {
                            String orderKey = reader.nextName();
                            if (orderKey.equals(this.pKeyDiagId)) {
                                diagId = reader.nextString();
                            } else if (orderKey.equals(this.pKeyDiagLabels)) {
                                reader.beginArray(); // Start of diagLabels [
                                while (reader.hasNext()) {
                                    reader.beginObject(); // Start of label {
                                    while (reader.hasNext()) {
                                        String labelKey = reader.nextName();
                                        if (labelKey.equals(this.pKeyLabelContent)) {
                                            String labelContent = reader.nextString();
                                            if (labelContent != null && labelContent.contains("复")) {
                                                isMatch = true;
                                            }
                                        } else {
                                            reader.skipValue();
                                        }
                                    }
                                    reader.endObject(); // End of label }
                                    if (isMatch) break; // Optimization: stop reading labels if match found
                                }
                                reader.endArray(); // End of diagLabels ]
                            } else {
                                reader.skipValue();
                            }
                        }
                        reader.endObject(); // End of order }

                        if (isMatch && diagId != null) {
                            return diagId; // Return immediately
                        }
                    }
                    reader.endArray();
                } else {
                    reader.skipValue();
                }
            }
            reader.endObject();

        } catch (Exception e) {
        }

        return null;
    }

    private int calculateDelay(RobConfig config) {
        if (config == null) return 5000;
        if (config.randomDelay <= config.delay) return config.delay;
        return config.delay + random.nextInt(config.randomDelay - config.delay + 1);
    }

    private void notifyRawResponse(String rawResponse, String requestType) {
        if (engineCallback != null && rawResponse != null) {
            try {
                engineCallback.onRawResponse(rawResponse, requestType);
            } catch (Exception e) {
            }
        }
    }

    private void notifyStatusChanged(String status) {
        if (engineCallback != null) {
            try {
                engineCallback.onStatusChanged(status);
            } catch (Exception e) {
            }
        }
    }

    public static class RobConfig {
        public int delay;
        public int randomDelay;
        public int refreshTime;
        public int waitTime;

        public RobConfig(int delay, int randomDelay, int refreshTime, int waitTime) {
            this.delay = delay;
            this.randomDelay = randomDelay;
            this.refreshTime = refreshTime;
            this.waitTime = waitTime;
        }

        @Override
        public String toString() {
            return String.format("RobConfig{delay=%d, randomDelay=%d, refreshTime=%d, waitTime=%d}",
                    delay, randomDelay, refreshTime, waitTime);
        }
    }

    public interface EngineCallback {
        void onRawResponse(String response, String requestType);
        void onStatusChanged(String status);
        void onLogInfo(String message);
        void onLogError(String message);
    }
}