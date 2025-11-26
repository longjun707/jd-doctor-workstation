package com.jd.doctor;

import java.io.*;
import java.net.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class TCPClient {
    private static final String TAG = "TCPClient";

    private final String host;
    private final int port;
    private final int connectionTimeout = 15000;

    // --- 新增：指数退避重连策略的配置 ---
    private static final int INITIAL_RECONNECT_INTERVAL = 5000; // 初始重连间隔 5秒
    private static final int MAX_RECONNECT_INTERVAL = 30000;   // 最大重连间隔 30秒
    private static final double RECONNECT_BACKOFF_FACTOR = 1.5;  // 每次失败后，间隔时间乘以1.5
    private int currentReconnectInterval = INITIAL_RECONNECT_INTERVAL;
    // ------------------------------------

    private Socket socket;
    private BufferedReader reader;
    private PrintWriter writer;
    private final AtomicBoolean isRunning = new AtomicBoolean(false);

    private ScheduledExecutorService executorService = Executors.newScheduledThreadPool(2);
    private MessageListener messageListener;

    public TCPClient(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public void connect() {
        if (isRunning.getAndSet(true)) {
            return;
        }
        
        // --- 新增：检查并重新创建已关闭的线程池 ---
        if (executorService == null || executorService.isShutdown()) {
            log("线程池已关闭，正在重新创建...");
            executorService = Executors.newScheduledThreadPool(2);
        }
        // -----------------------------------------

        log("开始首次连接...");
        executorService.submit(this::performConnection);
    }

    private void performConnection() {
        try {
            socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), connectionTimeout);
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
            writer = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF-8"), true);

            log("TCP连接成功");
            currentReconnectInterval = INITIAL_RECONNECT_INTERVAL; // 连接成功后，重置重连间隔
            notifyConnectionChange(true);

            startReceiveLoop();

        } catch (Exception e) {
            logError("TCP连接失败", e);
            cleanupAndScheduleReconnect();
        }
    }

    private void startReceiveLoop() {
        while (isRunning.get()) {
            try {
                String message = reader.readLine();
                if (message == null) {
                    log("服务器关闭连接");
                    cleanupAndScheduleReconnect();
                    break;
                }
                if (messageListener != null) {
                    messageListener.onMessageReceived(message);
                }
            } catch (IOException e) {
                if (isRunning.get()) {
                    logError("连接已断开", e);
                    cleanupAndScheduleReconnect();
                }
                break;
            }
        }
    }

    public void disconnect() {
        log("主动断开TCP连接");
        if (isRunning.getAndSet(false)) {
            cleanup();
            
            if (executorService != null && !executorService.isShutdown()) {
                // --- 修改：使用 shutdownNow 并等待终止 ---
                log("正在关闭执行器服务...");
                executorService.shutdownNow(); // 立即尝试停止所有正在执行的任务
                try {
                    // 等待一段时间以允许任务终止
                    if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                        logError("线程池未能在5秒内终止", null);
                    }
                } catch (InterruptedException e) {
                    logError("等待线程池终止时被中断", e);
                    executorService.shutdownNow(); // 再次尝试
                    Thread.currentThread().interrupt();
                }
                // -----------------------------------------
            }
        }
    }

    public boolean sendMessage(String message) {
        if (!isRunning.get() || writer == null) {
            return false;
        }
        executorService.submit(() -> {
            writer.println(message);
            if (writer.checkError()) {
                logError("消息发送失败，连接可能已断开", null);
                cleanupAndScheduleReconnect();
            }
        });
        return true;
    }

    private void cleanupAndScheduleReconnect() {
        if (!isRunning.get()) return;

        cleanup();
        notifyConnectionChange(false);

        // --- 修改：实现指数退避和随机抖动 ---
        long nextReconnectDelay = (long) (currentReconnectInterval + (Math.random() * 1000)); // 增加随机抖动
        log("将在 " + (nextReconnectDelay / 1000) + " 秒后尝试重连...");
        executorService.schedule(this::performConnection, nextReconnectDelay, TimeUnit.MILLISECONDS);

        // 更新下一次的重连间隔
        currentReconnectInterval = (int) (currentReconnectInterval * RECONNECT_BACKOFF_FACTOR);
        if (currentReconnectInterval > MAX_RECONNECT_INTERVAL) {
            currentReconnectInterval = MAX_RECONNECT_INTERVAL;
        }
        // ------------------------------------
    }

    private void cleanup() {
        try { if (reader != null) reader.close(); } catch (IOException e) { }
        try { if (writer != null) writer.close(); } catch (Exception e) { }
        try { if (socket != null) socket.close(); } catch (IOException e) { }
    }

    private void notifyConnectionChange(boolean connected) {
        if (messageListener != null) {
            try {
                messageListener.onConnectionStatusChanged(connected);
            } catch (Exception e) {
                logError("连接状态通知异常", e);
            }
        }
    }

    public void setMessageListener(MessageListener listener) {
        this.messageListener = listener;
    }

    private void log(String message) { System.out.println("[" + TAG + "] " + message); }
    private void logError(String message, Exception e) { System.err.println("[" + TAG + "] ERROR: " + message); }

    public interface MessageListener {
        void onMessageReceived(String message);
        void onConnectionStatusChanged(boolean connected);
    }
}
