package com.jd.doctor;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.DownloadManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.util.Log;
import android.widget.ProgressBar;
import android.widget.TextView;

import org.json.JSONObject;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * 版本检测和更新管理器（独立自治）
 * 功能：自动获取Activity、检查版本、提示更新、下载APK、显示进度
 */
public class VersionChecker {
    private static final String TAG = "VersionChecker";
    
    // 版本检测接口
    private static final String VERSION_API = "http://154.44.25.188:9378/api/jdhealth/getVersion";
    
    // 当前版本号（需要修改为实际版本）
    private static final String CURRENT_VERSION = "3.8.6";
    
    // 单例模式
    private static VersionChecker instance;
    private static boolean isInitialized = false;
    
    private Activity activity;
    private final OkHttpClient httpClient;
    private AlertDialog progressDialog;
    private long downloadId = -1;
    private DownloadManager downloadManager;
    private BroadcastReceiver downloadReceiver;
    private boolean hasChecked = false; // 防止重复检查
    private VersionCheckCallback callback; // 回调接口
    
    /**
     * 版本检测回调接口
     */
    public interface VersionCheckCallback {
        void onLogInfo(String message);
        void onLogError(String message);
        void onVersionChecked(String currentVersion, String serverVersion, boolean needUpdate);
    }
    
    private VersionChecker() {
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(10, TimeUnit.SECONDS)
                .build();
    }
    
    /**
     * 获取单例实例
     */
    public static synchronized VersionChecker getInstance() {
        if (instance == null) {
            instance = new VersionChecker();
        }
        return instance;
    }
    
    /**
     * 设置回调接口
     */
    public void setCallback(VersionCheckCallback callback) {
        this.callback = callback;
    }
    
    /**
     * 初始化（在Frida注入时调用）
     * 会自动Hook Activity生命周期来获取Activity并检查版本
     */
    public static void initialize() {
        if (isInitialized) {
            return;
        }
        
        VersionChecker checker = getInstance();
        checker.setupActivityHook();
        isInitialized = true;
    }
    
    /**
     * 设置Activity Hook（自动获取Activity）
     * 这是Java层的准备工作，实际Hook需要在JavaScript层完成
     */
    private void setupActivityHook() {
        // 注意：实际的Hook逻辑在JavaScript的Frida脚本中实现
        // 当Activity可用时，JavaScript会调用 setActivity() 方法
    }
    
    /**
     * 设置Activity（由Frida脚本调用）
     */
    public void setActivity(Activity activity) {
        if (this.activity == null && activity != null) {
            this.activity = activity;
            notifyLogInfo("Activity已设置: " + activity.getClass().getName());
            
            // Activity设置后自动检查版本（仅一次）
            if (!hasChecked) {
                checkForUpdate();
                hasChecked = true;
            }
        }
    }
    
    /**
     * 通知日志信息
     */
    private void notifyLogInfo(String message) {
        if (callback != null) {
            callback.onLogInfo(message);
        }
    }
    
    /**
     * 通知日志错误
     */
    private void notifyLogError(String message) {
        if (callback != null) {
            callback.onLogError(message);
        }
    }
    
    /**
     * 检查版本更新
     */
    public void checkForUpdate() {
        if (activity == null) {
            notifyLogError("Activity未设置，无法检查版本");
            return;
        }
        
        notifyLogInfo("开始检查版本更新...");
        
        Request request = new Request.Builder()
                .url(VERSION_API)
                .get()
                .build();
        
        httpClient.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                notifyLogError("版本检测请求失败: " + e.getMessage());
                if (activity != null) {
                    activity.runOnUiThread(() -> {
                        showErrorDialog("版本检测失败", "无法连接到服务器，请检查网络连接");
                    });
                }
            }
            
            @Override
            public void onResponse(Call call, Response response) throws IOException {
                if (!response.isSuccessful()) {
                    notifyLogError("版本检测响应失败: " + response.code());
                    return;
                }
                
                try {
                    String responseBody = response.body().string();
                    notifyLogInfo("版本检测响应: " + responseBody);
                    
                    JSONObject jsonResponse = new JSONObject(responseBody);
                    int code = jsonResponse.optInt("code", -1);
                    
                    if (code != 1) {
                        notifyLogError("版本检测接口返回错误: " + jsonResponse.optString("msg"));
                        return;
                    }
                    
                    JSONObject data = jsonResponse.optJSONObject("data");
                    if (data != null) {
                        String serverVersion = data.optString("version", "");
                        String module = data.optString("module", "京东医生");
                        String remark = data.optString("remark", "");
                        String downloadUrl = data.optString("download_url", "");
                        
                        notifyLogInfo("当前版本: " + CURRENT_VERSION + ", 服务器版本: " + serverVersion);
                        
                        // 比较版本号
                        boolean needUpdate = !CURRENT_VERSION.equals(serverVersion) && !downloadUrl.isEmpty();
                        
                        // 通知版本检测结果
                        if (callback != null) {
                            callback.onVersionChecked(CURRENT_VERSION, serverVersion, needUpdate);
                        }
                        
                        if (needUpdate) {
                            notifyLogInfo("发现新版本，准备显示更新对话框");
                            activity.runOnUiThread(() -> {
                                showUpdateDialog(serverVersion, module, remark, downloadUrl);
                            });
                        } else {
                            notifyLogInfo("当前已是最新版本");
                        }
                    }
                } catch (Exception e) {
                    notifyLogError("解析版本信息失败: " + e.getMessage());
                }
            }
        });
    }
    
    /**
     * 显示更新提示对话框
     */
    private void showUpdateDialog(String newVersion, String module, String remark, String downloadUrl) {
        String message = "发现新版本: " + newVersion + "\n\n";
        if (!remark.isEmpty()) {
            message += "更新说明:\n" + remark;
        } else {
            message += "请更新到最新版本";
        }
        
        new AlertDialog.Builder(activity)
                .setTitle("版本更新 - " + module)
                .setMessage(message)
                .setCancelable(false)
                .setPositiveButton("立即更新", (dialog, which) -> {
                    startDownload(downloadUrl, newVersion);
                })
                .setNegativeButton("稍后更新", (dialog, which) -> {
                    dialog.dismiss();
                })
                .show();
    }
    
    /**
     * 显示错误对话框
     */
    private void showErrorDialog(String title, String message) {
        new AlertDialog.Builder(activity)
                .setTitle(title)
                .setMessage(message)
                .setPositiveButton("确定", null)
                .show();
    }
    
    /**
     * 开始下载APK
     */
    private void startDownload(String downloadUrl, String version) {
        try {
            notifyLogInfo("开始下载更新 v" + version);
            notifyLogInfo("下载地址: " + downloadUrl);
            
            downloadManager = (DownloadManager) activity.getSystemService(Context.DOWNLOAD_SERVICE);
            
            // 创建下载请求
            DownloadManager.Request request = new DownloadManager.Request(Uri.parse(downloadUrl));
            request.setTitle("京东医生更新");
            request.setDescription("正在下载 v" + version);
            request.setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);
            request.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, "jd_doctor_" + version + ".apk");
            
            // 允许移动网络和WiFi下载
            request.setAllowedNetworkTypes(DownloadManager.Request.NETWORK_MOBILE | DownloadManager.Request.NETWORK_WIFI);
            
            // 开始下载
            downloadId = downloadManager.enqueue(request);
            notifyLogInfo("下载任务已创建，ID: " + downloadId);
            
            // 显示下载进度对话框
            showProgressDialog();
            
            // 注册下载完成监听
            registerDownloadReceiver();
            
            // 开始监控下载进度
            startProgressMonitor();
            
        } catch (Exception e) {
            notifyLogError("开始下载失败: " + e.getMessage());
            showErrorDialog("下载失败", "无法启动下载，请检查存储权限");
        }
    }
    
    /**
     * 显示下载进度对话框
     */
    private void showProgressDialog() {
        android.view.View view = activity.getLayoutInflater().inflate(
                android.R.layout.select_dialog_item, null);
        
        // 创建进度条视图
        android.widget.LinearLayout layout = new android.widget.LinearLayout(activity);
        layout.setOrientation(android.widget.LinearLayout.VERTICAL);
        layout.setPadding(50, 50, 50, 50);
        
        TextView textView = new TextView(activity);
        textView.setText("正在下载更新...");
        textView.setTextSize(16);
        textView.setPadding(0, 0, 0, 20);
        
        ProgressBar progressBar = new ProgressBar(activity, null, android.R.attr.progressBarStyleHorizontal);
        progressBar.setMax(100);
        progressBar.setId(android.R.id.progress);
        
        TextView percentView = new TextView(activity);
        percentView.setId(android.R.id.text1);
        percentView.setText("0%");
        percentView.setTextAlignment(android.view.View.TEXT_ALIGNMENT_CENTER);
        percentView.setPadding(0, 10, 0, 0);
        
        layout.addView(textView);
        layout.addView(progressBar);
        layout.addView(percentView);
        
        progressDialog = new AlertDialog.Builder(activity)
                .setTitle("下载更新")
                .setView(layout)
                .setCancelable(false)
                .setNegativeButton("取消下载", (dialog, which) -> {
                    cancelDownload();
                })
                .create();
        
        progressDialog.show();
    }
    
    /**
     * 开始监控下载进度
     */
    private void startProgressMonitor() {
        new Thread(() -> {
            boolean downloading = true;
            while (downloading) {
                DownloadManager.Query query = new DownloadManager.Query();
                query.setFilterById(downloadId);
                
                try (Cursor cursor = downloadManager.query(query)) {
                    if (cursor != null && cursor.moveToFirst()) {
                        int statusIndex = cursor.getColumnIndex(DownloadManager.COLUMN_STATUS);
                        int status = cursor.getInt(statusIndex);
                        
                        if (status == DownloadManager.STATUS_SUCCESSFUL || 
                            status == DownloadManager.STATUS_FAILED) {
                            downloading = false;
                        } else if (status == DownloadManager.STATUS_RUNNING) {
                            int totalIndex = cursor.getColumnIndex(DownloadManager.COLUMN_TOTAL_SIZE_BYTES);
                            int downloadedIndex = cursor.getColumnIndex(DownloadManager.COLUMN_BYTES_DOWNLOADED_SO_FAR);
                            
                            long total = cursor.getLong(totalIndex);
                            long downloaded = cursor.getLong(downloadedIndex);
                            
                            if (total > 0) {
                                int progress = (int) ((downloaded * 100) / total);
                                
                                activity.runOnUiThread(() -> {
                                    if (progressDialog != null && progressDialog.isShowing()) {
                                        ProgressBar progressBar = progressDialog.findViewById(android.R.id.progress);
                                        TextView percentView = progressDialog.findViewById(android.R.id.text1);
                                        
                                        if (progressBar != null) {
                                            progressBar.setProgress(progress);
                                        }
                                        if (percentView != null) {
                                            percentView.setText(progress + "%");
                                        }
                                    }
                                });
                            }
                        }
                    }
                } catch (Exception e) {
                    notifyLogError("查询下载进度失败: " + e.getMessage());
                }
                
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    break;
                }
            }
        }).start();
    }
    
    /**
     * 注册下载完成广播接收器
     */
    private void registerDownloadReceiver() {
        downloadReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                long id = intent.getLongExtra(DownloadManager.EXTRA_DOWNLOAD_ID, -1);
                if (id == downloadId) {
                    if (progressDialog != null && progressDialog.isShowing()) {
                        progressDialog.dismiss();
                    }
                    
                    // 检查下载状态
                    DownloadManager.Query query = new DownloadManager.Query();
                    query.setFilterById(downloadId);
                    
                    try (Cursor cursor = downloadManager.query(query)) {
                        if (cursor != null && cursor.moveToFirst()) {
                            int statusIndex = cursor.getColumnIndex(DownloadManager.COLUMN_STATUS);
                            int status = cursor.getInt(statusIndex);
                            
                            if (status == DownloadManager.STATUS_SUCCESSFUL) {
                                notifyLogInfo("✅ APK下载完成，使用文件管理器打开");
                                openWithFileManager();
                            } else {
                                notifyLogError("APK下载失败，状态码: " + status);
                                showErrorDialog("下载失败", "APK下载失败，请重试");
                            }
                        }
                    }
                }
            }
        };
        
        activity.registerReceiver(downloadReceiver, 
                new IntentFilter(DownloadManager.ACTION_DOWNLOAD_COMPLETE));
    }
    
    /**
     * 使用文件管理器打开下载的APK
     */
    private void openWithFileManager() {
        try {
            notifyLogInfo("准备使用文件管理器打开APK...");
            
            // 使用DownloadManager.getUriForDownloadedFile获取content URI
            Uri apkUri = downloadManager.getUriForDownloadedFile(downloadId);
            
            if (apkUri == null) {
                notifyLogError("无法获取下载文件的URI");
                showErrorDialog("打开失败", "无法获取下载文件，请手动在下载目录查看");
                return;
            }
            
            notifyLogInfo("APK URI: " + apkUri.toString());
            
            // 获取文件路径信息
            String fileName = null;
            try (Cursor cursor = downloadManager.query(new DownloadManager.Query().setFilterById(downloadId))) {
                if (cursor != null && cursor.moveToFirst()) {
                    int fileUriIndex = cursor.getColumnIndex(DownloadManager.COLUMN_LOCAL_URI);
                    int titleIndex = cursor.getColumnIndex(DownloadManager.COLUMN_TITLE);
                    String fileUri = cursor.getString(fileUriIndex);
                    fileName = cursor.getString(titleIndex);
                    notifyLogInfo("下载文件: " + fileName);
                    notifyLogInfo("文件路径: " + fileUri);
                }
            }
            
            // 使用 ACTION_VIEW 配合 content URI，让系统选择合适的应用打开
            Intent intent = new Intent(Intent.ACTION_VIEW);
            intent.setDataAndType(apkUri, "application/vnd.android.package-archive");
            
            // 设置必要的flags
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                intent.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK);
                notifyLogInfo("Android 7.0+: 已设置临时读取权限");
            } else {
                intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            }
            
            // 显示选择器，让用户选择用什么应用打开（文件管理器或安装器）
            Intent chooser = Intent.createChooser(intent, "选择打开方式");
            chooser.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            
            notifyLogInfo("正在打开文件选择器...");
            activity.startActivity(chooser);
            notifyLogInfo("文件选择器已打开，可使用文件管理器或直接安装");
            
        } catch (Exception e) {
            notifyLogError("打开文件失败: " + e.getMessage());
            showErrorDialog("打开失败", "无法打开文件，请手动在下载目录查看");
        }
    }
    
    /**
     * 取消下载
     */
    private void cancelDownload() {
        if (downloadManager != null && downloadId != -1) {
            downloadManager.remove(downloadId);
        }
        if (progressDialog != null && progressDialog.isShowing()) {
            progressDialog.dismiss();
        }
    }
    
    /**
     * 清理资源（在Activity销毁时调用）
     */
    public void cleanup() {
        try {
            if (downloadReceiver != null) {
                activity.unregisterReceiver(downloadReceiver);
                downloadReceiver = null;
            }
        } catch (Exception e) {
            notifyLogError("清理资源失败: " + e.getMessage());
        }
        
        if (progressDialog != null && progressDialog.isShowing()) {
            progressDialog.dismiss();
        }
    }
}

