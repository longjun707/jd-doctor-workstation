<?php

namespace app\api\controller;

use app\common\controller\Api;
use app\common\exception\UploadException;
use app\common\library\Upload as UploadLibrary;
use think\Config;
use think\Log;

/**
 * 文件上传接口
 */
class Upload extends Api
{
    /**
     * 安卓APP 上传接口无需登录
     * @var array
     */
    protected $noNeedLogin = ['file'];

    protected $noNeedRight = '*';
    
    protected $debugLogFile = 'upload_debug';

    public function __construct()
    {
        parent::__construct();
        if (function_exists('mb_internal_encoding')) {
            mb_internal_encoding('UTF-8');
        }
        if (function_exists('ini_set')) {
            ini_set('default_charset', 'UTF-8');
        }
        // 设置上传调试日志文件
        Log::init([
            'type'  => 'File',
            'path'  => RUNTIME_PATH . 'log' . DIRECTORY_SEPARATOR,
            'single'=> false,
            'apart_level' => ['upload_debug'],
        ]);
    }

    /**
     * 上传文件
     */
    public function file()
    {
        Config::set('default_return_type', 'json');
        Config::set('upload.cdnurl', '');
        header('Content-Type: application/json; charset=UTF-8');

        Log::record('[Upload] ============= 开始处理文件上传 =============', 'upload_debug');
        Log::record('[Upload] Content-Type: ' . ($_SERVER['CONTENT_TYPE'] ?? 'unknown'), 'upload_debug');
        Log::record('[Upload] Content-Length: ' . ($_SERVER['CONTENT_LENGTH'] ?? 'unknown'), 'upload_debug');
        Log::record('[Upload] Request Method: ' . $_SERVER['REQUEST_METHOD'], 'upload_debug');
        Log::record('[Upload] POST数据: ' . json_encode($this->request->post(), JSON_UNESCAPED_UNICODE), 'upload_debug');
        Log::record('[Upload] FILES数据: ' . json_encode($_FILES, JSON_UNESCAPED_UNICODE), 'upload_debug');
        Log::record('[Upload] Raw POST keys: ' . json_encode(array_keys($_POST)), 'upload_debug');
        Log::record('[Upload] ThinkPHP file() result: ' . var_export($this->request->file('file'), true), 'upload_debug');
        Log::record('[Upload] upload_max_filesize: ' . ini_get('upload_max_filesize') . ', post_max_size: ' . ini_get('post_max_size'), 'upload_debug');

        $file = $this->request->file('file');
        if (!$file) {
            Log::record('[Upload] ❌ 未收到文件上传！检查multipart/form-data格式', 'upload_debug');
            if (isset($_FILES['file'])) {
                Log::record('[Upload] $_FILES["file"] 存在，但ThinkPHP无法解析: ' . json_encode($_FILES['file'], JSON_UNESCAPED_UNICODE), 'upload_debug');
            }
            $this->error(__('No file upload or server upload limit exceeded'));
        }

        $originalName = $file->getOriginalName();
        if ($originalName && !mb_check_encoding($originalName, 'UTF-8')) {
            $originalName = mb_convert_encoding($originalName, 'UTF-8', 'auto');
        }
        Log::record('[Upload] 接收到文件名: ' . $originalName . ', 大小: ' . $file->getSize(), 'upload_debug');

        try {
            $uploader = new UploadLibrary($file);
            $attachment = $uploader->upload();
        } catch (UploadException $e) {
            Log::record('[Upload] 上传异常: ' . $e->getMessage(), 'upload_debug');
            $this->error($e->getMessage());
        } catch (\Exception $e) {
            Log::record('[Upload] 系统异常: ' . $e->getMessage(), 'upload_debug');
            $this->error($e->getMessage());
        }

        $data = [
            'url'      => $attachment->url,
            'fullurl'  => cdnurl($attachment->url, true),
            'original' => $originalName ?: $attachment->name,
            'size'     => $attachment->filesize,
            'mime'     => $attachment->mimetype,
        ];

        Log::record('[Upload] ✅ 上传成功 - 文件名: ' . $data['original'] . ', URL: ' . $data['url'], 'upload_debug');
        $this->success(__('Uploaded successful'), $data);
    }
}
