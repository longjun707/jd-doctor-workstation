<?php

namespace app\api\controller;

use app\common\controller\Api;
use think\Db;

/**
 * 京东医生API接口
 */
class Jdhealth extends Api
{
    // 浏览器插件专用接口：不需要登录
    protected $noNeedLogin = ['getVersion', 'getToken', 'updateToken'];
    protected $noNeedRight = ['*'];
    
    /**
     * 初始化 - 自定义CORS处理
     */
    protected function _initialize()
    {
        // 手动处理CORS，允许所有来源
        if (isset($_SERVER['HTTP_ORIGIN'])) {
            header("Access-Control-Allow-Origin: " . $_SERVER['HTTP_ORIGIN']);
            header('Access-Control-Allow-Credentials: true');
            header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
            header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, Token');
            header('Access-Control-Max-Age: 86400');
        }
        
        // 处理OPTIONS预检请求
        if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
            exit(0);
        }
        
        // 不调用 parent::_initialize()，避免触发 check_cors_request() 检查
        $this->request = request();
    }

    /**
     * 获取京东医生客户端最新版本号（从数据版本表查询）
     * GET /api/jdhealth/getVersion
     * 
     * @return json 返回最新版本号信息
     */
    public function getVersion()
    {
        try {
            // 从数据版本表查询京东医生的版本信息
            $versionInfo = Db::name('data_version')
                ->where('module', '京东医生')
                ->order('id desc')
                ->find();
            
            if (!$versionInfo) {
                // 如果没找到，返回默认信息
                return json([
                    'code' => 1,
                    'msg' => '暂无版本信息',
                    'data' => [
                        'version' => '1.0.0',
                        'module' => '京东医生',
                        'update_time' => time(),
                        'remark' => '',
                        'download_url' => ''
                    ]
                ]);
            }
            
            // 返回版本信息
            return json([
                'code' => 1,
                'msg' => '获取成功',
                'data' => [
                    'version' => $versionInfo['version'] ?? '1.0.0',
                    'module' => $versionInfo['module'] ?? '京东医生',
                    'update_time' => (int)($versionInfo['update_time'] ?? 0),
                    'remark' => $versionInfo['remark'] ?? '',
                    'download_url' => $versionInfo['download_url'] ?? ''
                ]
            ]);
            
        } catch (\Exception $e) {
            // 记录详细错误信息
            \think\Log::record(sprintf(
                '[京东医生-版本查询] 数据库异常 - 错误:%s | 文件:%s:%d',
                $e->getMessage(),
                $e->getFile(),
                $e->getLine()
            ), 'error');
            
            return json(['code' => 0, 'msg' => '查询失败', 'data' => null]);
        }
    }
    
    /**
     * 获取医生Token信息（如果没有token则返回手机号和密码）
     * GET /api/jdhealth/getToken
     * 
     * @ApiParams (name="doctor_id", type="string", required=true, description="京东医生平台医生ID")
     * @return json 返回token或登录凭证
     */
    public function getToken()
    {
        // 获取参数
        $doctorId = trim($this->request->param('doctor_id', ''));
        
        // 参数验证
        if (!$doctorId) {
            return json(['code' => 0, 'msg' => '缺少doctor_id参数', 'data' => null]);
        }
        
        try {
            // 查询医生记录（使用doctor_id字段查询）
            $doctor = Db::name('jdhealth')
                ->where('doctor_id', $doctorId)
                ->whereNull('deletetime')
                ->field('id,doctor_id,username,phone,password,token')
                ->find();
            
            if (!$doctor) {
                return json(['code' => 0, 'msg' => '医生不存在', 'data' => null]);
            }
            
            // 判断是否有token
            if (!empty($doctor['token'])) {
                // 有token，直接返回token
                return json([
                    'code' => 1,
                    'msg' => '获取成功',
                    'data' => [
                        'has_token' => true,
                        'doctor_id' => $doctor['doctor_id'],
                        'token' => $doctor['token'],
                        'username' => $doctor['username']
                    ]
                ]);
            } else {
                // 没有token，返回手机号和加密的密码
                $encryptedPassword = $this->encryptPassword($doctor['password']);
                
                return json([
                    'code' => 1,
                    'msg' => '获取成功',
                    'data' => [
                        'has_token' => false,
                        'doctor_id' => $doctor['doctor_id'],
                        'username' => $doctor['username'],
                        'phone' => $doctor['phone'],
                        'password' => $encryptedPassword  // 返回加密后的密码
                    ]
                ]);
            }
            
        } catch (\Exception $e) {
            \think\Log::record(sprintf(
                '[京东医生-Token查询] 异常 - 医生ID:%s | 错误:%s',
                $doctorId,
                $e->getMessage()
            ), 'error');
            
            return json(['code' => 0, 'msg' => '查询失败', 'data' => null]);
        }
    }
    
    /**
     * 更新医生Token
     * GET /api/jdhealth/updateToken
     * 
     * @ApiParams (name="doctor_id", type="string", required=true, description="京东医生平台医生ID")
     * @ApiParams (name="token", type="string", required=true, description="新的token")
     * @return json 返回更新结果
     */
    public function updateToken()
    {
        // 获取参数（支持GET和POST）
        $doctorId = trim($this->request->param('doctor_id', ''));
        $token = trim($this->request->param('token', ''));
        
        // 参数验证
        if (!$doctorId) {
            return json(['code' => 0, 'msg' => '缺少doctor_id参数', 'data' => null]);
        }
        
        if (!$token) {
            return json(['code' => 0, 'msg' => '缺少token参数', 'data' => null]);
        }
        
        try {
            // 查询医生记录（使用doctor_id字段查询）
            $doctor = Db::name('jdhealth')
                ->where('doctor_id', $doctorId)
                ->whereNull('deletetime')
                ->find();
            
            if (!$doctor) {
                return json(['code' => 0, 'msg' => '医生不存在', 'data' => null]);
            }
            
            // 更新token
            $result = Db::name('jdhealth')
                ->where('doctor_id', $doctorId)
                ->update(['token' => $token]);
            
            if ($result !== false) {
                \think\Log::record(sprintf(
                    '[京东医生-Token更新] 成功 - 医生ID:%s | 用户名:%s | Token长度:%d',
                    $doctorId,
                    $doctor['username'],
                    strlen($token)
                ), 'info');
                
                return json([
                    'code' => 1,
                    'msg' => 'Token更新成功',
                    'data' => [
                        'doctor_id' => $doctorId,
                        'username' => $doctor['username'],
                        'token' => $token
                    ]
                ]);
            } else {
                return json(['code' => 0, 'msg' => '更新失败', 'data' => null]);
            }
            
        } catch (\Exception $e) {
            \think\Log::record(sprintf(
                '[京东医生-Token更新] 异常 - 医生ID:%s | 错误:%s',
                $doctorId,
                $e->getMessage()
            ), 'error');
            
            return json(['code' => 0, 'msg' => '更新失败', 'data' => null]);
        }
    }
    
    /**
     * DES加密密码（DES/CBC/PKCS5Padding）
     * @param string $password 原始密码
     * @return string 返回Base64编码的加密结果
     */
    private function encryptPassword($password)
    {
        // 如果密码为空，返回空字符串
        if (empty($password)) {
            return '';
        }
        
        try {
            // DES加密参数（根据京东医生的加密规范）
            $key = 'sa#65$f4';      // 8字节密钥
            $iv = 'gzsyfdgs';       // 8字节IV
            
            // 使用DES-CBC加密，PKCS5Padding（PHP中使用openssl）
            $encrypted = openssl_encrypt(
                $password,                    // 要加密的内容
                'DES-CBC',                    // 加密方法
                $key,                         // 密钥
                OPENSSL_RAW_DATA,            // 返回原始二进制数据
                $iv                           // 初始化向量
            );
            
            // 返回Base64编码的加密结果
            return base64_encode($encrypted);
            
        } catch (\Exception $e) {
            \think\Log::record('[京东医生] DES加密失败: ' . $e->getMessage(), 'error');
            return '';
        }
    }
    
    /**
     * DES解密密码（用于测试验证）
     * @param string $encryptedPassword Base64编码的加密密码
     * @return string 返回原始密码
     */
    private function decryptPassword($encryptedPassword)
    {
        if (empty($encryptedPassword)) {
            return '';
        }
        
        try {
            $key = 'sa#65$f4';
            $iv = 'gzsyfdgs';
            
            // Base64解码
            $encrypted = base64_decode($encryptedPassword);
            
            // DES-CBC解密
            $decrypted = openssl_decrypt(
                $encrypted,
                'DES-CBC',
                $key,
                OPENSSL_RAW_DATA,
                $iv
            );
            
            return $decrypted;
            
        } catch (\Exception $e) {
            \think\Log::record('[京东医生] DES解密失败: ' . $e->getMessage(), 'error');
            return '';
        }
    }
}

<?php

namespace app\api\controller;

use app\common\controller\Api;
use think\Db;

/**
 * 京东医生API接口
 */
class Jdhealth extends Api
{
    // 浏览器插件专用接口：不需要登录
    protected $noNeedLogin = ['getVersion', 'getToken', 'updateToken'];
    protected $noNeedRight = ['*'];
    
    /**
     * 初始化 - 自定义CORS处理
     */
    protected function _initialize()
    {
        // 手动处理CORS，允许所有来源
        if (isset($_SERVER['HTTP_ORIGIN'])) {
            header("Access-Control-Allow-Origin: " . $_SERVER['HTTP_ORIGIN']);
            header('Access-Control-Allow-Credentials: true');
            header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
            header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, Token');
            header('Access-Control-Max-Age: 86400');
        }
        
        // 处理OPTIONS预检请求
        if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
            exit(0);
        }
        
        // 不调用 parent::_initialize()，避免触发 check_cors_request() 检查
        $this->request = request();
    }

    /**
     * 获取京东医生客户端最新版本号（从数据版本表查询）
     * GET /api/jdhealth/getVersion
     * 
     * @return json 返回最新版本号信息
     */
    public function getVersion()
    {
        try {
            // 从数据版本表查询京东医生的版本信息
            $versionInfo = Db::name('data_version')
                ->where('module', '京东医生')
                ->order('id desc')
                ->find();
            
            if (!$versionInfo) {
                // 如果没找到，返回默认信息
                return json([
                    'code' => 1,
                    'msg' => '暂无版本信息',
                    'data' => [
                        'version' => '1.0.0',
                        'module' => '京东医生',
                        'update_time' => time(),
                        'remark' => '',
                        'download_url' => ''
                    ]
                ]);
            }
            
            // 返回版本信息
            return json([
                'code' => 1,
                'msg' => '获取成功',
                'data' => [
                    'version' => $versionInfo['version'] ?? '1.0.0',
                    'module' => $versionInfo['module'] ?? '京东医生',
                    'update_time' => (int)($versionInfo['update_time'] ?? 0),
                    'remark' => $versionInfo['remark'] ?? '',
                    'download_url' => $versionInfo['download_url'] ?? ''
                ]
            ]);
            
        } catch (\Exception $e) {
            // 记录详细错误信息
            \think\Log::record(sprintf(
                '[京东医生-版本查询] 数据库异常 - 错误:%s | 文件:%s:%d',
                $e->getMessage(),
                $e->getFile(),
                $e->getLine()
            ), 'error');
            
            return json(['code' => 0, 'msg' => '查询失败', 'data' => null]);
        }
    }
    
    /**
     * 获取医生Token信息（如果没有token则返回手机号和密码）
     * GET /api/jdhealth/getToken
     * 
     * @ApiParams (name="doctor_id", type="string", required=true, description="京东医生平台医生ID")
     * @return json 返回token或登录凭证
     */
    public function getToken()
    {
        // 获取参数
        $doctorId = trim($this->request->param('doctor_id', ''));
        
        // 参数验证
        if (!$doctorId) {
            return json(['code' => 0, 'msg' => '缺少doctor_id参数', 'data' => null]);
        }
        
        try {
            // 查询医生记录（使用doctor_id字段查询）
            $doctor = Db::name('jdhealth')
                ->where('doctor_id', $doctorId)
                ->whereNull('deletetime')
                ->field('id,doctor_id,username,phone,password,token')
                ->find();
            
            if (!$doctor) {
                return json(['code' => 0, 'msg' => '医生不存在', 'data' => null]);
            }
            
            // 判断是否有token
            if (!empty($doctor['token'])) {
                // 有token，直接返回token
                return json([
                    'code' => 1,
                    'msg' => '获取成功',
                    'data' => [
                        'has_token' => true,
                        'doctor_id' => $doctor['doctor_id'],
                        'token' => $doctor['token'],
                        'username' => $doctor['username']
                    ]
                ]);
            } else {
                // 没有token，返回手机号和加密的密码
                $encryptedPassword = $this->encryptPassword($doctor['password']);
                
                return json([
                    'code' => 1,
                    'msg' => '获取成功',
                    'data' => [
                        'has_token' => false,
                        'doctor_id' => $doctor['doctor_id'],
                        'username' => $doctor['username'],
                        'phone' => $doctor['phone'],
                        'password' => $encryptedPassword  // 返回加密后的密码
                    ]
                ]);
            }
            
        } catch (\Exception $e) {
            \think\Log::record(sprintf(
                '[京东医生-Token查询] 异常 - 医生ID:%s | 错误:%s',
                $doctorId,
                $e->getMessage()
            ), 'error');
            
            return json(['code' => 0, 'msg' => '查询失败', 'data' => null]);
        }
    }
    
    /**
     * 更新医生Token
     * GET /api/jdhealth/updateToken
     * 
     * @ApiParams (name="doctor_id", type="string", required=true, description="京东医生平台医生ID")
     * @ApiParams (name="token", type="string", required=true, description="新的token")
     * @return json 返回更新结果
     */
    public function updateToken()
    {
        // 获取参数（支持GET和POST）
        $doctorId = trim($this->request->param('doctor_id', ''));
        $token = trim($this->request->param('token', ''));
        
        // 参数验证
        if (!$doctorId) {
            return json(['code' => 0, 'msg' => '缺少doctor_id参数', 'data' => null]);
        }
        
        if (!$token) {
            return json(['code' => 0, 'msg' => '缺少token参数', 'data' => null]);
        }
        
        try {
            // 查询医生记录（使用doctor_id字段查询）
            $doctor = Db::name('jdhealth')
                ->where('doctor_id', $doctorId)
                ->whereNull('deletetime')
                ->find();
            
            if (!$doctor) {
                return json(['code' => 0, 'msg' => '医生不存在', 'data' => null]);
            }
            
            // 更新token
            $result = Db::name('jdhealth')
                ->where('doctor_id', $doctorId)
                ->update(['token' => $token]);
            
            if ($result !== false) {
                \think\Log::record(sprintf(
                    '[京东医生-Token更新] 成功 - 医生ID:%s | 用户名:%s | Token长度:%d',
                    $doctorId,
                    $doctor['username'],
                    strlen($token)
                ), 'info');
                
                return json([
                    'code' => 1,
                    'msg' => 'Token更新成功',
                    'data' => [
                        'doctor_id' => $doctorId,
                        'username' => $doctor['username'],
                        'token' => $token
                    ]
                ]);
            } else {
                return json(['code' => 0, 'msg' => '更新失败', 'data' => null]);
            }
            
        } catch (\Exception $e) {
            \think\Log::record(sprintf(
                '[京东医生-Token更新] 异常 - 医生ID:%s | 错误:%s',
                $doctorId,
                $e->getMessage()
            ), 'error');
            
            return json(['code' => 0, 'msg' => '更新失败', 'data' => null]);
        }
    }
    
    /**
     * DES加密密码（DES/CBC/PKCS5Padding）
     * @param string $password 原始密码
     * @return string 返回Base64编码的加密结果
     */
    private function encryptPassword($password)
    {
        // 如果密码为空，返回空字符串
        if (empty($password)) {
            return '';
        }
        
        try {
            // DES加密参数（根据京东医生的加密规范）
            $key = 'sa#65$f4';      // 8字节密钥
            $iv = 'gzsyfdgs';       // 8字节IV
            
            // 使用DES-CBC加密，PKCS5Padding（PHP中使用openssl）
            $encrypted = openssl_encrypt(
                $password,                    // 要加密的内容
                'DES-CBC',                    // 加密方法
                $key,                         // 密钥
                OPENSSL_RAW_DATA,            // 返回原始二进制数据
                $iv                           // 初始化向量
            );
            
            // 返回Base64编码的加密结果
            return base64_encode($encrypted);
            
        } catch (\Exception $e) {
            \think\Log::record('[京东医生] DES加密失败: ' . $e->getMessage(), 'error');
            return '';
        }
    }
    
    /**
     * DES解密密码（用于测试验证）
     * @param string $encryptedPassword Base64编码的加密密码
     * @return string 返回原始密码
     */
    private function decryptPassword($encryptedPassword)
    {
        if (empty($encryptedPassword)) {
            return '';
        }
        
        try {
            $key = 'sa#65$f4';
            $iv = 'gzsyfdgs';
            
            // Base64解码
            $encrypted = base64_decode($encryptedPassword);
            
            // DES-CBC解密
            $decrypted = openssl_decrypt(
                $encrypted,
                'DES-CBC',
                $key,
                OPENSSL_RAW_DATA,
                $iv
            );
            
            return $decrypted;
            
        } catch (\Exception $e) {
            \think\Log::record('[京东医生] DES解密失败: ' . $e->getMessage(), 'error');
            return '';
        }
    }
}

