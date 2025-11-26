<?php
namespace app\api\controller;

use app\common\controller\Api;
use think\Db;

/**
 * 药物和病症数据API
 */
class Medicine extends Api
{
    protected $noNeedLogin = ['*'];
    protected $noNeedRight = ['*'];
    
    /**
     * 获取所有数据（多药物、单药物、病症）- 用于客户端比对和提示
     * GET /api/medicine/getAllData?tenant_type=JD10004003
     * 
     * @apiParam {string} tenant_type 租户类型（可选），如 JD10004003
     */
    public function getAllData()
    {
        try {
            // 获取租户类型参数
            $tenantType = $this->request->param('tenant_type', '');
            
            // 获取医生工作台版本号
            $workbenchVersion = Db::name('data_version')
                ->where('module', '医生工作台')
                ->value('version');
            
            // 检查未成年功能和自动回复是否开启
            $minorEnabled = false;
            $autoReplyEnabled = false;
            if ($tenantType) {
                $tenantConfig = Db::name('tenant_config')
                    ->where('tenant_type', $tenantType)
                    ->where('is_active', 1)
                    ->find();
                if (!empty($tenantConfig)) {
                    $minorEnabled = $tenantConfig['minor_switch'] == 1;
                    $autoReplyEnabled = $tenantConfig['auto_reply_switch'] == 1;
                }
            }
            
            // 获取多药物列表（支持租户筛选）
            $multiDrugQuery = Db::name('multidrug')->where('status', 'normal');
            if ($tenantType) {
                $multiDrugQuery->where(function($query) use ($tenantType) {
                    $query->whereOr('tenant_types', '')
                          ->whereOr('tenant_types', 'LIKE', '%' . $tenantType . '%');
                });
            }
            $multiDrugs = $multiDrugQuery
                ->field('id,name,description,tenant_types')
                ->order('weigh desc,id asc')
                ->select();
            
            // 构建多药物名称数组（用于快速比对）
            $multiDrugNames = array_column($multiDrugs, 'name');
            
            // 获取单药物列表（带分类和租户筛选）
            $singleDrugQuery = Db::name('singledrug')->where('status', 'normal');
            if ($tenantType) {
                $singleDrugQuery->where(function($query) use ($tenantType) {
                    $query->whereOr('tenant_types', '')
                          ->whereOr('tenant_types', 'LIKE', '%' . $tenantType . '%');
                });
            }
            $singleDrugs = $singleDrugQuery
                ->field('id,name,category,description,tenant_types')
                ->order('weigh desc,id asc')
                ->select();
            
            // 构建单药物名称数组（用于快速比对）
            $singleDrugNames = array_column($singleDrugs, 'name');
            
            // 按分类分组单药物
            $singleDrugsByCategory = [];
            $singleDrugCategories = [];
            foreach ($singleDrugs as $drug) {
                $category = $drug['category'] ?: '未分类';
                if (!isset($singleDrugsByCategory[$category])) {
                    $singleDrugsByCategory[$category] = [];
                    $singleDrugCategories[] = $category;
                }
                $singleDrugsByCategory[$category][] = $drug;
            }
            
            // 获取病症列表（带分类和租户筛选）
            $symptomQuery = Db::name('symptom')->where('status', 'normal');
            if ($tenantType) {
                $symptomQuery->where(function($query) use ($tenantType) {
                    $query->whereOr('tenant_types', '')
                          ->whereOr('tenant_types', 'LIKE', '%' . $tenantType . '%');
                });
            }
            $symptoms = $symptomQuery
                ->field('id,name,category,description,tenant_types')
                ->order('weigh desc,id asc')
                ->select();
            
            // 构建病症名称数组（用于快速比对）
            $symptomNames = array_column($symptoms, 'name');
            
            // 按分类分组病症
            $symptomsByCategory = [];
            $symptomCategories = [];
            foreach ($symptoms as $symptom) {
                $category = $symptom['category'] ?: '未分类';
                if (!isset($symptomsByCategory[$category])) {
                    $symptomsByCategory[$category] = [];
                    $symptomCategories[] = $category;
                }
                $symptomsByCategory[$category][] = $symptom;
            }
            
            // 构建完整的返回数据
            $result = [
                // 多药物
                'multi_drugs' => [
                    'list' => $multiDrugs,
                    'names' => $multiDrugNames,  // 便于快速比对
                    'count' => count($multiDrugs)
                ],
                
                // 单药物
                'single_drugs' => [
                    'list' => $singleDrugs,
                    'names' => $singleDrugNames,  // 便于快速比对
                    'by_category' => $singleDrugsByCategory,
                    'categories' => array_values(array_unique($singleDrugCategories)),
                    'count' => count($singleDrugs)
                ],
                
                // 病症
                'symptoms' => [
                    'list' => $symptoms,
                    'names' => $symptomNames,  // 便于快速比对
                    'by_category' => $symptomsByCategory,
                    'categories' => array_values(array_unique($symptomCategories)),
                    'count' => count($symptoms)
                ],
                
                // 元数据
                'meta' => [
                    'tenant_type' => $tenantType ?: 'all',  // 当前租户类型
                    'minor_enabled' => $minorEnabled,  // 未成年功能是否开启
                    'auto_reply_enabled' => $autoReplyEnabled,  // 自动回复是否开启
                    'total_count' => count($multiDrugs) + count($singleDrugs) + count($symptoms),
                    'update_time' => time(),
                    'version' => $workbenchVersion ?: '1.0.0'  // 医生工作台版本号
                ]
            ];
            
        } catch (\Exception $e) {
            // 记录详细错误信息
            \think\Log::error('getAllData接口错误: ' . $e->getMessage());
            \think\Log::error('错误追踪: ' . $e->getTraceAsString());
            $this->error('获取失败：' . $e->getMessage());
        }
        
        // success() 会抛出异常来返回响应，所以要放在 try-catch 外面
        $this->success('获取成功', $result);
    }
    
    /**
     * 获取多药物列表
     */
    public function getMultiDrugs()
    {
        try {
            $list = Db::name('multidrug')
                ->where('status', 'normal')
                ->field('id,name,description')
                ->order('weigh desc,id asc')
                ->select();
            
            $this->success('获取成功', [
                'list' => $list,
                'total' => count($list)
            ]);
            
        } catch (\Exception $e) {
            $this->error('获取失败：' . $e->getMessage());
        }
    }
    
    /**
     * 获取单药物列表（带分类）
     */
    public function getSingleDrugs()
    {
        try {
            $list = Db::name('singledrug')
                ->where('status', 'normal')
                ->field('id,name,category,description')
                ->order('weigh desc,id asc')
                ->select();
            
            // 按分类分组
            $categories = [];
            foreach ($list as $drug) {
                $category = $drug['category'] ?: '未分类';
                if (!isset($categories[$category])) {
                    $categories[$category] = [];
                }
                $categories[$category][] = $drug;
            }
            
            $this->success('获取成功', [
                'list' => $list,
                'categories' => $categories,
                'total' => count($list)
            ]);
            
        } catch (\Exception $e) {
            $this->error('获取失败：' . $e->getMessage());
        }
    }
    
    /**
     * 获取病症列表（带分类）
     */
    public function getSymptoms()
    {
        try {
            $list = Db::name('symptom')
                ->where('status', 'normal')
                ->field('id,name,category,description')
                ->order('weigh desc,id asc')
                ->select();
            
            // 按分类分组
            $categories = [];
            foreach ($list as $symptom) {
                $category = $symptom['category'] ?: '未分类';
                if (!isset($categories[$category])) {
                    $categories[$category] = [];
                }
                $categories[$category][] = $symptom;
            }
            
            $this->success('获取成功', [
                'list' => $list,
                'categories' => $categories,
                'total' => count($list)
            ]);
            
        } catch (\Exception $e) {
            $this->error('获取失败：' . $e->getMessage());
        }
    }
    
    /**
     * 获取所有分类
     */
    public function getCategories()
    {
        try {
            // 获取单药物分类
            $drugCategories = Db::name('singledrug')
                ->where('status', 'normal')
                ->where('category', '<>', '')
                ->group('category')
                ->column('category');
            
            // 获取病症分类
            $symptomCategories = Db::name('symptom')
                ->where('status', 'normal')
                ->where('category', '<>', '')
                ->group('category')
                ->column('category');
            
            $this->success('获取成功', [
                'drug_categories' => array_values($drugCategories),
                'symptom_categories' => array_values($symptomCategories)
            ]);
            
        } catch (\Exception $e) {
            $this->error('获取失败：' . $e->getMessage());
        }
    }
    
    /**
     * 根据分类获取单药物
     */
    public function getSingleDrugsByCategory()
    {
        try {
            $category = $this->request->param('category', '');
            
            if (empty($category)) {
                $this->error('请指定分类');
            }
            
            $list = Db::name('singledrug')
                ->where('status', 'normal')
                ->where('category', $category)
                ->field('id,name,category,description')
                ->order('weigh desc,id asc')
                ->select();
            
            $this->success('获取成功', [
                'category' => $category,
                'list' => $list,
                'total' => count($list)
            ]);
            
        } catch (\Exception $e) {
            $this->error('获取失败：' . $e->getMessage());
        }
    }
    
    /**
     * 根据分类获取病症
     */
    public function getSymptomsByCategory()
    {
        try {
            $category = $this->request->param('category', '');
            
            if (empty($category)) {
                $this->error('请指定分类');
            }
            
            $list = Db::name('symptom')
                ->where('status', 'normal')
                ->where('category', $category)
                ->field('id,name,category,description')
                ->order('weigh desc,id asc')
                ->select();
            
            $this->success('获取成功', [
                'category' => $category,
                'list' => $list,
                'total' => count($list)
            ]);
            
        } catch (\Exception $e) {
            $this->error('获取失败：' . $e->getMessage());
        }
    }
    
    /**
     * 获取数据版本号
     * GET /api/medicine/getVersion
     * 
     * @return 返回医生工作台版本号信息
     */
    public function getVersion()
    {
        try {
            // 获取医生工作台版本信息
            $versionInfo = Db::name('data_version')
                ->where('module', '医生工作台')
                ->field('version,update_time,remark')
                ->find();
            
            if (!$versionInfo) {
                // 如果没有记录，返回默认版本
                $versionInfo = [
                    'version' => '1.0.0',
                    'update_time' => time(),
                    'remark' => '医生工作台'
                ];
            }
            
            $this->success('获取成功', [
                'version' => $versionInfo['version'],
                'update_time' => $versionInfo['update_time'],
                'remark' => $versionInfo['remark'],
                'check_time' => time()
            ]);
            
        } catch (\Exception $e) {
            \think\Log::error('getVersion接口错误: ' . $e->getMessage());
            $this->error('获取失败：' . $e->getMessage());
        }
    }
    
    /**
     * 检查租户开关状态（未成年功能、自动回复等）
     * GET /api/medicine/checkMinorSwitch?tenant_type=JD10004003
     * 
     * @apiParam {string} tenant_type 租户类型，如 JD10004003
     */
    public function checkMinorSwitch()
    {
        try {
            $tenantType = $this->request->param('tenant_type', '');
            
            if (empty($tenantType)) {
                $this->error('请提供租户类型参数');
            }
            
            // 查询该租户配置
            $tenantConfig = Db::name('tenant_config')
                ->where('tenant_type', $tenantType)
                ->find();
            
            $minorEnabled = false;
            $autoReplyEnabled = false;
            $message = '未配置';
            
            if ($tenantConfig) {
                if ($tenantConfig['is_active'] == 0) {
                    $message = '租户已禁用';
                } else {
                    $minorEnabled = ($tenantConfig['minor_switch'] == 1);
                    $autoReplyEnabled = ($tenantConfig['auto_reply_switch'] == 1);
                    $message = '配置正常';
                }
            }
            
            $this->success('查询成功', [
                'tenant_type' => $tenantType,
                'minor_enabled' => $minorEnabled,
                'auto_reply_enabled' => $autoReplyEnabled,
                'status_text' => $message,
                'config' => $tenantConfig ? [
                    'hospital_name' => $tenantConfig['hospital_name'],
                    'encrypt_suffix' => $tenantConfig['encrypt_suffix'],
                    'is_active' => $tenantConfig['is_active'],
                    'minor_switch' => $tenantConfig['minor_switch'],
                    'auto_reply_switch' => $tenantConfig['auto_reply_switch']
                ] : null,
                'check_time' => time()
            ]);
            
        } catch (\Exception $e) {
            \think\Log::error('checkMinorSwitch接口错误: ' . $e->getMessage());
            $this->error('查询失败：' . $e->getMessage());
        }
    }
    
    /**
     * 查询医生的问诊中数量（浏览器插件专用）
     * GET /api/medicine/getDiagnosisStatus?doctor_id=123
     * 
     * @apiParam {int} doctor_id 医生ID（必填）
     * @return 返回该医生的问诊中数量和设备信息
     */
    public function getDiagnosisStatus()
    {
        $doctorId = $this->request->param('doctor_id', 0);
        
        if (empty($doctorId)) {
            $this->error('请提供医生ID参数');
        }
        
        try {
            // 查询该医生的设备信息
            $device = Db::name('jdhealth')
                ->where('doctor_id', $doctorId)
                ->field('id,name,doing_diag_num')
                ->find();
            
            // 获取问诊中数量，找不到设备时返回0
            $doingDiagNum = $device ? (int)$device['doing_diag_num'] : 0;
            
        } catch (\Exception $e) {
            \think\Log::error('getDiagnosisStatus接口错误: ' . $e->getMessage());
            $this->error('查询失败：' . $e->getMessage());
        }
        
        // success() 会抛出异常，所以放在 try-catch 外面
        $this->success('查询成功', [
            'doctor_id' => (int)$doctorId,
            'doing_diag_num' => $doingDiagNum
        ]);
    }
    
    /**
     * 浏览器主动更新医生ID（根据医生姓名）
     * GET /api/medicine/updateDoctorId
     * 
     * @ApiParams (name="name", type="string", required=true, description="医生姓名")
     * @ApiParams (name="doctor_id", type="string", required=true, description="京东医生平台医生ID")
     * @return json 返回更新结果
     */
    public function updateDoctorId()
    {
        // 获取参数
        $name = trim($this->request->param('name', ''));
        $doctorId = trim($this->request->param('doctor_id', ''));
        
        // 参数验证
        if (!$name) {
            return json(['code' => 0, 'msg' => '缺少name参数', 'data' => null]);
        }
        
        if (!$doctorId) {
            return json(['code' => 0, 'msg' => '缺少doctor_id参数', 'data' => null]);
        }
        
        try {
            // 根据医生姓名查询记录
            $doctor = Db::name('jdhealth')
                ->where('name', $name)
                ->whereNull('deletetime')
                ->find();
            
            if (!$doctor) {
                \think\Log::record(sprintf(
                    '[更新医生ID] 未找到医生 - 姓名:%s',
                    $name
                ), 'warning');
                
                return json(['code' => 0, 'msg' => '医生不存在', 'data' => null]);
            }
            
            // 更新doctor_id
            $result = Db::name('jdhealth')
                ->where('id', $doctor['id'])
                ->update(['doctor_id' => $doctorId]);
            
            if ($result !== false) {
                \think\Log::record(sprintf(
                    '[更新医生ID] 成功 - 姓名:%s | 旧ID:%s | 新ID:%s',
                    $name,
                    $doctor['doctor_id'] ?: '空',
                    $doctorId
                ), 'info');
                
                return json([
                    'code' => 1,
                    'msg' => '医生ID更新成功',
                    'data' => [
                        'name' => $name,
                        'old_doctor_id' => $doctor['doctor_id'],
                        'new_doctor_id' => $doctorId,
                        'username' => $doctor['username']
                    ]
                ]);
            } else {
                return json(['code' => 0, 'msg' => '更新失败', 'data' => null]);
            }
            
        } catch (\Exception $e) {
            \think\Log::record(sprintf(
                '[更新医生ID] 异常 - 姓名:%s | 错误:%s',
                $name,
                $e->getMessage()
            ), 'error');
            
            return json(['code' => 0, 'msg' => '更新失败', 'data' => null]);
        }
    }
    
    /**
     * 浏览器插件更新医生二维码URL（根据医生姓名）
     * GET /api/medicine/updateUrl
     * 
     * @ApiParams (name="name", type="string", required=true, description="医生姓名")
     * @ApiParams (name="url", type="string", required=true, description="二维码链接URL")
     * @return json 返回更新结果
     */
    public function updateUrl()
    {
        // 获取参数
        $name = trim($this->request->param('name', ''));
        $url = trim($this->request->param('url', ''));
        
        // 参数验证
        if (!$name) {
            return json(['code' => 0, 'msg' => '缺少name参数', 'data' => null]);
        }
        
        if (!$url) {
            return json(['code' => 0, 'msg' => '缺少url参数', 'data' => null]);
        }
        
        try {
            // 根据医生姓名查询记录
            $doctor = Db::name('jdhealth')
                ->where('name', $name)
                ->whereNull('deletetime')
                ->find();
            
            if (!$doctor) {
                \think\Log::record(sprintf(
                    '[更新医生URL] 未找到医生 - 姓名:%s',
                    $name
                ), 'warning');
                
                return json(['code' => 0, 'msg' => '医生不存在', 'data' => null]);
            }
            
            // 更新url和updatetime
            $result = Db::name('jdhealth')
                ->where('id', $doctor['id'])
                ->update([
                    'url' => $url,
                    'updatetime' => date('Y-m-d H:i:s')
                ]);
            
            if ($result !== false) {
                \think\Log::record(sprintf(
                    '[更新医生URL] 成功 - 姓名:%s | 旧URL:%s | 新URL:%s',
                    $name,
                    $doctor['url'] ?: '空',
                    $url
                ), 'info');
                
                // 获取公开访问链接
                $domain = $this->request->domain();
                $publicUrl = $domain . '/index/qrcode/show?name=' . urlencode($name);
                
                return json([
                    'code' => 1,
                    'msg' => '医生URL更新成功',
                    'data' => [
                        'name' => $name,
                        'old_url' => $doctor['url'],
                        'new_url' => $url,
                        'public_url' => $publicUrl,
                        'qrcode_page' => $publicUrl,
                        'update_time' => date('Y-m-d H:i:s')
                    ]
                ]);
            } else {
                return json(['code' => 0, 'msg' => '更新失败', 'data' => null]);
            }
            
        } catch (\Exception $e) {
            \think\Log::record(sprintf(
                '[更新医生URL] 异常 - 姓名:%s | 错误:%s',
                $name,
                $e->getMessage()
            ), 'error');
            
            return json(['code' => 0, 'msg' => '更新失败：' . $e->getMessage(), 'data' => null]);
        }
    }
}

