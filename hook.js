/**
 * Frida Hook Script - 联欧医生端人脸验证绕过 (基于源码分析)
 * 
 * 登录流程分析:
 * 1. Activity调用 l(loginType) -> API.t(loginType)
 * 2. 成功后 h().setValue(TRUE)
 * 3. h()的Observer触发，调用 c(action, loginId, loginType) -> API.q0()
 * 4. 成功后 d().setValue(TRUE) 
 * 5. d()的Observer触发，获取位置并开始人脸识别
 * 
 * 绕过策略:
 * - Hook l()方法，强制调用成功回调
 * - Hook c()方法，强制调用成功回调
 * - 这样就会跳过实际的API请求，直接让验证成功
 */

console.log('\n' + '='.repeat(60));
console.log('🎯 联欧医生端 - 人脸验证绕过脚本 v3 (基于源码)');
console.log('='.repeat(60) + '\n');

Java.perform(function() {
    console.log('[*] Java 环境已就绪\n');
    
    // 打印应用信息
    const ActivityThread = Java.use('android.app.ActivityThread');
    const currentApplication = ActivityThread.currentApplication();
    const context = currentApplication.getApplicationContext();
    const packageName = context.getPackageName();
    
    console.log('📱 应用: ' + packageName);
    console.log('');
    
    try {
        // Hook FaceRecognitionViewModel
        const FaceRecognitionViewModel = Java.use('com.lojk.doctor.ui.mine.faceRecognition.faceLogin.FaceRecognitionViewModel');
        
        console.log('[*] 正在 Hook FaceRecognitionViewModel...\n');
        
        // 保存原始方法
        const originalL = FaceRecognitionViewModel.l;
        const originalC = FaceRecognitionViewModel.c;
        
        // ============================================
        // 关键Hook 1: l(loginType) - 初始化人脸登录
        // ============================================
        FaceRecognitionViewModel.l.implementation = function(loginType) {
            console.log('\n🎭 [FACE] l(loginType) 被调用');
            console.log('   参数: loginType=' + loginType);
            console.log('   ✅ 调用原始API，但强制成功回调');
            
            // 调用原始方法（发送API请求到后端）
            originalL.call(this, loginType);
            
            // 但立即强制设置 h() 的LiveData为TRUE（不管API结果）
            const BooleanClass = Java.use('java.lang.Boolean');
            this.h().setValue(BooleanClass.valueOf(true));
            
            console.log('   ✅ 已强制设置 h().setValue(TRUE)');
            return;
        };
        
        // ============================================
        // 关键Hook 2: c(action, loginId, loginType) - 确认登录
        // ============================================
        FaceRecognitionViewModel.c.implementation = function(action, loginId, loginType) {
            console.log('\n🎭 [FACE] c(action, loginId, loginType) 被调用');
            console.log('   参数: action=' + action);
            console.log('   参数: loginId=' + loginId);
            console.log('   参数: loginType=' + loginType);
            console.log('   ✅ 调用原始API进行真实登录');
            
            // 调用原始方法（发送真实API请求，让后端处理登录）
            originalC.call(this, action, loginId, loginType);
            
            // API会异步返回，我们等待一下然后强制设置成功
            // 注意：不设置 d().setValue(TRUE)，而是直接设置 i().setValue("")
            // 这样可以跳过人脸识别Fragment，直接触发登录成功跳转
            const self = this;
            setTimeout(function() {
                Java.perform(function() {
                    self.i().setValue("");
                    console.log('   ✅ 已强制设置 i().setValue("") - 触发登录成功');
                    console.log('   🎉 人脸验证流程已完成！');
                });
            }, 500);  // 延迟500ms让API有时间执行
            
            return;
        };
        
        // ============================================
        // 辅助Hook 3: f(context) - 阻止获取位置
        // ============================================
        FaceRecognitionViewModel.f.implementation = function(context) {
            console.log('\n🎭 [FACE] f(context) 被调用 - 获取位置');
            console.log('   ✅ 阻止获取位置，直接设置空位置');
            
            // 不获取位置，直接设置 k() 为空字符串
            this.k().setValue("");
            
            console.log('   ✅ 已设置 k().setValue("")');
            return;
        };
        
        // ============================================
        // 辅助Hook 4: m() - 上传人脸图片（如果前面方法失效才会走到这里）
        // ============================================
        try {
            FaceRecognitionViewModel.m.implementation = function(loginID, faceBase64, action, loginType, location) {
                console.log('\n🎭 [FACE] m() 被调用 - 上传人脸图片');
                console.log('   ⛔ 拦截人脸图片上传请求！');
                console.log('   参数: loginID=' + loginID);
                console.log('   参数: action=' + action);
                console.log('   参数: loginType=' + loginType);
                console.log('   参数: location=' + location);
                console.log('   参数: faceBase64长度=' + (faceBase64 ? faceBase64.length : 0));
                
                // 🚫 直接返回，不调用原始方法，完全阻止上传
                console.log('   ✅ 已阻止人脸图片上传');
                
                // 直接设置成功状态
                this.i().setValue("");
                const BooleanClass = Java.use('java.lang.Boolean');
                this.getShowLoadingLiveData().setValue(BooleanClass.valueOf(false));
                
                return;
            };
            console.log('[✓] m() Hook 完成');
        } catch (e) {
            console.log('[✗] m() Hook 失败: ' + e);
        }
        
        // ============================================
        // 监听Hook: 观察LiveData的变化
        // ============================================
        console.log('[*] 正在 Hook LiveData观察...\n');
        
        // Hook h() - 返回初始化状态的LiveData
        const originalH = FaceRecognitionViewModel.h;
        FaceRecognitionViewModel.h.implementation = function() {
            const result = originalH.call(this);
            console.log('🔍 [LiveData] h() 被访问 (初始化状态): ' + result);
            return result;
        };
        
        // Hook d() - 返回确认登录状态的LiveData
        const originalD = FaceRecognitionViewModel.d;
        FaceRecognitionViewModel.d.implementation = function() {
            const result = originalD.call(this);
            console.log('🔍 [LiveData] d() 被访问 (确认登录状态): ' + result);
            return result;
        };
        
        // Hook i() - 返回错误消息的LiveData
        const originalI = FaceRecognitionViewModel.i;
        FaceRecognitionViewModel.i.implementation = function() {
            const result = originalI.call(this);
            console.log('🔍 [LiveData] i() 被访问 (错误消息): ' + result);
            return result;
        };
        
        console.log('[✓] FaceRecognitionViewModel Hook 完成\n');
        
    } catch (e) {
        console.log('[✗] FaceRecognitionViewModel Hook 失败: ' + e + '\n');
    }
    
    // ============================================
    // Hook QRCode相关（监听二维码处理）
    // ============================================
    try {
        console.log('[*] 正在 Hook QRCode...\n');
        
        const QRCodeClass = Java.use('com.lojk.doctor.QRCode.c');
        
        // Hook a() - 处理二维码
        const originalA = QRCodeClass.a;
        if (originalA && originalA.overloads) {
            originalA.overloads.forEach(function(overload) {
                overload.implementation = function() {
                    console.log('\n📱 [QRCODE] a() 被调用 - 处理二维码');
                    console.log('   参数: ' + Array.prototype.slice.call(arguments).join(', '));
                    
                    // 继续正常执行
                    const result = overload.call(this, ...arguments);
                    console.log('   返回: ' + result);
                    return result;
                };
            });
        }
        
        // Hook b() - 显示Toast
        QRCodeClass.b.implementation = function(activity, str) {
            console.log('\n📱 [QRCODE] Toast: ' + str);
            return this.b(activity, str);
        };
        
        console.log('[✓] QRCode Hook 完成\n');
        
    } catch (e) {
        console.log('[✗] QRCode Hook 失败: ' + e + '\n');
    }
    
    // ============================================
    // Hook OkHttp - 拦截网络请求（最底层防御）
    // ============================================
    try {
        console.log('[*] 正在 Hook OkHttp 网络层...\n');
        
        const OkHttpClient = Java.use('okhttp3.OkHttpClient');
        const Request = Java.use('okhttp3.Request');
        const Response = Java.use('okhttp3.Response');
        const ResponseBody = Java.use('okhttp3.ResponseBody');
        const MediaType = Java.use('okhttp3.MediaType');
        
        // Hook RealCall.execute()
        const RealCall = Java.use('okhttp3.internal.connection.RealCall');
        const originalExecute = RealCall.execute;
        
        RealCall.execute.implementation = function() {
            const request = this.request();
            const url = request.url().toString();
            
            // 检查是否是人脸验证API
            if (url.indexOf('Face/VerifyFace') !== -1) {
                console.log('\n🚫 [NETWORK] 拦截人脸验证请求！');
                console.log('   URL: ' + url);
                console.log('   ⛔ 阻止请求发送，返回模拟成功响应\n');
                
                // 构造一个成功的响应
                const responseBody = ResponseBody.create(
                    MediaType.parse('application/json'),
                    '{"code":0,"msg":"success","data":{}}'
                );
                
                const response = Response.$new(request)
                    .code(200)
                    .message('OK')
                    .body(responseBody)
                    .build();
                
                return response;
            }
            
            // 其他请求正常执行
            return originalExecute.call(this);
        };
        
        console.log('[✓] OkHttp Hook 完成\n');
        
    } catch (e) {
        console.log('[✗] OkHttp Hook 失败: ' + e + '\n');
    }
    
    console.log('='.repeat(60));
    console.log('✅ 所有Hook完成！');
    console.log('='.repeat(60) + '\n');
    
    console.log('💡 工作原理:');
    console.log('  1. 拦截 l(loginType) 方法，直接设置 h() = TRUE');
    console.log('  2. 拦截 c(action, loginId, loginType) 方法');
    console.log('  3. 直接设置 i() = "" 触发登录成功跳转');
    console.log('  4. 拦截 f(context) 阻止获取位置');
    console.log('  5. 拦截 m() 阻止人脸图片上传');
    console.log('  6. 验证成功，无需人脸识别！\n');
});



