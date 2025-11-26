Java.perform(function () {
    // 目标实例的 hashCode（十六进制表示）
    const TARGET_HASH_CODE = "8fd82e7";
    const INTERVAL_SECONDS = 2; // 定时间隔（秒）

// 🔍 实例 hashCode: 929db6
// 🔍 实例 hashCode: fa3e4ef
// 🔍 实例 hashCode: 8637bfc
// 🔍 实例 hashCode: 30ac285
// 🔍 实例 hashCode: ab788da
// 🔍 实例 hashCode: e73e10b
// 🔍 实例 hashCode: f6a5be8
// 🔍 实例 hashCode: 5ba0201
// 🔍 实例 hashCode: a9558a6
// 🔍 实例 hashCode: 8fd82e7
// 🔍 实例 hashCode: 77d4e94
// 🔍 实例 hashCode: 8c3bd3d
// 🔍 实例 hashCode: 92e5932

    function sendRequest(instance) {
        try {
            console.log("🚀 正在发送请求...");
            
            // 获取必要的类引用
            var RequestBuilder = Java.use('okhttp3.Request$Builder');
            var RequestBody = Java.use('okhttp3.RequestBody');
            var MediaType = Java.use('okhttp3.MediaType');

            // 创建 RequestBuilder
            var builder = RequestBuilder.$new();

            // 设置请求URL
            builder.url("https://api.m.jd.com/api/JDDAPP_diag_doctorReceive");

            // 创建请求体
            var mediaType = MediaType.parse("application/json");
            var body = RequestBody.create(
                mediaType,
                '{"diagId":812246744161541,"receiveEntranceSource":2}'
            );

            // 构建完整请求
            builder.post(body);
            builder.addHeader("Content-Type", "application/json");
            var request = builder.build();

            // 发送请求（同步）
            var response = instance.newCall(request).execute();

            // 处理响应
            console.log("✅ 响应码:", response.code());

            // 读取响应体
            var responseBody = response.body();
            if (responseBody) {
                var bodyString = responseBody.string();
                console.log("响应体:", bodyString);
                responseBody.close();
            } else {
                console.log("⚠️ 响应体为空");
            }

            // 关闭响应
            response.close();

            console.log("🎉 请求发送成功!");
        } catch (e) {
            console.log("❌ 请求发送失败:", e);
        }
    }

    console.log("🔍 开始搜索目标实例: hashCode=" + TARGET_HASH_CODE);

    Java.choose('okhttp3.OkHttpClient', {
        onMatch: function (instance) {
            try {
                // 1. 获取实例的 hashCode
                const instanceObj = Java.cast(instance, Java.use('java.lang.Object'));
                const instanceHash = instanceObj.hashCode().toString(16);
                  console.log("🔍 实例 hashCode:", instanceHash);
                // 2. 检查是否为目标实例
                if (instanceHash.toLowerCase() !== TARGET_HASH_CODE.toLowerCase()) {
                    return "continue";
                }

                console.log("🎯 找到目标实例: " + instanceHash);

                // 立即发送第一次请求
                sendRequest(instance);

                // 设置定时器
                setInterval(function() {
                    sendRequest(instance);
                }, INTERVAL_SECONDS * 1000);

                return "stop"; // 找到目标后停止搜索

            } catch (e) {
                console.log("❌ 实例匹配失败:", e);
                return "continue";
            }
        },
        onComplete: function () {
            console.log("✅ 实例搜索完成");
        }
    });
});

