Java.perform(function () {
    const TargetButton = Java.use('com.example.MyButton'); // 替换为目标类名

    TargetButton.onClick.implementation = function () {
        console.log("[✓] 拦截点击事件并自动触发");
        this.onClick(); // 调用原方法（模拟真实点击）
    };
});