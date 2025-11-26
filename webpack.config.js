// webpack.config.js
const path = require('path');
const WebpackObfuscator = require('webpack-obfuscator');
const CopyWebpackPlugin = require('copy-webpack-plugin');

module.exports = {
  // 定义三个入口点
  entry: {
    background: './background.js',
    content: './content.js',
    'page/main.bundle': './page/main.js', // 将所有页面脚本打包成一个文件
  },
  output: {
    path: path.resolve(__dirname, 'dist'), // 输出到 dist 文件夹
    filename: '[name].js', // 输出文件名将与入口名相同
  },
  plugins: [
    // 插件1: 复制 manifest.json 和其他静态资源
    new CopyWebpackPlugin({
      patterns: [
        { from: 'manifest.json', to: 'manifest.json' },
        { from: 'jsQR.js', to: 'jsQR.js' },
        { from: 'qrcodeMonitor.js', to: 'qrcodeMonitor.js' },
        // patientListener.js 现在已经打包进 main.bundle.js，不需要单独复制
        // 如果您有图标等其他静态资源，也在这里添加
        // { from: 'icons', to: 'icons' }
      ],
    }),
    // 插件2: 对所有输出的JS文件进行混淆
    new WebpackObfuscator({
      rotateStringArray: true, // 旋转字符串数组
      stringArray: true,
      stringArrayThreshold: 0.75,
      deadCodeInjection: true,
      deadCodeInjectionThreshold: 0.4,
      debugProtection: false,
      // 更多配置请参考 webpack-obfuscator 文档
    }, []),
  ],
  // 解析配置
  resolve: {
    extensions: ['.js', '.json'],
    mainFields: ['main', 'module']
  },
  // 模式设置为 'production' 会自动启用代码压缩 (Terser)
  mode: 'production',
};
