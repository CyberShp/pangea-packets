# Windows 便携版

适用范围：Windows 10/11 x64，个人本机运行。解压整个 Pangea 文件夹到当前用户可写目录，双击 Pangea.exe。无需安装 Python 或 Node.js。浏览器打开 http://127.0.0.1:18765/；保留控制台窗口，按 Ctrl+C 停止后台。关闭浏览器不会停止后台。

端口被占用时启动失败；先关闭已有实例。启动失败会显示原因。企业终端可能拦截未签名程序，请按内部软件审核流程处理。

## 数据与升级

异常报文场景、主机配置和执行记录保存在 Pangea.exe 同级 app-data 文件夹。备份前停止程序；升级时解压到新目录，然后复制旧 app-data。主机配置包含明文凭据，只允许本人访问该目录；不要上传或分享运行数据。日志在控制台显示，执行记录保存在 app-data。

iBMC 当前为演示流程，数据在相同浏览器、相同地址的本地存储中，复制程序目录不会迁移它。清理浏览器数据会清除这些演示记录。

## 内网测试环境

Windows 提供操作页面、报文构造与导出。实际收发报文通过 SSH 在授权 Linux 测试主机上执行；该主机须事先准备 Python、Scapy、抓包所需 libpcap 和相应执行权限。运行平台不会自动安装远端依赖。请先完成主机连接和环境检查，再在隔离测试环境执行。

服务仅监听本机回环地址，适用于个人操作台。首次内网验收应在无 Python/Node.js、断外网的 Windows 电脑检查启动、保存、重启、预览、导出，再验证授权远端主机上的收发与卡件结果。

## 构建与下载

GitHub Actions → Windows portable → Run workflow。成功后下载 Pangea-windows-x64 制品，外层压缩包内包含便携 ZIP 和 SHA256SUMS.txt。使用 PowerShell `Get-FileHash .\Pangea-windows-x64.zip -Algorithm SHA256` 校验后转入内网。

构建使用 Windows x64 / Python 3.12 / Node.js 22。归档附有源码提交号和本次实际依赖版本清单。前端依赖由 package-lock.json 固定；后台依赖遵循 requirements.txt 的兼容范围，因此不同日期重建可能使用不同版本。GitHub 构建验证不替代干净离线终端和真实卡件验收。
