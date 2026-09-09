# 方法来源与内容边界

查阅日期：2026-09-10。本包是面向 iBMC 的原创操作规程与样例；公开指南用于方法分类和进一步核对，不随包复制指南正文，也没有引入社区 Skill、二进制或第三方执行脚本。

| 来源 | 定位 | 本包用途 |
| --- | --- | --- |
| [OWASP WSTG v4.2](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/) | 4.1 信息收集，4.4 认证，4.5 授权，4.6 会话，4.7 输入验证，4.10 业务逻辑 | Web/API 方法分类与检查方向 |
| [WSTG v4.2 输入验证目录](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/) | 4.7.1/2 XSS、4.7.12 命令注入、4.7.19 SSRF | 方法定位；具体产品适用性由资料和观测决定 |
| [OWASP ISTG 固件](https://owasp.org/owasp-istg/03_test_cases/firmware/) | 固件、已安装固件、更新机制 | 固件材料、权限、更新与恢复的检查方向 |

WSTG 使用上述固定版本链接；ISTG 链接为滚动页面，查阅日期不等于固定内容快照。引用源后续变化时，先核对方法差异再修订包版本，不自动替换已审查用例。

OWASP 页面注明其内容通常采用 CC BY-SA 4.0，具体以来源页及项目许可证为准。若后续复制或改编其正文，须核对适用许可证并履行署名与相同方式共享等要求。本次未审计或授权任何第三方工具的分发；不得从本文件推断仓库其他文件的许可证。
