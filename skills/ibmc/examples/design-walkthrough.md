# BMC-Lab R12 离线设计演练

日期：2026-09-10。包版本：0.1.0。输入：[product-brief.md](product-brief.md)。本记录为作者在当前会话读取六项 Skill 后的离线演练，非独立模型评测、平台调用或实机测试。所有观测都是输入中的虚构记录。

## 1. 产品信息收集

project_id=LAB-R12，型号=BMC-Lab，版本=R12，样机=A，板卡修订/详细配置=unknown。依据 DOC-01 第 2 节。

| source_id | 版本和定位 | 性质 | 适用性/限制 |
| --- | --- | --- | --- |
| DOC-01 | R12 第 2 节 | 文档声明 | 产品与隔离要求 |
| DOC-02 | R12 第 3 节 | 文档声明 | 接口和预期权限，待正式确认 |
| DOC-03 | R11 第 4 节 | 文档声明 | Reader 镜像权限与 R12 资料冲突，适用性未确认 |
| DOC-04 | R12 第 5 节 | 文档声明 | 更新声明，无启动/恢复实证 |
| OBS-01 | R12 / SIM-A / 09:00 +08:00 | 模拟观测 | 仅管理网 Reader 的 GET |
| OBS-02 | R12 / SIM-B / 09:01 +08:00 | 模拟观测 | 超时原因未知 |
| SIM-01 | R12 / req-7 | 模拟结果 | 任务与请求关联缺失，时间 unknown |

| module_id | 模块与入口 | 角色/资源 | 来源与缺口 |
| --- | --- | --- | --- |
| MOD-ACCOUNT | 账户；接口 unknown | Reader/Admin | DOC-01；操作权限细节 unknown |
| MOD-MEDIA | GET/POST /lab/media，imageUrl | 远程镜像、服务端访问目标 | DOC-01/02/03；POST 角色要求待确认 |
| MOD-UPDATE | GET/POST /lab/update | 更新元数据、固件/任务 | DOC-02/04；GET Reader，POST Admin；测试包和恢复材料缺失 |
| MOD-LOG | GET /lab/logs/{id} | 导出任务所属用户及内容 | DOC-02；仅可读自己的任务；账号和测试资源未准备 |

需产品负责人确认 R12 角色表及变更说明；需测试负责人补窗口、测试账号、限速和受控接收端；需固件负责人补合法包、恢复和启动证据。TLS 组件只有名称，不生成 CVE 或漏洞结论。

## 2. 攻击面

| surface_id | 模块/入口 | 位置/身份/版本 | 事实与来源 | 限制 |
| --- | --- | --- | --- | --- |
| SUR-MEDIA | MOD-MEDIA / POST /lab/media | unknown / Admin（文档）/ R12 | DOC-02 声明 URL 获取 | 无主动观测；Reader 权限冲突 |
| SUR-UPDATE-GET | MOD-UPDATE / GET /lab/update | 管理网 / Reader / R12 | OBS-01 / SIM-A 返回元数据 | 仅支持该次读取；不支持更新执行权限结论 |
| SUR-UPDATE-POST | MOD-UPDATE / POST /lab/update | unknown / Reader / R12 | SIM-01 的 req-7 返回 403 | task-9 无法关联；版本状态 unknown |
| SUR-BUSINESS | 管理服务 / HTTPS | 业务网 / 未登录 / R12 | OBS-02 / SIM-B 超时 | 隔离是否有效仍 unknown |
| SUR-LOG | MOD-LOG / GET /lab/logs/{id} | unknown / 任务拥有者（文档）/ R12 | DOC-02 声明下载功能 | 未观察实际权限行为 |

最小采集建议：确认拓扑和目标健康后，按批准的同条件只读操作补采管理网/业务网响应、网络路径和访问控制日志。目标、速率、并发、时长及停止阈值待批准；当前无执行授权。不得将两组不同身份/位置快照判为版本差异。

## 3. 风险与路径

以下优先级均为设计建议，待测试人员确认，不代表漏洞评级。

| risk_id | 模块/暴露面 | 建议优先级与理由 | 条件与反证/缺口 |
| --- | --- | --- | --- |
| RISK-MEDIA | MOD-MEDIA / SUR-MEDIA | 优先：用户输入影响服务端访问目标 | DOC-02 已声明目标限制；能否越界 unknown |
| RISK-UPDATE | MOD-UPDATE / SUR-UPDATE-POST | 优先：涉及固件状态和高权限动作 | SIM-01 有拒绝码；关联与真实状态不足 |
| RISK-LOG | MOD-LOG / SUR-LOG | 后续：不同用户导出内容隔离 | DOC-02 声明归属限制；无实际证据 |

| path_id / 起始身份 / 目标 | 逐步前提、证据和状态 | 方法与用例 |
| --- | --- | --- |
| PATH-MEDIA / Admin / 超出允许源的受控目标 | 输入 URL（DOC-02，文档 supported）→ BMC 获取（DOC-01，文档 supported、运行 unknown）→ 目标限制失效（无证据，candidate） | WEB-SSRF / CASE-001；整条 candidate |
| PATH-UPDATE / Reader / 提交更新 | Reader 可读取（OBS-01，模拟 supported）→ Reader 提交（SIM-01，有拒绝响应）→ 创建更新任务（关联缺失，unknown） | FW-UPDATE-AUTHZ / CASE-002；整条 unknown |
| PATH-LOG / 一个普通测试账号 / 他人导出内容 | 取得自己的任务（DOC-02，文档 supported）→ 请求另一测试账号的合成任务（未执行，candidate）→ 返回受限内容（unknown） | WEB-DOWNLOAD、WEB-AUTHZ；用例待后续设计，未覆盖 |

## 4. 用例设计

两例共有：revision=1，project_id=LAB-R12，样机 A/R12；design_status=draft，execution_status=not_run。执行前须确认详细配置、目标、网络位置、账号引用、允许动作、请求/并发/时长上限、监控、窗口和恢复责任人。具体值 unknown，当前执行准入为 blocked。人工设计审查与执行审批均未完成。

### CASE-001：远程镜像的目标限制

- module_id：MOD-MEDIA；path_ids：PATH-MEDIA；method_id：WEB-SSRF；source_ids：DOC-01 第 2 节、DOC-02 第 3 节、DOC-03 第 4 节。
- 目标/适用性：POST /lab/media 的 imageUrl 由服务端使用，适用目标限制验证；以 Admin 设计，Reader 权限冲突不作已解决处理。
- 前置条件：确认 R12 规则；提供合法合成镜像、允许源及策略外但明确获准用于测试的受控目标。解析与接收端记录可关联。不得使用生产服务或真实秘密。
- 正常对照：Admin 提交允许源的测试镜像，确认服务端访问和任务正常；对照未建立则后续结论受限。
- 输入类别：允许的受控 URL、策略外受控 URL；重定向分支另建修订/用例，不宣称本例已覆盖。
- 步骤：记录角色、任务和挂载基线；执行正常对照并清理；只改变目标为已批准的策略外受控地址；收集请求响应、任务和两端关联日志；取消测试任务、卸载测试镜像并复核基线。
- 预期行为：正常目标可用，策略外目标被阻止访问。
- pass：正常对照有效，策略外目标被阻止，完整的服务端和接收端证据相互印证。
- fail：带本次关联标记的记录证明 BMC 访问了明确禁止的测试目标。
- inconclusive：只有接口响应、接收端无记录但采集完整性不明，或不能确认请求由 BMC 发出。
- 证据：身份引用、输入类别及标记、时间、完整响应、出站/接收端日志、任务及挂载前后状态。
- 停止与恢复：设备告警、失联或目标超出批准范围即停；取消任务并卸载。恢复操作接口/负责人 unknown，须补齐后才允许执行。

### CASE-002：Reader 更新提交权限

- module_id：MOD-UPDATE；path_ids：PATH-UPDATE；method_id：FW-UPDATE-AUTHZ；source_ids：DOC-02 第 3 节、DOC-04 第 5 节、OBS-01。
- 目标/适用性：验证 Reader 可读取元数据但不能提交更新；不能用 OBS-01 的 200 推导提交权限。
- 前置条件：确认权限要求，准备隔离样机、合法测试包、Admin/Reader、版本和任务基线、写入授权及旁路恢复。上述材料目前不全。
- 正常对照：在单独批准的写入窗口验证 Admin 合法提交及状态，恢复基线后再验证 Reader；不能用无效包导致的拒绝代替权限对照。
- 输入类别：相同合法测试包和接口，改变授权身份；不混入包损坏条件。
- 步骤：记录版本/配置/任务和角色；完成 Admin 正常对照及恢复；Reader 向 POST /lab/update 提交同类合法包；关联请求 ID、任务、审计和版本变化；按批准方案清理恢复。
- 预期行为：Reader 提交被拒绝且不触发更新，获准 Admin 正常操作有效。
- pass：对照成立，Reader 请求与状态证据完整，拒绝且未创建相应更新任务或改变版本/配置。
- fail：Reader 请求被可靠关联到非预期更新任务或受保护状态改变，即使响应为 403。
- inconclusive：只有拒绝码或任务无法关联、状态日志缺失。
- 证据：包摘要、角色引用、请求 ID、响应、任务创建者/时间、版本/配置基线、审计与恢复记录。
- 停止与恢复：出现非预期任务、写入、告警或失联立即停后续输入并按既定旁路方案恢复；不自动断电。恢复方案 unknown，当前不得执行。

### 方法覆盖与未覆盖

WEB-SSRF、FW-UPDATE-AUTHZ 已形成草稿；WEB-DOWNLOAD/WEB-AUTHZ 有适用依据但尚未形成日志下载用例。WEB-XSS、WEB-UPLOAD、WEB-INJECTION、WEB-SESSION 缺足够资料，适用性待定，不标为通过或不适用。FW-INTEGRITY 有文档声明，缺包与实证；FW-ROLLBACK、FW-RECOVERY、FW-BOOT-TRUST 缺策略/恢复/启动证据。FW-INVENTORY 缺版本与补丁资料。未覆盖项保留，不生成产品全量安全结论。

## 5. 模拟结果复核

SIM-01 的 case_id/revision=unknown；仅与 CASE-002 的验证问题相关，不能追溯认定它执行了当前草稿。run_id=SIM-01，证据=SIM-01/req-7/task-9，环境=R12/Reader、位置和时间 unknown。

判定：inconclusive。403 是拒绝响应事实；task-9 缺身份、时间、请求关联，既不能证明越权成功，也不能证明无状态改变。恢复状态 unknown。PATH-UPDATE 保持 unknown，不建立已确认漏洞。

复测要求：补齐 CASE-002 前置条件，冻结当前 SIM-01 原始记录；在批准环境关联请求与任务、对照前后版本和配置并记录恢复。当前两例仍 not_run，不计入执行覆盖。
