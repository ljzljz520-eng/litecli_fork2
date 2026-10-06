# litecli 能力门禁（SQLite Authorizer + ExecutionPlan + 策略审计）PRD

## Overview
- **Summary**: 在 litecli 的数据库连接上安装 SQLite authorizer 作为执行期强制后端；在特殊命令注册表显式声明 `filesystem`、`process`、`extension`、`network`、`write-schema`（及 `write-data`）capability；执行前将多语句与嵌套来源（`.read`、favorite、LLM）编译为 `ExecutionPlan`，策略按交互/批处理模式做 allow/confirm/deny 决策，确认界面展示真实副作用，审计记录 plan hash、决策与实际 authorizer 事件，并可仅凭 plan hash 与脱敏记录重放决策。
- **Purpose**: SQLite 具备 ATTACH/VACUUM INTO 写文件、`load_extension` 加载动态库、`PRAGMA writable_schema` 直改系统表、sqlean `readfile/writefile/eval` 等文件/进程能力，且这些语句可藏在多语句、`.read` 文件、favorite 参数替换、LLM 生成 SQL 等嵌套来源中。现有 `destructive_warning` 仅基于关键字、只覆盖提示符直输路径。需要单一、统一、可审计的门禁，保证相同危险操作无论来源得到相同判定，且拒绝在任何副作用发生之前生效。
- **Target Users**: 在交互式终端、脚本批处理（`-e`/stdin）、启动命令、自动化/LLM 辅助场景下使用 litecli 的所有用户；以及需要事后审计与决策重放的合规使用者。

## Goals
- 连接级强制：每条连接（含 `.open` 重连、sqlean 与标准库 sqlite3 两种后端）安装 authorizer；危险事件在授权回调中 fail-closed。
- 注册表声明：特殊命令的客户端副作用（system/`.load`/`.read`/`.output`/`.once`/`pipe_once`/pager/`.import`/`.open`/`\llm`）显式声明 capability，作为静态计划与执行期检查依据。
- ExecutionPlan：执行前编译多语句与嵌套来源；统一来源签名 `prompt | read | startup | favorite | llm | execute | stdin`；plan hash 基于脱敏规范化结构。
- 统一策略：判定输入仅为 capability(+动作细分)+模式(交互/批处理)+规则，来源只记录不授权；五类来源同等判定。
- 真实确认：交互模式确认界面逐条列出真实副作用（capability、动作、真实目标，如文件路径/函数名/表名）；批处理无法确认时升级为拒绝。
- 审计重放：JSONL 审计包含 plan hash、来源签名、模式、脱敏条目、决策与命中规则、实际 authorizer 事件、结果；不含原始敏感 SQL；可凭 plan hash 确定性重放决策。
- 兼容：兼容 sqlean-py 与不同 SQLite 版本（常量缺失时用数值码表）；保持既有普通 SQL 体验（SELECT/普通 DML/CREATE 默认放行但审计）。

## Non-Goals
- 不实现基于角色/多用户的权限系统或远程策略下发。
- 不对查询结果数据（行内容）做审计或脱敏。
- 不替换 SQLite 自身的扩展沙箱语义（sqlean 对 SQL 内 `load_extension()` 的内置禁止继续有效）。
- 不新增网络/文件系统能力本身，只做声明、门禁与审计。
- 不重构补全引擎、输出格式化等与门禁无关模块。

## Background & Context

### 现状（代码事实）
- 执行主路径：[sqlexecute.py](file:///Users/kkcarrot/swe-project/litecli_fork2/litecli/sqlexecute.py) `SQLExecute.run()` 用 `sqlparse.split` 拆多语句，逐句 `special.execute(cur, sql)` 或 `cur.execute(sql)`，是生成器。
- 绕过主路径的直接执行：favorite 处理器、`watch`、`.import`、dbcommands 内部直接 `cur.execute()`；`.read`（[main.py execute_from_file](file:///Users/kkcarrot/swe-project/litecli_fork2/litecli/main.py#L220-L235)）读取文件后递归调用 `sqlexecute.run()`。
- 来源入口：提示符 `one_iteration`、启动 `startup_commands()`、批处理 `-e`/stdin（`run_query`）、`.read`、`\f` favorite、`\llm`（LLM 生成 SQL 后放到 prompt default 由用户回车执行）。
- 注册表：[special/main.py](file:///Users/kkcarrot/swe-project/litecli_fork2/litecli/packages/special/main.py) `SpecialCommand` namedtuple + `special_command`/`register_special_command`，别名机制。
- 现有确认：`destructive_warning` + `confirm_destructive_query`（drop/shutdown/delete/truncate/alter 关键字；非 tty 返回 None 即放行）。
- 后端：`import sqlean` 失败则回退 `sqlite3`；`tox -e sqlean` 安装 `sqlean-py`。

### 实测事实（sqlean-py, SQLite 3.50.4 / 标准库 3.53.4）
- `sqlean.connect()` 返回的连接同样支持 `set_authorizer(cb)`，回调 5 参数 `(action, arg1, arg2, dbname, trigger)`。
- 事件码：`SQLITE_FUNCTION=31`（arg2 为函数名：`load_extension`/`readfile`/`writefile`/`eval`）、`SQLITE_ATTACH=24`（arg1 为文件名；`ATTACH` 与 `VACUUM INTO` 均触发）、`SQLITE_PRAGMA=19`（`writable_schema` 的 arg2 为 `ON/OFF/RESET`）、CREATE 1-8、DROP 10-17、`SQLITE_ALTER_TABLE=26`、DELETE 9、INSERT 18、UPDATE 23。
- authorizer 在动作执行前被调用；回调 DENY 时副作用不发生（`writefile` 未写文件）。
- sqlean 内置禁止 SQL 层 `load_extension()`（"not authorized"）；扩展加载实际经 `.load` 的 `conn.load_extension()` Python API（authorizer 看不到，必须在特殊命令层拦截）。
- `cur.execute` 一次只允许一条语句；多语句由 litecli 预先拆分。

## Functional Requirements

- **FR-1 连接级 authorizer**：`SQLExecute.connect()` 建立的每条连接立即安装 authorizer 回调；`.open` 重连后同样安装；普通只读事件（SELECT/READ/PRAGMA 普通项等）始终放行，危险事件仅在已授权执行作用域内放行，无作用域时 fail-closed DENY。
- **FR-2 capability 注册表**：扩展 `SpecialCommand` 与注册/装饰器 API，新增 `capabilities` 集合字段（默认空），并为既有命令声明：
  - `process`：`system`、`pager`（设置外部 PAGER）、`\pipe_once`、`\e`（外部编辑器）、`\llm`（外部进程+网络）；
  - `filesystem`：`.read`、`.output`/`tee`、`.once`、`.import`（含 `write-data`）、`.open`、`\e`；
  - `extension`：`.load`；
  - `network`：`\llm`；
  - favorite/watch 的内部 SQL 不加静态集合，按编译期展开/静态分析得到 capability。
- **FR-3 ExecutionPlan 编译**：执行前把输入编译为有序 `ExecutionPlan`：sqlparse 拆句；特殊命令按注册表识别；`.read` 递归读取并展开（深度上限、环检测）；favorite 取配置模板展开（参数替换后结构不超出模板授权，见 FR-9）；LLM 调用本身作为 network/process 条目、其生成 SQL 在执行前以 `llm` 来源编译；每条目标注来源链、动词、规范化模板（字面量脱敏为 `?`）与 capability(+动作细分)。
- **FR-4 plan hash**：plan hash = sha256(规范化 JSON：条目顺序、kind、动词、脱敏模板、capability+动作、来源类型链)。不含任何字面量值、文件内容、favorite 参数值；相同结构 SQL 仅字面量不同则 hash 相同；来源不同 hash 可不同但决策相同。
- **FR-5 策略引擎**：从 liteclirc `[policy]` 段加载规则；每个 capability 对 `interactive` 与 `batch` 两种模式分别给 `allow/confirm/deny`；支持动作细分覆盖（`write_schema_create` 默认 `allow,allow`；drop/alter/truncate/writable_schema 跟随 `write_schema` 默认 `confirm,deny`）；`write_data` 默认 `allow,allow`；文件/进程/扩展/网络默认 `confirm,deny`。判定函数签名仅依赖 `(capability集合, 模式, 规则版本)`，不读取来源身份。
- **FR-6 统一来源判定**：提示符、`.read`、startup、favorite、LLM（及 execute/stdin 批处理）的相同危险操作产生相同 verdict 与命中规则；来源链只进入计划与审计。用跨来源参数化测试锁定。
- **FR-7 确认界面**：verdict=confirm 且可交互时，执行前展示分组真实副作用（条目序号、capability、动作、真实目标，如 `ATTACH '/data/x.db'`、`writefile('/tmp/x')`、`DROP TABLE users`、`.read /path/f.sql`），用户确认后整体执行；拒绝/否定则整计划不执行。
- **FR-8 批处理升级**：模式=batch（`-e`、stdin 管道、无 tty）时 confirm 升级为 deny；错误信息说明命中 capability、动作与规则，进程以非零码退出（批处理路径）。
- **FR-9 执行作用域与嵌套再入**：决策通过后开启执行作用域，authorizer 持有"已授权 capability 集"与事件收集器；作用域内 `.read` 递归 run、favorite/watch/`.import` 处理器内直接 `cur.execute` 均受 authorizer 约束；favorite 文本替换注入的新能力（如模板 SELECT 被替换出 DROP）必须 DENY；特殊命令处理器执行前由守卫按该条目 capability 校验，客户端副作用（如 system 子进程）在拒绝时不启动。
- **FR-10 副作用前拒绝**：多语句计划中任一危险条目被拒，整计划在第 1 条执行前中止（已测：库/表/文件无变更、无子进程）；authorizer DENY 的 SQLite 错误翻译为含 capability 名称的友好错误。
- **FR-11 审计记录**：JSONL（配置 `policy_audit_log`，默认 `~/.config/litecli/policy-audit.jsonl`）；每条记录含时间、plan hash、来源签名链、模式、规则版本与规则矩阵快照、脱敏规范化条目、决策（verdict+规则 id+理由）、实际 authorizer 事件（事件名/capability/裁决，参数仅保留分类所需名称，值脱敏）、执行结果与耗时；写入失败 fail-safe（提示但不阻断主流程）。
- **FR-12 重放**：提供 Python API 按 plan hash 读取审计记录并重算决策，得到与记录一致的 verdict/规则；重放只依赖记录内的脱敏计划与规则快照，不需要原始 SQL；记录被篡改/计划 hash 不一致时可检测。提供特殊命令 `policyaudit [plan-hash]` 查看记录与重放结果。
- **FR-13 版本兼容**：action 码映射使用内置数值常量表并在可用时读取 `sqlite3.SQLITE_*` 常量；常量缺失（旧 SQLite）不崩溃；无法分类的事件按"危险类 fail-closed、只读类放行"处理并在 DEBUG/审计留痕；sqlean 与 sqlite3 双后端测试通过。
- **FR-14 配置与开关**：liteclirc 新增 `[policy]` 段（enabled、各 capability 双模式判定、网络函数名映射、嵌套深度、audit_log）；CLI 提供最小覆盖开关（如 `--policy-mode`/`--allow-dangerous` 等，最终形态在实现中收敛但必须有显式批处理放行途径）；策略禁用时行为回退到现有 destructive_warning 语义。

## Non-Functional Requirements
- **NFR-1 安全性**：静态分析可遗漏时，authorizer 是最终强制点；两者都必须覆盖五类 capability；拒绝路径零副作用（测试可证）。
- **NFR-2 性能**：计划编译/authorizer 回调对普通 SELECT 会话无可感知开销；authorizer 回调内不做 IO/正则重操作。
- **NFR-3 可维护性**：新代码独立成包（`litecli/packages/guard/`），与 special、sqlexecute 通过小接口耦合；snake_case、ruff line-length 140、类型注解（Python 3.10 目标，`|` 联合类型）。
- **NFR-4 可测试性**：策略/确认器/时钟/文件读取均可注入；既有 228 项测试通过（测试夹具使用 allow-all 测试策略），新门禁在独立夹具与双后端下验证。
- **NFR-5 隐私**：审计默认不落任何原始 SQL、字面量值、文件内容；交互确认界面才显示真实目标。

## Constraints
- **Technical**: Python >=3.10（类型检查目标），运行时同时兼容 stdlib sqlite3 与 sqlean-py；sqlparse 为唯一 SQL 解析依赖；不得引入新第三方依赖。
- **Business**: 保持普通用法（建表、查询、批处理导出、favorite、补全）默认可用；行为收紧（批处理危险操作默认拒绝）须在 CHANGELOG 与配置模板中说明并可配置回退。
- **Dependencies**: 无新增运行时依赖；测试额外支持 sqlean-py（已在 dev extras 流程中）。

## Assumptions
- 用户未另行指定时采用推荐基线：危险四类（filesystem/process/extension/network）交互确认、批处理拒绝；`write-schema` 的破坏性动作（drop/alter/truncate/writable_schema）交互确认/批处理拒绝，CREATE 默认放行并审计；普通 DML 默认放行并审计。所有默认值均可通过 `[policy]` 修改。
- 交互式 startup 命令可在 REPL 启动前使用同一套确认（stdin 为 tty 时）；拒绝即跳过该条并继续。
- LLM 生成 SQL 仍经用户回车执行；回车时以 `llm` 来源签名进入同一门禁；`\llm` 调用本身（外发请求/外部进程）先于调用被门禁。
- 审计中文件名等参数以脱敏形式存储（仅界面显示真值）；函数名/pragma 名等"分类名称"不属于敏感值。

## Acceptance Criteria

### AC-1: 每条连接安装并执行 authorizer（双后端）
- **Type**: `rule`
- **Given**: 使用 stdlib sqlite3 或 sqlean-py 后端新建连接或执行 `.open` 重连
- **When**: 检查连接
- **Then**: authorizer 已安装；危险事件（31/24/19-writable_schema/1-8/10-17/26 等）在无授权作用域时返回 DENY，只读事件返回 OK
- **Pass Condition**: 双后端下单元测试断言回调已安装且无作用域 DENY 危险事件；`.open` 后回调仍生效
- **Evidence**: `tests/test_guard_*.py` 双后端运行输出

### AC-2: 特殊命令注册表显式声明 capability
- **Type**: `rule`
- **Given**: 注册表构建完成
- **When**: 检查 COMMANDS 中相关命令（含别名）
- **Then**: system/pager/pipe_once/\e/\llm 含 process；.read/.output/.once/.import/.open/\e 含 filesystem；.load 含 extension；\llm 含 network；.import 同时含 write-data
- **Pass Condition**: 注册表断言测试全部通过；装饰器/注册 API 支持 capabilities 参数且向后兼容（默认空集合）
- **Evidence**: 注册表单测

### AC-3: 多语句与嵌套来源在执行前编译为 ExecutionPlan
- **Type**: `rule`
- **Given**: 包含多语句、`.read`（含嵌套 .read/环/超深）、`\f` favorite、LLM 标签 SQL 的输入
- **When**: 执行前调用编译
- **Then**: 得到有序条目，来源链正确（prompt/read:<n>/startup/favorite:<n>/llm/batch），`.read` 递归展开并对环/超深给出确定结果，favorite 以配置模板展开，字面量被规范化
- **Pass Condition**: 计划编译单测覆盖以上全部情形且无文件/数据库副作用
- **Evidence**: `tests/test_guard_plan.py`

### AC-4: plan hash 脱敏且跨来源稳定可复算
- **Type**: `rule`
- **Given**: 仅字面量不同的两条相同结构 SQL；以及分别来自提示符/.read/startup/favorite/LLM 的同一危险语句
- **When**: 计算 plan hash
- **Then**: 字面量不同 hash 相同；规范化模板不含原始字面量；由审计记录中的脱敏计划可独立复算同一 hash
- **Pass Condition**: hash 单测通过；grep 审计产物无原始字面量
- **Evidence**: `tests/test_guard_plan.py`、`tests/test_guard_audit.py`

### AC-5: 策略按模式决策且跨来源同等
- **Type**: `rule`
- **Given**: 默认规则与自定义 `[policy]` 规则
- **When**: 同一危险操作分别以 prompt/read/startup/favorite/llm 来源在 interactive 与 batch 模式决策
- **Then**: 同模式同 capability  verdict 完全一致（与来源无关）；interactive=confirm、batch=deny（默认危险四类与破坏性 schema 动作）；CREATE/普通 DML=allow；规则 id 与理由一致
- **Pass Condition**: 来源×模式矩阵参数化测试全部通过
- **Evidence**: `tests/test_guard_policy.py`

### AC-6: 确认界面展示真实副作用
- **Type**: `rule`
- **Given**: 含 ATTACH/writefile/DROP/.load/.read/system 等条目的计划，注入式确认器
- **When**: interactive 决策为 confirm
- **Then**: 界面在执行前列出每条副作用的序号/capability/动作/真实目标（真实路径、函数名、表名）；确认→执行；否定→整计划不执行；展示内容可由测试精确断言
- **Pass Condition**: 确认界面渲染单测 + 集成测试（yes/no 两路径）
- **Evidence**: `tests/test_guard_integration.py`

### AC-7: 拒绝在任何副作用之前生效并说明 capability
- **Type**: `rule`
- **Given**: 多语句输入第 N 条命中拒绝策略；或 system/.load 命中拒绝
- **When**: 执行
- **Then**: 前序语句不执行、表/文件无变化、无子进程启动、无扩展加载；错误信息含 capability、动作、命中规则；批处理退出码非零
- **Pass Condition**: 副作用前后状态对比测试通过；错误文案断言通过；批处理 CliRunner exit_code != 0
- **Evidence**: `tests/test_guard_integration.py`

### AC-8: 审计记录 plan hash、决策与实际 authorizer 事件且不含敏感 SQL
- **Type**: `rule`
- **Given**: allow/confirm/deny 三类执行（含 authorizer DENY 事件）
- **When**: 检查 JSONL 审计文件
- **Then**: 每条记录含 plan_hash、source_signature、mode、规则版本/快照、脱敏条目、decision(verdict/rule/reasons)、authorizer_events(名称/capability/裁决)、outcome；不含原始 SQL、绑定值、文件内容（可用独特字面量串做泄露扫描）
- **Pass Condition**: 审计单测通过并做泄露扫描（独特敏感串不出现在文件中）
- **Evidence**: `tests/test_guard_audit.py`

### AC-9: 仅凭 plan hash 与脱敏审计记录重放决策
- **Type**: `rule`
- **Given**: 审计文件与其中某条 plan hash（无原始 SQL 环境）
- **When**: 调用重放 API 与 `policyaudit <hash>` 命令
- **Then**: 重算 verdict/规则与记录一致；记录被改动时重放报告不一致；重放过程不访问任何原始 SQL
- **Pass Condition**: 重放单测（含篡改检测）与特殊命令测试通过
- **Evidence**: `tests/test_guard_audit.py`、`tests/test_guard_command.py`

### AC-10: sqlean 与多 SQLite 版本兼容
- **Type**: `rule`
- **Given**: 安装/未安装 sqlean-py 两种环境；模拟常量缺失的后端
- **When**: 运行全量测试
- **Then**: 两套环境测试均通过；常量缺失时能力映射仍正确（数值表），未知 action 不导致崩溃且危险类 fail-closed
- **Pass Condition**: `.venv` 下分别以 sqlean/sqlean-off 运行 pytest 全绿；常量缺失注入测试通过
- **Evidence**: 两套 pytest 输出

### AC-11: 处理器内直接执行与 favorite 注入不可绕过
- **Type**: `rule`
- **Given**: favorite 模板为 SELECT、参数文本拼入 DROP/ATTACH；watch 循环危险语句；`.import`/describe 拼接输入
- **When**: 经特殊命令执行
- **Then**: 超出模板/计划授权的 authorizer 事件被 DENY 且无副作用；拒绝信息含 capability
- **Pass Condition**: 绕过尝试测试全部被拒
- **Evidence**: `tests/test_guard_integration.py`

### AC-12: 工程质量与回归
- **Type**: `rule`
- **Given**: 完整改动
- **When**: 运行既有套件、ruff、ty
- **Then**: 既有 228 项测试保持通过；`ruff check`/`ruff format --check` 无告警；`ty check litecli` 无新增错误；CHANGELOG 含 Unreleased 条目；liteclirc 含 `[policy]` 文档
- **Pass Condition**: 命令输出全部干净
- **Evidence**: CI 命令本地输出

### AC-U1: 统一门禁设计质量
- **Type**: `rubric`
- **Dimension**: 单一入口、纵深防御（静态计划 + 注册表 + authorizer 三层一致）、来源不可授权的纯粹性
- **Scale**: 1-5
- **Anchors**: 1 = 各来源仍有独立判断路径或可绕过；3 = 主路径统一但个别特殊命令旁路；5 = 所有来源经同一编译/决策/作用域管线，三层 capability 语义一致
- **Pass Threshold**: >= 4
- **Evidence**: 代码审查 + AC-5/AC-11 证据

### AC-U2: 拒绝与确认的可用性
- **Type**: `rubric`
- **Dimension**: 信息完整性（capability/动作/目标/规则）、措辞可理解性、批处理与交互的一致性
- **Scale**: 1-5
- **Anchors**: 1 = 仅 "not authorized"；3 = 有 capability 但缺目标或规则；5 = 用户可仅凭提示判断风险来源与处置方式
- **Pass Threshold**: >= 4
- **Evidence**: 界面文案审查与 AC-6/AC-7 断言

## Open Questions
- 无（用户选择跳过澄清，采用 Assumptions 中的推荐基线；全部默认值可通过配置修改，实现中如遇必须分叉的决策点再回到本规格更新）。
