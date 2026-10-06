# litecli 能力门禁 - Implementation Plan

> AC 映射见 [spec.md](./spec.md)。任务按依赖顺序排列；每个任务的测试随实现一起完成。
> 新代码目录：`litecli/packages/guard/`（capabilities / authorizer / plan / policy / audit / confirm / guard）。

## Task 1: capability 模型与特殊命令注册表扩展
- **Status**: `completed`
- **Completion Evidence**: `guard/capabilities.py`；SpecialCommand 新增 capabilities 字段（默认空 frozenset，别名继承）；全部命令声明完成（system/pager/\pipe_once/\e/\llm/.output/tee/.once/.read/.open/.load/.import）；`command_capabilities`/`lookup_command`。证据：`tests/test_guard_registry.py` 5 项全绿；全套 233 passed。
- **Priority**: high
- **Depends On**: None
- **Description**:
  - 新增 `litecli/packages/guard/capabilities.py`：定义 capability 常量（filesystem/process/extension/network/write-schema/write-data）与动作细分标签（attach/vacuum_into/function/load_extension/pragma/special、create/drop/alter/truncate/writable_schema/master_write、insert/update/delete 等）。
  - 扩展 `SpecialCommand` namedtuple 增加 `capabilities: frozenset[str]`（默认空 frozenset）；`special_command`/`register_special_command` 增加 `capabilities` 参数，向后兼容；别名继承声明。
  - 按 FR-2 给既有命令加声明：system/pager/\pipe_once/\e/\llm(process)；.read/.output(tee)/.once/.import/.open/\e(filesystem)；.load(extension)；\llm(network)；.import(write-data)。
  - 注册表新增查询助手：`command_capabilities(name) -> frozenset[str]`。
- **Acceptance Criteria Addressed**: AC-2, AC-12
- **Test Requirements**:
  - `rule` TR-1.1: COMMANDS 中各命令（含别名）capability 集合与 FR-2 完全一致；未声明命令为空集合；既有注册 API 不传新参数时行为不变（既有套件通过）。证据：`tests/test_guard_registry.py`。
  - `rule` TR-1.2: 旧调用方式构造的 SpecialCommand/注册表在所有既有测试中可用（228 项基线不破）。证据：pytest 输出。
- **Notes**: namedtuple 加字段须给默认值（改为带默认值的 NamedTuple 类或工厂封装），避免破坏位置构造。

## Task 2: SQLite authorizer 控制器
- **Status**: `completed`
- **Completion Evidence**: `guard/authorizer.py`（数值码表 1-33；FUNCTION/ATTACH/PRAGMA/DDL/目录写/数据写映射；scope fail-closed；DDL 内部目录写与 VACUUM INTO 内部库的隐含授权；scope 退出复位 writable_schema；拒绝优先级；enabled=False 放行；后端常量缺失兜底）。证据：`tests/test_guard_authorizer.py` 双后端参数化 17 用例（32 passed/2 skipped，skip 为 stdlib 无 sqlean 函数）；ruff check/format 干净。
- **Priority**: high
- **Depends On**: Task 1
- **Description**:
  - 新增 `authorizer.py`：`AuthorizerEvent`（action 数值、action 名、capability、分类名 arg（仅函数名/pragma 名/表名等）、值是否脱敏、verdict）、`AuthorizerScope`（授权 capability 集、事件收集列表、plan 节点关联）、`AuthorizerController.install(conn)`。
  - 内置数值码表（1-34 全量名称），运行时优先读取后端模块的 `SQLITE_*` 常量做校验/补名；常量缺失可正常工作。
  - 事件→capability 映射：31 FUNCTION（按可配置函数名表：load_extension→extension；readfile/writefile/lstat/mkdir/symlink→filesystem；eval→process；http_* 等→network，默认表+策略配置覆盖）；24 ATTACH→filesystem（含 VACUUM INTO，区分动作标签）；19 PRAGMA（writable_schema→write-schema，其余只读放行）；1-8/10-17/26/29/30→write-schema（create/drop/alter/vtable 标签）；对 sqlite_master/sqlite_schema 的 9/18/23→write-schema(master_write)；9/18/23 普通表→write-data；其余事件（READ/SELECT/TRANSACTION/SAVEPOINT/REINDEX/ANALYZE/RECURSIVE 等）不携带危险 capability。
  - 回调裁决：无危险 capability→OK；有 capability 且在当前 scope 授权集→OK；否则 DENY 并记录（含最近一次拒绝供错误翻译）。无活动 scope 时危险事件 DENY（fail-closed）。
  - 兼容：5 参数回调；sqlean 连接直接可用；DENY 后由上层翻译错误。
- **Acceptance Criteria Addressed**: AC-1, AC-10, AC-11
- **Test Requirements**:
  - `rule` TR-2.1: 在 stdlib 与 sqlean 连接上安装后，CREATE/ATTACH/PRAGMA writable_schema/FUNCTION(load_extension/readfile/writefile/eval) 在无 scope 时被 DENY 且副作用不发生（writefile 后文件不存在；ATTACH 后无新库）；SELECT/普通 PRAGMA 放行。证据：双后端 pytest 输出。
  - `rule` TR-2.2: scope 授权集内事件 OK 且事件被收集；scope 外/回收后恢复 DENY；拒绝事件含 capability 与动作标签。证据：controller 单测。
  - `rule` TR-2.3: 删除/模拟缺失 `SQLITE_FUNCTION` 等常量后映射仍正确（数值表）；未知 action 码不崩溃（只读类放行并留痕）。证据：monkeypatch 单测。
- **Notes**: 控制器实例按 SQLExecute 生命周期持有；回调中禁止 IO/正则。

## Task 3: ExecutionPlan 编译器
- **Status**: `completed`
- **Completion Evidence**: `guard/plan.py`（SourceOrigin 七类来源链；PlanEntry/ExecutionPlan+sha256 hash；sqlparse 静态分析覆盖 DDL/DML/ATTACH/VACUUM INTO/PRAGMA/目录写/危险函数；字面量正则脱敏；.read 递归/环/超深/缺文件确定性 unresolved；favorite/watch 展开；target 仅界面用不入 hash/审计）。证据：`tests/test_guard_plan.py` 43 用例全绿（含 hash 稳定性、来源链传播、脱敏泄露扫描）；全套 309 passed。
- **Priority**: high
- **Depends On**: Task 1
- **Description**:
  - 新增 `plan.py`：`SourceOrigin(kind, label(脱敏展示用), parent)`、`PlanEntry(seq, kind=sql|special, origin, verb, normalized_template, capabilities(dict[cap, set[detail]]), target(真实目标,仅界面用,不进审计), expansion_key)`、`ExecutionPlan(entries, source_signature, plan_hash, created_at)`。
  - `PlanCompiler`：sqlparse 拆句（保持 `\fs` 原样等现状特例）；特殊命令识别（parse_special_command + COMMANDS，含别名/+/- verbosity 剥离）。
  - 静态 SQL 分析器（sqlparse token）：首动词；ATTACH/DETACH；VACUUM INTO；PRAGMA 名与值；CREATE/DROP/ALTER/TRUNCATE/REPLACE/INSERT/UPDATE/DELETE；直接写 sqlite_master/sql_schema；函数调用名集合（sqlparse Function）。
  - 规范化：字符串/数值/十六进制字面量与绑定参数 → `?`；折叠空白；保留关键字/标识符/函数名/pragma 名；规范化结果为 hash 与审计输入。真实 target（路径/表名/函数名）单独字段仅供界面。
  - 嵌套展开：`.read <file>` 经可注入 file_reader 递归展开（深度上限可配置，默认 8；环检测；读失败标记 unresolved，其 capability 仍按声明参与决策）；favorite 经 provider 取模板展开（记录 favorite:<name>，参数占位不替换）；`system`/`.output` 等不展开；watch 参数中的 SQL 静态分析；LLM 生成 SQL 以 llm 来源编译（在其执行边界）。
  - plan_hash：sha256(canonical JSON[条目 kind/verb/normalized_template/caps+details/来源类型链])。
- **Acceptance Criteria Addressed**: AC-3, AC-4
- **Test Requirements**:
  - `rule` TR-3.1: 多语句保序、特殊命令识别（含别名/verbosity）、五类动词/函数/pragma/attach/vacuum/master-write 静态识别正确。证据：`tests/test_guard_plan.py`。
  - `rule` TR-3.2: `.read` 递归展开、超深与环返回确定错误条目且不做无限递归；favorite 模板展开来源链正确；file_reader/provider 可注入（测试不触盘）。
  - `rule` TR-3.3: 仅字面量不同的两计划 normalized/hash 相同；hash 输入中无字面量值；由 normalized 数据可独立复算 hash；target 字段不参与 hash/审计序列化。
  - `rule` TR-3.4: 来源链标签 prompt/read/startup/favorite/llm/execute/stdin 正确传播到每个嵌套条目。
- **Notes**: 规范化仅需"结构稳定"，不追求与 SQLite AST 等价；作者izer 是语义后端。

## Task 4: 策略引擎与 [policy] 配置加载
- **Status**: `completed`
- **Completion Evidence**: `guard/policy.py`（Verdict/Mode/PolicyRule/Policy/Decision；条目级最严格聚合；默认基线；detail 覆盖（WS-CREATE）；from_config 容错+destructive_warning 兼容；规则快照+digest；纯函数 replay）。证据：`tests/test_guard_policy.py` 39 用例全绿（默认矩阵、7 来源同等、非法配置回退、篡改快照检测）；全套 348 passed。
- **Priority**: high
- **Depends On**: Task 1, Task 3
- **Description**:
  - 新增 `policy.py`：`Verdict(allow/confirm/deny)`、`Mode(interactive/batch)`、`PolicyRule(capability, mode, verdict, detail=None, id)`、`Policy(rules, version, digest)`、`Decision(plan_hash, verdict, entry_decisions[(seq,verdict,rule_id,reason,capability,detail)])`。
  - `decide(plan, mode, policy)`：条目级裁决取最严格（deny>confirm>allow）；裁决输入仅 capability+detail+mode+规则；不读取 origin。
  - 默认规则集（FR-5）：filesystem/process/extension/network=(confirm,deny)；write-schema 破坏性 detail=(confirm,deny)、create detail=(allow,allow)；write-data=(allow,allow)。
  - `Policy.from_config(cfg)`：读取 `[policy]` 段（enabled、capability 行 `interactive,batch`、write_schema_create、network_functions、max_nest_depth、audit_log）；解析失败回退默认并 WARN；`destructive_warning=false` 时 write-schema 破坏性回退 allow（兼容旧语义）。
  - 规则矩阵快照（小 JSON）随 Decision 产出供审计重放；`replay(normalized_plan, mode, rules_snapshot) -> Decision` 纯函数。
  - 网络函数名映射同步给 authorizer 控制器。
- **Acceptance Criteria Addressed**: AC-5, AC-9, AC-12
- **Test Requirements**:
  - `rule` TR-4.1: 来源×模式×capability 矩阵参数化测试：同能力同模式 verdict/rule_id 跨 5 来源完全一致；默认基线裁决正确。证据：`tests/test_guard_policy.py`。
  - `rule` TR-4.2: 自定义配置（含非法值/缺段/缺省回退、destructive_warning 映射）正确加载；规则 digest 随配置变化。
  - `rule` TR-4.3: replay 纯函数对同一 normalized 输入复现一致 verdict/规则 id；规则快照不同时结果随快照且可报告差异；全程不接触原始 SQL（测试以脱敏对象调用）。
- **Notes**: Mode 与 origin 严格正交：origin 永不出现在裁决条件中。

## Task 5: 审计 JSONL 记录与读取
- **Status**: `completed`
- **Completion Evidence**: `guard/audit.py`（build_record 脱敏字段集；AuditLog JSONL 追加/fail-safe/find_by_hash/iter_records；resolve_audit_path 默认/关闭；replay_record 校验 hash+重算 verdict；hash_redacted_entries 可由审计条目独立复算）。证据：`tests/test_guard_audit.py` 16 用例全绿（四种 outcome、独特密钥泄露扫描、篡改检测、不可写路径 fail-safe）；全套 364 passed。
- **Priority**: high
- **Depends On**: Task 3, Task 4
- **Description**:
  - 新增 `audit.py`：`AuditRecord` 序列化（ts/plan_hash/source_signature/mode/policy_version/rules_snapshot/entries(脱敏)/decision/authorizer_events/outcome/duration_ms）；`AuditLog.append()` 原子追加 JSONL（打开失败 fail-safe 并一次性提示）。
  - 脱敏：条目仅输出 normalized_template/cap/detail/origin kind；authorizer 事件只输出 action 名/capability/verdict 与分类名（函数名/pragma 名），字面量/路径值/文件内容一律不落盘；target 字段不序列化。
  - `find_by_hash(path, plan_hash)`、`iter_records(path)`、`replay_record(record, policy)`（校验 hash 一致 + 重算决策）。
  - 默认路径 `~/.config/litecli/policy-audit.jsonl`（`audit_log = default`），可关（`audit_log = ""`/off）。
- **Acceptance Criteria Addressed**: AC-8, AC-9
- **Test Requirements**:
  - `rule` TR-5.1: allow/confirm(user yes)/deny/authorizer-DENY 四种 outcome 各产出一条合法 JSONL，必填字段齐全；执行异常 outcome=denied/error 也有记录。证据：`tests/test_guard_audit.py`。
  - `rule` TR-5.2: 用独特敏感串（表中插入的密钥样式字面量、绝对路径、文件内容）做泄露扫描：审计文件 0 命中；界面 target 不经过审计序列化。
  - `rule` TR-5.3: find_by_hash/replay_record 复算一致；篡改 normalized 或 decision 字段后 hash/重放不一致被检出。
  - `rule` TR-5.4: 路径不可写时 fail-safe（不抛断主流程，返回告警状态）。

## Task 6: 确认界面
- **Status**: `completed`
- **Completion Evidence**: `litecli/packages/guard/confirm.py`（ConfirmationItem/action_label/confirmation_items/render_confirmation/Confirmer Protocol/AutoConfirmer/ClickConfirmer）；危险函数真实参数展示经 plan `_find_functions_with_args()`；`tests/test_guard_confirm.py` 8 用例全绿。
- **Priority**: medium
- **Depends On**: Task 3, Task 4
- **Description**:
  - 新增 `confirm.py`：`render_confirmation(plan, decision) -> str`（按 capability 分组：序号、capability、动作、真实 target）；`Confirmer` 协议（`confirm(plan, decision) -> bool`），默认 click 实现复用 prompt_utils；非 tty/批处理 confirmer 不可用→None（由守卫升级 deny）。
  - 文案含 capability 名称与命中间（为 FR-7/FR-8 服务）。
- **Acceptance Criteria Addressed**: AC-6, AC-U2
- **Test Requirements**:
  - `rule` TR-6.1: 渲染输出对 ATTACH/DROP/writefile/.load/system/.read 逐条含序号/capability/动作/真实目标；注入假 confirmer 时 yes→放行、no→整计划不执行。证据：单测+集成测试。
  - `rubric` TR-6.2: 文案可用性维度 1-5（锚点同 AC-U2），阈值 >=4；证据：审查渲染样例断言关键字段齐备。

## Task 7: ExecutionGuard 门面
- **Status**: `completed`
- **Completion Evidence**: `litecli/packages/guard/guard.py`：PolicyDenied/PreparedExecution/ExecutionGuard（prepare/scope/authorize_entry/attach_connection）；deny 先审计后抛错；嵌套不重新提示且 caps⊆grants（NESTED-GRANT）；DROP/ALTER/TRUNCATE 授权自动附带 write-data:*；`tests/test_guard_guard.py` 16 用例全绿。
- **Priority**: high
- **Depends On**: Task 2, Task 3, Task 4, Task 5, Task 6
- **Description**:
  - 新增 `guard.py`：`PolicyDenied(Exception)`（含 capability/detail/rule_id/seq/模式/可读消息）；`ExecutionGuard(compiler, policy, controller, audit, confirmer, mode, clock)`。
  - `prepare(text, origin) -> PreparedExecution`：编译→决策→（confirm 交互）→产出授权 scope 能力集；deny/否定：先写审计 outcome=denied 再抛 PolicyDenied（零副作用）。
  - `scope()` 上下文：arm/disarm controller、收集 authorizer 事件、结束写审计（含耗时/outcome）；嵌套再入：已在 scope 内时对子文本重新编译，要求其 capability 集合 ⊆ 已授权集（含 detail），否则 PolicyDenied；特殊命令分发前 `authorize_special(entry/command)` 校验。
  - 提供给 SQLExecute 的执行钩子接口（按计划条目执行而不是重新拆句；特殊命令仍走 special.execute）。
- **Acceptance Criteria Addressed**: AC-5, AC-6, AC-7, AC-8, AC-11, AC-U1
- **Test Requirements**:
  - `rule` TR-7.1: 多语句第 N 条 deny：prepare 阶段抛错，scope 未 arm、未执行任何条目、审计有 denied 记录。证据：集成测试。
  - `rule` TR-7.2: scope 内嵌套 run（模拟 .read/favorite 文本）能力扩张被拒；system 特殊命令在拒绝时 handler 未被调用（spy 断言）。
  - `rule` TR-7.3: allow 路径 authorizer 事件全部收集并入审计；authorizer DENY 翻译异常携带最近拒绝事件的 capability/detail。
  - `rubric` TR-7.4: 单一入口纯粹性（AC-U1 维度）阈值 >=4；证据：代码走查清单（所有执行入口都经 guard 的证据列表）。

## Task 8: SQLExecute 接线
- **Status**: `completed`
- **Completion Evidence**: `sqlexecute.py`：guard=None 走 `_run_legacy()` 保旧行为；启用时普通函数体内 prepare（PolicyDenied 先于首次 next），`_run_guarded()` 按 root 条目执行；connect/.open 均 attach；`PlanEntry.is_root` 标记；全套件 411 passed 无回归。
- **Priority**: high
- **Depends On**: Task 7
- **Description**:
  - `sqlexecute.py`：构造 `ExecutionGuard`（policy/audit/confirmer/mode 可注入，默认从内置默认策略构建）；`connect()` 安装 controller（初始连接与 `.open` 重连）。
  - 重构 `run()`：先 `guard.prepare(statement, origin)`（origin 由调用方在执行上下文设置，默认 prompt/internal 可注入），随后按计划条目执行（保持现有生成器 yield 协议与 `\G`、not-connected 特例）；特殊命令分发前 authorize_special；异常 PolicyDenied 直接向上抛；sqlite "not authorized" 翻译为 PolicyDenied 文案。
  - scope 包裹整个生成器生命周期（含嵌套 run 再入）；暴露 `execution_mode`/临时 origin 上下文 API 给 main 层。
  - 保留 `tables()/table_columns()/databases()` 等内部只读路径（无危险事件，天然放行），不强制 scope。
- **Acceptance Criteria Addressed**: AC-1, AC-7, AC-10, AC-11, AC-12
- **Test Requirements**:
  - `rule` TR-8.1: 既有 executor 套件在 allow-all 测试策略下全绿；新强制策略夹具下普通 SELECT/CREATE/INSERT 放行、危险操作 prepare 即拒。证据：pytest 双策略输出。
  - `rule` TR-8.2: `.open` 后 authorizer 重新安装（危险事件 DENY 可证）；连接为 sqlean/sqlite3 均成立。
  - `rule` TR-8.3: run() 生成器在第一次 next 前即完成 prepare（测试：仅创建生成器未迭代时拒绝也已生效/审计已写），保证副作用前拒绝。

## Task 9: LiteCli/main 来源、模式与 LLM 接线
- **Status**: `completed`
- **Completion Evidence**: `main.py`：init_guard 从 [policy] 构建；policy_mode（tty/--policy-mode/auto）；prompt/read/startup/execute/stdin/llm 六来源；LLM 未编辑才记 llm；旧 destructive 提示在 guard 启用时跳过；batch 拒绝 exit 1、REPL 红字继续；CLI 冒烟验证 -e deny 与 pty 交互确认 y 后 DROP 生效。
- **Priority**: high
- **Depends On**: Task 8
- **Description**:
  - `main.py`：从 `[policy]` 构建 Policy/AuditLog/Confirmer 注入 SQLExecute；模式设定：tty REPL=interactive，`-e`/stdin=batch；startup 经 run 时 origin=startup（interactive 可确认，拒绝则跳过该条并提示）；提示符 origin=prompt。
  - LLM：`\llm` 调用前以 special 条目的 network+process 走门禁（deny 直接提示，不调用外部命令）；LLM 返回 SQL 设置 prompt default 时挂 llm 待执行来源标记，用户回车执行时 origin=llm；用户自行编辑/手输回落后重置为 prompt。
  - 移除旧重复确认点（one_iteration/execute_from_file/stdin/watch 的 confirm_destructive_query 调用由守卫统一承接；prompt_utils 函数保留不删）；批处理路径捕获 PolicyDenied → 红字 + exit 1；REPL 捕获 → 红字继续；PolicyDenied 不写入成功 history。
  - 提供 CLI 最小覆盖：`--policy-mode`（interactive/batch 强制）与配置 `[policy] enabled`；如实现中选择 `--allow-dangerous` 等开关须在 liteclirc/CHANGELOG 同步。
- **Acceptance Criteria Addressed**: AC-5, AC-6, AC-7, AC-8
- **Test Requirements**:
  - `rule` TR-9.1: CliRunner 批处理（-e/stdin）危险操作 exit_code!=0 且输出含 capability；安全操作 exit 0 且输出不变（回归既有 batch 测试）。
  - `rule` TR-9.2: 交互模拟（注入 confirmer）下提示符与 LLM 来源同一 DROP 得到相同确认文案/verdict；LLM 拒绝时 handle_llm/run_external_cmd 未被调用。
  - `rule` TR-9.3: startup 危险条目在 interactive 注入 confirmer 时被询问；被拒后跳过且其他 startup 条目继续；history 不记录 PolicyDenied 为成功。

## Task 10: 特殊命令处理器与嵌套执行适配
- **Status**: `completed`
- **Completion Evidence**: `iocommands.py` watch 仅在 current_guard() 为 None 时走旧确认；favorite 直接 cur.execute 由 scope authorizer 兜底；集成测试覆盖 .read 嵌套一次确认、TOCTOU（stale reader→NESTED-GRANT）、favorite 注入与 watch payload 嵌套标记。
- **Priority**: high
- **Depends On**: Task 8
- **Description**:
  - `.read`（execute_from_file）：保持递归 run，嵌套再入由 scope 校验；文件读取失败行为不变；destructive 旧确认调用删除。
  - favorite/watch/`.import`/dbcommands：确认其直接 cur.execute 处于 scope 内（authorizer 约束）；watch 移除自有 destructive 提示（守卫在执行前统一确认一次）；补 capability 缺口（若发现处理器内额外副作用，补注册声明）。
  - `\fs/\fd` 写配置文件行为评估：不属 DB 危险能力，保持现状但不进入计划授权（界面可见即可）。
- **Acceptance Criteria Addressed**: AC-3, AC-11
- **Test Requirements**:
  - `rule` TR-10.1: favorite 参数注入（SELECT 模板 + 恶意参数产生 DROP/ATTACH）被 authorizer DENY 且无副作用；watch 危险语句在批处理拒绝、交互确认后执行；`.import` 在授权策略下行为与现状一致（既有测试通过）。
  - `rule` TR-10.2: `.read` 文件内含 system/多语句危险条目时，整计划执行前拒绝且文件中前序语句也不执行。

## Task 11: `policyaudit` 特殊命令
- **Status**: `completed`
- **Completion Evidence**: main.py 注册 `policyaudit`（无 capabilities）：无参摘要表、hash 前缀重放 MATCH/MISMATCH；CLI 冒烟确认输出；`tests/test_guard_command.py` 7 用例全绿。
- **Priority**: medium
- **Depends On**: Task 5, Task 9
- **Description**:
  - 注册 `policyaudit [plan-hash]`（PARSED_QUERY，声明无危险 capability）：无参数列出最近记录摘要（时间/mode/verdict/plan_hash 前 12 位/命中 capability）；带 hash 展示该记录并执行重放（记录决策 vs 重算决策，一致/不一致标记）。
- **Acceptance Criteria Addressed**: AC-9
- **Test Requirements**:
  - `rule` TR-11.1: 经 special.execute 调用：无参数列表、带 hash 展示并重放一致；篡改记录文件后重放报告 MISMATCH。证据：`tests/test_guard_command.py`。

## Task 12: 配置模板与 CHANGELOG
- **Status**: `completed`
- **Completion Evidence**: `litecli/liteclirc` 追加 `[policy]` 注释段；`CHANGELOG.md` Unreleased 含 Features/Behavior Changes；get_config 合并后 from_config 解析有测试覆盖。
- **Priority**: medium
- **Depends On**: Task 4
- **Description**:
  - `litecli/liteclirc` 增加 `[policy]` 段及注释（enabled、各 capability 默认、write_schema_create、network_functions、max_nest_depth、audit_log 路径说明）；同步测试配置无需改动（默认安全操作不受影响）。
  - `CHANGELOG.md` 顶部 Unreleased：Features（能力门禁/计划/审计）、Behavior Changes（批处理危险操作默认拒绝）、配置说明。
- **Acceptance Criteria Addressed**: AC-12
- **Test Requirements**:
  - `rule` TR-12.1: get_config 合并默认配置后 [policy] 键齐全且默认值可被 Policy.from_config 正确解析；CHANGELOG 含 Unreleased 与三个分组。证据：配置加载测试 + 文件断言。

## Task 13: 集成测试与双后端矩阵
- **Status**: `completed`
- **Completion Evidence**: `tests/test_guard_integration.py` 17 用例（两模式、六来源平权、.read 链、batch 副作用前拒绝、unresolved、TOCTOU、favorite、sqlean writefile 后端缺失即 skip）；全量 411 passed/4 skipped/1 xfailed/1 xpassed；sqlean 3.50.4 与 stdlib 3.53.4 均通过。
- **Priority**: high
- **Depends On**: Task 9, Task 10, Task 11
- **Description**:
  - `tests/test_guard_integration.py` 端到端（经 executor/LiteCli）：ATTACH/VACUUM INTO/writable_schema/.load(假路径拒绝即止)/system/.read 嵌套/LLM 来源/favorite 注入/多语句前序不执行/真实副作用探针（文件存在性、表存在性、spawn spy）；交互（假 confirmer）与批处理两模式；来源同等矩阵端到端复核。
  - conftest：既有 `executor` 夹具注入 allow-all 测试策略（保持 228 基线）；新增 `guard_executor` 强制默认策略夹具。
  - 双后端：sqlean-py 安装/卸载两种环境全量 pytest。
- **Acceptance Criteria Addressed**: AC-1..AC-11
- **Test Requirements**:
  - `rule` TR-13.1: 集成用例在 sqlean 与 stdlib 两后端全部通过；缺失后端时 skip 而非 fail。
  - `rule` TR-13.2: 副作用探针断言（文件/表/进程）全部通过；关键拒绝路径错误文案断言含 capability/规则。

## Task 14: 全量质量门
- **Status**: `completed`
- **Completion Evidence**: 两轮独立审查闭环（见 review.md）：首轮 NOT READY（3C/2H）全部修复，二轮 READY；其 follow-up 中 M-1（持久化/ATTACH 文件型虚表反查）、L-1（字符串内注释标记脱敏残留）、L-3（同名普通表误判）、L-2（execv 丢审计）亦已修复。最终质量门：pytest 453 passed/6 skipped/1 xfailed/1 xpassed；ruff guard 包与新测试 0 告警，修改文件不高于 HEAD 基线（main.py 28 vs 49、llm.py 3 vs 3）；ty guard/llm 新代码 0 诊断，main.py 仅存量诊断；CLI 冒烟（-e allow/deny、policyaudit 重放、pty 交互确认、注释泄露扫描）通过。
- **Priority**: high
- **Depends On**: Task 13
- **Description**:
  - `ruff check`、`ruff format --check`、`ty check litecli`、双后端全量 pytest；修复全部发现；自查所有执行入口（prompt/.read/startup/favorite/llm/-e/stdin/watch/import）均经守卫的走查证据。
- **Acceptance Criteria Addressed**: AC-12, AC-U1, AC-U2
- **Test Requirements**:
  - `rule` TR-14.1: 四条命令输出干净（0 error/0 新增类型错误/测试全绿双后端）。
  - `rubric` TR-14.2: AC-U1>=4、AC-U2>=4，证据为独立审查记录。
