# 独立审查记录：统一能力门禁（policy guard）

## 结论：READY（两轮审查闭环）

---

## 第一轮：NOT READY — 3 Critical / 2 High / 若干 Medium

全部修复并通过第二轮复核。

### C-1 `.import` 授权 detail 与真实 authorizer 事件不匹配
- **问题**：plan 对 `.import` 只声明 special detail，但处理器运行时真实执行 INSERT（action 18，write-data/insert），交互确认后仍可能被 authorizer 二次拒绝或授权语义不一致。
- **修复**：`guard/plan.py` 的 `_COMMAND_DETAIL_OVERRIDES[".import"]` 改为 `{filesystem: read_file, write-data: (special, insert)}`；override 支持 tuple 展开多 detail。
- **测试**：`test_guard_integration.py` `.import` 交互落 2 条授权路径、batch count=0；`test_guard_plan.py` 断言 `{special, insert}`。

### C-2 双引号字面量与注释文本泄露到 plan hash / 审计
- **问题**：旧的分层正则先按单引号遮罩，`"secret"` 与 `-- secret`、`/* secret */` 文本可进入 normalized SQL。
- **修复（第二轮 L-1 又加固，见下）**：去注释 + 单双引号遮罩，analyze_sql 始终用原始 SQL 保证能力识别不降级。
- **测试**：`test_guard_audit.py` 泄露扫描覆盖单/双引号、行/块注释；`test_guard_plan.py` 脱敏断言。

### C-3 sqlean fileio 系列函数/虚表绕过
- **问题**：`fileio_read/write/append/mkdir/symlink/mode`、`lsmode`、`fileio_ls/lsdir/scanfile/fileio_scan` 及 `CREATE VIRTUAL TABLE ... USING vsv(...)` 未被识别为 filesystem。
- **修复**：
  - `capabilities.py` 默认函数能力表补全 fileio 全部入口；新增 `FILE_READING_VTABLE_MODULES`。
  - `plan.py` 静态识别 `USING <module>`；`authorizer.py` action 29 按模块名分类，action 20 对表值文件函数分类。
- **测试**：9 个函数入口参数化、5 个虚表模块参数化、sqlean lsdir/skip 探测。

### H-1 `\llm` 三种拼写绕过 prepare
- **修复**：`\llm` 无条件注册（未装包时 hidden），aliases 含 `\ai/.ai/.llm`；`main.py` llm 循环内先 `guard.prepare(text, origin)`，deny 红字中止；handle_llm 包在 scope 内。

### H-2 `\e` 编辑器绕过
- **修复**：`\e` 交互前用合成标记 `guard.prepare("\\e", origin)`；deny 即返回；编辑后 SQL 在 scope 外重新走完整 run 流程。

### Medium（同批修复）
- 审计 replay 增加规则快照校验：`policy.rules_snapshot_digest()`，记录含 `rules_digest`；replay 输出 `rules_snapshot_ok`（被篡改可检出，旧记录为 None）。
- 未知 authorizer action 改 fail-closed（scope 内事件入审计）。
- ruff 问题清零（含 TRY004、未用 import）。

**第一轮质量门**：447 passed / 5 skipped / 1 xfailed / 1 xpassed；独立复核 READY。

---

## 第二轮 follow-up 复核与处理

第二轮 READY 后提出 1 Medium + 4 Low，其中 4 项在本轮修复：

### M-1 持久化/ATTACH 带入的文件型虚表可绕过 runtime backtick（已修复）
- **问题**：`CREATE VIRTUAL TABLE v USING vsv(filename='/path')` 一旦经确认落盘，之后无 scope 上下文的普通 `SELECT * FROM v` 触发的 READ 事件（action 20）只带实例表名 `v`，无法静态/按名识别；ATTACH 预埋同理。
- **修复**：`AuthorizerController.refresh_table_index()` 遍历 `PRAGMA database_list` 各 schema（含 temp）的 `sqlite_master`，按 `rootpage=0 + USING 模块名 ∈ FILE_READING_VTABLE_MODULES` 建立文件虚表集合，同时建立普通表集合；READ 分类先查虚表集合、再按表值函数名（排除真实同名普通表）。索引在 install、scope 开始、每条 entry 执行前、ATTACH 事件后刷新。
- **测试**：`test_persistent_file_vtable_read_denied_in_later_scope`（sqlean，模块缺失即 skip；先授权创建，新空授权 scope 内 SELECT 被 deny 且文件未读）；`test_regular_table_named_like_file_module_is_not_filesystem`（L-3 同名普通表回归）。

### L-1 注释标记出现在字符串内时脱敏残留（已修复）
- **问题**：`'secret--token'` 被行注释正则吞掉闭合引号，前半片段泄露；未闭合 `/*` 同理。
- **修复**：`plan.py` 新增单一有状态扫描器 `_mask_strings_and_comments()`，引号态内不识别注释标记，支持 `''/""` 转义、`x''/b''` blob 前缀、未闭合引号/注释到 EOF。
- **测试**：`test_normalization_comment_markers_inside_strings_are_literal`。

### L-2 `\llm install/uninstall` 的 os.execv 丢审计（已修复）
- **问题**：execv 替换进程映像，scope 的 `with` 不退出，confirmed 执行不写审计。
- **修复**：`special/llm.py` 新增 `before_restart_hooks`，execv 前调用（hook 异常仅 debug 不阻断重启）；`main.py init_guard` 注册 `guard.flush_active_for_restart()`；Guard 支持提前落盘审计且抑制 execv 被打桩时的重复写入。
- **测试**：`test_flush_active_for_restart_writes_audit_exactly_once`、`test_run_external_cmd_invokes_restart_hooks`。

### L-3 普通用户表命名为 lsdir/scanfile 等被误判（已修复）
- 随 M-1 的普通表索引一并解决（rootpage>0 的同名表不按文件表处理）。

### L-4 无 scope 时 UNKNOWN action 拒绝不入审计（保留，by design）
- 无 scope 即无 plan/decision 上下文（如 guard 安装前的内部初始化调用），fail-closed 拒绝已生效并有 warning 日志；scope 内的未知事件正常入审计。不做改动。

---

## 最终质量门

- pytest：**453 passed, 6 skipped, 1 xfailed, 1 xpassed**（stdlib sqlite3 3.53.4 + sqlean 3.50.4）。
- ruff：`litecli/packages/guard/` 与 9 个 test_guard_*.py 0 告警；被修改的存量文件不高于工作树/HEAD 基线（main.py 28 vs HEAD 49；llm.py 3 vs HEAD 3）。
- ty：guard 包与 llm.py 新代码 0 诊断；main.py 仅存量诊断（formatter/query、PromptSession、click stream、output() Iterable truthiness warning）。
- CLI 冒烟：batch `.import` deny 输出 filesystem/read_file；注释内密钥审计 0 命中；`policyaudit` replay `rules_snapshot_ok=True/MATCH`；pty 交互确认通过。

## 关键安全属性复核

1. 同一危险操作跨 prompt/.read/startup/favorite/llm/execute/stdin 六来源同策略（来源只记录不授权），有参数化矩阵。
2. 拒绝在 SQLite 执行副作用前生效：prepare 阶段策略拒绝 + authorizer 运行时 backstop，双重；错误文案含 capability/detail。
3. 审计脱敏：字面量/路径值/文件内容永不入库；可凭 plan hash + 规则快照重放决策（含防篡改标记）。
4. 版本兼容：未知 action/常量 fail-closed；sqlean 能力缺失时测试 skip，不影响 stdlib 行为。
