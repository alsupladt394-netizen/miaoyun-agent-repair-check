# 喵云Agent修复检测

针对一次已确认的未授权 Komari Agent 部署所编写的检测与定向遏制脚本。

> 重要：旧仓库中的 `remove-unauthorized-komari-agent.sh` 已撤销。旧版本存在进程误识别缺陷，在特定情况下可能错误隔离系统 Bash。不要再运行旧命令、旧固定 commit 或旧 SHA-256。

## 安全设计

- 启动后先显示风险告知，只有输入小写 `y` 才显示菜单。
- `1` 为只读检测，不创建文件、不停止服务、不修改防火墙。
- `2` 为检测并修复；还需输入大写 `REPAIR` 二次确认。
- 只有“精确 Agent 路径与已知攻击端点同时成立”或精确 unit 的 `ExecStart` 同时包含二者时，才满足修复门槛。
- 不根据命令行单独杀进程，不根据同尺寸或同哈希移动任何副本。
- 自动隔离只允许 `/opt/komari`、精确 systemd unit 和精确 drop-in 目录。
- `/opt/komari`、Agent 或 unit 出现符号链接、硬链接、挂载点或异常路径时，自动修复拒绝执行。
- 不调用不可信 unit 的 `ExecStop`，不执行 init 脚本或可疑二进制。
- 修复前后校验 Bash、账号文件和 SSH 配置的不变量。
- 仅隔离不删除，生成证据归档、SHA-256 和人工回滚说明。

这只是针对已知 IOC 的定向遏制工具。主机一旦被攻击者获得 root 权限，最终仍应从可信镜像重建并轮换全部凭据。

## 下载与运行

不要使用 `curl | bash`。请下载、校验后再运行：

```bash
curl --fail --silent --show-error --location \
  --proto '=https' --tlsv1.2 \
  'https://raw.githubusercontent.com/alsupladt394-netizen/miaoyun-agent-repair-check/main/miaoyun-agent-repair-check.sh' \
  -o /tmp/miaoyun-agent-repair-check.sh

printf '%s  %s\n' \
  '5e40fb25e12c0f65c92ba5895604fe8f9c0dea5cc57be71f8f90e88c328f23a1' \
  '/tmp/miaoyun-agent-repair-check.sh' | sha256sum -c -

sudo bash /tmp/miaoyun-agent-repair-check.sh
```

只有校验显示 `OK` 才能继续。正式发布后应优先使用 README 中标明的固定 commit URL，而不是可变的 `main`。

## 菜单

```text
1) 检测（只读，不修改系统）
2) 修复（先检测，强 IOC 命中后才允许隔离）
```

修复模式会将证据与隔离目录保留在 `/opt/.miaoyun-agent-ir-*`，并在 `/tmp` 生成压缩归档及 `.sha256`。这些文件可能含 Token、主机名和内部信息，禁止直接公开上传。

## 安全验证

仓库包含 ShellCheck、语法检查及一次性 Debian 容器回归测试，覆盖：

- 未同意风险时不显示菜单；
- 检测模式只读；
- 合法 Komari 指向其他服务端时拒绝修复；
- Agent 指向 Bash 的符号链接时拒绝修复；
- Agent 与 Bash 形成硬链接时拒绝修复；
- 真实强 IOC 场景仅隔离白名单路径；
- 所有测试前后 Bash SHA-256 必须保持一致。

## 兼容性

目标系统为 Debian 12 及使用 Bash、systemd 目录布局和 iptables 兼容命令的常见 Linux 发行版。缺少安全预检所需工具时，修复模式会拒绝执行。
