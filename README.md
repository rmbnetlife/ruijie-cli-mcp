# Ruijie CLI MCP Server

A Telnet-based MCP tool for Ruijie RGOS network device CLI, forked from [cisco-cli-mcp](https://github.com/XunMInt/cisco-cli-mcp) with critical adaptations for Ruijie devices.

## 锐捷 vs 思科：关键差异

| 问题 | 思科 (cisco-cli) | 锐捷 (ruijie-cli) |
|------|------------------|-------------------|
| 分页 | `terminal length 0` 稳定生效 | 可能因缓冲区截断而失败；增加运行时 `--More--` 处理 |
| 命令截断 | 罕见 | syslog 消息填满缓冲区时常见；增加发送前排空缓冲区 |
| `--More--` 格式 | ` --More--` | ` --More-- `（带尾部空格）；自动发送空格翻页 |
| 会话超时 | 标准 | vty 闲置后退到 "Press RETURN to get started"；自动恢复 |
| 日志干扰 | 较少 | OSPF/BGP syslog 可打断输出；分离到独立 `logs` 字段 |
| `do` 命令 | 支持 `do show` 在配置模式执行 | 不支持；自动 `end` 退回特权模式再执行 |
| `| section` | 支持 `show run | section X` | 不支持；自动移除 `| section` 过滤 |
| `logging console warning` | 支持 | 不支持（已移除） |

## 功能特性

- 智能连接管理：终端激活、TCP 预热、自动 `enable` 进入特权模式
- **登录认证支持**：自动检测并处理 "Username:" 和 "Password:" 提示，支持用户名密码认证
- `--More--` 自动处理：检测分页提示并自动发送空格继续
- 输出截断防护：每次发送命令前排空缓冲区
- 会话超时恢复：检测 "Press RETURN to get started" 并自动回车恢复
- 日志消息过滤：将 `%OSPF-...` 等 syslog 与命令输出分离
- 配置模式自动退出：检测到配置模式自动 `end` 退回特权模式
- 命令预处理：自动移除 `do` 前缀和 `| section` 过滤（锐捷不支持）
- 设备模式检测：优先从输出末尾匹配，避免多命令场景误判
- 智能等待机制：检测到提示符立即返回
- 耗时命令优化：自动识别 ping、traceroute、show running-config

## 工具列表

- **telnet_connect**: 建立 Telnet 连接，返回会话 ID 和设备当前模式
  - 参数：`host`, `port`, `timeout`, `username`（默认 admin）, `password`（默认 admin）
  - 自动检测并处理登录认证提示
- **telnet_execute**: 在指定会话执行命令，返回输出、设备模式和日志
- **telnet_list_sessions**: 列出所有活动会话
- **telnet_disconnect**: 断开指定会话

## 安装

```bash
cd ruijie-cli-mcp
pip install -e .
```

## 使用

### 作为 MCP 服务器运行

```bash
ruijie-cli-mcp
```

### 配置 MCP 客户端

```json
{
  "mcpServers": {
    "ruijie-cli": {
      "command": "ruijie-cli-mcp"
    }
  }
}
```

## 返回格式

### telnet_connect

```json
{
  "success": true,
  "sessionId": "xxx-xxx-xxx",
  "deviceMode": "Ruijie#",
  "message": "连接成功"
}
```

**参数说明：**
- `host`: 设备 IP 地址
- `port`: Telnet 端口（默认 23）
- `timeout`: 连接超时时间（毫秒，默认 5000）
- `username`: 登录用户名（默认 admin）
- `password`: 登录密码（默认 admin）

**认证流程：**
1. 连接建立后自动检测 "Username:" 提示
2. 如检测到认证提示，自动发送用户名和密码
3. 处理密码强度警告（"password is too weak"）并继续登录
4. 无需认证的设备可直接进入 CLI 模式

### telnet_execute

```json
{
  "success": true,
  "output": "命令输出内容...",
  "deviceMode": "R1#",
  "logs": ["*Apr 19 14:20:13: %OSPF-4-ERRRCV: ..."]
}
```

## 系统提示词

```text
你是锐捷网络设备配置助手，擅长配置锐捷路由器和交换机

1、你可以使用 ruijie-cli MCP 工具连接锐捷设备
2、telnet_connect 支持 username 和 password 参数，默认均为 "admin"，会自动处理登录认证
3、对于耗时操作如 ping、traceroute、show running-config 等，建议将 wait_ms 设置为 3000-10000 毫秒或更长时间
4、每次发送命令时，务必记住当前系统模式（特权模式、全局配置模式等），根据模式调整命令
5、如果之前已连接，使用 telnet_list_sessions 复用现有会话
6、不确定的配置要先执行 show 操作确认
7、所有配置结合用户给出的拓扑信息，不清楚的地方反问用户
8、命令错误时可使用 "?" 命令查看可用选项
9、调用工具前简要说明操作意图
10、注意：锐捷设备的命令体系与思科高度相似但有细微差异，如 interface 命名用 GigabitEthernet 而非 GigabitEthernet0/0
11、设备日志消息会自动分离到 logs 字段，不影响命令输出的解读
```

## 适用设备

- 锐捷 RG-NSE 仿真环境
- 锐捷 RGOS 系列交换机（S5750/S3750/S2600 等）
- 锐捷 RGOS 系列路由器（RSR 系列）
- 其他命令体系与锐捷兼容的网络设备
