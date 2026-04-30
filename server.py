"""
Ruijie CLI MCP Server

A Model Context Protocol server for Telnet session management,
optimized for Ruijie RGOS network devices.

Key differences from Cisco (cisco-cli-mcp):
1. --More-- pagination handler: auto-detects and sends space to continue
2. Robust terminal length 0: increased delay + retry on failure
3. Output truncation prevention: buffer cleanup before each command
4. Session timeout recovery: detects "Press RETURN to get started" and sends Enter
5. Log message filtering: separates %OSPF-... log messages from command output
"""

import asyncio
import uuid
import re
import json
import logging
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional

import telnetlib3
from mcp.server.fastmcp import FastMCP

# 配置日志
logger = logging.getLogger("ruijie-cli")

# 创建 FastMCP 实例
mcp = FastMCP("Ruijie CLI MCP Server")

# ============================================================
# 设备提示符检测
# ============================================================

def detect_device_mode(output: str) -> str:
    """
    从输出中检测锐捷设备当前模式

    支持的模式:
    - R1>      用户模式
    - R1#      特权模式
    - R1(config)#      全局配置模式
    - R1(config-if)#   接口配置模式
    - R1(config-router)# 路由配置模式
    - R1(config-subif)#  子接口配置模式
    - R1(config-vlan)#   VLAN 配置模式

    注意：优先从输出末尾匹配提示符，避免多命令输出中匹配到中间的旧提示符。
    """
    if not output:
        return "unknown"

    # 清理输出中的控制字符
    clean_output = output.replace('\x08', '').replace(' \b', '')

    # 优先从最后几行查找提示符（避免匹配到中间的旧提示符）
    lines = clean_output.strip().split('\n')
    for line in reversed(lines[-10:]):
        line = line.strip()
        # 精确匹配提示符行
        if re.match(r'^[A-Za-z0-9_-]+(\([a-z0-9-]+\))?[#>]$', line):
            return line

    # 兜底: 宽松正则匹配（兼容末尾有少量空白的情况）
    patterns = [
        r'[\r\n]([A-Za-z0-9_-]+\([a-z0-9-]+\)[#>])\s*$',  # 配置模式
        r'[\r\n]([A-Za-z0-9_-]+[#>])\s*$',                  # 特权/用户模式
    ]

    for pattern in patterns:
        match = re.search(pattern, clean_output)
        if match:
            return match.group(1).strip()

    return "unknown"


# ============================================================
# 辅助函数: 日志消息过滤
# ============================================================

def split_logs_from_output(output: str) -> tuple[str, list[str]]:
    """
    将锐捷设备输出中的日志消息与命令正常输出分离

    锐捷日志格式:
      *Mon DD HH:MM:SS: %PROTOCOL-N-SEVERITY: message
      例如: *Apr 19 14:20:13: %OSPF-4-ERRRCV: Received invalid packet...

    Args:
        output: 原始输出

    Returns:
        (clean_output, log_messages): 清理后的输出和日志消息列表
    """
    log_pattern = re.compile(
        r'\r?\n\*[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}:\s+%\S+'
    )
    log_messages = log_pattern.findall(output)
    clean_output = log_pattern.sub('', output)
    return clean_output, log_messages


def filter_more_trailers(output: str) -> str:
    """
    清理输出中所有残留的 --More-- 标记

    锐捷 --More-- 出现在行尾，格式为:
      --More-- (后面可能有空格、\r\n 或其他内容直到行尾)
    
    由于自动翻页机制处理后，原始的 --More-- 文本会残留在输出流中间，
    需要将所有出现位置清理掉。
    """
    # 移除所有 --More-- 标记（含其后的非换行空白字符，保留换行符）
    output = re.sub(r'--More--[^\r\n]*', '', output)
    return output


# ============================================================
# TelnetSession 数据类
# ============================================================

@dataclass
class TelnetSession:
    """表示一个 Telnet 会话"""
    session_id: str
    host: str
    port: int
    reader: telnetlib3.TelnetReader
    writer: telnetlib3.TelnetWriter
    connected_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """转换为字典格式"""
        return {
            "sessionId": self.session_id,
            "host": self.host,
            "port": self.port,
            "connectedAt": self.connected_at.isoformat(),
        }


# ============================================================
# TelnetSessionManager — 会话管理器
# ============================================================

class TelnetSessionManager:
    """Telnet 会话管理器，针对锐捷 RGOS 设备优化"""

    def __init__(self):
        self.sessions: dict[str, TelnetSession] = {}

    async def _drain_output(self, reader: telnetlib3.TelnetReader, timeout: float = 0.3) -> str:
        """
        排空 reader 缓冲区中的所有待读数据

        Args:
            reader: Telnet 读取器
            timeout: 每次读取的超时时间

        Returns:
            排出的所有数据
        """
        output = ""
        try:
            while True:
                data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if not data:
                    break
                output += data
        except asyncio.TimeoutError:
            pass
        return output

    async def _handle_login_auth(
        self,
        writer: telnetlib3.TelnetWriter,
        reader: telnetlib3.TelnetReader,
        username: str = "admin",
        password: str = "admin",
        timeout: float = 5.0,
    ) -> bool:
        """
        处理 Telnet 登录认证（用户名/密码提示）

        锐捷设备可能配置为需要用户名和密码认证：
        - 显示 "Username:" 提示
        - 显示 "Password:" 提示
        - 密码 weakness 警告后仍可登录

        Args:
            writer: Telnet 写入器
            reader: Telnet 读取器
            username: 用户名（默认 admin）
            password: 密码（默认 admin）
            timeout: 总超时时间（秒）

        Returns:
            是否认证成功
        """
        start_time = asyncio.get_event_loop().time()
        output = ""
        auth_state = "waiting_username"  # waiting_username -> sent_username -> sent_password -> done

        while asyncio.get_event_loop().time() - start_time < timeout:
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=0.5)
                if data:
                    output += data
                    logger.debug(f"[auth] 读取到 {len(data)} 字节：{repr(data[:100])}")

                    # 检测用户名提示
                    if auth_state == "waiting_username" and "Username:" in output:
                        logger.info("[auth] 检测到 Username 提示，发送用户名")
                        writer.write(username + "\r\n")
                        await writer.drain()
                        auth_state = "sent_username"
                        output = ""
                        continue

                    # 检测密码提示
                    if auth_state in ["sent_username", "waiting_password"] and "Password:" in output:
                        logger.info("[auth] 检测到 Password 提示，发送密码")
                        writer.write(password + "\r\n")
                        await writer.drain()
                        auth_state = "sent_password"
                        output = ""
                        continue

                    # 检测密码强度警告（可选，不影响登录）
                    if auth_state == "sent_password" and "password is too weak" in output:
                        logger.warning("[auth] 密码强度警告，继续登录流程")
                        output = ""
                        continue

                    # 检测登录成功（出现设备提示符）
                    if auth_state == "sent_password":
                        clean = output.replace('\x08', '').replace(' \b', '')
                        if re.search(r'[\r\n][A-Za-z0-9_-]+[#>]\s*$', clean):
                            logger.info("[auth] 认证成功")
                            return True

            except asyncio.TimeoutError:
                # 超时检查
                if auth_state == "sent_password":
                    # 已发送密码，检查是否已登录
                    clean = output.replace('\x08', '').replace(' \b', '')
                    if re.search(r'[\r\n][A-Za-z0-9_-]+[#>]\s*$', clean):
                        logger.info("[auth] 认证成功（超时前已登录）")
                        return True

        # 超时或无认证提示，返回当前状态
        if auth_state == "waiting_username":
            logger.info("[auth] 未检测到用户名提示，设备可能无需认证")
            return True  # 无需认证也算成功
        return False

    async def _send_with_retry(
        self,
        writer: telnetlib3.TelnetWriter,
        reader: telnetlib3.TelnetReader,
        command: str,
        retry_count: int = 3,
        success_delay: float = 0.5,
        drain_delay: float = 0.8,
    ) -> bool:
        """
        发送命令并重试确认

        锐捷设备 Telnet 通道中，如果缓冲区有残留输出（特别是 syslog 消息），
        后续命令的首字母可能被截断。此函数通过重试机制确保命令被完整执行。

        Args:
            writer: Telnet 写入器
            reader: Telnet 读取器
            command: 要发送的命令
            retry_count: 最大重试次数
            success_delay: 每次发送后的等待时间
            drain_delay: 重试前的排空等待时间

        Returns:
            是否成功执行（未出现 % Unknown command）
        """
        for attempt in range(retry_count):
            # 发送前先排空缓冲区
            if attempt > 0:
                await asyncio.sleep(drain_delay)
                await self._drain_output(reader, timeout=0.2)

            writer.write(command + "\r\n")
            await writer.drain()
            await asyncio.sleep(success_delay)

            # 读取响应
            response = await self._drain_output(reader, timeout=0.2)

            # 检查是否执行成功
            if "% Unknown command" not in response and "% Invalid input" not in response:
                return True

            logger.debug(f"命令 '{command}' 第 {attempt + 1} 次执行失败，准备重试: {response[:100]}")

        return False

    async def connect(
        self, host: str, port: int, timeout: int = 5000, username: str = "admin", password: str = "admin"
    ) -> str:
        """
        建立 Telnet 连接

        连接流程（针对锐捷设备优化）:
        1. TCP 连接建立
        2. 终端激活（发送回车处理 "Press RETURN to get started"）
        3. 登录认证（处理 Username:/Password: 提示）
        4. TCP 预热（发送 ? 产生大量输出以初始化通道）
        5. 排空预热输出（含 syslog 消息）
        6. 检测当前模式，若为用户模式(>)则自动 enable 进入特权模式(#)
        7. 配置模式检测与退出（回到特权模式）
        8. 禁用分页（terminal length 0，带重试，需特权模式）
        """
        timeout_seconds = timeout / 1000.0

        try:
            # Step 1: 建立 TCP 连接
            reader, writer = await asyncio.wait_for(
                telnetlib3.open_connection(host, port),
                timeout=timeout_seconds
            )

            session_id = str(uuid.uuid4())
            session = TelnetSession(
                session_id=session_id,
                host=host,
                port=port,
                reader=reader,
                writer=writer,
            )
            self.sessions[session_id] = session

            # Step 2: 终端激活
            # 锐捷设备长时间闲置后会退出到 "Press RETURN to get started"
            # 需要多次发送回车确保进入 CLI 模式
            await asyncio.sleep(0.5)
            for i in range(5):
                writer.write("\r\n")
                await writer.drain()
                await asyncio.sleep(0.3)

            # Step 3: 登录认证处理
            # 锐捷设备可能配置为需要用户名/密码认证
            # 先读取初始输出，检测是否有 "Username:" 提示
            await asyncio.sleep(0.5)
            auth_output = await self._drain_output(reader, timeout=1.0)
            logger.debug(f"[connect] 认证前输出：{repr(auth_output[:200]) if auth_output else 'empty'}")

            # 检测是否需要认证
            if "Username:" in auth_output or "username:" in auth_output:
                logger.info("[connect] 检测到用户名提示，开始登录认证")
                # 发送用户名
                writer.write("admin\r\n")
                await writer.drain()
                await asyncio.sleep(0.5)
                
                # 读取密码提示
                password_output = await self._drain_output(reader, timeout=1.0)
                logger.debug(f"[connect] 密码提示输出：{repr(password_output[:200]) if password_output else 'empty'}")
                
                if "Password:" in password_output or "password:" in password_output:
                    # 发送密码
                    writer.write("admin\r\n")
                    await writer.drain()
                    await asyncio.sleep(1.0)
                    
                    # 读取认证结果
                    auth_result = await self._drain_output(reader, timeout=1.0)
                    logger.debug(f"[connect] 认证结果：{repr(auth_result[:300]) if auth_result else 'empty'}")
                    
                    # 检测密码强度警告（可选）
                    if "password is too weak" in auth_result:
                        logger.warning("[connect] 密码强度警告，继续登录流程")
                        # 继续读取登录成功后的输出
                        await asyncio.sleep(0.5)
                        auth_result = await self._drain_output(reader, timeout=1.0)
            else:
                logger.info("[connect] 未检测到用户名提示，设备可能无需认证")

            # Step 4: TCP 预热
            # 发送 ? 命令产生大量输出，确保 TCP 通道完全建立
            for i in range(5):
                writer.write("?\r\n")
                await writer.drain()
                await asyncio.sleep(0.3)

            # Step 4: 排空所有预热输出
            initial_output = await self._drain_output(reader, timeout=0.5)

            logger.debug(f"[connect] 预热输出长度: {len(initial_output)}")

            # Step 5: 检测当前模式，若为用户模式(>)则自动 enable
            # 锐捷设备 terminal length 0 需要特权模式才能执行
            current_mode = detect_device_mode(initial_output)
            if current_mode.endswith(">"):
                # 用户模式，需要 enable 进入特权模式
                logger.info(f"[connect] 检测到用户模式 {current_mode}，自动 enable")
                writer.write("enable\r\n")
                await writer.drain()
                await asyncio.sleep(0.5)
                await self._drain_output(reader, timeout=0.3)

            # Step 6: 检测并退出配置模式
            # 重新检测模式（enable 后可能变化）
            await asyncio.sleep(0.2)
            check_output = await self._drain_output(reader, timeout=0.2)
            combined_output = initial_output + check_output

            if '(config' in combined_output:
                writer.write("end\r\n")
                await writer.drain()
                await asyncio.sleep(0.5)
                await self._drain_output(reader, timeout=0.3)

            # Step 7: 禁用分页 - terminal length 0
            # 使用重试机制确保命令被完整执行（避免首字母截断）
            # 注意：此命令必须在特权模式(# )下才能执行
            success = await self._send_with_retry(
                writer, reader,
                "terminal length 0",
                retry_count=3,
                success_delay=0.8,
                drain_delay=1.0,
            )

            if not success:
                logger.warning("terminal length 0 执行失败，将在运行时处理 --More--")

            # 最终排空缓冲区
            await self._drain_output(reader, timeout=0.3)

            return session_id

        except asyncio.TimeoutError:
            raise ConnectionError(f"连接超时: {host}:{port}")
        except Exception as e:
            raise ConnectionError(f"连接失败: {host}:{port} - {str(e)}")

    async def _handle_more_pages(
        self,
        session: TelnetSession,
        output: str,
        total_wait_seconds: float,
        start_time: float,
    ) -> tuple[str, bool]:
        """
        处理锐捷设备的 --More-- 分页提示

        当检测到 --More-- 时，自动发送空格键继续获取下一页输出。
        同时检查命令是否实际完成（通过设备提示符判断）。

        Args:
            session: 当前 Telnet 会话
            output: 当前已收集的输出
            total_wait_seconds: 总等待时间上限
            start_time: 开始时间

        Returns:
            (output, completed): 完整输出和是否已完成
        """
        current_output = output
        max_pages = 100  # 防止无限循环
        page_count = 0

        while page_count < max_pages:
            current_time = asyncio.get_event_loop().time()
            if current_time - start_time >= total_wait_seconds:
                break

            # 检查末尾是否有 --More--
            if re.search(r'--More--\s*$', current_output):
                # 发送空格键继续下一页
                session.writer.write(" ")
                await session.writer.drain()

                # 读取下一页输出
                page_count += 1
                try:
                    while True:
                        data = await asyncio.wait_for(
                            session.reader.read(4096),
                            timeout=0.5
                        )
                        if data:
                            current_output += data

                        # 检查是否到了最后一页（出现设备提示符）
                        clean = current_output.replace('\x08', '').replace(' \b', '')
                        if re.search(r'[\r\n][A-Za-z0-9_-]+(\([a-z0-9-]+\))?[#>]\s*$', clean):
                            return current_output, True

                        # 检查是否还有更多页
                        if re.search(r'--More--\s*$', current_output):
                            break  # 继续外层循环发送空格

                except asyncio.TimeoutError:
                    pass
            else:
                break

        return current_output, False

    def _check_prompt(self, output: str) -> bool:
        """
        检查输出中是否包含设备提示符

        Args:
            output: 命令输出

        Returns:
            是否检测到提示符
        """
        clean_output = output.replace('\x08', '').replace(' \b', '')
        # 提示符正则: hostname# 或 hostname> 或 hostname(config-xxx)#
        prompt_pattern = re.compile(
            r'[\r\n]([A-Za-z0-9_-]+(\([a-z0-9-]+\))?[#>])\s*$'
        )
        return bool(prompt_pattern.search(clean_output))

    def _check_session_timeout(self, output: str) -> bool:
        """
        检测会话是否已超时退出

        锐捷设备 vty 会话闲置一段时间后，会退回到 "Press RETURN to get started" 状态。

        Args:
            output: 当前输出

        Returns:
            是否检测到会话超时
        """
        return "Press RETURN to get started" in output

    def _is_config_mode(self, mode: str) -> bool:
        """
        判断当前是否处于配置模式

        锐捷配置模式包括:
        - hostname(config)#         全局配置
        - hostname(config-if)#      接口配置
        - hostname(config-router)#  路由配置
        - hostname(config-subif)#   子接口配置
        - hostname(config-vlan)#    VLAN 配置
        """
        return "(config" in mode if mode else False

    async def _ensure_privilege_mode(
        self, session: TelnetSession, current_mode: str
    ) -> str:
        """
        确保会话处于特权模式(#)

        如果当前在配置模式，自动发送 end 退回特权模式。
        如果当前在用户模式(>)，自动发送 enable。

        Args:
            session: 当前会话
            current_mode: 当前检测到的模式

        Returns:
            退回后的实际模式
        """
        if self._is_config_mode(current_mode):
            logger.info(f"[execute] 检测到配置模式 {current_mode}，自动 end 退回特权模式")
            session.writer.write("end\r\n")
            await session.writer.drain()
            await asyncio.sleep(0.8)
            end_output = await self._drain_output(session.reader, timeout=0.5)
            end_mode = detect_device_mode(end_output) if end_output else "unknown"
            logger.debug(f"[execute] end 后模式: {end_mode}, 输出尾部: {repr(end_output[-80:]) if end_output else 'empty'}")
            return end_mode if end_mode != "unknown" else current_mode
        elif current_mode.endswith(">"):
            logger.info(f"[execute] 检测到用户模式 {current_mode}，自动 enable")
            session.writer.write("enable\r\n")
            await session.writer.drain()
            await asyncio.sleep(0.8)
            enable_output = await self._drain_output(session.reader, timeout=0.5)
            enable_mode = detect_device_mode(enable_output) if enable_output else "unknown"
            logger.debug(f"[execute] enable 后模式：{enable_mode}, 输出尾部：{repr(enable_output[-80:]) if enable_output else 'empty'}")
            return enable_mode if enable_mode != "unknown" else current_mode

    def _preprocess_command(self, command: str) -> str:
        """
        预处理命令，将思科风格的命令转换为锐捷兼容格式

        锐捷不支持:
        1. do <command>  — 配置模式下执行 exec 命令，需先 end 退回特权模式
        2. | section <regex> — show 命令的 section 过滤，需用完整输出

        Args:
            command: 原始命令

        Returns:
            预处理后的命令（do 和 | section 会被移除）
        """
        cmd = command.strip()

        # 移除 do 前缀（配置模式执行 exec 命令）
        # 锐捷不支持 do，但上层逻辑会自动 end 退回特权模式，所以去掉 do 前缀即可
        if cmd.lower().startswith("do "):
            cmd = cmd[3:].strip()
            logger.info(f"[execute] 移除 do 前缀: do {cmd} → {cmd}")

        # 移除 | section 过滤（锐捷不支持）
        # 保留管道前的命令部分
        section_match = re.match(r'^(.+?)\s*\|\s*section\s*.*$', cmd, re.IGNORECASE)
        if section_match:
            cmd = section_match.group(1).strip()
            logger.info(f"[execute] 移除 | section 过滤: {command} → {cmd}")

        return cmd

    def _needs_privilege_mode(self, command: str) -> bool:
        """
        判断命令是否需要特权模式才能执行

        show、ping、traceroute、debug、clear 等命令需要特权模式。
        注意：configure、interface、router、vlan 是配置命令，需要在配置模式下执行，
        但它们的前置命令 configure terminal 需要特权模式。
        """
        cmd = command.strip().lower()
        privilege_prefixes = [
            'show', 'ping', 'traceroute', 'tracert',
            'debug', 'clear', 'reload', 'copy',
            'write', 'erase', 'delete', 'terminal',
            'ip ', 'no ',
        ]
        return any(cmd.startswith(prefix) for prefix in privilege_prefixes)

    async def execute(
        self, session_id: str, command: str, wait_ms: int = 2000
    ) -> str:
        """
        在指定会话执行命令

        针对锐捷设备的优化:
        1. 命令预处理（移除 do 前缀、| section 过滤）
        2. 配置模式自动退出（end 回特权模式执行 show 命令）
        3. 发送命令前先排空缓冲区（防止 syslog 截断）
        4. --More-- 自动处理（发送空格继续翻页）
        5. 会话超时自动恢复（检测 "Press RETURN" 并回车）
        6. 运行时日志消息过滤

        Args:
            session_id: 会话 ID
            command: 要发送的命令
            wait_ms: 最大等待时间（毫秒）

        Returns:
            命令输出（含日志消息列表）
        """
        if session_id not in self.sessions:
            raise ValueError(f"会话不存在: {session_id}")

        session = self.sessions[session_id]

        # 空命令只用于检测模式，不做特殊处理
        command_stripped = command.strip()

        # === 命令预处理 ===
        if command_stripped:
            original_command = command_stripped
            command_stripped = self._preprocess_command(command_stripped)
            command = command_stripped  # 后续使用预处理后的命令
        else:
            original_command = ""

        # 自动检测耗时命令并调整等待时间
        command_lower = command_stripped.lower()
        long_running_commands = [
            'ping', 'traceroute', 'tracert', 'show tech',
            'copy', 'write', 'reload', 'debug',
            'show running-config',  # 锐捷 show running-config 输出可能很长
            'show startup-config',
        ]

        for cmd in long_running_commands:
            if command_lower.startswith(cmd):
                wait_ms = max(wait_ms, 12000)
                break

        wait_seconds = wait_ms / 1000.0

        # === 检测并确保特权模式 ===
        # 如果当前在配置模式且需要执行 show 等特权命令，自动 end 退回
        if command_stripped and self._needs_privilege_mode(command_stripped):
            # 发送一个空行来获取当前提示符（避免缓冲区为空无法检测模式）
            session.writer.write("\r\n")
            await session.writer.drain()
            await asyncio.sleep(0.3)
            stale = await self._drain_output(session.reader, timeout=0.3)
            current_mode = detect_device_mode(stale)
            logger.debug(f"[execute] 模式检测: stale尾部={repr(stale[-60:]) if stale else 'empty'}, mode={current_mode}")
            if current_mode != "unknown":
                await self._ensure_privilege_mode(session, current_mode)
                # 退回后再次排空
                await asyncio.sleep(0.1)
                stale = ""
        else:
            stale = ""

        # === 发送前缓冲区清理 ===
        # 排空残留的 syslog 消息，防止截断后续命令
        if command_stripped:
            await asyncio.sleep(0.15)
            stale = await self._drain_output(session.reader, timeout=0.1)
            if stale:
                logger.debug(f"[execute] 排空缓冲区 {len(stale)} 字节")

        # === 检查会话是否超时 ===
        if self._check_session_timeout(stale if command_stripped else ""):
            logger.info("[execute] 检测到会话超时，发送回车恢复")
            session.writer.write("\r\n")
            await session.writer.drain()
            await asyncio.sleep(0.5)
            await self._drain_output(session.reader, timeout=0.3)

        # === 发送命令 ===
        session.writer.write(command + "\r\n")
        await session.writer.drain()

        # === 收集输出 ===
        output = ""
        start_time = asyncio.get_event_loop().time()
        last_data_time = start_time

        while True:
            current_time = asyncio.get_event_loop().time()
            elapsed = current_time - start_time

            if elapsed >= wait_seconds:
                break

            try:
                data = await asyncio.wait_for(
                    session.reader.read(4096),
                    timeout=0.1
                )
                if data:
                    output += data
                    last_data_time = current_time

                    # 检测会话超时
                    if self._check_session_timeout(output):
                        session.writer.write("\r\n")
                        await session.writer.drain()
                        await asyncio.sleep(0.5)
                        recovery_data = await self._drain_output(session.reader, timeout=0.3)
                        output += recovery_data
                        continue

                    # 检测 --More-- 分页
                    if re.search(r'--More--\s*$', output):
                        output, completed = await self._handle_more_pages(
                            session, output, wait_seconds, start_time
                        )
                        if completed:
                            break
                        continue

                    # 检测设备提示符 → 命令完成
                    if self._check_prompt(output):
                        # 等待额外数据（可能有延迟到达的 syslog）
                        await asyncio.sleep(0.3)
                        try:
                            extra_data = await asyncio.wait_for(
                                session.reader.read(4096),
                                timeout=0.15
                            )
                            if extra_data:
                                output += extra_data
                                # 额外数据可能包含 --More--
                                if re.search(r'--More--\s*$', output):
                                    output, _ = await self._handle_more_pages(
                                        session, output, wait_seconds, start_time
                                    )
                        except asyncio.TimeoutError:
                            pass
                        break

            except asyncio.TimeoutError:
                # 沉默超时检查
                silence_duration = current_time - last_data_time
                if silence_duration >= 1.0 and output:
                    if self._check_prompt(output):
                        break
                    # 检查 --More--
                    if re.search(r'--More--\s*$', output):
                        output, completed = await self._handle_more_pages(
                            session, output, wait_seconds, start_time
                        )
                        if completed:
                            break
                        continue
            except Exception as e:
                logger.debug(f"[execute] 读取异常: {e}")

        # === 后处理 ===
        # 分离日志消息和正常输出
        clean_output, log_messages = split_logs_from_output(output)
        clean_output = filter_more_trailers(clean_output)

        # 如果有日志消息，附加到输出的末尾
        result = clean_output
        if log_messages:
            result += "\r\n---\r\n[设备日志消息]\r\n"
            for msg in log_messages:
                result += msg.strip() + "\r\n"

        return result

    def list_sessions(self) -> list[dict]:
        """列出所有活动会话"""
        return [session.to_dict() for session in self.sessions.values()]

    async def disconnect(self, session_id: str) -> bool:
        """断开指定会话"""
        if session_id not in self.sessions:
            raise ValueError(f"会话不存在: {session_id}")

        session = self.sessions[session_id]

        try:
            session.writer.close()
        except Exception:
            pass

        del self.sessions[session_id]
        return True


# ============================================================
# 全局会话管理器实例
# ============================================================

session_manager = TelnetSessionManager()


# ============================================================
# MCP 工具定义
# ============================================================

@mcp.tool()
async def telnet_connect(host: str, port: int, timeout: int = 5000, username: str = "admin", password: str = "admin") -> str:
    """
    建立 Telnet 连接

    Args:
        host: 主机地址
        port: 端口号
        timeout: 连接超时时间（毫秒，默认5000）

    Returns:
        连接结果，包含会话ID和设备当前模式
        设备模式说明：
        - "R1>" 表示用户模式，需要执行 enable 进入特权模式
        - "R1#" 表示特权模式，可以执行 show 命令
        - "R1(config)#" 表示全局配置模式
        - "R1(config-if)#" 表示接口配置模式
        - "R1(config-router)#" 表示路由配置模式
    """
    try:
        session_id = await session_manager.connect(host, port, timeout, username, password)
        # 发送空命令获取当前提示符
        initial_output = await session_manager.execute(session_id, "", 1000)
        device_mode = detect_device_mode(initial_output)
        return json.dumps({
            "success": True,
            "sessionId": session_id,
            "deviceMode": device_mode,
            "message": "连接成功"
        }, ensure_ascii=False)
    except ConnectionError as e:
        return json.dumps({
            "success": False,
            "error": str(e)
        }, ensure_ascii=False)


@mcp.tool()
async def telnet_execute(session_id: str, command: str, wait_ms: int = 2000) -> str:
    """
    在指定会话执行命令

    Args:
        session_id: 会话ID
        command: 要发送的命令
        wait_ms: 最大等待时间（毫秒，默认2000）
                 系统会智能检测设备提示符，检测到后立即返回，无需等满超时时间。
                 对于 ping、traceroute 等耗时命令，系统会自动增加等待时间至12秒。

    Returns:
        命令输出（JSON格式）
        - success: 是否成功
        - output: 命令输出内容
        - deviceMode: 当前设备模式（如 R1#、R1>、R1(config)# 等）
        - logs: 设备日志消息列表（如有）
    """
    try:
        output = await session_manager.execute(session_id, command, wait_ms)

        # 分离日志和正常输出用于 mode 检测
        clean_for_detection, _ = split_logs_from_output(output)
        device_mode = detect_device_mode(clean_for_detection)

        # 提取日志消息列表
        _, log_messages = split_logs_from_output(output)
        clean_output = filter_more_trailers(clean_for_detection)

        return json.dumps({
            "success": True,
            "output": clean_output if clean_output else "",
            "deviceMode": device_mode,
            "logs": [msg.strip() for msg in log_messages] if log_messages else []
        }, ensure_ascii=False)
    except ValueError as e:
        return json.dumps({"success": False, "error": str(e)}, ensure_ascii=False)
    except RuntimeError as e:
        return json.dumps({"success": False, "error": str(e)}, ensure_ascii=False)


@mcp.tool()
def telnet_list_sessions() -> str:
    """
    列出所有活动会话

    Returns:
        会话信息（JSON格式）
    """
    sessions = session_manager.list_sessions()
    if not sessions:
        return "当前没有活动会话"

    result = "活动会话列表:\n"
    for session in sessions:
        result += f"- ID: {session['sessionId']}\n"
        result += f"  主机: {session['host']}:{session['port']}\n"
        result += f"  连接时间: {session['connectedAt']}\n"
    return result


@mcp.tool()
async def telnet_disconnect(session_id: str) -> str:
    """
    断开指定会话

    Args:
        session_id: 会话ID

    Returns:
        断开结果
    """
    try:
        await session_manager.disconnect(session_id)
        return f"会话 {session_id} 已断开"
    except ValueError as e:
        return f"错误: {str(e)}"


# ============================================================
# 入口
# ============================================================

def main():
    """入口函数"""
    mcp.run()


if __name__ == "__main__":
    main()
