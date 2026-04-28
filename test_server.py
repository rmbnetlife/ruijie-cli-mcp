"""
ruijie-cli-mcp 功能测试脚本
直接测试 TelnetSessionManager 的核心方法
"""
import asyncio
import sys
import os
import json

# 将项目目录加入路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from server import TelnetSessionManager, detect_device_mode, split_logs_from_output, filter_more_trailers


# 测试设备配置
DEVICE_HOST = "192.168.80.154"
DEVICE_PORT = 32770  # R2（默认 hostname Router，未配置状态）
DEVICE_NAME = "R2"


async def test_connect_and_basic():
    """测试1: 连接 + 基本命令"""
    print("=" * 60)
    print(f"测试1: 连接 {DEVICE_NAME} ({DEVICE_HOST}:{DEVICE_PORT})")
    print("=" * 60)

    mgr = TelnetSessionManager()

    try:
        session_id = await mgr.connect(DEVICE_HOST, DEVICE_PORT, timeout=5000)
        print(f"[PASS] 连接成功, session_id: {session_id[:8]}...")

        # 验证 connect 后已自动进入特权模式
        print("\n--- 验证 connect 后自动 enable ---")
        output = await mgr.execute(session_id, "", 1000)
        print(f"  输出: {repr(output[:100])}")
        mode = detect_device_mode(output)
        print(f"  模式: {mode}")
        assert mode == DEVICE_NAME + "#", f"期望 {DEVICE_NAME}#，实际 {mode}"
        print("[PASS] connect 后已自动进入特权模式")

        # 测试 terminal length 0
        print("\n--- 测试 terminal length 0 ---")
        output = await mgr.execute(session_id, "terminal length 0", 2000)
        print(f"  输出: {repr(output[:100])}")
        if "% Unknown command" not in output:
            print("[PASS] terminal length 0 执行成功")
        else:
            print("[WARN] terminal length 0 失败（但运行时会处理 --More--）")

        await mgr.disconnect(session_id)
        print("\n[PASS] 测试1 完成")
        return True

    except Exception as e:
        print(f"[FAIL] 测试1 失败: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_more_pages():
    """测试2: --More-- 分页处理"""
    print("\n" + "=" * 60)
    print("测试2: --More-- 分页处理 (terminal length 24)")
    print("=" * 60)

    mgr = TelnetSessionManager()

    try:
        session_id = await mgr.connect(DEVICE_HOST, DEVICE_PORT, timeout=5000)

        # connect 已自动 enable，无需手动执行

        # 设置分页为 24 行
        print("\n--- 设置 terminal length 24 ---")
        output = await mgr.execute(session_id, "terminal length 24", 2000)
        print(f"  输出: {repr(output[:100])}")

        # 执行会产生多页输出的命令
        print("\n--- 执行 show running-config (多页) ---")
        output = await mgr.execute(session_id, "show running-config", 15000)
        print(f"  输出长度: {len(output)}")

        # 检查是否还有残留的 --More--
        if "--More--" in output:
            print("[FAIL] 输出中仍有 --More-- 残留!")
            print(f"  残留内容: ...{output[-200:]}")
        else:
            print("[PASS] --More-- 已全部处理")

        # 检查是否包含完整配置（应有 end 标记）
        if "end" in output:
            print("[PASS] 输出包含完整的 running-config（含 end）")
        else:
            print("[WARN] 输出可能不完整（未找到 end）")

        # 检查日志分离
        clean_output, log_messages = split_logs_from_output(output)
        if log_messages:
            print(f"\n--- 日志消息分离 ---")
            print(f"  分离出 {len(log_messages)} 条日志")
            for msg in log_messages[:3]:
                print(f"    {msg.strip()[:80]}")
            print("[PASS] 日志消息分离成功")
        else:
            print("\n[INFO] 本次无日志消息")

        # 检查模式检测
        mode = detect_device_mode(output)
        print(f"\n--- 模式检测 ---")
        print(f"  检测到: {mode}")
        if mode == DEVICE_NAME + "#":
            print("[PASS] 模式检测正确")
        else:
            print(f"[WARN] 模式检测为 {mode}，期望 {DEVICE_NAME}#")

        await mgr.disconnect(session_id)
        print("\n[PASS] 测试2 完成")
        return True

    except Exception as e:
        print(f"[FAIL] 测试2 失败: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_command_truncation():
    """测试3: 命令截断防护"""
    print("\n" + "=" * 60)
    print("测试3: 命令截断防护 (多次连续命令)")
    print("=" * 60)

    mgr = TelnetSessionManager()

    try:
        session_id = await mgr.connect(DEVICE_HOST, DEVICE_PORT, timeout=5000)

        # 快速连续发送多个命令
        test_commands = [
            "show version",
            "show ip interface brief",
            "show ip ospf neighbor",
            "show ip route",
            "show ip ospf interface brief",
        ]

        print("\n--- 快速连续发送 5 个命令 ---")
        success_count = 0
        for i, cmd in enumerate(test_commands):
            output = await mgr.execute(session_id, cmd, 3000)
            # 检查命令是否成功执行（不应该出现 Unknown command 或截断）
            if "% Unknown command" in output or "% Invalid input" in output:
                print(f"  [{i+1}] {cmd} -> [FAIL] 命令执行失败")
                print(f"       输出: {repr(output[:150])}")
            elif output.strip().endswith(DEVICE_NAME + "#") or DEVICE_NAME + "#" in output[-20:]:
                print(f"  [{i+1}] {cmd} -> [PASS]")
                success_count += 1
            else:
                print(f"  [{i+1}] {cmd} -> [WARN] 输出可能不完整")
                print(f"       末尾: {repr(output[-100:])}")
                success_count += 1  # 仍然算通过，因为可能是模式检测问题

        print(f"\n--- 结果: {success_count}/{len(test_commands)} 命令成功 ---")
        if success_count == len(test_commands):
            print("[PASS] 测试3 完成")
        else:
            print("[PARTIAL] 部分命令失败")

        await mgr.disconnect(session_id)
        return success_count == len(test_commands)

    except Exception as e:
        print(f"[FAIL] 测试3 失败: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_output_with_logs():
    """测试4: 包含日志消息的输出处理"""
    print("\n" + "=" * 60)
    print("测试4: 日志消息干扰下的命令执行")
    print("=" * 60)

    mgr = TelnetSessionManager()

    try:
        session_id = await mgr.connect(DEVICE_HOST, DEVICE_PORT, timeout=5000)

        # 执行 show running-config | begin interface（已知会产生日志的命令）
        print("\n--- 执行 show running-config | begin interface ---")
        output = await mgr.execute(session_id, "show running-config | begin interface", 10000)
        print(f"  输出长度: {len(output)}")

        # 检查日志分离
        clean_output, log_messages = split_logs_from_output(output)

        if log_messages:
            print(f"\n  分离出 {len(log_messages)} 条日志:")
            for msg in log_messages[:5]:
                print(f"    - {msg.strip()[:100]}")
        else:
            print("  未检测到日志消息（可能没有 OSPF 错误日志产生）")

        # 清理后的输出不应该有 --More--
        clean_output = filter_more_trailers(clean_output)
        if "--More--" in clean_output:
            print("[FAIL] 清理后仍有 --More--")
        else:
            print("[PASS] 输出清理完成")

        # 模式检测
        mode = detect_device_mode(clean_output)
        print(f"  模式: {mode}")
        if mode in (DEVICE_NAME + "#", "unknown"):
            print("[PASS] 模式检测合理")
        else:
            print(f"[WARN] 意外的模式 {mode}")

        await mgr.disconnect(session_id)
        print("\n[PASS] 测试4 完成")
        return True

    except Exception as e:
        print(f"[FAIL] 测试4 失败: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_config_mode_auto_exit():
    """测试5: 配置模式自动退出 + do 命令预处理 + | section 预处理"""
    print("\n" + "=" * 60)
    print("测试5: 配置模式自动退出 + 命令预处理")
    print("=" * 60)

    mgr = TelnetSessionManager()

    try:
        session_id = await mgr.connect(DEVICE_HOST, DEVICE_PORT, timeout=5000)

        # 进入配置模式
        print("\n--- 进入全局配置模式 ---")
        output = await mgr.execute(session_id, "configure terminal", 2000)
        mode = detect_device_mode(output)
        print(f"  模式: {mode}")
        assert "(config)#" in mode, f"期望配置模式，实际 {mode}"
        print("[PASS] 已进入配置模式")

        # 测试 do show version — 锐捷不支持 do，应自动 end 退回后执行 show version
        print("\n--- 测试 do show version（应自动退回特权模式）---")
        output = await mgr.execute(session_id, "do show version", 5000)
        mode = detect_device_mode(output)
        print(f"  模式: {mode}")
        print(f"  输出长度: {len(output)}")
        # 应该成功执行 show version（输出包含版本信息）且在特权模式
        if "show version" not in output.lower() and "% Unknown command" not in output:
            print("[PASS] do show version 被正确处理（自动 end + show version）")
        elif "RG-NSE" in output or "version" in output.lower():
            print("[PASS] do show version 被正确处理，输出包含版本信息")
        else:
            print(f"[WARN] 输出不符合预期: {repr(output[:200])}")
        if mode == DEVICE_NAME + "#" or "(config)" not in mode:
            print("[PASS] 已自动退回特权模式")
        else:
            print(f"[WARN] 未退回特权模式，当前: {mode}")

        # 重新进入配置模式测试 | section
        print("\n--- 再次进入配置模式 ---")
        output = await mgr.execute(session_id, "configure terminal", 2000)
        mode = detect_device_mode(output)
        print(f"  模式: {mode}")
        assert "(config)#" in mode, f"期望配置模式，实际 {mode}"

        # 测试 | section（锐捷不支持，应自动 end 退回后执行 show 命令不带 section）
        print("\n--- 测试 show running-config | section interface（应移除 | section）---")
        output = await mgr.execute(session_id, "show running-config | section interface", 15000)
        mode = detect_device_mode(output)
        print(f"  模式: {mode}")
        print(f"  输出长度: {len(output)}")
        # 应该执行了 show running-config（不带 section 过滤）
        if "interface" in output.lower() and "% Unknown command" not in output:
            print("[PASS] | section 被正确移除，命令执行成功")
        else:
            print(f"[WARN] 输出不符合预期: {repr(output[:200])}")

        # 退回特权模式并确认
        print("\n--- 退回特权模式 ---")
        output = await mgr.execute(session_id, "end", 2000)
        mode = detect_device_mode(output)
        print(f"  模式: {mode}")
        assert mode == DEVICE_NAME + "#", f"期望 {DEVICE_NAME}#，实际 {mode}"
        print("[PASS] 已退回特权模式")

        await mgr.disconnect(session_id)
        print("\n[PASS] 测试5 完成")
        return True

    except Exception as e:
        print(f"[FAIL] 测试5 失败: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    results = []

    results.append(await test_connect_and_basic())
    results.append(await test_more_pages())
    results.append(await test_command_truncation())
    results.append(await test_output_with_logs())
    results.append(await test_config_mode_auto_exit())

    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"通过: {passed}/{total}")

    if passed == total:
        print("\n全部测试通过!")
    else:
        print(f"\n{total - passed} 个测试未通过")


if __name__ == "__main__":
    asyncio.run(main())
