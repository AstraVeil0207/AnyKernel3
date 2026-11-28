#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""builtin 分支 seccomp 过滤模式改造脚本。

背景:
  SukiSU-Nova builtin 分支在 app 启动路径 (kernel/hook/setuid_hook.c)
  对管理器与授权应用直接调用 disable_seccomp(), 导致管理器进程自身的
  seccomp 过滤器被清除, 管理器首页 "Seccomp 状态" 显示"未启用"。
  main 分支 / BakaSU 的对应实现是: 保留过滤器 ("过滤模式"), 仅通过
  seccomp action cache 放行 reboot。

处理:
  1. kernel/hook/setuid_hook.c: 6 处 disable_seccomp() 调用点改写为
     ">=5.10 保留过滤器并放行 reboot / <5.10 维持 disable_seccomp()"
     (seccomp action cache 由 GKI 5.10+ 内核 backport, 与 BakaSU 一致)。
  2. kernel/core/unity.h (builtin 为单编译单元, 该清单决定 include 顺序):
     在 infra/event_queue 之后接入 infra/seccomp_cache.{h,c},
     使其先于 hook/setuid_hook.c 编译。

所有替换严格校验命中次数, 上游代码变化时报错退出 (幂等可重入)。
用法: python3 patch_setuid_hook.py <KernelSU 目录>
"""

import re
import sys
from pathlib import Path

# 保留过滤器时的替换块 (与 main 分支 setuid_hook.c 写法一致,
# 额外加 5.10 版本守卫, 因为 action cache 在更早的内核中不存在)
CACHE_BLOCK = (
    "#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)\n"
    "\t\tif (current->seccomp.mode == SECCOMP_MODE_FILTER && current->seccomp.filter) {\n"
    "\t\t\tspin_lock_irq(&current->sighand->siglock);\n"
    "\t\t\tksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);\n"
    "\t\t\tspin_unlock_irq(&current->sighand->siglock);\n"
    "\t\t}\n"
    "#else\n"
    "\t\tdisable_seccomp();\n"
    "#endif"
)

# (匹配正则, 预期命中次数, 说明)。上游源码使用 Tab 缩进。
# SUSFS 路径: handle_zygote_setresuid / handle_zygote_next_setresuid
#             各 1 处管理器 + 1 处授权应用
SETUID_RULES = [
    (re.compile(
        r'(if \(likely\(ksu_is_manager_appid_valid\(\)\) && unlikely\(is_uid_manager\(ruid\)\)\) \{\n)'
        r'\t\tdisable_seccomp\(\);'),
     2, "SUSFS 管理器分支"),
    (re.compile(
        r'(if \(ksu_is_allow_uid_for_current\(ruid\)\) \{\n)'
        r'\t\tdisable_seccomp\(\);'),
     2, "SUSFS 授权应用分支"),
]

# 非 SUSFS 路径 ksu_handle_setresuid_cred: 管理器 (goto install_ksu_fd) 与
# 授权应用 (goto kill_seccomp) 最终都落入 kill_seccomp 标签, 由该处 1 个调用
# 统一执行 disable_seccomp(); 改写该调用即可同时覆盖两种情况。
SETUID_LABEL = (
    re.compile(
        r'(kill_seccomp:\n)'
        r'\tdisable_seccomp\(\);\n'
        r'(\tset_thread_flag\(TIF_KSU_MANAGED\);)'),
    1, "非 SUSFS 路径汇聚标签",
)

UNITY_HEADER_ANCHOR = re.compile(r'(#include "infra/event_queue\.h"\n)')
UNITY_SOURCE_ANCHOR = re.compile(r'(#include "infra/event_queue\.c"\n)')
SECCOMP_HEADER = '#include "infra/seccomp_cache.h"\n'
SECCOMP_SOURCE = '#include "infra/seccomp_cache.c"\n'


def patch_setuid_hook(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    if "ksu_seccomp_allow_cache" in text:
        print(f"{path.name}: 已包含 seccomp 过滤模式逻辑，跳过")
        return

    total = 0
    for pattern, expected, name in SETUID_RULES:
        text, n = pattern.subn(lambda m: m.group(1) + CACHE_BLOCK, text)
        if n != expected:
            sys.exit(f"::error::setuid_hook.c {name} 命中 {n} 处 (预期 {expected})，"
                     f"SukiSU-Nova builtin 上游代码可能已变化，请更新补丁")
        total += n

    # 非 SUSFS 路径: 两条 goto 都汇入 kill_seccomp 标签, 改写该处调用即覆盖全部。
    label_pattern = SETUID_LABEL[0]
    text, n = label_pattern.subn(lambda m: m.group(1) + CACHE_BLOCK + "\n" + m.group(2), text)
    if n != 1:
        sys.exit(f"::error::setuid_hook.c 非 SUSFS 路径汇聚标签命中 {n} 处 (预期 1)，"
                 f"SukiSU-Nova builtin 上游代码可能已变化，请更新补丁")
    total += 1

    if SECCOMP_HEADER not in text:
        text = SECCOMP_HEADER + text
    path.write_text(text, encoding="utf-8")
    print(f"setuid_hook.c: 已改写 {total} 处 disable_seccomp() 调用点为过滤模式")


def patch_unity(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    changed = False
    if SECCOMP_HEADER not in text:
        text, n = UNITY_HEADER_ANCHOR.subn(lambda m: m.group(1) + SECCOMP_HEADER, text)
        if n != 1:
            sys.exit("::error::unity.h 未找到 infra/event_queue.h 头文件锚点，"
                     "SukiSU-Nova builtin 上游代码可能已变化，请更新补丁")
        changed = True
    if SECCOMP_SOURCE not in text:
        text, n = UNITY_SOURCE_ANCHOR.subn(lambda m: m.group(1) + SECCOMP_SOURCE, text)
        if n != 1:
            sys.exit("::error::unity.h 未找到 infra/event_queue.c 源文件锚点，"
                     "SukiSU-Nova builtin 上游代码可能已变化，请更新补丁")
        changed = True
    path.write_text(text, encoding="utf-8")
    if changed:
        print("unity.h: 已接入 infra/seccomp_cache.{h,c}（先于 hook/setuid_hook.c 编译）")
    else:
        print("unity.h: 已包含 infra/seccomp_cache 接入，跳过")


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(f"用法: {sys.argv[0]} <KernelSU 目录>")
    kdir = Path(sys.argv[1])
    setuid = kdir / "kernel" / "hook" / "setuid_hook.c"
    unity = kdir / "kernel" / "core" / "unity.h"
    if not setuid.is_file() or not unity.is_file():
        sys.exit(f"::error::未找到 {setuid} 或 kernel/core/unity.h，"
                 "SukiSU-Nova builtin 目录结构可能已变化")
    patch_unity(unity)
    patch_setuid_hook(setuid)


if __name__ == "__main__":
    main()
