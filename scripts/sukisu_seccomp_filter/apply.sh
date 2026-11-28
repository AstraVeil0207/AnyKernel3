#!/usr/bin/env bash
# SukiSU-Nova builtin 分支 seccomp 过滤模式补丁
#
# 背景:
#   builtin 在 app 启动路径 (kernel/hook/setuid_hook.c) 对管理器与授权应用
#   直接调用 disable_seccomp(), 管理器进程自身的 seccomp 过滤器被清除,
#   管理器首页 "Seccomp 状态" 显示"未启用"。main 分支 / BakaSU 的实现是
#   保留过滤器 ("过滤模式"), 仅通过 seccomp action cache 放行 reboot。
#   上游 builtin 的注释明确说明它没有这个实现, 因此需要本地补齐。
#
# 处理:
#   1. 分发 infra/seccomp_cache.{h,c} (与 main 分支同源, 额外带 5.10 版本守卫,
#      因为 action cache 在更早的内核中不存在);
#   2. 调用 patch_setuid_hook.py 改写 5 处 disable_seccomp() 调用点, 并把
#      seccomp_cache 接入 core/unity.h (builtin 为单编译单元)。
#
# 守卫: 按 setuid_hook.c 中是否已含 ksu_seccomp_allow_cache 判断,
#       重复执行幂等。
#
# 用法: apply.sh [KernelSU 目录]（调用方工作目录需为 $KERNEL_ROOT）

set -eo pipefail

KSU_DIR="${1:-KernelSU}"

fail() {
  echo "::error::$1"
  exit 1
}

[ -d "$KSU_DIR" ] || fail "未找到 KernelSU 目录: $KSU_DIR"

COMPAT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SETUID_FILE="$KSU_DIR/kernel/hook/setuid_hook.c"
UNITY_FILE="$KSU_DIR/kernel/core/unity.h"

# main 分支已内置过滤模式, 上游 builtin 后续跟进后同样自动跳过。
if [ -f "$SETUID_FILE" ] && grep -q 'ksu_seccomp_allow_cache' "$SETUID_FILE"; then
  echo "setuid_hook.c 已包含 seccomp 过滤模式逻辑，跳过"
  exit 0
fi

[ -f "$SETUID_FILE" ] || fail "未找到 $SETUID_FILE，SukiSU-Nova 结构可能已变化"
[ -f "$UNITY_FILE" ] || fail "未找到 $UNITY_FILE，SukiSU-Nova 结构可能已变化"
[ -d "$KSU_DIR/kernel/infra" ] || fail "未找到 $KSU_DIR/kernel/infra 目录，SukiSU-Nova 结构可能已变化"

cp "$COMPAT_DIR/seccomp_cache.h" "$KSU_DIR/kernel/infra/seccomp_cache.h" \
  || fail "seccomp_cache.h 分发失败"
cp "$COMPAT_DIR/seccomp_cache.c" "$KSU_DIR/kernel/infra/seccomp_cache.c" \
  || fail "seccomp_cache.c 分发失败"

python3 "$COMPAT_DIR/patch_setuid_hook.py" "$KSU_DIR" \
  || fail "seccomp 过滤模式补丁应用失败（SukiSU-Nova builtin 上游代码可能已变化）"

grep -q 'ksu_seccomp_allow_cache' "$SETUID_FILE" \
  || fail "seccomp 过滤模式补丁应用后校验失败 (setuid_hook.c)"
grep -q '#include "infra/seccomp_cache.c"' "$UNITY_FILE" \
  || fail "seccomp 过滤模式补丁应用后校验失败 (core/unity.h)"
grep -q '#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)' "$KSU_DIR/kernel/infra/seccomp_cache.c" \
  || fail "seccomp_cache.c 版本守卫校验失败"

echo "seccomp 过滤模式已启用：管理器首页 Seccomp 状态将显示\"过滤模式\""
