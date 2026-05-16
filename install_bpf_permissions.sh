#!/bin/bash
# install_bpf_permissions.sh
# 
# 安装 BPF 设备权限守护进程，使 access_bpf 组的用户可以抓包。
# 效果等同于 Wireshark.app 的 "Install ChmodBPF" 功能。
#
# 使用方法（需要管理员权限，只需执行一次）：
#   sudo ./install_bpf_permissions.sh
#
# 安装后重启或执行 sudo launchctl load /Library/LaunchDaemons/dev.gowireshark.ChmodBPF.plist 即可生效。

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "❌ 需要 root 权限，请使用: sudo $0"
    exit 1
fi

PLIST_PATH="/Library/LaunchDaemons/dev.gowireshark.ChmodBPF.plist"
GROUP="access_bpf"

# 确保 access_bpf 组存在
if ! dscl . -read /Groups/$GROUP &>/dev/null; then
    echo "创建 $GROUP 组..."
    dseditgroup -o create -q $GROUP
fi

# 确保当前用户在组里
REAL_USER="${SUDO_USER:-$(whoami)}"
if ! dseditgroup -o checkmember -m "$REAL_USER" $GROUP &>/dev/null; then
    echo "将 $REAL_USER 添加到 $GROUP 组..."
    dseditgroup -o edit -a "$REAL_USER" -t user $GROUP
fi

# 创建 LaunchDaemon plist
cat > "$PLIST_PATH" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.gowireshark.ChmodBPF</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>chgrp access_bpf /dev/bpf* &amp;&amp; chmod g+rw /dev/bpf*</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/ChmodBPF.log</string>
</dict>
</plist>
PLIST

chmod 644 "$PLIST_PATH"
chown root:wheel "$PLIST_PATH"

# 立即加载
launchctl load "$PLIST_PATH"

# 立即执行一次
chgrp access_bpf /dev/bpf* && chmod g+rw /dev/bpf*

echo ""
echo "✅ BPF 权限已配置完成！"
echo "   - 用户 $REAL_USER 已在 $GROUP 组"
echo "   - /dev/bpf* 设备已设置为组可读写"
echo "   - LaunchDaemon 已安装（重启后自动生效）"
echo ""
echo "现在可以直接使用 gowireshark-mcp 的实时抓包功能了。"
