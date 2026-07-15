#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 sudo 运行此安装脚本" >&2
  exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
BINARY=${1:-"$PROJECT_DIR/dist/tor-country-manager-linux-amd64"}

if [ ! -f "$BINARY" ]; then
  echo "找不到可执行文件：$BINARY" >&2
  exit 1
fi

apt-get update
apt-get install -y --no-install-recommends tor tor-geoipdb ca-certificates

if ! getent passwd tor-manager >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/tor-country-manager \
    --shell /usr/sbin/nologin tor-manager
fi

# The distro's default client is not used; this manager starts its own instances.
systemctl disable --now tor@default.service >/dev/null 2>&1 || true

install -m 0755 "$BINARY" /usr/local/bin/tor-country-manager
install -d -o tor-manager -g tor-manager -m 0750 /var/lib/tor-country-manager
CONFIG=/var/lib/tor-country-manager/config.json
if [ ! -f "$CONFIG" ]; then
  if [ -f /etc/tor-country-manager/config.json ]; then
    install -o tor-manager -g tor-manager -m 0640 \
      /etc/tor-country-manager/config.json "$CONFIG"
    echo "已将旧配置迁移到 $CONFIG"
  else
    install -o tor-manager -g tor-manager -m 0640 \
      "$PROJECT_DIR/config.example.json" "$CONFIG"
  fi
fi
chown tor-manager:tor-manager "$CONFIG"
chmod 0640 "$CONFIG"
install -m 0644 "$SCRIPT_DIR/tor-country-manager.service" /etc/systemd/system/tor-country-manager.service
systemctl daemon-reload
systemctl enable --now tor-country-manager.service

echo "安装完成。"
echo "首次打开Web页面时，请设置至少8位的管理员密码。"
echo "Web 界面仅监听 127.0.0.1:8080，建议通过 SSH 隧道访问。"
echo "ssh -L 8080:127.0.0.1:8080 -L 1080:127.0.0.1:1080 用户名@服务器IP"
