# Tor Country Manager

[![Build releases](https://github.com/caichengle666/tor-country-manager/actions/workflows/build.yml/badge.svg)](https://github.com/caichengle666/tor-country-manager/actions/workflows/build.yml)
[![Build Docker image](https://github.com/caichengle666/tor-country-manager/actions/workflows/docker.yml/badge.svg)](https://github.com/caichengle666/tor-country-manager/actions/workflows/docker.yml)

面向 Ubuntu 的轻量 Tor 国家出口管理器。它不修改 Tor 协议或 Tor 核心源码，而是管理多个独立客户端实例，并提供：

- 中文 Web 管理页面
- 按国家启动、停止和切换 Tor 出口
- 自动读取当前运行中的 Tor 出口节点，只显示有可用节点的国家
- 按洲展示国家，并显示每个国家的节点数量
- 展开国家后按 TCP 握手延迟排序具体出口 IP
- 使用 Tor 节点指纹锁定用户选择的出口 IP
- 一个固定的 SOCKS5 入口，新连接转发至当前所选国家
- 出口 IP 自动检测
- 每个国家独立的数据目录和日志
- 常驻实例数量上限及最久未使用实例自动淘汰
- 可选管理令牌认证
- 首次使用设置Web管理员密码，后续使用安全会话登录
- 管理页面可修改上游SOCKS5地址、用户名和密码

本项目与 The Tor Project 没有隶属或背书关系。Tor程序和相关组件继续使用它们各自的许可证。

## GitHub 自动构建

每次推送到 `main` 都会自动测试并生成以下构建产物：

- Windows x64
- Linux x64 / ARM64
- macOS Intel / Apple Silicon
- Docker linux/amd64 / linux/arm64

推送形如 `v1.0.0` 的标签时，GitHub会自动创建Release并附加所有二进制文件和SHA-256校验表。Docker镜像发布到：

```text
ghcr.io/caichengle666/tor-country-manager:latest
```

## 安全模型

Web 页面和 SOCKS5 代理默认只监听 `127.0.0.1`。不要把无认证 SOCKS5 端口或 Tor 内部端口直接暴露到公网。远程使用时推荐 SSH 隧道或 VPN。

管理员密码以 PBKDF2-SHA256 加盐哈希保存在状态目录的 `web-password.hash`，不会以明文写入配置。上游 SOCKS5 密码按用户要求保存在 `config.json`，请限制该文件的读取权限。通过Web修改代理配置后需要重启管理器才能生效。

切换国家只影响新连接，现有 TCP 连接不会被迁移。`ExitNodes` 和 GeoIP 分类不保证某个国家始终有可用出口，也不保证地理信息绝对准确。

## Ubuntu 构建

需要 Go 1.22 或更高版本：

```bash
cd manager
mkdir -p dist
CGO_ENABLED=0 go test ./...
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
  -o dist/tor-country-manager-linux-amd64 .
```

## Ubuntu 安装

```bash
cd manager
sudo sh deploy/install.sh
```

安装脚本会安装 `tor`、`tor-geoipdb` 和必要证书，生成随机管理令牌，并创建 systemd 服务。

## 连接

在本地电脑建立隧道：

```bash
ssh -L 8080:127.0.0.1:8080 \
    -L 1080:127.0.0.1:1080 用户名@服务器IP
```

打开 `http://127.0.0.1:8080`，填入安装时显示的管理令牌，选择国家。应用程序使用 SOCKS5 代理 `127.0.0.1:1080`。

测试：

```bash
curl --socks5-hostname 127.0.0.1:1080 https://check.torproject.org/api/ip
```

查看服务：

```bash
sudo systemctl status tor-country-manager
sudo journalctl -u tor-country-manager -f
```

1GB 内存的服务器建议将 `max_running` 保持在 `5` 到 `7`。达到上限后，选择新国家会停止最早启动且当前未使用的实例。

可写配置位于 `/var/lib/tor-country-manager/config.json`，仅允许 `tor-manager` 服务用户访问。Web管理页面修改上游代理时会写入该文件。修改后执行：

```bash
sudo systemctl restart tor-country-manager
```

## Docker

Docker默认只将Web和SOCKS5端口绑定到宿主机本地地址：

```bash
docker compose up -d
```

打开 `http://127.0.0.1:8080`，首次使用设置管理员密码。应用数据和可写配置保存在Docker命名卷中：

```bash
docker compose logs -f
docker compose down
```

不要把 `1080` 端口无认证地映射到公网。

## macOS

先安装Tor：

```bash
brew install tor
cp deploy/macos/config.example.json config.json
```

Apple Silicon默认使用 `/opt/homebrew`。Intel Mac需要将 `config.json` 中的Tor和GeoIP路径改为 `/usr/local`，然后运行对应架构的GitHub构建产物：

```bash
chmod +x tor-country-manager-macos-arm64
./tor-country-manager-macos-arm64 -config config.json
```
