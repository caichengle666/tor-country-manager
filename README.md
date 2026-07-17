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
- 多个国家在线时可立即切换统一 SOCKS5 入口的当前出口，无需重建实例
- 出口 IP 自动检测
- Web 卡片显示 Tor 启动进度；节点目录支持强制刷新并保留上次成功数据
- 每个国家独立的数据目录和日志
- 常驻实例数量上限及最久未使用实例自动淘汰
- 正式 Tor 实例意外退出时自动重启，连续失败最多重试 3 次
- 每分钟检查在线国家的实际 Tor 链路；连续失败 3 次时自动切换同国家备用节点
- 公共 `/healthz` 返回在线国家、出口 IP、链路延迟、节点延迟、连接数和自动切换记录
- 可选管理令牌认证
- 首次使用设置Web管理员密码，后续使用安全会话登录；同一 IP 连续失败 5 次会锁定 5 分钟
- 管理页面可修改上游SOCKS5地址、用户名和密码
- 管理页面可设置最多同时在线国家数（1～32）和电路轮换间隔，保存后立即生效
- 客户端API可从一个或多个候选国家中自动选择最低延迟出口
- 每个国家具有重启后不变的独立SOCKS5端口，并使用API密钥认证
- API密钥保存后立即生效；切换节点时先验证新Tor实例，再切流并排空旧连接

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

管理员密码以 PBKDF2-SHA256 加盐哈希保存在状态目录的 `web-password.hash`，不会以明文写入配置。上游 SOCKS5 密码和客户端API密钥保存在 `config.json`，请限制该文件的读取权限。通过Web修改上游代理或客户端API密钥会立即生效；监听地址和客户端入口端口仍需重启。也可以使用环境变量 `TOR_CLIENT_API_KEY` 注入客户端密钥，此时环境变量不会写回配置文件。
已启动国家和已选出口节点保存在状态目录的 `runtime-state.json`。管理器重启后会自动恢复这些路线；手动停止国家或因在线数量限制被停止时，会从恢复列表移除。

电路轮换通过 Tor ControlPort 的 `SIGNAL NEWNYM` 完成，只影响后续新电路，不会强制中断现有 TCP 连接。请确保状态目录仅允许管理器运行用户读写，因为 ControlPort 的认证 cookie 保存在每个实例的数据目录中。

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

## 客户端多国家自动选择

先在Web管理设置中生成客户端API密钥。查询当前可选国家：

```bash
curl -H "Authorization: Bearer API密钥" \
  http://127.0.0.1:8080/api/v1/countries
```

从美国、日本、新加坡中自动选择TCP延迟最低的节点：

```bash
curl -X POST -H "Authorization: Bearer API密钥" \
  -H "Content-Type: application/json" \
  -d '{"countries":["us","jp","sg"],"policy":"lowest_latency"}' \
  http://127.0.0.1:8080/api/v1/routes
```

按填写顺序故障转移可将策略改为 `failover`。返回结果中的 `socks5_address` 是该国家的固定入口；SOCKS5用户名为国家代码，密码为同一个客户端API密钥。首次启动通常会返回 `ready: false`，客户端应查询状态，直到 `ready: true`：

```bash
curl -H "Authorization: Bearer API密钥" \
  http://127.0.0.1:8080/api/v1/routes/us

curl --proxy-user 'us:API密钥' \
  --socks5-hostname 127.0.0.1:20538 \
  https://check.torproject.org/api/ip
```

固定端口按两位国家代码计算，默认范围为 `20000-20675`。例如美国 `us` 为 `20538`，日本 `jp` 为 `20249`。统一入口 `1080` 仍跟随Web当前出口，不受客户端API选择影响。

## 健康检查与自动恢复

无需登录即可读取详细健康状态：

```bash
curl http://127.0.0.1:8080/healthz
```

响应包含所有在线和故障国家；`online_countries` 与 `failed_countries` 分别统计数量。每个国家返回实际 Tor 链路延迟 `latency_ms`、出口节点 TCP 延迟 `node_tcp_latency_ms`、出口 IP、活动连接数、连续失败次数和最近自动切换记录。Tor进程重启达到上限的实例会以 `status: "error"` 和 `last_error` 保留在报告中。管理器每60秒并行检查一次；单个国家连续失败3次时，会排除当前节点并启动同国家备用节点，确认新线路可用后再切流和排空旧连接。切换失败后冷却10分钟，旧线路会保留。

当多个在线国家在同一轮检查中全部失败时，`global_failure` 会变为 `true`，并暂停自动换节点。这通常表示本机网络或上游代理整体不可用，换出口节点无法解决。

`/healthz` 是公共只读接口，不要求Web登录。默认仅监听 `127.0.0.1`；如果将Web端口暴露到公网，在线国家与出口IP也会公开。

查看服务：

```bash
sudo systemctl status tor-country-manager
sudo journalctl -u tor-country-manager -f
```

默认允许同时保持 `10` 个国家实例在线。达到上限后，选择新国家会停止最早启动且当前未使用的实例。10个实例建议至少准备2GB内存；1GB服务器建议将 `max_running` 调低到 `5` 到 `7`。

可写配置位于 `/var/lib/tor-country-manager/config.json`，仅允许 `tor-manager` 服务用户访问。Web管理页面修改在线数量、电路轮换、上游代理或客户端API密钥后会写入该文件并立即应用。只有监听地址和客户端入口端口发生变化时才需要重启服务。

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

配置既可以保存在命名卷中，也可以把宿主机的单个 `config.json` 绑定到 `/data/config.json`。管理页面兼容这两种挂载方式；单文件绑定挂载无法使用文件替换操作，程序会自动改为同步写回挂载文件。

节点切换不会立即关闭旧Tor实例。新实例确认出口可用后，新连接切换到新实例；旧连接最长保留 `drain_timeout_seconds`（默认120秒），连接提前结束时会立即回收旧实例。API密钥保存后立即用于API和新SOCKS5连接，旧密钥随即失效。监听地址和基础端口的改变仍需要重启，因为它们涉及操作系统监听套接字。

不要把 `1080` 端口无认证地映射到公网。

Docker如需使用国家入口，应只映射实际需要的端口，例如美国和日本：

```yaml
ports:
  - "127.0.0.1:20538:20538"
  - "127.0.0.1:20249:20249"
```

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
