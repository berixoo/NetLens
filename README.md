# NetLens

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/PySide6-6.5+-green?style=for-the-badge&logo=qt&logoColor=white" alt="PySide6">
  <img src="https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="Windows">
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License">
</p>

<p align="center">
  <b>局域网代理服务暴露检测工具</b><br>
  支持校园网级大规模扫描、两阶段主机发现、系统代理切换、代理记忆
</p>

---

## 功能特性

| 功能 | 说明 |
|------|------|
| **两阶段校园网扫描** | 先快速发现存活主机，再深度扫描代理端口，支持 /16 级网段 |
| **多线程端口扫描** | 线程池 1-256 可调，默认 128 线程并发 |
| **协议自动识别** | HTTP CONNECT、SOCKS4、SOCKS5，附带 banner 抓取 |
| **代理连通性验证** | 通过代理实际转发流量到 httpbin.org，确认可用性 |
| **系统代理切换** | 一键应用到 Windows 系统代理（注册表 + wininet 广播），支持关闭 |
| **代理记忆** | 自动保存已验证代理到 `proxy_memory.json`，支持重新测试连通性 |
| **扫描汇总弹窗** | 扫描结束后统一展示所有发现的代理，用户选择应用哪个 |
| **风险等级评估** | CRITICAL / HIGH / MEDIUM / LOW / INFO 五级分类 |
| **多种目标格式** | 单 IP、CIDR、短横线范围、逗号分隔列表、文件导入 |
| **导出报告** | CSV、JSON、纯文本日志 |
| **暗色主题 UI** | Catppuccin Mocha 配色 |

## 快速开始

```bash
# 克隆仓库
git clone https://github.com/berixoo/NetLens.git
cd NetLens

# 安装依赖
pip install -r requirements.txt

# 启动
python app.py
```

## 扫描模式

| 模式 | 范围 | 适用场景 |
|------|------|----------|
| 本机子网 | /24（254 台） | 当前所在子网 |
| 校园网段 | /16（65534 台） | 整栋楼 / 整个校区网段 |
| 自定义 | 用户输入 | 任意 IP 列表、CIDR 或范围 |

超过 256 台主机时自动启用两阶段扫描：

```
Phase 1 — 发现（~1s/主机）
  探测端口: 443, 80, 22, 8080
  超时: 1 秒
  输出: 存活主机列表

Phase 2 — 深度扫描
  仅扫描存活主机的全部代理端口
  协议识别 + banner + 连通性验证
```

## 默认代理端口

| 端口 | 常见服务 |
|------|----------|
| 7890 | Clash HTTP |
| 7891 | Clash SOCKS5 |
| 1080 | 通用 SOCKS |
| 10808 | V2Ray / Xray HTTP |
| 10809 | V2Ray / Xray SOCKS5 |
| 8080 | 通用 HTTP |
| 8118 | Privoxy |
| 3128 | Squid |

## 界面操作

1. **选择扫描模式** — 下拉框选择 本机子网 / 校园网段 / 自定义
2. **点击「校园扫描」** — 一键扫描校园网段，自动开启两阶段模式
3. **检测到代理后弹窗** — 选择「使用此代理」设为系统代理，或「跳过并继续扫描」
4. **已保存代理** — 点击按钮查看历史记录，一键应用或删除
5. **导出** — 点击导出 CSV / JSON / 日志

## 代理记忆

扫描发现的代理自动保存到 `proxy_memory.json`：

```json
{
  "ip": "10.16.88.217",
  "port": 7890,
  "proxy_type": "HTTP",
  "latency_ms": 16.0,
  "use_count": 3,
  "success_count": 2
}
```

下次启动点击「已保存代理」即可直接使用，无需重新扫描。

## 项目结构

```
NetLens/
├── app.py                      # 启动入口
├── requirements.txt
├── proxy_memory.json           # 代理记忆（自动生成，已 gitignore）
├── src/
│   ├── core/
│   │   ├── protocol.py         # HTTP/SOCKS4/SOCKS5 协议检测
│   │   ├── scanner.py          # 两阶段扫描引擎
│   │   └── reporter.py         # 风险评估、CSV/JSON/日志导出
│   ├── ui/
│   │   └── main_window.py      # PySide6 界面
│   └── utils/
│       ├── logger.py           # 线程安全日志
│       ├── network.py          # IP 解析、CIDR、校园网发现
│       ├── proxy_memory.py     # 代理记忆持久化
│       └── proxy_switch.py     # Windows 系统代理控制
└── logs/                       # 扫描日志（自动生成，已 gitignore）
```

## 风险等级

| 等级 | 含义 |
|------|------|
| CRITICAL | 开放无认证代理，已验证可达 |
| HIGH | 检测到开放无认证代理 |
| MEDIUM | 需认证的代理或无法识别的服务 |
| LOW | 开放端口但非代理服务 |
| INFO | 端口关闭或不可达 |

## 系统要求

- Python 3.10+
- Windows 10/11（代理切换功能依赖注册表和 wininet）
- 管理员权限（设置系统代理时需要）

## License

MIT
