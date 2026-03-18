# zai-proxy

zai-proxy 是一个基于 Go 语言的代理服务，将 z.ai 网页聊天转换为 OpenAI API 和 Anthropic Messages API 兼容格式。用户使用自己的 z.ai token 进行调用。

## 功能特性

- **双 API 支持**：OpenAI API 和 Anthropic Messages API 兼容格式
- **流式响应**：支持流式和非流式响应
- **多模型支持**：GLM-5、GLM-4.7、GLM-4.6、GLM-4.5 等多种模型
- **思考模式**：支持 thinking 模式，返回推理过程
- **联网搜索**：支持 search 和 deepsearch 模式
- **多模态输入**：支持图片输入（URL 和 Base64）
- **工具调用**：Anthropic API 支持 Toolify 风格的 XML 工具调用
- **匿名访问**：支持免登录的匿名 Token
- **代理池**：支持 HTTP/HTTPS/SOCKS5 代理池，自动健康检查和故障转移
- **自动签名**：自动生成和更新 z.ai 签名

## 快速开始

### 安装运行

```bash
# 克隆项目
git clone https://github.com/kao0312/zai-proxy.git
cd zai-proxy

# 安装依赖
go mod download

# 运行服务
go run main.go
```

### Docker 一键部署

```bash
docker run -d -p 8000:8000 ghcr.io/kao0312/zai-proxy:latest
```

自定义端口和日志级别：

```bash
docker run -d -p 8080:8000 -e LOG_LEVEL=debug ghcr.io/kao0312/zai-proxy:latest
```

## 环境变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| PORT | 监听端口 | 8000 |
| LOG_LEVEL | 日志级别（debug/info/warn/error） | info |
| PROXY_FILE | 代理列表文件路径（可选） | - |

## 获取 z.ai Token

### 方式一：使用匿名 Token（免登录）

直接使用 `free` 作为 API key，服务会自动获取一个匿名 token：

```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer free" \
  -H "Content-Type: application/json" \
  -d '{"model": "GLM-4.6", "messages": [{"role": "user", "content": "hello"}]}'
```

### 方式二：使用个人 Token

1. 登录 https://chat.z.ai
2. 打开浏览器开发者工具 (F12)
3. 切换到 Application/Storage 标签
4. 在 Cookies 中找到 `token` 字段
5. 复制其值作为 API 调用的 Authorization

## API 端点

| 端点 | 说明 |
|------|------|
| `/v1/chat/completions` | OpenAI 兼容的聊天完成接口 |
| `/v1/messages` | Anthropic Messages API 兼容接口 |
| `/v1/models` | 获取可用模型列表 |

## 支持的模型

| 模型名称 | 上游模型 | 说明 |
|----------|----------|------|
| GLM-5 | glm-5 | 最新旗舰模型 |
| GLM-4.7 | glm-4.7 | 高性能模型 |
| GLM-4.6 | GLM-4-6-API-V1 | 稳定版本 |
| GLM-4.5 | 0727-360B-API | 经典版本 |
| GLM-4.5-Air | 0727-106B-API | 轻量版本 |
| GLM-5-V | glm-5v | 多模态视觉模型 |
| GLM-4.6-V | glm-4.6v | 多模态视觉模型 |
| GLM-4.5-V | glm-4.5v | 多模态视觉模型 |

### 模型标签

模型名称支持以下后缀标签（可组合使用）：

- `-thinking`: 启用思考模式，响应会包含推理过程
- `-search`: 启用联网搜索模式
- `-deepsearch`: 启用深度搜索模式（自动包含 search）

示例：
- `GLM-5-thinking`
- `GLM-5-search`
- `GLM-5-deepsearch-thinking`
- `GLM-4.7-thinking-search`

## 使用示例

### OpenAI API 格式

```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer YOUR_ZAI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "GLM-5",
    "messages": [{"role": "user", "content": "hello"}],
    "stream": true
  }'
```

### Anthropic Messages API 格式

```bash
curl http://localhost:8000/v1/messages \
  -H "x-api-key: YOUR_ZAI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "GLM-5",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "hello"}]
  }'
```

### 思考模式示例

```bash
curl http://localhost:8000/v1/messages \
  -H "x-api-key: YOUR_ZAI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "GLM-5",
    "max_tokens": 2048,
    "thinking": {"type": "enabled", "budget_tokens": 1000},
    "messages": [{"role": "user", "content": "解释量子纠缠"}]
  }'
```

### 工具调用示例（Anthropic API）

```bash
curl http://localhost:8000/v1/messages \
  -H "x-api-key: YOUR_ZAI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "GLM-5",
    "max_tokens": 1024,
    "tools": [{
      "name": "get_weather",
      "description": "获取天气信息",
      "input_schema": {
        "type": "object",
        "properties": {
          "location": {"type": "string", "description": "城市名称"}
        },
        "required": ["location"]
      }
    }],
    "messages": [{"role": "user", "content": "北京天气怎么样？"}]
  }'
```

### 多模态请求

```json
{
  "model": "GLM-5-V",
  "messages": [
    {
      "role": "user",
      "content": [
        {"type": "text", "text": "描述这张图片"},
        {"type": "image_url", "image_url": {"url": "https://example.com/image.jpg"}}
      ]
    }
  ]
}
```

支持的图片格式：
- HTTP/HTTPS URL
- Base64 编码 (data:image/jpeg;base64,...)

## 代理池配置

创建代理列表文件（例如 `proxies.txt`），每行一个代理：

```
http://user:pass@proxy1.example.com:8080
socks5://proxy2.example.com:1080
http://10.0.0.1:3128
```

设置环境变量：

```bash
export PROXY_FILE=/path/to/proxies.txt
```

代理池特性：
- 自动健康检查（每 30 秒）
- 故障自动转移
- 支持 HTTP/HTTPS/SOCKS5 协议
- 失败代理冷却时间 60 秒
- 最多重试 3 次
