# 喵喵派协议调用示例

## 介绍

本库是用于喵喵派协议调用示例

目前喵喵派默认有3个协议，通讯全程使用加密，请自行切换分支来获取。

# 协议优缺点对比

| 协议       | 优点                                                     | 缺点                                         |
|------------|--------------------------------------------------------|--------------------------------------------|
| **UDP**    | - 低延迟<br>- 实现简单，资源占用低<br>- 支持广播和多播                     | - 不可靠传输，1.1版本开始增加ACK<br>- 无流控机制<br>- 安全性低  |
| **TCP**    | - 可靠传输，数据完整性高<br>- 长连接管理简单<br>- 兼容性强                   | - 较高延迟<br>- 资源占用多<br>- 不支持广播或多播            |
| **WebSocket** | - 双向通信，实时性好<br>- 兼容性强，易穿越防火墙<br>- 超高安全性，使用了TLS 加密和身份认证 | - 实现复杂度高<br>- 需维持长连接，增加服务器负担<br>- 延迟高于 UDP |

