# mist-server

**Mist (雾)** 代理协议的服务端实现。

## 特性
- 真 TLS 1.3 + 真域名证书
- SNI 分流：Mist 流量走协议处理，其他走后端（如 Xray）
- 访客伪装站（decoy）：非 Mist 流量看到正常网站
- XChaCha20-Poly1305 加密
- 多路复用、心跳、会话恢复
- UDP 中继（DNS、QUIC）

## 安装

```bash
git clone https://github.com/cien121/mist-server.git
cd mist-server
go build -o mist-server ./cmd/mist-server
go build -o mist-keygen ./cmd/mist-keygen
```

## 生成账号

```bash
./mist-keygen
# 输出 Client ID (16字节hex) 和 Auth Key (32字节base64)
```

## 配置

`config.json`:
```json
{
  "listen": ":443",
  "mist_domain": "mist.example.com",
  "cert_file": "/path/to/fullchain.pem",
  "key_file": "/path/to/privkey.pem",
  "accounts": "/path/to/accounts.json",
  "mist_backend": "127.0.0.1:14431",
  "default_backend": "127.0.0.1:14433"
}
```

`accounts.json`:
```json
{
  "client-id-hex": "auth-key-base64"
}
```

## 运行

```bash
./mist-server -config config.json
```

## 协议规约

见 [SPEC.md](SPEC.md)。
